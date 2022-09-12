## This program will request a Fargate ECS call
## The ECS container is a waves leasing collector task
## Config settings are read from S3 bucket, config.json 
## Trigger : API gateway call with some env key/values pairs
## Output : Fargate ECS request
##
## NOTES
## - Lambda IAM Role needs besides policy 'ecs:runtask' also
##   policy 'iam.passrole' for the ecsTaskexecution role,
##   else lambda will be deniedaccess if container image is
##   requested from registry.
## =========================================================
import time
import json
import boto3
import botocore
import requests             ## custom Layer module (aws native doesn't work)
import bcrypt               ## custom Layer module [For hashing and salting]
import pprint
import os
import jwt                  ## custom Layer module
import base58               ## custom layer module
import pybase64 as base64   ## custom Layer module

from botocore.exceptions import ClientError
from jwt.exceptions import ExpiredSignatureError
from jwt.exceptions import InvalidSignatureError
from time import sleep

pp = pprint.pprint
settings_bucket         = os.environ.get("script_settings_bucket")
config_file             = os.environ.get("scripts_settingsfile")
account_handling_config = os.environ.get("account_handling_config")
secretkeyname           = os.environ.get("my_webtoken_secret")
data_bucket             = os.environ.get("wldaas_data_bucket")
lpos_config_file        = os.environ.get("waves_lpos_settings")

#Set Global constants
client          = boto3.client('dynamodb')
dynamodbtable   = 'WLDaaS'
tableindex_jwt  = 'Wallet-JWToken-index'
tableindex_apikey = 'Wallet-Apikey-index'
cte             = int(time.time())          ## Current time (epoch secs)
day_secs        = 24*3600                   ## One day in seconds
sessionid = 'unspecified yet'
mywavespaymenttxid = 'unspecified yet'

my_json_constants = {
                        "waves" :   {
                                        "querynode_api" : "https://nodes.wavesnodes.com",
                                        "txinfo_uri" : "/transactions/info/",
                                        "wldaas_pay_validate_sleeptimer" : 1,
                                        "wldaas_pay_validate_retries" : 2
                                    }
                    }

tablekeys   = {
                'pkey'      : 'Wallet',
                'skey'      : 'Email',
                'ct'        : 'Creationtime',
                'et'        : 'Expiretime',
                'pwdhash'   : 'Passwordhash',
                'signuphash': 'Signuphash',
                'jwtoken'   : 'JWToken',
                'paytxid'   : 'Paytxid',
                'walletadd' : 'Walletadd',
                'freeruns'  : 'Freeruns',
                'taskstate' : 'Taskstate',
                'apikeyhash': 'APIkeyhash'
              }

pk = tablekeys['pkey']
sk = tablekeys['skey']
skjwt = tablekeys['jwtoken']
skapikey = tablekeys['apikeyhash']

##file names/paths
datapath             = 'data/'           ##Object folder to store WLDaaS results
bdfile               = 'batchinfo.json'  ##File which stores block numbers
settings_file        = 'settings.json'   ##File which stores user specific settings
leaseinfofile_prefix = 'prevleaseinfo_startblock_'


## Check S3 object key existence
## ===========================================================
def s3_object_existence(bucket, key):
    s3 = boto3.resource('s3')
    
    try:
        s3.Object(bucket, key).load()
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == "404":
            # The object does not exist.
            return False
        else:
            # Something else has gone wrong.
            raise
    else:
        # The object does exist.
        return True
## =============== END S3 object existence check =============


## Read S3 object function
## params:
## - bucket : S3 bucket name
## - key.   : object name
## ===========================================================
def read_s3_object(bucket,key):
    s3 = boto3.resource('s3')
    s3object = s3.Bucket(bucket).Object(key)
    file_content = s3object.get()['Body'].read().decode('utf-8')
    return file_content
## =============== END Get S3 object function ================


## Write S3 object function
## params:
## - bucket : S3 bucket name
## - key    : object name
## - data   : object data to write
## ===========================================================
def write_s3_object(bucket,key, data):
    s3 = boto3.resource('s3')
    s3object = s3.Bucket(bucket).Object(key)
    file_content = s3object.put(Body=data)
    return file_content
## =============== END Get S3 object function ================


## Find all url arguments given by user
## Do Basic sanity checking
## Create strings "key=value" and add to command array
## If missing required key or disruptive value, add 'abort' to array
## The command array will be send along in the ecs runtask call
## params;
## - paramstring : json dict with all given args as key/value pairs
##
## return cmd_array with all pairs as strings [ "key1=value", "key2=value" ]
def set_url_args(paramstring):
    
    ## Left column URL params set by frontend
    ## Right column syntax set in cmd_array and send to container
    # wallet=       ('myleasewallet='')
    # startblock=   (first leaser block, is payblock at first start, 'startblock=')
    # payblock=     (start scanning for next run, 'payblock=')
    # stopblock=    (stop scanning, 'stopblock=')
    # blocks=       (window size, 'blocks=')
    # pay=          (do also payments, 'pay=')

    
    ## batchdata written by container: 
    # {"batchdata":{"paymentid":"3","scanstartblock":"","paystartblock":"","paystopblock":""}}
    
    ## paramstring : urls arguments set by user input
    ## define here the literally the keynames that could be set by user
    w       = 'wallet'
    s3_wallet_folder = 's3_wallet_folder'
    start   = 'startblock' ##First leaser block
    stop    = 'stopblock'
    pay     = 'payblock'
    blocks  = 'blocks'
    reset   = 'reset'
    force   = 'force'
    payrequest = 'pay'
    fs          = 'feeshare'
    rs          = 'rewardshare'
    email       = 'email'
    wavestxid = 'mywavespaymenttxid'
    
    
    cmd_array = [ 'sessionid='+sessionid ]
    abort = False
    
    #print('paramstring received from Frontend:')
    #print(paramstring)
    
    if w in paramstring: ##wallet found
        if len(paramstring[w]) != 0:  ##Values found in URL 
            commandstring = 'myleasewallet' + '=' + paramstring[w]
            cmd_array.append(commandstring)
            
            """
            ## Check if batchinfo file exists (if not, it is the first run)
            batchinfo_s3_object = paramstring[s3_wallet_folder] + '/' + datapath + bdfile

            if (s3_object_existence(data_bucket, batchinfo_s3_object) == True): ##This is NOT the first run, batchinfo exists
                ##Check if previous leaseinfo file exists
                previous_leaseinfo_file = paramstring[s3_wallet_folder] + '/' + datapath + leaseinfofile_prefix + paramstring[pay] + '.json'
                
                ##Check is the previous leaseinfo file is available and the overwrite toggle switch was set
                ##If no previous leaseinfo file is there, we have no leaser info and thus active leasers will be missed
                ##The overwrite togle switch is used to overwrite this if desired
                if (s3_object_existence(data_bucket, previous_leaseinfo_file) == False and paramstring[reset].lower() == 'false'):
                    abort = True ##The payblock to start scanning was changed to a value from which we do not have leaseinfo stored
                    aborttext = "No previous leasinfo file for block " + paramstring[pay] + " available.\nUse toggle switch 'overwrite' to start from block " + paramstring[pay]
                    abortmsg = { "abortmsg" : aborttext } ##Extract this message and create alert in frontend
                    cmd_array.append(abortmsg)
            """
    
            if start in paramstring: ##startblock found
                if len(paramstring[start]) != 0:
                    commandstring = start + '=' + paramstring[start]
                    cmd_array.append(commandstring)
    
            if stop in paramstring: ##stopblock found
                if len(paramstring[stop]) != 0:
                    commandstring = stop + '=' + paramstring[stop]
                    cmd_array.append(commandstring)

            if pay in paramstring: ##payblock found
                if len(paramstring[pay]) != 0:
                    commandstring = pay + '=' + paramstring[pay]
                    cmd_array.append(commandstring)

            if blocks in paramstring: ##block window found
                if len(paramstring[blocks]) != 0:
                    commandstring = blocks + '=' + paramstring[blocks]
                    cmd_array.append(commandstring)
                    
            if reset in paramstring: ##reset found, overwrite some previous data
                value = paramstring[reset].lower() ##Turn to lowercase
                commandstring = reset + '=' + value
                cmd_array.append(commandstring)

            if force in paramstring: ##start if stopblock > current height
                value = paramstring[force].lower() ##Turn to lowercase
                commandstring = force + '=' + value
                cmd_array.append(commandstring)
            
            if payrequest in paramstring:
                value = paramstring[payrequest].lower() ##Turn to lowercase
                commandstring = 'dopayments' + '=' + value #'pay' name can not be used due to overlap with 'paystart'
                cmd_array.append(commandstring)
                
            if fs in paramstring: ##feeshare found
                if len(paramstring[fs]) != 0:
                    commandstring = fs + '=' + paramstring[fs]
                    cmd_array.append(commandstring)

            if rs in paramstring: ##rewardshare found
                if len(paramstring[rs]) != 0:
                    commandstring = rs + '=' + paramstring[rs]
                    cmd_array.append(commandstring)
            
            if email in paramstring: ##email found
                if len(paramstring[email]) != 0:
                    commandstring = email + '=' + paramstring[email]
                    cmd_array.append(commandstring)
            
            if wavestxid in paramstring: ##paytransaction id found
                if len(paramstring[wavestxid]) != 0:
                    commandstring = wavestxid + '=' + paramstring[wavestxid]
                    cmd_array.append(commandstring)
                    global mywavespaymenttxid
                    mywavespaymenttxid = paramstring[wavestxid]
            
            if s3_wallet_folder in paramstring: ##s3 wallet folder is found
                if len(paramstring[s3_wallet_folder]) != 0:
                    commandstring = s3_wallet_folder + '=' + paramstring[s3_wallet_folder]
                    cmd_array.append(commandstring)

            else: #no payment was found, abort
                abort = True
            
        else: ##No values found in URL, set abort
            abort = True
            aborttext = "No values found in url. Nothing to do."
            abortmsg = { "abortmsg" : aborttext } ##Extract this message and create alert in frontend
            
    else: ## No wallet found, set abort
        abort = True
        aborttext = "No wallet address in url. Nothing to do."
        abortmsg = { "abortmsg" : aborttext } ##Extract this message and create alert in frontend
    
    if abort == True: cmd_array.append('abort') ##No usefull arguments in url
    
    return cmd_array


## Method to decode web token
## Checked on expiration and signature validation
## return decoded token or error
## params:
## - token: encoded webtoken
## - wallet: wallet address
## - mytime: the account creation time
def decode_token (token, secret):

        try:
                header_data = jwt.get_unverified_header(token)
                decoded_token = jwt.decode(
                                        token,
                                        key=secret,
                                        algorithms=[header_data['alg'], ]
                )
        except InvalidSignatureError as error:
                print(f'Unable to decode jwt token, error: {error}')
                print(' ** Someone tampering with tokens? **')

                result = { "alert" : "Token error. Login again." }

        except ExpiredSignatureError as error:
                print(f'Unable to decode jwt token, error: {error}')
                print('Token expiration, need renewal.')

                result = { "alert" : "Token expired. Login again." }

        except:
                print(f'Unable to decode jwt token, error: {error}')

                result = { "alert" : "Undefined Token error. Contact admin." }

        else:
                result = { "data" : decoded_token }

        return result
## ============= END decode token method ==============



    
    
    

## Method to authenticate the token found in the cookie
## input:
## - token from browser
## - secret from aws secret manager
## ===========================================================
def authenticate (token, secret):
        
        returnkeys = []
        result = { "authenticated" : False }
        decoderesult = decode_token (token, secret)

        if ('alert' not in decoderesult and 'data' in decoderesult): ##Seems a valid token

                wallet = decoderesult['data']['wallet']
                
                ##Query wallet/token from DB
                ##If wallet/token is found, there is an 'Items' array with value, else array is empty
                items = query_item ( pk, skjwt, wallet, token, tableindex_jwt ) ##all items are returned
                
                #print(items['Items'][0]) ##TROUBLESHOOT PRINT, ONLY FOR TESTING
                email = items['Items'][0][sk]['S']
                walletadd = items['Items'][0][tablekeys['walletadd']]['S']
                
                try:
                        items['Items'][0][skjwt] ##if the token was in the query, this should work

                except: ##Security issue, no item found, this is not aligned to original login
                        print('Someone tampering with tokens!')
                        result['alert'] = "Misaligned token content. Login again."

                else:
                        try:
                                items['Items'][0]['Signuphash']

                        except: ##Token Authentication successfull
                                result['authenticated'] = True

                        else: ##Account waiting for validation
                                result['alert'] = "Account waiting for validation. Check email."

        else: ##We have an invalid token
                print('Invalid token detected.')
                result['authenticated'] = False
                result['alert'] = "Authentication Token seems invalid. Login again."

        if result['authenticated']: ##If token was succesfully authenticated
            returnkeys.append(wallet)
            returnkeys.append(email)
            returnkeys.append(walletadd)
        
        return result, returnkeys
## ============= END authenticate token method ==============




## Method to get a database item
## params:
## - pkey: primary key (the value of the key)
## - skey: sort key (the value of the key)
## - keys=[]: array with all the keys to get from the item
##
## The params used should be available in the db as no results
##
## return body
## if there are no items : body will be { "Item" = {} } (length 0)
## if there are items: body will be { "Item" : { queried objects } }
##
## example;
## - wallet="Abc1234xyZ"
## - username="test@domain.nl"
## - password="Passwordhash" <- item key name
## - pwd_reset_id="password_Reset" <- item key name
##
## get_item ( wallet, username, keys=[ password, pwd_reset_id ] )
## ===========================================================
def get_item (pkey, skey, keys=[]):
    
    itemtotal = len(keys)
    
    Keydata = {
                'Wallet': { 'S' : pkey },
                'Email' : { 'S' : skey }
              }

    
    if itemtotal == 0:  ## Retreive all key values from an item
        data = client.get_item(
                TableName = dynamodbtable,
                Key=Keydata
        )
    else:           ## Retreive only values specified with keys array
        projectexpressionstring = ""
        for item in keys:
            index = keys.index(item)
            projectexpressionstring += item
            if index < itemtotal-1: projectexpressionstring += ","

        data = client.get_item(
                TableName = dynamodbtable,
                ProjectionExpression = projectexpressionstring,
                Key=Keydata
        )
        
    response = {
      'statusCode': 200,
      'body': data,
      'headers': {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    }
    return response['body']
## ================ END get database item ===================





## Method to get query second index database item
## params:
## - pkeyheader: Name of the primary key
## - sortkeyheader: Name of the sort key
## - pkeyattr: Value for the primary key
## - skeyattr: Value for the sortkey
## - tableindexname: name of the secondary index
## - keys = [ 'attribute1', 'attribute2', 'attributeX' ] /which attribute values
##
## return
## - If no hit, return empty dict object
## - If it is a hit, there is an key 'Items' returned with attr/values
## =============================================================================
def query_item ( pkeyheader, sortkeyheader, pkeyattr, skeyattr, tableindexname, keys=[] ):
    
    itemtotal = len(keys)
    keyconditionstring = pkeyheader+" = :v_"+pkeyheader+" AND "+sortkeyheader+" = :v_"+sortkeyheader

    if itemtotal == 0:  ## Retreive all key values from an item
    
        data = client.query(
        TableName = dynamodbtable,
        IndexName = tableindexname,
        KeyConditionExpression = keyconditionstring,
        ExpressionAttributeValues = {
            ":v_"+pkeyheader : { "S" : pkeyattr },
            ":v_"+sortkeyheader : { "S" : skeyattr }
        },
        ScanIndexForward = False
        )
    
    else:       ## Filter with projection exxpression and only retreive keys=[ ] items
    
        projectexpressionstring = ""
        
        for item in keys:
            index = keys.index(item)
            projectexpressionstring += item
            if index < itemtotal-1: projectexpressionstring += ","

        data = client.query(
        TableName = dynamodbtable,
        IndexName = tableindexname,
        KeyConditionExpression = keyconditionstring,
        ExpressionAttributeValues = {
            ":v_"+pkeyheader : { "S" : pkeyattr },
            ":v_"+sortkeyheader : { "S" : skeyattr }
        },
        ProjectionExpression = projectexpressionstring,
        ScanIndexForward = False
        )


    response = {
      'statusCode': 200,
      'body': data,
      'headers': {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    }
    
    return response['body']
## ========================== END get database item ============================




## Main function
## ===========================================================
def lambda_handler(event, context):
    #print(context)
    #print(event)
    
    webtokensecret  = json.loads(get_secret(secretkeyname))['tokensecret'] ##secret for token creation
    json_config = json.loads(read_s3_object(settings_bucket,config_file))
    json_config_accounts = json.loads(read_s3_object(settings_bucket, account_handling_config))
    json_config_lpos = json.loads(read_s3_object(settings_bucket, lpos_config_file))
    #ed = int(json_config_accounts['timers']['webtoken_expiration_hrs'])  ##Expiration duration webtoken
    ed = float(json_config_accounts['timers']['webtoken_expiration_hrs'])  ##Expiration duration webtoken
    acao = json_config_accounts['acao']  ##Access-Control-Allow-Origin domain (Cloudfront origin)
    cookiedomain    = json_config_accounts['cookiedomain'] ##Domain to set in browsercookie

    
    ## LambdaContext([aws_request_id is unique string]
    global sessionid
    sessionid = context.aws_request_id
    eventheaders = event['headers']
    paramstring = event['queryStringParameters'] ##Catch all url parameters from Frontend/API server
    
    print('paramstring :', paramstring)
    
    if 'cookie' not in eventheaders.keys() and 'apikey' not in paramstring.keys():    ##Found no cookie
        #print('No cookie found. Need to login first.')
        cookie = False
        resp_body = {}
        alerttext = ""
        ## Next procedure is to check if the payment was done and the cookie expired in between
        ## Waves txid will be send to browser and the user can login again
        ## Browser can pick it up can start collector without a new payment needed
        wavestxid = paramstring.get('mywavespaymenttxid') ## Get waves transaction id
        
        if wavestxid != None: ## Waves Transaction ID discovered (payment was done)
            print('Waves payment for WLDaaS service was done, but cookie expired in between.')
            
            alerttext = "Your transaction was received while your session cookie expired.\n" +\
                        "Please login again and the collector task will start automatically.\n" +\
                        "In case of problems, keep the Waves txid as reference;\n" +\
                        "\n-- " + wavestxid + " --\n" +\
                        "*********************************************************\n" +\
                        " DO NOT refresh or close your browser until logged in\n" +\
                        " again and the collector task has been started."
            
            resp_body['wavestxid'] = wavestxid
            #resp_body['paramstring'] = paramstring

            
        else: ## No waves transaction discovered, normal session expiration
            alerttext = "Session expired, please login."

        print('No cookie present. Client needs to login.')
        
        resp_body['alert'] = alerttext
        resp_body['browserreload'] = True
        
    else: ##Session with cookie OR with API key => start authentication and subsequent requests

        authresult = {}
        mycookie = eventheaders.get('cookie')
        myapikey = paramstring.get('apikey')
        
        if mycookie != None:                    # Frontend session with Cookie
            sessiontype = 'websession'
            token = mycookie.split('=', 1)[-1]  # Extract auth token from cookie
            authresult, partkeys = authenticate (token, webtokensecret)
            
        elif myapikey != None:                  # API session
            myapikeybytes = str.encode(myapikey) 
            email = paramstring.get('email')
            wallet = paramstring.get('wallet') 
            sessiontype = 'apisession'
            apikeyhashtablehead = tablekeys['apikeyhash']
            walletaddtablehead = tablekeys['walletadd']
            freeruntablehead = tablekeys['freeruns']
            
            try:
                #item = get_item( wallet, email, keys=[ apikeyhashtablehead ] ).get('Item')
                item = get_item( wallet, email ).get('Item')
                sapikeyhash = item.get(apikeyhashtablehead)['B']
                freerunbudget = item.get(freeruntablehead)
                if freerunbudget != None:
                    freerunbudget = int(freerunbudget['N'])
                else:
                    freerunbudget = 0
                
                if len(sapikeyhash) > 0: ##API hash found (not zero)
                    print('Found API keyhash. Authenticating session.')
                    if bcrypt.checkpw ( myapikeybytes, sapikeyhash): #API key received matches with stored hash
                        print('API key authenticated succesfully.')
                        authresult['authenticated'] = True
                        partkeys = [ wallet, email, item.get(walletaddtablehead)['S'] ]
                    else:
                        alerttext = 'API key authentication failed'
                        authresult['authenticated'] = False
                        authresult['alert'] = alerttext

                else:
                    alerttext = 'No APIkey hash available. Authentication invalid.'
                    authresult['authenticated'] = False
                    authresult['alert'] = alerttext

                        
            except:
                alerttext = 'No APIkey hash available. Authentication invalid.'
                authresult['authenticated'] = False
                authresult['alert'] = "Authentication Token seems invalid. Login again."

    
        else:
            sessiontype = 'invalid'
            alerttext = 'invalid parameters used.'
            authresult['alert'] = alerttext
            authresult['authenticated'] = False 
        

        
        if authresult['authenticated']:     ##VALID token authentication
        
            result = {}
            if sessiontype == 'websession':
                cookie = True
                result['paramstring_validation'] = 'VALID'
            elif sessiontype == 'apisession':
                result = validate_paramstring(paramstring, json_config_lpos)
                if result['paramstring_validation'] == 'INVALID':
                    print(result)
        
        #VALID token authentication & VALID parameter string
        if authresult['authenticated'] and result['paramstring_validation'] == 'VALID':

            if len(partkeys) != 0:  ##keys were returned by authenticate function
                wallet = partkeys[0]
                email = partkeys[1]
                walletadd = partkeys[2]
            else:
                wallet = 'No wallet found in token data!'   ##This should not happen
                email = 'No email found in token data!'     ##This should not happen
            
            s3_wallet_folder = wallet + '__' + walletadd   
            paramstring['wallet'] = wallet ##Add wallet to paramstring
            paramstring['email'] = email ##Add email to paramstring
            paramstring['s3_wallet_folder'] = s3_wallet_folder
            nrkey = 'loadnextrun' ##This url key is used to reload batchinfo.json
            configurekey = 'settings' ##This url key is used to get/set default settings
            resetkey = 'reset' ##This url key is used to neglect previous leasedata files found ('true'/'false')
            s3settingsobject = s3_wallet_folder + '/' + settings_file ##Customer settings file
            getuniquepayid = 'getuniquepayid' ##This url key is used when a blockchain payment to WLDaaS wallet should be done
            
            print('sessionid: ' + sessionid + ', url paramstring received: ')
            print(paramstring)
            
            if nrkey in paramstring: ##Button 'reload next run data' requested
                value = paramstring[nrkey].lower()
                if value == 'true' or value == 'yes': ##Get data from store and return to Frontend
                    print("reload next batchdata requested, wallet: " + wallet + ' (' + s3_wallet_folder + ')')
                    
                    ##Start retreive batchinfo data from S3
                    batchinfo_s3_object = s3_wallet_folder + '/' + datapath + bdfile
                    
                    try:    ##Load batchinfodata for next run if available
                        batchdata = json.loads(read_s3_object(data_bucket, batchinfo_s3_object))
                    except: ##No batchdata found (no collector run done yet)
                        resp_body = { "alert" : "No batchdata found.\nStart your first collector run.",
                                      "wallet" : wallet } ##If no next run data found, set empty data
                    else: ##Found next run batchdata
                        resp_body = batchdata
                        resp_body['wallet'] = wallet
                        resp_body['alert'] = "Succesfully loaded blocks for next run."
                        
                    try:    ##Load default settingsfile if available
                        defaults = json.loads(read_s3_object(data_bucket, s3settingsobject))
                    except:
                        resp_body['defaults'] = "none"
                    else:
                        resp_body['defaults'] = defaults
                   
                    
            elif configurekey in paramstring:  ##Button 'settings' was pushed
                ckvalue = paramstring[configurekey] #Value of settings param
                
                if ckvalue == 'load':  ##Request to load data from store file
                    try:
                        json_custom_settings = json.loads(read_s3_object(data_bucket,s3settingsobject))
                    except:
                        resp_body = { "alert" : "No settings configured yet.\nPlease set some defaults." }
                    else:
                        resp_body = { "settings" : json_custom_settings } ##Return all settings
                    
                else:   ##Request to save data to settings file
                    ckbytes = ckvalue.encode('utf-8')
                    settingsdata_json = (base64.b64decode(ckbytes)).decode('utf-8')
                    write_s3_object(data_bucket, s3settingsobject, settingsdata_json )
                    resp_body = { "alert" : "settings saved.",
                                  "settings" : settingsdata_json }
                                  
            elif getuniquepayid in paramstring:  ##Unique payid needed for payment to WLDaaS wallet
                ## Also check here if the previous leaseinfo file is found for the requested block
                ## If not, try to find nearest lower block and return nearest block
                ## If no previous leaseinfo file found at all return firstleaserblock
                encodedbase58Bytes = bytes(sessionid, "utf-8")
                encodedbase58String = base58.b58encode(encodedbase58Bytes).decode("utf-8")

                print(  'A pay transaction for a WLDaaS service is needed.\n' +
                        'Returning Pay-ref.ID: ' + sessionid + ' (base58: ' + encodedbase58String + ')\n' +
                        'This id will be set in the Waves Txs attachment and is used to verify the payment,\n' +
                        'before the WLDaaS service is delivered.')
                
                resp_body = {
                                "uniquepayid" : {
                                    "utf8" : sessionid,
                                    "base58" : encodedbase58String
                                }
                            }
                
                ##Check if there is a previous leaseinfo file available for the requested payblock
                ## ===============================================================================
                prevleaseinfoblockprefix = s3_wallet_folder + '/' + datapath + leaseinfofile_prefix
                if sessiontype == 'websession':
                    requestedblock = paramstring['prevleaseinfoblock']
                elif sessiontype == 'apisession':
                    requestedblock = paramstring['payblock']
                    
                reset = paramstring.get(resetkey) ##false or true or None

                try:
                    foundfile = get_matching_s3_keys ( data_bucket, prefix=prevleaseinfoblockprefix+requestedblock, suffix='.json' )[0]
                    
                except: ## File for requested block not found, let's try to find the nearest lower if available
                    print('Could not find previous leaseinfo file for requested payblock: ' + requestedblock)
                    nearestblocklist = get_matching_s3_keys ( data_bucket, prefix=prevleaseinfoblockprefix, suffix='.json', findnearest=requestedblock )
                    
                    if nearestblocklist != [] and reset == 'true': ##Overwrite with start from requested block
                        print('Found previous leasedata files, but overwrite was requested. Start from requested.')
                        resp_body["uniquepayid"]["previousleaseinfo"] = 'forcerequested'
                        
                    elif nearestblocklist != []: #We caught the nearest and offer to start from there
                        nearestblock = nearestblocklist[0]  #Get nearest block from list
                        print('Found nearest lower previous leasinfo file for block ' + str(nearestblock))
                        resp_body["uniquepayid"]["previousleaseinfo"] = str(nearestblock)
                        
                    else:
                        print('There is no previous leasinfo file found at all. Scanning should start from 1st leaser block.')
                        host = my_json_constants['waves']['querynode_api']
                        uriadd = (json_config_lpos['api_uris']['active_leases']).replace('{address}', wallet)
                        allleases = get_api_request(host+uriadd).get('answerlist')
                        if allleases == None: allleases = []
                        myfirstleaserblock = find_1st_leaser_block(allleases, wallet)
                        if myfirstleaserblock != 0: ##Found first leaser block 
                            resp_body["uniquepayid"]["isfirstleaserblock"] = "yes"
                        resp_body["uniquepayid"]["previousleaseinfo"] = str(myfirstleaserblock)
                else:
                    print('Found match for ' + foundfile)
                    resp_body["uniquepayid"]["previousleaseinfo"] = str(requestedblock) 
                ## ===============================================================================


                
                if paramstring.get('freerun') == 'true':    ##A free run was requested
                    print('FREE RUN REQUESTED!!')
                    
                    if sessiontype == 'websession':
                        try:
                            items = query_item ( pk, skjwt, wallet, token, tableindex_jwt, keys=['Freeruns'] ) ##check freerun amount
                            freerunbudget = int(items['Items'][0]['Freeruns']['N'])
                        except:
                            freerunbudget = 0
                    
                    if freerunbudget > 0:   ##Free run accepted
                        resp_body['uniquepayid']['freerun'] = 'accept'
                        freerunbudget -= 1
                        ## Put here update actions to decrease freeruns -1 & add FREERUN to payref id
                        update_item(wallet, email, paytxid=sessionid+'-FREERUN', freeruns=freerunbudget, action='set') 
                        
                    else:
                        resp_body['uniquepayid']['freerun'] = 'reject'
                    
                else:
                    ## Store this payment ID in db, expect this ID when Waves Txs is validated
                    ## Waves transaction needs to save use this ID in attachment
                    ## Add freerun to sessionid
                    update_item(wallet, email, paytxid=sessionid, action='set') 


            else: ##Collector run requested
                
                if sessiontype == 'websession':
                    sortkeyvalue = token
                elif sessiontype == 'apisession':
                    sortkeyvalue = email
                    
                ## Start validator of received payment for the WLDaaS service
                result = valid_payment_received (json_config_lpos, my_json_constants, paramstring, sortkeyvalue, sessiontype)

                if result.get('VALID_PAYMENT') != None:
                    print('Succesfully validated payment received. Proceed to container task start.')
                    payrefid = result.get('VALID_PAYMENT')
                    
                    proceed_to_collector_start = True
                    
                elif result.get('UNCHECKED_PAYMENT') != None:
                    print('Could not check payment received. Blockchain unreachable.')
                    print('But will start collector task anyway.')
                    payrefid = result.get('UNCHECKED_PAYMENT')
                    
                    proceed_to_collector_start = True
                    
                else:
                    print('There are errors, payment validation check was invalid')
                    payid = result.get('refpayid')
                    resp_body = { "alert" : result.get('alert'),
                                  "errordata" : result }
                    
                    proceed_to_collector_start = False
                
                if proceed_to_collector_start == True:
                    
                    containername = json_config['containername']
                    ecs_override_json = { 'overrides' : { 'containerOverrides' : '' } }
                    override_array = [] ##Array with all override parameters for ECS API call 
                    ecs_cmds = set_url_args(paramstring) ##receive array with container overrides
                    ecs_cmds.append('payrefid=' + payrefid)
                    print(ecs_cmds)
                
                    ##NOTE
                    ##Values with spaces needs to pushed with quotes into array ecs_cmds
                    ##the container will split the arguments on space. The quotes are needed
                    ##to contain one string value and not having it splitted due to the space
                    ##i.e.: servicename="My Name" instead of servicename=My Name
                
                    try:    ##Load default settingsfile if available
                        defaults = json.loads(read_s3_object(data_bucket, s3settingsobject))
                    except: ##No default settings file available
                        print('No settingsfile available.')
                        ecs_cmds.append('servicename="Waves Service"')
                        ecs_cmds.append('nopayoutaddresses=')
                    else: ##Default settings file available
                        print('Succesfully loaded default settings from settingsfile.')
                        update_ecs_cmds_array (defaults, ecs_cmds)
    
                    if 'abort' not in ecs_cmds:  ##Valid input, we can launch a container task
                    
                        print('paramstring send to container:')
                        print(ecs_cmds)
                    
                        obj = { 'name' : containername,
                                'command' : ecs_cmds }
    
                        override_array.append(obj)
                        ecs_override_json['overrides']['containerOverrides'] = (override_array)
                        client = boto3.client('ecs')
                    
                        print('Override array used in contailer task start:')
                        print(ecs_override_json['overrides']['containerOverrides'])
                        print()
                        print('Container ' + containername + ' start initiated.')
                    
                        response = client.run_task(
                            cluster= json_config['cluster'],
                            launchType= json_config['launchType'],
                            taskDefinition= json_config['taskDefinition'],
                            count= int(json_config['count']),
                            platformVersion= json_config['platformVersion'],
                            networkConfiguration= json_config['networkConfiguration'],
                            overrides= ecs_override_json['overrides']  ## Used for custom values for wallet, startblock, stopblock etc.
                        )
                    
                        #print(response)
                        update_item (wallet, email, removekeyarray=[ 'paytxid' ], action='remove' ) ## Paytxid can not be used anymore
                        
                        ##Estimate how long the collector task will take
                        one_block_collect_delay = float(json_config_lpos['toolbaseconfig']['one_block_collect_time_mins'])
                        if sessiontype == 'websession':
                            blocks  = int(paramstring['blocks'])
                        elif sessiontype == 'apisession':
                            blocks  = int(paramstring['stopblock']) - int(paramstring['payblock']) + 1
                            
                        estimated_collect_time  = int(blocks * one_block_collect_delay) ##expected collector time in minutes
                        
                        
                        
                        resp_body = { "alert" : "Collector task started.\n" +
                                                "You will receive an email when finished.\n" +
                                                "This run is expected to take " + str(estimated_collect_time) + " minutes.\n" }
                                                
                        resp_body['wavestxid'] = "delete_key"
      
                    else:   ##'abort' set due to invalid url params, exit
                        ##Extract abort message object ('abortmsg') in array and set in resp_body as alert
                        ##print(ecs_cmds)
                        for item in ecs_cmds:
                            if isinstance(item, dict):
                                if 'abortmsg' in item:
                                    alert = item['abortmsg']

                        try:
                            alert
                        except: ##If alert text was not set in url return array, then set default error
                            alert = "Invalid values used.\nAborted collector run :-("
        
                        resp_body = {
                                    "body": { 
                                        "params_used" : paramstring,
                                        "params_example" : [
                                                "wallet=3P7ajba4wWLXq6t1G8VaoaVqbUb1dDp8fm4",
                                                "startblock=110000",
                                                "stopblock=120000",
                                                "blocks=10000",
                                                "payblock=110000",
                                                "reset=yes_no",
                                                "force=yes_no"
                                                ]
                                    },
                                    "alert" : alert,
                                    "wavestxid" : "delete_key"
                                }
        
        elif authresult['authenticated'] and result['paramstring_validation'] == 'INVALID':
            resp_body = { "alert" : result['alert'] }
            if sessiontype == 'apisession':
                if result.get('solution') != None:
                    resp_body['solution'] = result.get('solution')
            print(resp_body)
        
        elif authresult['authenticated'] == False:  ##INVALID Token/API authentication
            if sessiontype == 'websession':
                text = 'Invalid webtoken authentication'
            elif sessiontype == 'apisession':
                text = 'Invalid API key'

            if not authresult['alert']: resp_body = { "alert" : text }
            else: resp_body = { "alert" : authresult["alert"] }
            
            if sessiontype == 'websession':
                resp_body['wavestxid'] = 'delete_key'
                resp_body['browserreload'] = True
        
        ##END else Found cookie, start authentication of token
        
        
    returnobject = {
                     'statusCode': 200,
                     'headers': {
                            'Access-Control-Allow-Headers': 'Content-Type',
                            'Access-Control-Allow-Origin': acao,
                            'Access-Control-Expose-Headers': 'token',
                            'Access-Control-Allow-Credentials' : 'true',
                            'Access-Control-Allow-Methods': 'GET'
                                },
                     'body' : json.dumps(resp_body)
                   }
    
    return returnobject
                            
## =================== END Main function =====================


## Function that GET json object
## input params;
## - fullurl: http(s)//node:(port)/uri
## - jsonobject: key value pairs to feed (optional)
## 
## return json object received
## ========================= BEGIN ===========================
def get_api_request (fullurl, jsonobject=None):
    if jsonobject is None:
        jsonobject = {}

    returnobject = {}

    try:
        response = requests.get(fullurl, jsonobject)
    except:
        message = "Errors prevented to fullfill api call to " + fullurl
        returnobject =  {
                            "message" : message,
                            "statuscode" : 999
                        }

        return returnobject

    else:
        sc = response.status_code
        jr = response.json()
        
        if isinstance(jr, list):
            returnobject['answerlist'] = jr
        else:
            returnobject = jr
            
        returnobject['statuscode'] = sc

        return returnobject
## =========================  END  ===========================



# This function validates all parameter key/values for an API request
def validate_paramstring (url_parameterstring, json_config_lpos):
    
    result          = { "paramstring_validation" : 'VALID' }
    startblock      = url_parameterstring.get('startblock')
    payblock        = url_parameterstring.get('payblock')
    stopblock       = url_parameterstring.get('stopblock')
    feeshare        = url_parameterstring.get('feeshare')
    rewardshare     = url_parameterstring.get('rewardshare')
    
    
    
    force           = url_parameterstring.get('force')
    if force != None:
        force = force.lower()
    
    pay             = url_parameterstring.get('pay')
    if pay != None:
        pay = pay.lower()
    
    loadnextrun     = url_parameterstring.get('loadnextrun')
    if loadnextrun != None:
        loadnextrun = loadnextrun.lower()
        
    getuniquepayid  = url_parameterstring.get('getuniquepayid')
    if getuniquepayid != None:
        getuniquepayid = getuniquepayid.lower()
        
    
    print('Validating url parameters used.')
    
    
    if 'email' not in url_parameterstring.keys():
        alerttext = 'Missing username idendity, usage: email=yourusername@domain.com'
        result["paramstring_validation"] = 'INVALID'
        result["alert"] = alerttext
        return result
    
    if loadnextrun == 'true' or loadnextrun == 'yes':
        return result
    
    if getuniquepayid == 'true' or getuniquepayid == 'yes':
        if payblock != None:
            return result
        else:
            alerttext = "Missing payblock (Where this session will start), usage: payblock=<block>"
            result["paramstring_validation"] = 'INVALID'
            result["alert"] = alerttext
            return result
     
    if 'mywavespaymenttxid' not in url_parameterstring.keys():
        alerttext = 'Missing waves transaction-id. Can not validate your WLDaaS service payment, usage: mywavespaymenttxid=<Waves TxID>'
        solutiontext = 'Request a unique payid with option: getuniquepayid=true'
        result["paramstring_validation"] = 'INVALID'
        result["alert"] = alerttext
        result["solution"] = solutiontext
        return result
        
    if 'pay' not in url_parameterstring.keys() or (pay != 'true' and pay != 'false'):
        alerttext = 'Missing "pay" option, usage: pay=false|true. -> true: collect only with report OR false: delivers also the mass transaction data in json format'
        result["paramstring_validation"] = 'INVALID'
        result["alert"] = alerttext
        return result
    
    
    try:
        startblock = int(startblock)
        if startblock <= 0:
            alerttext = 'startblock needs to be a positive integer. Ideally the 1st leaser block.'
            result["paramstring_validation"] = 'INVALID'
            result["alert"] = alerttext
            return result
    except:
        if startblock == None:
            alerttext = 'need startblock, usage: startblock=<1st leaser block>'
        else:
            alerttext = 'startblock needs to be an integer. Ideally the 1st leaser block.'
            
        result["paramstring_validation"] = 'INVALID'
        result["alert"] = alerttext
        return result
    
    
    try:
        payblock = int(payblock)
        if payblock <= 0:
            alerttext = 'payblock needs to be a positive integer'
            result["paramstring_validation"] = 'INVALID'
            result["alert"] = alerttext
            return result
        elif payblock < startblock:
            alerttext = 'payblock can not be smaller then startblock.'
            result["paramstring_validation"] = 'INVALID'
            result["alert"] = alerttext
            return result
    except:
        if payblock == None:
            alerttext = 'need payblock (where to start this session), usage: payblock=<block>'
        else:
            alerttext = 'payblock needs to be an integer'
            
        result["paramstring_validation"] = 'INVALID'
        result["alert"] = alerttext
        return result
    
    apinode = json_config_lpos['paymentconfig']['querynode_api']
    current_block_url = apinode + json_config_lpos['api_uris']['blockchainheight']
    currentblock = int(get_api_request (current_block_url)['height'])
    
    if force == 'yes' or force == 'true':
        #apinode = json_config_lpos['paymentconfig']['querynode_api']
        #current_block_url = apinode + json_config_lpos['api_uris']['blockchainheight']
        #respons = get_api_request (current_block_url)
        #currentblock = int(respons['height'])
        stopblock = currentblock-1
        url_parameterstring['stopblock'] = str(stopblock)
                                
    
    try:
        stopblock = int(stopblock)
        if stopblock <= 0:
            alerttext = 'stopblock needs to be a positive integer'
            result["paramstring_validation"] = 'INVALID'
            result["alert"] = alerttext
            return result
        elif stopblock <= payblock:
            alerttext = 'stopblock needs to be greater then payblock'
            result["paramstring_validation"] = 'INVALID'
            result["alert"] = alerttext
            return result
        elif stopblock > currentblock-1:
            alerttext = 'stopblock (paystopblock) needs to be smaller or equal then current blockchain height'
            result["paramstring_validation"] = 'INVALID'
            result["alert"] = alerttext
            return result
    except:
        if stopblock == None:
            alerttext = 'need stopblock (where to stop this session), usage: stopblock=<block>'
        else:
            alerttext = 'stopblock needs to be an integer'
            
        result["paramstring_validation"] = 'INVALID'
        result["alert"] = alerttext
        return result
    
    try:
        feeshare = int(feeshare)
        if feeshare <= 0:
            alerttext = 'feeshare percentage needs to be between greater then 0'
            result["paramstring_validation"] = 'INVALID'
            result["alert"] = alerttext
            return result
    except:
        if feeshare == None:
            alerttext = 'need feeshare percentage, usage: feeshare=<nr>'
        else:
            alerttext = 'feeshare needs to be an integer'
            
        result["paramstring_validation"] = 'INVALID'
        result["alert"] = alerttext
        return result
        
    try:
        rewardshare = int(rewardshare)
        if rewardshare <= 0:
            alerttext = 'rewardshare percentage needs to be between greater then 0'
            result["paramstring_validation"] = 'INVALID'
            result["alert"] = alerttext
            return result
    except:
        if rewardshare == None:
            alerttext = 'need rewardshare percentage, usage: rewardshare=<nr>'
        else:
            alerttext = 'rewardshare needs to be an integer'
            
        result["paramstring_validation"] = 'INVALID'
        result["alert"] = alerttext
        return result
    

    
    return result



## Function to check validity of the Waves payment for WLDaaS
## It receives the waves TxID and checked the pay refid from the
## attachment. This payref id should be equal to the expected payref id
## that was stored in the database.
## If the database contains FREERUN in the pay refid string, it is a free run
## 
## input params;
## - my_json_constants: object with app constant values
## - json_config_lpos: shared lpos configsettings from s3 file
## - paramstring: all url parameters received as json
## - token: token extracted from browsercookie
## 
## return
## - alerttext when there are invalid results
## - 'VALID_PAYMENT' when the collector run can be started
## ========================= BEGIN ===========================
def valid_payment_received (json_config_lpos, my_json_constants, paramstring, token, sessiontype):
    
    print('Collector session type requested: ', sessiontype)
    
    freerun_txid_replace_text   = 'Aquired free run, no Waves transaction done.'
    wallet              = paramstring['wallet']
    waves_txid         = paramstring['mywavespaymenttxid']
    #waves_txid          = "cDVwEZd7gCofCjL7FzqPTyFRMt7n1pH5dQnDmRYbCvq" ##FOR TESTING, TXID DOES NOT EXIST
    
    waves_querynode     = my_json_constants['waves']['querynode_api']
    waves_txinfo_uri    = my_json_constants['waves']['txinfo_uri']
    waves_api_url       = waves_querynode + waves_txinfo_uri + waves_txid
    sleeptimer          = my_json_constants['waves']['wldaas_pay_validate_sleeptimer']
    api_call_retries    = my_json_constants['waves']['wldaas_pay_validate_retries']
    wldaas_wallet       = json_config_lpos['paymentconfig']['wldaas_paywallet']
    
    if sessiontype == 'apisession':
        email = paramstring['email']
        paytxidtablehead = tablekeys['paytxid']
        payidexpected = get_item (wallet, email, keys=[ paytxidtablehead ])['Item']
        if len(payidexpected) != 0:
            payidexpected = payidexpected[paytxidtablehead]['S']
        else:
            payidexpected = "None available"
    elif sessiontype == 'websession':    
        dbitems             = query_item(pk, skjwt, wallet, token, tableindex_jwt)
        payidexpected       = dbitems['Items'][0][tablekeys['paytxid']]['S']
        #payidexpected       = "2fc2de2b-00ff-48f7-9a0d-2f23c2b6d264" ##FOR TESTING, SIMULATE SAME refid used
    
    if waves_txid+'-FREERUN' == payidexpected:  ##It is a valid freerun
        alerttext = { "VALID_PAYMENT" : waves_txid }
        paramstring['mywavespaymenttxid'] = freerun_txid_replace_text
        
    else:
        for count in range(api_call_retries): ##Try again two times if api call answers
    
            sleep(sleeptimer)   ## Wait X seconds (blockchain could be slow)
            json_respons        = get_api_request(waves_api_url)

            #If key in json_respons does not exist, it returns None
            if json_respons.get('statuscode') == 200:

                receiver            = json_respons['recipient']
                receiver_expected   = wldaas_wallet
                attachmentbase58    = json_respons['attachment']
                payidreceived       = base58.b58decode(attachmentbase58).decode('utf-8')
                amount              = json_respons['amount']
            
                print('Waves transaction to validate:')
                print('Tx ID:', waves_txid)
                print('attachment (base58):', attachmentbase58) 
                print('pay id received :', payidreceived)
                print('pay id expected :', payidexpected)
            
                if receiver != receiver_expected:       ## Incorrect wallet used for payment
                    alerttext = { "alert" : "Transaction was not send to WLDaas wallet:\n" +
                                            receiver_expected + "\n\n" +
                                            "Collector task not started.",
                                  "payrefid" : payidexpected }
                              
                elif payidreceived != payidexpected:    ## Incorrect ref.payid's in comparison
                    if sessiontype == 'websession':
                        alerttext = { "alert" : "Pay ref.id was incorrect.\n" +
                                                "ref.id used: " + payidreceived + "\n" +
                                                "ref.id expect: " + payidexpected + "\n" +
                                                "\nSave this message and contact node admin.",
                                      "payrefid" : payidexpected }
                    elif sessiontype == 'apisession':
                        if len(payidreceived) == len(payidexpected): #Different Paytxid's
                            alerttext = { "alert" : "Pay ref.id was incorrect.\n" +
                                                    "ref.id used: " + payidreceived + "\n" +
                                                    "ref.id expect: " + payidexpected + "\n",
                                          "payrefid" : payidexpected,
                                          "solution" : "Did you use correct Waves TxID and referenced correct Paytxid: " + payidexpected + " ?" }
                        else:
                            alerttext = { "alert" : "Pay ref.id was incorrect.\n" +
                                                    "ref.id used: " + payidreceived + "\n" +
                                                    "ref.id expect: " + payidexpected + "\n",
                                          "payrefid" : payidexpected,
                                          "solution" : "use option: getuniquepayid=true to receive Paytxid" }

                else:   ## Valid payment to WLDaaS
                    alerttext = { "VALID_PAYMENT" : payidexpected }
            
                break
        
            elif json_respons.get('statuscode') != 404 and json_respons.get('statuscode') != 999:
                alerttext = { "alert" : json_respons.get('message'),
                              "payrefid" : payidexpected }
                break
        
            else:
                ##Errors getting API responses or errors from Waves Blockchain nodes (404 and 999)
                alerttext = { "alert" : json_respons.get('message'),
                              "payrefid" : payidexpected }
                          
                if json_respons.get('statuscode') == 999:
                    alerttext = { "UNCHECKED_PAYMENT" : payidexpected } ##Indefinite timeouts

    return alerttext
## =========================  END  ===========================



## Method to create a web token
## Set expiration time according key/value from config
## Create a secret which is used to create token hash
## return token
## params:
## - ed: expiration time token
## ===========================================================
def create_token (expireduration_hrs, secret, wallet):

    current_time = int(time.time())
    #eds          = expireduration_hrs * 3600
    eds          = int(expireduration_hrs * 3600)
    expire_time  = current_time + eds

    payload_data = {
                "sub": "WLDaaS service",
                "wallet": wallet,
                "exp" : expire_time
    }

    token = jwt.encode(
                payload=payload_data,
                key=secret
    )

    return token
## ============= END create token method ==============


## Create Cookie
##
## ===========================================================
def create_cookie (expiration_dure, webtoken, cookiedomain):
    
    tname = 'token'                     ##Token name
    tvalue = webtoken                   ##Token value
    #maxage  = expiration_dure * 3600    ##expire duration in secs
    maxage  = int(expiration_dure * 3600)    ##expire duration in secs
    path    = '/'                       ##valid url path starts
    ss      = 'None'                     ##How are XSFR handled
    domain      = cookiedomain      ##domain + subdomains valid

    cookie = tname + "=" + tvalue + ";" +\
             "Max-Age=" + str(maxage) + ";" +\
             "Path=" + path + ";" +\
             "SameSite=" + ss + ";" +\
             "Domain=" + domain + ";" +\
             "Secure" + ";" +\
             "HttpOnly"
             
    return cookie
## =================== END create cookie =====================



## ============= GET secret from secret manager ==============
def get_secret(secretkeyname):

    secret_name = secretkeyname
    region_name = "eu-north-1"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            
            return secret
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            
            return decoded_binary_secret
## ==================== END get secret =======================


## Function that loads the settings from the default file
## and loads them to the ecs_cmds array, which is send
## to the container initiation
## =========================== Start =========================
def update_ecs_cmds_array (defaults, ecs_cmds):
    if 'servicename' in defaults:
        ecs_cmds.append("servicename=\"" + defaults['servicename'] + "\"")
    else:
        ecs_cmds.append("servicename=\"Waves Service\"")

    if 'transactionattachment' in defaults:
        ecs_cmds.append("transactionattachment=" + defaults['transactionattachment'])

    if 'blockwindowsize' in defaults:
        for item in ecs_cmds:
            if 'blocks=' in item: ecs_cmds.remove(item)
        ecs_cmds.append("blocks=" + defaults['blockwindowsize'])

    if 'nopayoutaddresses' in defaults:
        nopayarray = defaults['nopayoutaddresses']
        items = len(nopayarray)
        string = ''
        for address in nopayarray:
            index = nopayarray.index(address)
            if index == 0: string = "\""
            string += address
            if index+1 == items: string += "\""
            else: string += " "

        ecs_cmds.append("nopayoutaddresses=" + string)
## ==================== END get defaults =======================


## The database has a composite primary key (pkey + skey)
## params:
## - pkey       : partition key [ var match type in DB ]
## - skey       : sort key [ var match type in DB ]
## - removekeyarray=[ 'key1', 'key2' ] Removes keys from item if action="remove"
## - pwdhash=<hash> new password hash (byte type)
## - et=<expiration time epoch format>  When item will expire and be removed from DB
## - signuphash=<string> New hash value used when signup is validated (key should be removed)
## ========================= UPDATE item ==========================
def update_item (pkey, skey, removekeyarray=None, paytxid=None, pwdhash=None, et=None, signuphash=None, freeruns=None, taskstate=None, action="set"):

    arguments = locals() #Which params do we have (json dict). NOTE: Keep as first else we see all vars
    table = boto3.resource('dynamodb').Table(dynamodbtable)
    updateexpressionstring = action #start the updateexpression with the action argument 
    values = {} #Values for the database update action
    
    tablekeyobject = {
                        pk : pkey,
                        sk : skey
                     }
        
    if action.lower() == "remove": #Remove all items found in the removekeyarray
        for key in removekeyarray:
            updateexpressionstring += " " + tablekeys[key]
            if key != removekeyarray[-1]: updateexpressionstring += ","
        
        response = table.update_item(
                    Key = tablekeyobject,
                    UpdateExpression=updateexpressionstring,
                    ReturnValues="ALL_NEW"
        )
        
    elif action.lower() == "set":                           #Update attributes that do not have value 'None'
        del arguments['pkey']                               #not needed for list ExpressionAttributeValues
        del arguments['skey']                               #not needed for list ExpressionAttributeValues
        if removekeyarray: del arguments['removekeyarray']  #not needed for list ExpressionAttributeValues
        del arguments['action']                             #not needed for list ExpressionAttributeValues
        if signuphash: del arguments['signuphash']          #not needed for list ExpressionAttributeValues

        cnt = 0
        for key in arguments: #Find all keys that needs update (skip 'None' values)

            if arguments[key] != None:
                    tablekey = tablekeys[key]
                    updateexpressionstring += " " + tablekey + " = :" + key + "," #create update string
                    value = ":"+key #add key for value
                    values[value] = arguments[key] #add value

            cnt += 1
            if cnt == len (arguments): updateexpressionstring = updateexpressionstring[:-1]
            
        response = table.update_item(
                    Key = tablekeyobject,
                    UpdateExpression=updateexpressionstring,
                    ExpressionAttributeValues=values,
                    ReturnValues="ALL_NEW"
        )
    
    return response
## ============ END update item to database ===================


## ==================== START get matching s3 object list ======================
def get_matching_s3_keys ( bucket, prefix='', suffix='', findnearest=None ):

    """
    Generate array of s3 object keys requested
    The array is created by an effcient generation function
    Check s3 object one by one and if it's a hit, add to array
    The generation function needs to be used in a loop. 

    if empty s3 list, the return is empty array
    else return array of all matching s3 object keys
    """
    array = []

    def generate_matching_s3_keys ( bucket, prefix, suffix ):

        """
        Generate the keys in an S3 bucket.
        Use a for X in generate_matching_s3_keys ( ... ) loop to catch the
        matching keys.

        :param bucket: Name of the S3 bucket.
        :param prefix: Only fetch keys that start with this prefix (optional).
        :param suffix: Only fetch keys that end with this suffix (optional).

        references:
        - https://alexwlchan.net/2017/07/listing-s3-keys/
        - https://stackoverflow.com/questions/231767/what-does-the-yield-keyword-do
        """

        s3 = boto3.client('s3')
        kwargs = {'Bucket': bucket}

        # If the prefix is a single string (not a tuple of strings), we can
        # do the filtering directly in the S3 API.
        if isinstance(prefix, str):
            kwargs['Prefix'] = prefix

        while True:

            # The S3 API response is a large blob of metadata.
            # 'Contents' contains information about the listed objects.
            resp = s3.list_objects_v2(**kwargs)

            try:    ## Check if there are valid keys founds
                resp['Contents']
            except:
                #Found No s3 file matches
                break

            for obj in resp['Contents']:
                key = obj['Key']
                if key.startswith(prefix) and key.endswith(suffix):
                    yield key

            # The S3 API is paginated, returning up to 1000 keys at a time.
            # Pass the continuation token into the next response, until we
            # reach the final page (when this field is missing).
            try:
                kwargs['ContinuationToken'] = resp['NextContinuationToken']
            except KeyError:
                break
    

    ## Start function
    ## loop through full s3 object key names
    ## Filter on prefix and suffix (optional)
    ## If argument findnearest is given it will search for the nearest lower file
    ## than the block value that was given for findnearest=<xxx>
    ## else it is a normal search and all keys found are added to array
    ## return the array

    nearestblock = 0    ##This is the nearest lower block used to adapt the requested payblock

    for key in generate_matching_s3_keys ( bucket, prefix, suffix ):
        if findnearest != None: ##Try to find the nearest lower leaseinfo file for findnearest=block
            if key.startswith(prefix):  key = key[len(prefix):]
            if key.endswith(suffix):    key = key[:-len(suffix)]
            prblock = int(key)
            reqblock = int(findnearest)
            if prblock < reqblock and prblock > nearestblock:
                nearestblock = prblock
                try:
                    array[0] = nearestblock 
                except:
                    array.append(nearestblock)
        
        else:
            array.append(key)

    return array
## ===================== END get matching s3 object list =======================


## ======================= START find 1st leaser block =========================
    """
    If there are no leasers return 0
    If there are leasers return blockheight from first leaser
    arguments;
    - leaeserlist: list will all lease objects received from api request
      to /leases/active/<wallet address>
    
    """
def find_1st_leaser_block(leaserlist, wallet):

    firstleaserblock = 0

    if len(leaserlist) != 0: #There are active leases

        for obj in leaserlist:
            leaseheight = obj['height']
            if firstleaserblock == 0:
                firstleaserblock = leaseheight
            elif leaseheight < firstleaserblock:
                firstleaserblock = leaseheight

    else:
        print('no active leases found for address ' + wallet)


    return firstleaserblock
## ======================== END find first leaser block ========================
