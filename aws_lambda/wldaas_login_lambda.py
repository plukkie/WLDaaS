import json
import jwt                          ## custom Layer module
import bcrypt                       ## custom Layer module [For hashing and salting]
import numpy                        ## custom Layer module
import pybase64 as base64           ## custom Layer module
import smtplib
import boto3
import time
import os
import hashlib                      ## create hashes from strings
import pprint
import base58
import random 

from urllib import parse
from pprint import pprint as pp
from botocore.exceptions import ClientError
from jwt.exceptions import ExpiredSignatureError
from jwt.exceptions import InvalidSignatureError
from uuid import uuid4 ##Used for API key generationm (apikey = uuid() generates an API string)

pp = pprint.pprint

##file names/paths
datapath        = 'data/'
bdfile          = 'batchinfo.json'
defaultsfile    = 'settings.json'

#get env values
settings_bucket = os.environ.get("script_settings_bucket")
config_file     = os.environ.get("scripts_settingsfile")
secretkeyname   = os.environ.get("my_webtoken_secret")
data_bucket     = os.environ.get("wldaas_data_bucket")
script_subpath  = os.environ.get("script_subpath")

#Set Global constants
client          = boto3.client('dynamodb')
dynamodbtable   = '<<DBASE_NAME>>'
cte             = int(time.time())          ## Current time (epoch secs)
day_secs        = 24*3600                   ## One day in seconds

tablekeys   = {
                'pkey'          : 'Wallet',
                'skey'          : 'Email',
                'ct'            : 'Creationtime',
                'et'            : 'Expiretime',
                'pwdhash'       : 'Passwordhash',
                'signuphash'    : 'Signuphash',
                'jwtoken'       : 'JWToken',
                'walletadd'     : 'Walletadd',
                'newpwdhash'    : 'Newpasswordhash',
                'pwdresetid'    : 'Password_Reset',
                'apikeyhash'    : 'APIkeyhash'
              }

bd          = {
                "batchdata" : {
                                "paymentid": "",
                                "scanstartblock": "",
                                "paystartblock": "",
                                "paystopblock": ""
                              }
              }
            
pk  = tablekeys['pkey']
sk  = tablekeys['skey']
jwtk = tablekeys['jwtoken']
tableindex_jwt  = 'Wallet-JWToken-index'

## ===========================================================
def lambda_handler(event, context):
    
    if 'cookie' in event['headers']:  #Check if a cookie was received
        cookiereceived = True
        print('Request with cookie received')
    elif 'apikey' in event['headers']:
        cookiereceived = False
        apirequest = True
        print('direct API request')
    else:
        cookiereceived = False
        print('Request without cookie received')
    
    #cookiereceived = False
    webtokensecret  = json.loads(get_secret(secretkeyname))['tokensecret'] ##secret for token creation
    json_config     = json.loads(read_s3_object(settings_bucket,config_file)) ##Get App config settings
    au              = int(json_config['timers']['account_unused_expiration_hrs']) ## Account unused expiration timer (hrs)

    #ed              = int(json_config['timers']['webtoken_expiration_hrs'])  ##Expiration duration webtoken
    ed              = float(json_config['timers']['webtoken_expiration_hrs'])  ##Expiration duration webtoken
    acao            = json_config['acao']  ##Access-Control-Allow-Origin domain (Cloudfront origin)
    cookiedomain    = json_config['cookiedomain'] ##Domain to set in browsercookie
    request_body    = json.loads(event['body'])
    mybody          = {}
    mycookie        = "none"
    returnobject    = {}
    
    #pp(request_body)
    #pp(request_body.get('loginsecret'))
    
    if request_body.get('loginsecret') != None:     ## Normal Login request
        print('execute normal login request')
        
        loginbase64str  = request_body['loginsecret'] #base64 encoded string from frontend
        loginsecret     = str(base64.b64decode(loginbase64str), 'utf-8')
        json_params     = dict(parse.parse_qsl(parse.urlsplit('http://?' + loginsecret).query))
        username        = json_params['username']                              ## String
        base64password  = json_params['password']                              ## Base64 encoded String
        password        = str(base64.b64decode(base64password), 'utf-8')       ## Normal Decoded password
        wallet          = json_params['wallet']                                ## String
        webtokensecret  = json.loads(get_secret(secretkeyname))['tokensecret'] ##secret for token creation
        mybody, mycookie, batchdata = login(wallet, username, password, ed, webtokensecret, cookiereceived, cookiedomain, au)
        
    elif request_body.get('newpassword') != None:   ## Password change request
        print('Change password request')
        wallet                                  = request_body.get('nodewallet')
        username                                = request_body.get('username')
        newpassword                             = request_body.get('newpassword')
        pwdconfirmid                            = create_random_number()        ## Used to match email confirmation request
        linkcreationtime                        = int(time.time())
        request_body['pwd_reset_id']            = pwdconfirmid                  ## Add reset id to body
        request_body['pwd_reset_request_time']  = linkcreationtime              ## Add reset request time to body
        pwdbytes                                = str.encode(newpassword)       ## Byte: needed for bcrypt input
        salt                                    = bcrypt.gensalt()              ## Byte: Generate a salt for the password uniqueness
        pwdhashed                               = bcrypt.hashpw(pwdbytes, salt) ## Byte: Hash created from 'salt + password'
        
        ## NOTE
        ## newpwdhash bytes type is encoded by DynamoDB to Base64 when saved 
        update_item (wallet, username, pwdresetid=pwdconfirmid, newpwdhash=pwdhashed,  action="set")
        del request_body['newpassword']
        
        send_email(json_config, request_body)
        mybody['alert'] = 'Please confirm password change in email send to ' + username
    
    elif request_body.get('pwdresetconfirmation') != None:  ## Password change confirmation clicked in email
        print('Change passsord request was confirmed by user click in email.')
        pwdresetconfirmdata = json.loads(decode_base58 ( request_body.get('pwdresetconfirmation') ))
        
        username            = pwdresetconfirmdata.get('username')
        wallet              = pwdresetconfirmdata.get('nodewallet')
        pwdresetid          = pwdresetconfirmdata.get('pwd_reset_id')
        linkcreationtime    = int(pwdresetconfirmdata.get('pwd_reset_request_time'))
        currenttime         = int(time.time())
        reset_expiredure    = int(float(json_config['timers']['passwordresetexpiration']) * 3600)  ## Reset link expiration in seconds
        newpwdresetidkey    = tablekeys['pwdresetid']
        newpwdhashkey       = tablekeys['newpwdhash']
        
        if linkcreationtime+reset_expiredure > currenttime: ## Reset link not expired
            print('Password reset link was used.')
            item = get_item( wallet, username, keys=[ newpwdresetidkey, newpwdhashkey ] ).get('Item')
            
            #print('item from Db:', item)

            if len(item) == 0:  ## No change details found
                alerttext = "This link was already used."
                mybody["alert"] = alerttext

            else:   ## Get expected reset id from item and compare
            
                Bytezero = str.encode("")   ## Empty Byte string, needed to update Byte attribute to Zero in DynamoDB
                
                try:    ## Test if keys exist
                    pwdresetid_expected = item[newpwdresetidkey]['S']
                    newpasswordhash = item[newpwdhashkey]['B']
                except:
                    pwdresetid_expected = ""
                    newpasswordhash = Bytezero
                
                if pwdresetid == pwdresetid_expected:   ## Value match, valid confirmation
                    print('Valid reset id match.')
                    update_item (wallet, username, pwdhash=newpasswordhash, newpwdhash=Bytezero, pwdresetid="", action="set")
                    alerttext = "Succesfully changed password.\nPlease login."
                    mybody["alert"] = alerttext
                    
                else:   ## Unsuccessfull compare
                    alerttext = "No matching change request found.\nNo password change done."
                    print(alerttext)
                    mybody["alert"] = alerttext
            
        else:   ## link expired
            alerttext = "Password reset link expired."
            print(alerttext)
            mybody["alert"] = alerttext

    elif request_body.get('create_apikey') == "true":  ## Request to create API key
    
        print('API key requested')
        if cookiereceived == False:
            alerttext = "Cookie expired, please login."
            mybody["alert"] = alerttext
            mybody['browserreload'] = True
            
        else: #There is a Cookie
            ## Decode webtoken, authenticate user, generate API key, store in DB and inform user
            mycookie = event['headers']['cookie'] 
            token = mycookie.split('=', 1)[-1]              ##Get auth token from cookie
            authresult, partkeys = authenticate (token, webtokensecret)
            wallet      = partkeys[0]
            email       = partkeys[1]
            walletadd   = partkeys[2]
            
            if authresult.get('authenticated') == True:     ##VALID token authentication
                print('Succesfull token authentication. Proceed with API key generation.')
                apikey          = str(uuid4()).upper()             ## String
                apikeybytes     = str.encode(apikey)               ## Bytes
                salt            = bcrypt.gensalt()                 ## Bytes: salt for the API hash uniqueness
                apikeyhashed    = bcrypt.hashpw(apikeybytes, salt) ## Bytes: Hash created from 'salt + password'
                update_item(wallet, email, apikeyhash=apikeyhashed, action='set')
                
                mybody["apikey"] = apikey

                
            else:           ##INVALID token authentication
                alerttext = 'Invalid token authentication'
                if not authresult['alert']:
                    mybody = { "alert" : alerttext }
                else:
                    mybody = { "alert" : authresult["alert"] }
    
    elif request_body.get('check_apikey') == "true":  ## Check if API key already created
    
        if cookiereceived == False:
            alerttext = "Cookie expired, please login."
            mybody["alert"] = alerttext
            mybody['browserreload'] = True
            
        else: #There is a Cookie
            ## Decode webtoken, authenticate user, check API key exists and inform user
            mycookie = event['headers']['cookie'] 
            token = mycookie.split('=', 1)[-1]              ##Get auth token from cookie
            authresult, partkeys = authenticate (token, webtokensecret)
            wallet      = partkeys[0]
            email       = partkeys[1]
            walletadd   = partkeys[2]
            
            if authresult.get('authenticated') == True:     ##VALID token authentication
                print('Succesfull token authentication. Proceed with API key existence check.')
                
                ## Check if API key exists or not, return text in mybody
                apikeyhashtablehead = tablekeys['apikeyhash']
                item = get_item( wallet, email, keys=[ apikeyhashtablehead ] ).get('Item')
                #if the APIkeyhash value is empty : {'APIkeyhash': {'B': b''}}, len() = 0!
                #if there is no table key APIkeyhash : {}
                if item.get(apikeyhashtablehead) != None: ##found APIkeyhash, check if value
                    keylength = len(item[apikeyhashtablehead]['B'])
                    if keylength == 0:
                        inlinetext = 'No API key present currently.'
                    else:
                        inlinetext = 'Currently there is an API key active. If you lost it, just create a new one. The current one becomes invalid.'

                else:
                    inlinetext = 'No API key present currently.'

                mybody["inlinetext"] = inlinetext
                
            else:           ##INVALID token authentication
                alerttext = 'Invalid token authentication'
                if not authresult['alert']:
                    mybody = { "alert" : alerttext }
                else:
                    mybody = { "alert" : authresult["alert"] }
    
    
    
    elif request_body.get('delete_apikey') == "true":  ## DELETE API key if present
    
        if cookiereceived == False:
            alerttext = "Cookie expired, please login."
            mybody["alert"] = alerttext
            mybody['browserreload'] = True
            
        else: #There is a Cookie
            ## Decode webtoken, authenticate user, check API key existence, delete & inform user
            mycookie = event['headers']['cookie'] 
            token = mycookie.split('=', 1)[-1]              ##Get auth token from cookie
            authresult, partkeys = authenticate (token, webtokensecret)
            wallet      = partkeys[0]
            email       = partkeys[1]
            walletadd   = partkeys[2]
            
            if authresult.get('authenticated') == True:     ##VALID token authentication
                print('Succesfull token authentication. Proceed with API key existence check.')
                
                ## Check if API key exists or not, return text in mybody
                apikeyhashtablehead = tablekeys['apikeyhash']
                item = get_item( wallet, email, keys=[ apikeyhashtablehead ] ).get('Item')
                #if the APIkeyhash value is empty : {'APIkeyhash': {'B': b''}}, len() = 0!
                #if there is no table key APIkeyhash : {}
                if item.get(apikeyhashtablehead) != None: ##found APIkeyhash, check if value
                    keylength = len(item[apikeyhashtablehead]['B'])
                    if keylength == 0:
                        inlinetext = 'No API key present currently. Nothing to delete.'
                    else:
                        update_item(wallet, email, removekeyarray=[ 'apikeyhash' ], action='remove')
                        inlinetext = 'Deleted API key. If API access is required, create an API key again.'

                else:
                    inlinetext = 'No API key present currently. Nothing to delete.'

                mybody["inlinetext"] = inlinetext
                
            else:           ##INVALID token authentication
                alerttext = 'Invalid token authentication'
                if not authresult['alert']:
                    mybody = { "alert" : alerttext }
                else:
                    mybody = { "alert" : authresult["alert"] }
    
    
    else:   ## No valid url used
        print('Invalid request from user.')
        errortext  = "invalid request"
        alerttext   = "Faulty request done. Check url parameters."
        mybody = { "error" : errortext,
                   "alert" : alerttext }
    
    #pp(mybody)
    
    ## This is the http respons that returns to the frontend
    ## S3 website origin is domain 'http://wldaas.s3-website.eu-north-1.amazonaws.com'
    ## The s3 domain is only used as the origin if we would not use Cloudfront and we would access s3 directly
    returnobject = { 'statusCode': 200,
                     #'headers': { 'Access-Control-Allow-Origin': '*' },
                     'headers': {
                                    'Access-Control-Allow-Origin': acao,
                                    'Access-Control-Expose-Headers': 'token',
                                    'Access-Control-Allow-Credentials' : 'true'
                                },
                     'body': json.dumps(mybody)
                   }
                   
    
    if mycookie != "none":
        #print('set cookie :', mycookie)
        returnobject['headers']['Set-Cookie'] = mycookie ##Set cookie with token

    #print(returnobject)
    return returnobject ##This returns the actual respons to the requester of the lambda call (API gateway)
## ==================== END Main handler =====================


## Compare login details with database
## return auth result, cookie, batchdata and default settings
## ===========================================================
def login(wallet, username, password, expireduration, webtokensecret, cookiereceived, cookiedomain, au):
    
    resp_body = {}
    cookie = 'none'
    batchdata = { "batchdata" : "none" }
    item = get_item(wallet, username) #If user/wallet exists, there is an 'Item' available, else no 'Item'
    
    if item.get('Item') != None: #Get wallet addon string from Item
        walletadd = item['Item'][tablekeys['walletadd']]['S']
        s3_wallet_folder = wallet + '__' + walletadd
        batchinfo_s3_object = s3_wallet_folder + '/' + datapath + bdfile
        defaults_s3_object = s3_wallet_folder + '/' + defaultsfile
    
        print(batchinfo_s3_object)
    
        try:
            spasswordhash = item['Item'][tablekeys['pwdhash']]['B'] ##Check if a password hash is found
        except: #User/wallet not found, invalid auth request
            resp_body = { "alert" : "Invalid login." }
            print('Invalid login (username/wallet combi not found).')
        else: #user/wallet combination is found
            if tablekeys['signuphash'] in item['Item']:             ##Check if account waits for confirmation
                resp_body = { "alert" : "Waiting for account validation.\nDid you check your email?" }
            else:   ## Go Check if password is valid
            
                ct = item['Item'][tablekeys['ct']]['N']     ##Account creation time
                pwdbytes    = str.encode(password)          ## Byte: needed for bcrypt input

                if bcrypt.checkpw ( pwdbytes, spasswordhash): #Login password hash matches with stored hash
                
                    if cookiereceived == False:  ##If there was no cookie send along, create and store it
                        webtoken = create_token (expireduration, webtokensecret, wallet) #Create webtoken
                        cookie = create_cookie (expireduration, webtoken, cookiedomain)  #create cookie
                        update_item (wallet, username, action='set', jwtoken=webtoken)  #Add webtoken to DB item
                    
                    update_expire_time ( wallet, username, au ) #Set new expiration time


                    try:    ##Load batchinfodata for next run if available
                        batchdata = json.loads(read_s3_object(data_bucket, batchinfo_s3_object))
                    except: ##No batchdata found (no collector run done yet)
                        resp_body = bd  ##If no next run data found, set empty data
                    else: ##Found next run batchdata
                        resp_body = batchdata
                        resp_body['alert'] = "Found batchdata for next collector run.\nResults loaded."
                
                    try:    ##Load default settingsfile if available
                        defaults = json.loads(read_s3_object(data_bucket, defaults_s3_object))
                    except:
                        resp_body['defaults'] = "none"
                    else:
                        resp_body['defaults'] = defaults
                    
                
                    #print("passwords match")
                    resp_body['waveswallet'] = wallet
                    resp_body['auth'] = "success"

                else:
                    #print("Passwords do not match")
                    resp_body = { "alert" : "Invalid password." }
    
    else:
        print('Username/Wallet combination used but not found in DB.')
        resp_body = { "alert" : "Invalid" } 
         
         
    return resp_body, cookie, batchdata
## =================== END login method ======================



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
    eds          = int(expireduration_hrs * 3600) ## Expire duration seconds
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
    
    tname = 'token'                       ##Token name
    tvalue = webtoken                     ##Token value
    #maxage  = expiration_dure * 3600     ##expire duration in secs
    maxage  = int(expiration_dure * 3600) ##expire duration in secs
    path    = '/'                         ##valid url path starts
    ss      = 'None'                      ##How are XSFR handled
    #domain      = '.amazonaws.com'       ##domain + subdomains valid
    domain = cookiedomain

    ## The Domain should be the domain of the endpoint for which the cookie
    ## should be send along. So, if the frontend runs on ''.cloudfront.net' and
    ## the there is an API endpoint fetched on ''.amazonaws.com' which should
    ## use the cookie then the domain should be set on '.amazonaws.com' and not
    ## on the frontend domain.

    cookie = tname + "=" + tvalue + ";" +\
             "Max-Age=" + str(maxage) + ";" +\
             "Path=" + path + ";" +\
             "SameSite=" + ss + ";" +\
             "Domain=" + domain + ";" +\
             "Secure" + ";" +\
             "HttpOnly"
             
    return cookie
## =================== END create cookie =====================




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

    
## The database has a composite primary key (pkey + skey)
## This function can set, update & remove an item
## This is determinded by the action key
## The key names for the attributes should come from the global
## tablekeys constant (See Top of Lambda function)
## These keynames can be used in the calling of the function.
##
## params:
## - pkey       : partition key [ var match type in DB ] -> Mandatory
## - skey       : sort key [ var match type in DB ] -> mandatory
## - removekeyarray=[ 'key1', 'key2' ] Removes keys from item if action="remove"
## - pwdhash=<hash> new password hash (byte type)
## - et=<expiration time epoch format>  When item will expire and be removed from DB
## - signuphash=<string> New hash value used when signup is validated (key should be removed)
## - JWtoken=<string>
##
## NOTE
## A type binary attribute is automatically encoded to Base64 string by DynamoDB
## when saved to database
## =============================================================================
def update_item ( pkey, skey, removekeyarray=None, pwdhash=None, et=None,
                  signuphash=None, jwtoken=None, pwdresetid=None,
                  newpwdhash=None, apikeyhash=None, action="set" ):

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

            if arguments[key] != None:  ## value set for an attribute
                    tablekey = tablekeys[key]   ## Name for the key in table
                    updateexpressionstring += " " + tablekey + " = :" + key + "," #create update string
                    value = ":"+key #add key for value
                    values[value] = arguments[key] #add value

            cnt += 1
            if cnt == len (arguments): updateexpressionstring = updateexpressionstring[:-1]  ## Last attribute
            
        pp('UpdateExpression:')
        print(updateexpressionstring)
        pp('ExpressionAttributeValues:')
        print(values)
            
        response = table.update_item(
                    Key = tablekeyobject,
                    UpdateExpression=updateexpressionstring,
                    ExpressionAttributeValues=values,
                    #ReturnValues="ALL_NEW"
                    ReturnValues="NONE" 
        )
    
    return response
## ============ END update item to database ===================


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


## Method that updates the expire timer
## This is used to avoid account exparation and automated removal
## It should be updated in the following cases;
## 1. When account is activated
## 2. When a user logs in
## params:
## - wallet: pkey, wallet address
## - username: skey, username
## - au: expiration duration in hrs
## 
## ===========================================================
def update_expire_time ( wallet, username, au ):
    
    now = int(time.time()) #now, epoch seconds
    expiretime = now + au*3600 #current time + account expire time in hrs from configfile 
    update_item(wallet, username, et=expiretime, action='set')
## ============ END update expiration time ===================


## Function to create a random number of 10 integers
## Used for i.e. pasdsw3ord reset confirmation
## ========================= START =======================
def create_random_number():

    rangestart      = 0
    rangeend        = 9
    totalnumbers    = 10
    addon           = ""

    for count in range(0, totalnumbers):
        number = random.randint(rangestart, rangeend)
        addon += str(number)

    return addon
##===========================  END  ======================


## Create base58 string from json object
## ================================== START ====================================
def create_base58_string ( jsonobject ):

    jsonstring = json.dumps(jsonobject)
    jsonBytes = jsonstring.encode('utf-8')
    base58Bytes = base58.b58encode(jsonBytes)
    base58string = base58Bytes.decode('utf-8')

    return base58string
## ==================================. END  ====================================


## Decode bytes58 string to normal string
## ================================ START =====================================
def decode_base58 ( base58string ):
    try:
        encoded = base58string.encode('ascii')
        #print(encoded)
        encodedBytes = bytes(encoded)
        decodedBytes = base58.b58decode(encodedBytes)
        mystring = decodedBytes.decode('utf8')
    except:
        print('not a valid base58 string')
        return base58string

    return mystring
## ================================= END ======================================    



## Send email method
##
## ================== BEGIN send email ======================
def send_email(script_config, request_body):

    sc              = script_config
    rb              = request_body
    
    mh              = sc['mail_settings']['password_reset_mail']
    mailserver      = sc['mail_settings']['server']['name']
    mailserverport  = sc['mail_settings']['server']['port']
    mailuser        = sc['mail_settings']['account']['username']
    mailpwd         = 'wwvrcusksjlrlxov'            ## Gmail app password
    mailsender      = mh['mail_from']
    mh['receiver']  = rb['username']
    receivers       = [ mh['receiver'] ]

    mailtemplate    = read_s3_object(settings_bucket, script_subpath + mh['mailtemplate'])
    
    jsonstring      = create_base58_string (request_body)
    mh['pwdresetaddon']  = "?pwdresetconfirmation=" + jsonstring
    mh['passwordresetexpiration'] = sc['timers']['passwordresetexpiration']
    
    for key in mh:
        value = mh[key]
        searchstring = "<" + key + ">" #String to search for in mailtemplate
        if searchstring in mailtemplate:
            #print('found searchstring ' + searchstring + ' in mail template and replaced it with: ' + value)
            mailtemplate = mailtemplate.replace(searchstring, str(value)) ##Replace string with value
    
    try:
        server = smtplib.SMTP_SSL(mailserver, int(mailserverport))
        server.ehlo()
        server.login(mailuser, mailpwd)
        server.sendmail(mailsender, receivers, mailtemplate)
        server.close()
        print('Password reset email sent to ' + mh['receiver'] + '!')

    except Exception as exception:
        print("Error: %s!\n\n" % exception)

## ================== END send email ========================


## Method to decode web token
## Checked on expiration and signature validation
## return decoded token or error
## params:
## - token: encoded webtoken
## - wallet: wallet address
## - mytime: the account creation time
## ================================ START ======================================
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
## ======================== END decode token method ============================


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




## Method to authenticate the token found in the cookie
## input:
## - token from browser
## - secret from aws secret manager
## ================================== START ====================================
def authenticate (token, secret):
        
        returnkeys = []
        result = { "authenticated" : False }
        decoderesult = decode_token (token, secret)

        if ('alert' not in decoderesult and 'data' in decoderesult): ##Seems a valid token

                wallet = decoderesult['data']['wallet']
                
                ##Query wallet/token from DB
                ##If wallet/token is found, there is an 'Items' array with value, else array is empty
                items = query_item ( pk, jwtk, wallet, token, tableindex_jwt ) ##all items are returned
                
                #print(items['Items'][0]) ##TROUBLESHOOT PRINT, ONLY FOR TESTING
                email = items['Items'][0][sk]['S']
                walletadd = items['Items'][0][tablekeys['walletadd']]['S']
                
                try:
                        items['Items'][0][jwtk] ##if the token was in the query, this should work

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
## ====================== END authenticate token method ========================
