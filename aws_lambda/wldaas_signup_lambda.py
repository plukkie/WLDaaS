import json as JSON
import cookies              ## custom Layer module
import jwt                  ## custom Layer module
import bcrypt               ## custom Layer module [For hashing and salting]
import numpy                ## custom Layer module
import pybase64 as base64   ## custom Layer module
import boto3
import time
import smtplib
import os
import random
from pprint import pprint as pp

client          = boto3.client('dynamodb')
dynamodbtable   = '<<DATABASE_NAME>>'
pkeyname        = 'Wallet'
skeyname        = 'Email'
cte             = int(time.time())          ## Current time (epoch secs)

tablekeys   = {
                'pkey'      : 'Wallet',
                'skey'      : 'Email',
                'ct'        : 'Creationtime',
                'et'        : 'Expiretime',
                'pwdhash'   : 'Passwordhash',
                'signuphash': 'Signuphash',
                'newpwdhash': 'Newpasswordhash',
                'freeruns'  : 'Freeruns'
              }

    
pk  = tablekeys['pkey']
sk  = tablekeys['skey']

#get script configuration from configfile
settings_bucket = os.environ.get("script_settings_bucket")
config_file     = os.environ.get("scripts_settingsfile")


## MAIN function
## This method is used to signup a user or delete an account
## 'resp_body' is the text message that is received back
## by the frontend website
## ===========================================================
def lambda_handler(event, context):
    
    json_config     = JSON.loads(read_s3_object(settings_bucket,config_file))
    et              = int(json_config['timers']['signup_expiration_hrs'])   ## Waiting hours to receive signup verification email
    au              = int(json_config['timers']['account_unused_expiration_hrs']) ## Account unused expiration timer (hrs)

    reqbody     = JSON.loads(event['body'])     ## JSON
    
    try:
        signuphash = reqbody['signuphash'] ## Check if it's a request to activate an account
    except: #New signup
        activate = False
        username    = reqbody['username']           ## String
        password    = reqbody['password']           ## String
        wallet      = reqbody['wallet']             ## String
        
    else: #Activate an account
        activate    = True
        wallet      = reqbody['wallet']
        username    = reqbody['username'] 
        pp('Account validation started, wallet: \'' + wallet + '\'.')

    item = get_item(wallet, username) #If user/wallet exists, there is an 'Item' available, else not

    if (activate): ##User used activation link, make account permanent
        print('Need to remove expire TTL and signuphash')
        try:
            itemdetails = item['Item']
        except: ##No item found for user/wallet, expired
            print('wallet & username not found (' + wallet + ' / ' + username + ')')
            print('Registration expired.')
            resp_body = 'Activation expired. Please signup again.'
        else: ##Check if database entry for signuphash is same
    
            try:
                ssignuphash = itemdetails['Signuphash']['S']
            except: #There is no signuphash, Account is already activated
                resp_body = 'Account is already activated.'
            else: #Signuphash found, let's compare values
                if (signuphash == ssignuphash): ##match!
                    print('Match found for activation. Remove signuphash from table for user : "' + username + '".')
                    update_item(wallet, username, removekeyarray=[ 'signuphash' ], action='remove')
                    update_expire_time ( wallet, username, au ) #Set new expiration time
                
                resp_body = 'Account activated. Enjoy!'\
                            '\n--------------------------'\
                            '\n username: ' + username + \
                            '\n wallet: ' + wallet
            
    else: ##Start new Signup
        try:
            itemdetails = item['Item']
        except: #Account requested is free to use, start create account
            walletadd = create_wallet_number_addon()     ## Integer of 10 numbers used to add to wallet on S3 object storage
            pp('Account creation started for user \'' + username + '\', wallet \'' + wallet + '\'.')
            pwdbytes    = str.encode(password)          ## Byte: needed for bcrypt input
            salt        = bcrypt.gensalt()              ## Byte: Generate a salt for the password uniqueness
            pwdhashed   = bcrypt.hashpw(pwdbytes, salt) ## Byte: Hash created from 'salt + password'
            signuphash  = salt.decode('utf-8')          ## String: Used for one time verification
            put_item(wallet, username, pwdhashed, salt, et, signuphash, walletadd, json_config) ##Write item to table
            resp_body = 'Account created.\nCheck your email with further instructions.'
            print('User added.')
            send_email(username, json_config, et, signuphash, wallet)
        
        else: #Found existing account
            susername = itemdetails['Email']['S']
            swallet = itemdetails['Wallet']['S']
            if (username == susername and wallet == swallet): #Account already taken
                resp_body = 'Sorry, this account is already registered.'\
                            '\n-----------------------------------------'\
                            '\n username: ' + username + \
                            '\n wallet: ' + wallet
            else:
                resp_body = 'Sorry, we could not help you. Contact administrator.'
            
    
    return {
        'statusCode': 200,
        'headers' : {
            'Access-Control-Allow-Origin': '*' ##Required for CORS support to work
            ## 'Access-Control-Allow-Credentials': true ## Required for cookies, authorization headers with HTTPS
        },
        #'body': JSON.dumps(event)
        #'body' : JSON.dumps(resp_test_body)
        'body' : JSON.dumps(resp_body)
        #'body' : JSON.dumps('Your account is created.')
    }
## =============== END MAIN function =========================


## Read S3 object function
## params:
## - bucket : S3 bucket name
## - key.   : object name
## return file content
## ===========================================================
def read_s3_object(bucket,key):
    s3 = boto3.resource('s3')
    s3object = s3.Bucket(bucket).Object(key)
    file_content = s3object.get()['Body'].read().decode('utf-8')
    return file_content
## =============== END Get S3 object function ================


## Write item to database method
## The database has a composite primary key (pkey + skey)
## params:
## - pkey       : partition key
## - skey       : sort key
## - pwdhash    : Hash of the user password (type: bytes)
## - salt       : One time Salt used for signup 
## - walletadd  : string of 10 integers to make unique S3 
##
## NOTE
## If an item is written to DynamoDB, the AWS web console
## can have couple of minutes delay to have the item available
## in the console!
## ===========================================================
def put_item (pkey, skey, pwdhash, salt, et, signuphash, walletadd, json_config):

    freeruns    = json_config['timers']['start_freeruns']  ## How many free runs as a signup gift

    data = client.put_item (
        TableName=dynamodbtable,
        Item={
                'Email': {
                    'S': skey
                },
                'Wallet': {
                    'S': pkey
                },
                'Passwordhash' : {
                    'B': pwdhash
                },
                'Signuphash' : {
                    'S' : signuphash
                },
                'Creationtime' : {
                    'N' : str(cte)
                },
                'Expiretime' : {
                    'N' : str(cte + et*3600)
                },
                'Walletadd' : {
                    'S' : walletadd
                },
                'Freeruns' : {
                    'N' : str(freeruns)
                }
        }
    )

    response = {
        'statusCode': 200,
        'body': 'successfully created item!',
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        }
    }
    return response
## ============ END write item to database ===================



## The database has a composite primary key (pkey + skey)
## params:
## - pkey       : partition key [ var match type in DB ]
## - skey       : sort key [ var match type in DB ]
## - removekeyarray=[ 'key1', 'key2' ] Removes keys from item if action="remove"
## - pwdhash=<hash> new password hash (byte type)
## - et=<expiration time epoch format>  When item will expire and be removed from DB
## - signuphash=<string> New hash value used when signup is validated (key should be removed)
## ===========================================================
def update_item (pkey, skey, removekeyarray=None, pwdhash=None, et=None, signuphash=None, action="set"):

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
    

## Method to get a database item
## params:
## - pkey: primary key
## - skey: sort key
## ===========================================================
def get_item (pkey, skey):
    data = client.get_item(
        TableName = dynamodbtable,
            Key={
                'Wallet': {
                    'S' : pkey
                },
                'Email' : {
                    'S' : skey
                }
            }
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


  
## Send email method
## params:
## - username : email address from signup recipient
## - jsonconfig : json from configuration file
## ===========================================================
def send_email(username, json_config, et, signuphash, wallet):

    bccaddress      = 'plukkie@gmail.com'
    ms              = json_config['mail_settings']
    mailserver      = ms['server']['name']                  ## Gmail
    mailserverport  = ms['server']['port']
    mailuser        = ms['account']['username']
    mailpwd         = 'wwvrcusksjlrlxov'                    ## Gmail app password
    from_text       = ms['signup_mail']['from_text']
    mailsender      = ms['signup_mail']['mail_from']
    mailsubject     = ms['signup_mail']['subject']
    admin           = ms['signup_mail']['admin']
    
    ## Make one base64 encoded string of the wallet, username and signup hash
    ## This way, the keys can not be eavesdropped
    ## signupsecret function is eventually type string
    signup_confirm_params = '?wallet=' + wallet + '&username=' + username + '&signuphash=' + signuphash
    signupsecret            = base64.b64encode(signup_confirm_params.encode("utf-8")).decode()

    ##pp('signup secret(base64 hash)' + signupsecret)
    activationlink  = ms['signup_mail']['activationlink']+'?signupsecret='+signupsecret
    
    receivers       = [ username, bccaddress ] 
    
    message = """From: """+from_text+"""
To: <"""+username+""">
MIME-Version: 1.0
Content-type: text/html
Subject: """+mailsubject+"""

<p>Thanks for signing up to WLDaaS.
Please activate your account by using the provided link.</p>
<p>---------------------------------------------------<br>
Please click this link to activate your account:
<a href="""+activationlink+"""> WLDaaS account activation link</a><br>
---------------------------------------------------<br>
Be sure to followup within """+str(et)+""" hour or else the registration will automatically expire and be removed.</p>
<p>If you did not sign up for this service, it could be that someone used your email to register for WLDaaS.
If so, DO NOT USE the provided link. The registration will then fail and is automatically removed.
If you did click the link, send an email to : """+admin+""" with a request to remove the registration.</p>

<p>Thank you for your registration and enjoy the WLDaaS service!</p>

"""

    try:
        server = smtplib.SMTP_SSL(mailserver, int(mailserverport))
        server.ehlo()
        server.login(mailuser, mailpwd)
        server.sendmail(mailsender, receivers, message)
        server.close()
        print('Email sent!')
    except Exception as exception:
        print("Error: %s!\n\n" % exception)
## ================== End send email ========================


## Function to create a random number of 10 integers
## This is added to the Waves wallet address to ensure
## a unique S3 object string, in case the wallet address
## is used more then one time.
## ========================= START =======================
def create_wallet_number_addon():

    rangestart      = 0
    rangeend        = 9
    totalnumbers    = 10
    addon           = ""

    for count in range(0, totalnumbers):
        number = random.randint(rangestart, rangeend)
        addon += str(number)

    return addon
##===========================  END  ======================
