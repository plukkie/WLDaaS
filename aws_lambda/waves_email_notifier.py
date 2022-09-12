import json
import boto3
import time
import smtplib
import os
import pybase64 as base64

# get script configuration from configfile
settings_bucket = os.environ.get("script_settings_bucket")
script_subpath  = os.environ.get("script_settings_path")
config_file     = os.environ.get("scripts_settingsfile")


## Main function
## It extracts the name of the s3 triggerfile
## The json content reads:
## - session data: all data used in the collector and payment (if applicable)
## - results: all data that the container jobs created as output with summary
## - mailheaders: the mail header data like sender, receiver, mailtemplate etc...
##
## The mailtemplate is the mail body with the message outlined that is send to
## the client. All vars are replaced by the values found in the session and result
## data.
## 
## ===================== BEGIN MAIN ==========================
def lambda_handler(event, context):
    
    # Extract S3 triggerobject & bucket
    trigger_bucket      = event['Records'][0]['s3']['bucket']['name']
    trigger_file        = event['Records'][0]['s3']['object']['key']

    script_config       = json.loads(read_s3_object(settings_bucket,config_file))
    jsondata            = json.loads(read_s3_object(trigger_bucket,trigger_file))
    sessiondata         = jsondata['session']
    results             = jsondata['results']
    mailheaders         = jsondata['mailheaders']
    mailtemplate        = read_s3_object(settings_bucket, script_subpath + mailheaders['mailtemplate'])

    
    if sessiondata['dopayments'] == 'false':
        print('collector session done without payments.')
    else:
        print('collector session done with payment request.')
        if results.get('zerosharing') == True:
            print('Nothing to share. No pay transaction to leasers needed.')
    
    
    send_email(script_config, mailheaders, sessiondata, results, mailtemplate)
    
    return {
        'statusCode': 200,
        'body': json.dumps('Finishe Lambda waves_email_notifier!')
    }
## ======================= END MAIN ==========================


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
    

## Send email method
##
##
## ================== BEGIN send email ======================
def send_email(script_config, mailheaders, sessiondata, results, mailtemplate):

    sc                  = script_config
    mh                  = mailheaders
    sd                  = sessiondata
    res                 = results
    mh['frontendlink']  = sc['frontendlink']
    mailserver      = sc['server']['name']
    mailserverport  = sc['server']['port']
    mailuser        = sc['account']['username']
    mailpwd         = 'wwvrcusksjlrlxov'            ## Gmail app password
    mailsender      = mh['mail_from']
    receivers       = mh['receivers']
    
    #print(res)
    
    for key in mh:  ## This searches for the mail header tags and replaces in mailtemplate file
        value = mh[key]
        searchstring = "<" + key + ">" #String to search for in mailtemplate
        if searchstring in mailtemplate:
            #print('found searchstring ' + searchstring + ' in mail template and replaced it with: ' + value)
            mailtemplate = mailtemplate.replace(searchstring, str(value)) ##Replace string with value
    
    for key in sd:  ## This searches for the sessiondata tags and replaces in mailtemplate file
        value = sd[key]
        searchstring = "<" + key + ">" #String to search for in mailtemplate
        if searchstring in mailtemplate:
            #print('found searchstring ' + searchstring + ' in mail template and replaced it with: ' + value)
            mailtemplate = mailtemplate.replace(searchstring, str(value)) ##Replace string with value
    
    for key in res: ## This searches for the results tags and replaces in mailtemplate file
        value = res[key]
        if key == 'assetcounters':
            for asset in value:
                #print(asset)
                for key in value[asset]:
                    counter = value[asset][key]
                    searchstring = "<" + key + "> " + asset #String to search for in mailtemplate
                    replacestring = str(counter) + " " + asset
                    if searchstring in mailtemplate:
                        #print('found searchstring ' + searchstring + ' in mail template and replaced it with: ' + value)
                        mailtemplate = mailtemplate.replace(searchstring, replacestring) ##Replace string with value
        
        elif key == 's3_presigned_urls_base64':
            for item in value: #item = keyname, value=whole item object
                displaytext = value[item]['displaytext']
                paramvalue = value[item]['link']
                linkhref = sc['frontendlink'] + "?" + item + "=" + paramvalue
                searchstring = "<" + item + ">" #String to search for in mailtemplate
                replacestring = "<a href=" + linkhref + ">" + displaytext + "</a>"
                if searchstring in mailtemplate:
                    #print('found searchstring ' + searchstring + ' in mail template and replaced it with: ' + value)
                    mailtemplate = mailtemplate.replace(searchstring, replacestring) ##Replace string with value

        elif key == 's3_presigned_urls':
            for item in value: #item = keyname, value=whole item object
                displaytext = value[item]['displaytext']
                linkhref = value[item]['link']
                try:
                    expiretime =  round(int(value[item]['expiresecs'])/3600/24)
                except:
                    expiretime = 'No expiration'
                    
                searchstring = "<" + item + ">" #String to search for in mailtemplate
                replacestring = "<a href=" + linkhref + ">" + displaytext + "</a> Expires in " + str(expiretime) + " days"
                if searchstring in mailtemplate:
                    #print('found searchstring ' + searchstring + ' in mail template and replaced it with: ' + value)
                    mailtemplate = mailtemplate.replace(searchstring, replacestring) ##Replace string with value

        else:
            searchstring = "<" + key + ">" #String to search for in mailtemplate
            replacestring = str(value)
            if searchstring in mailtemplate:
                #print('found searchstring ' + searchstring + ' in mail template and replaced it with: ' + value)
                mailtemplate = mailtemplate.replace(searchstring, replacestring) ##Replace string with value

    
    
    try:
        server = smtplib.SMTP_SSL(mailserver, int(mailserverport))
        server.ehlo()
        server.login(mailuser, mailpwd)
        server.sendmail(mailsender, receivers, mailtemplate)
        server.close()
        print('Email sent to ' + sd['email'] + '!')
        print('Report:')
        #print(mailtemplate)
    except Exception as exception:
        print("Error: %s!\n\n" % exception)
## ================== END send email ========================
