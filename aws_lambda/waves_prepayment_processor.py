import json
import boto3
import logging
import os
import math
import numpy as np
import pprint
import pybase64 as base64
import base58

from datetime import datetime
from botocore.exceptions import ClientError
from botocore.client import Config

pp = pprint.pprint

#ENV vars
my_script_bucket                    = os.environ.get("script_settings_bucket")
my_script_path                      = os.environ.get("wldaas_scripts")
my_default_lease_report_template    = os.environ.get("default_leasing_report_template")
my_script_settings                  = os.environ.get("this_settingsfile")
shared_script_settings              = os.environ.get("shared_settingsfile")
my_data_bucket                      = os.environ.get("wldaas_data_bucket")
data_package_download_bucket        = os.environ.get("wldaas_data_package_bucket")

#Constants
wexp                                = 8.0   ##Waves decimals


## Read S3 object
## If errors, add error details to global object
## trigger_details['errors']
##
## params:
## - bucket : S3 bucket name
## - key    : object name
## return:
## - filecontent
## ========================== START Read S3 ============================
def read_s3_object(bucket, key):
    try:
        s3 = boto3.resource('s3')
        s3object = s3.Bucket(bucket).Object(key)
        file_content = s3object.get()['Body'].read().decode('utf-8')
    except:
        print('Error reading s3 object: \n -bucket: ' + bucket + '\n -object: ' + key + '\n\nExit')
        trigger_details['errors'] = {
                                        "awsservice" : "s3",
                                        "lambda" : lambdaname,
                                        "msg" : "Error reading s3 object",
                                        "bucket" : bucket,
                                        "key" : key,
                                        "payments" : "false"
                                    }
    else:
        return file_content
## ========================== END Read S3 ============================


## Write S3 object
## If errors, add to global object trigger_details['errors']
## params:
## - bucket : S3 bucket name
## - key    : object name
## - data   : object data to write
## - datatype : 'json' or 'text/html'
## - contenttype = 'binary/octet-stream'
## return:
## - filecontent
## ========================== START Write S3 ============================
def write_s3_object(bucket,key, data, datatype='json', contenttype="text/html"):
    
    if datatype == 'json':
        data = json.dumps(data)
        
    try:
        s3 = boto3.resource('s3')
        s3object = s3.Bucket(bucket).Object(key)
        file_content = s3object.put(Body=data, ContentType=contenttype)
    except:
        print('Error writing s3 object: \n -bucket: ' + bucket + '\n -object: ' + key + '\n\nExit')
        trigger_details['errors'] = {
                                        "awsservice" : "s3",
                                        "lambda" : lambdaname,
                                        "msg" : "Error writing s3 object",
                                        "bucket" : bucket,
                                        "key" : key,
                                        "payments" : "false"
                                    }
    else:
        pass
## ============================ END write S3  ============================


## Function that strips lease objects who should not get payed
## relevant data to report is stored in the trigger_details dictionary
## arguments
## - lst: the leasedata list
## return
## - list with only objects that get payed
## ======================== START Cleanup leasedata ==========================
def cleanup_leasedata_list(lst):

    newlist = []
    counterlist = {}
    
    for index, obj in enumerate(lst): ##Loop through all leasedata records
        try:
            assetid = obj['assetId']
        except:
            assetid = 'Waves'

        if counterlist.get(assetid) == None: ##Add asset to counterlist if not yet added
            counterlist[assetid] =  {
                                        "totalfees": trigger_details['results']['assetcounters'][assetid]['totalfees'],
                                        "feesshared": 0,
                                        "nopayaddresscnt": 0,
                                        "payaddresscnt": 0,
                                        "payaddressamount": 0,
                                        "nopayaddressamount": 0,
                                        "nodeprofit": 0,
                                        "effectivenodeprofit": 0
                                    }

        if obj.get('pay') == 'no':
            counterlist[assetid]['nopayaddresscnt'] +=1
            counterlist[assetid]['nopayaddressamount'] += obj['amount']
        else:
            counterlist[assetid]['payaddresscnt'] +=1
            counterlist[assetid]['payaddressamount'] += obj['amount']
            newlist.append(obj)

    for asset in counterlist:
        if asset == 'Waves': decimals = wexp
        counterlist[asset]['nopayaddressamount']    = counterlist[asset]['nopayaddressamount']/pow(10, decimals)
        counterlist[asset]['payaddressamount']      = counterlist[asset]['payaddressamount']/pow(10, decimals)
        counterlist[asset]['feesshared']            = format(counterlist[assetid]['payaddressamount'] +\
                                                      counterlist[assetid]['nopayaddressamount'], '.'+str(int(wexp))+'f')
        counterlist[asset]['nodeprofit']            = format(float(counterlist[asset]['totalfees']) -\
                                                      float(counterlist[asset]['feesshared']), '.'+str(int(wexp))+'f')
        counterlist[asset]['effectivenodeprofit']   = format(float(counterlist[asset]['nodeprofit']) +\
                                                      float(counterlist[asset]['nopayaddressamount']), '.'+str(int(wexp))+'f')


    trigger_details['results']['assetcounters'] = counterlist

    return newlist
## ========================= END Cleanup leasedata ==========================

    

## Function that create complete masstransfer objects, maximized by the 
## Waves masstxs limit (currently 100). The data will be written to S3
## and can be consumed by the waves transaction app (signer).
##
## arguments
## - lst: the leasedata list
## return
## - list with only objects that get payed
## ====================== START Create limited masstx dict ====================
def create_masstransfer_limitted_list(lst):

    # Format masstransfer JSON code
    # -----------------------------
    # massTransfer(
    #               {
    #                   assetId: 'base58string', (if not given, defaults to WAVES asset)
    #                   transfers:  [{
    #                       amount: LONG,
    #                       recipient: 'string',
    #                               }],
    #                   attachment: 'base58string',
    #               }
    #             )
    #------------------------------
    masstransferlist = []
    masstxlimit    = int(this_conf_settings['masstx_limit'])

    for obj in lst:
        thistransfer =  {
                            "recipient" : obj['recipient'],
                            "amount" : obj['amount']
                        }

        masstransferlist.append(thistransfer)

    records = len(masstransferlist) #How many leaserecords in total
    #print('total records:' + str(records))
    masstxs = math.ceil(records/float(masstxlimit)) #How many masstransfers do we need
    #print('mass transaction needed: ' + str(masstxs))

    # This creates list with arrays of transfer batches
    # masstransferblocks = { [{transfers}], [{transfers}], [{transfers}] }
    # NOTE
    # can not split an empty array
    if masstxs != 0: masstransferlist = np.array_split(masstransferlist, masstxs)
    #print('splitted masstransfer array:')
    #pp(list(masstransferlist))
    
    cnt = 0
    lst = [] #Reset list
    attachment = trigger_details['session'].get('transactionattachment')
    attachmentbase58 = attachment
    
    if attachment != 'none':

        attachment = decode_base58 (attachment)
        print(attachment)
        
    for transfers in masstransferlist:
        masstxobject = {}
        cnt +=1
        masstxobject["transfers"] = list(transfers)
        if attachment != 'none':
            masstxobject["attachment"] = attachmentbase58
        lst.append({ "transferdata_masstx_"+str(cnt) : masstxobject })

    return lst
## ======================= END Create limited masstx dict =====================


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


## Function that terminates further processing, because of errors
## If relevant settings for the s3 error message write can not be loaded
## they are set manually.
## The message written to S3, will trigger the email function
##
## no return -> exit
## ============================= START terminate =============================
def terminate():
    
    currenttime = datetime.now().strftime('%d-%m-%Y_%Hh%Mm%Ss')
    
    print('There are errors. Abort payprocessor.')
    
    try:
        fileprefix              = shared_conf_settings['toolbaseconfig']['collectorfilesprefix']
        email_trigger_bucket    = shared_conf_settings['paymentconfig']['wldaas_s3_trigger_bucket']
    except:
        fileprefix              = 'collected_'
        email_trigger_bucket    = 'wldaas-email-triggers'
        
    try:
        sessionid
    except:
        sessionid = 'errors-prevented-sessionid-retrieval'

    s3_file     = fileprefix + sessionid + '_' + currenttime + '.json'
    write_s3_object(email_trigger_bucket, s3_file, trigger_details)
    exit()
## ============================== END terminate ==============================

 
## ====================== START write finish trigger =========================
def write_end_result_trigger_file():
    
    currenttime             = datetime.now().strftime('%d-%m-%Y_%Hh%Mm%Ss')
    email_trigger_bucket    = shared_conf_settings['paymentconfig']['wldaas_s3_trigger_bucket']
    fileprefix              = shared_conf_settings['paymentconfig']['wldaas_s3_email_trigger_prefix']
    s3_file                 = fileprefix + sessionid + '_' + currenttime + '.json'
    
    write_s3_object(email_trigger_bucket, s3_file, trigger_details)
## ======================= END write finish trigger ==========================


## ====================== START create s3 presigned url ========================
def create_s3_presigned_url ( bucket_name, object_name, expiration=3600, region='eu-north-1' ):

    """Generate a presigned URL to share an S3 object

    :param bucket_name: string
    :param object_name: string
    :param expiration: Time in seconds for the presigned URL to remain valid
    :return: Presigned URL as string. If error, returns None.
    """
    expiration = int(expiration)
    # Generate a presigned URL for the S3 object
    s3_client = boto3.client('s3', config=Config(signature_version='s3v4', region_name=region))

    try:
        response = s3_client.generate_presigned_url('get_object',
                                                    Params={'Bucket': bucket_name,
                                                            'Key': object_name},
                                                    ExpiresIn=expiration)
    except ClientError as e:
        logging.error(e)
        return None

    return response
## ======================= END create s3 presigned url =========================


## ======================== START create base64 message ========================
def create_base64_string(message):

    Bytes           = message.encode('ascii')
    base64_Bytes    = base64.b64encode(Bytes)
    base64_message  = base64_Bytes.decode('ascii')

    return base64_message
## ========================= END create base64 message =========================


## ==================== START write html report for leasers ====================
## Function that grabs an html template and replaces the tags with the
## generated data in this function
##
## params;
## - templatebucket : location of html template
## - templateobject : name of template inclusive paths in bucket (unique)
## - outputbucket   : name of bucket to store report (unique name)
## 
## return           : html object (string)
## -----------------------------------------------------------------------------
def create_html_lease_report(reporttemplate, collectorresults):
    print('Creating HTML report.')
    
    htmltp  = reporttemplate                        ## HTML lease report template 
    cr      = collectorresults                      ## JSON object of Collector results 
    sd      = collectorresults['session']           ## Session meta data
    res     = collectorresults['results']           ## Collection result counters
    ds      = collectorresults['distributionstats'] ## Recipient amounts
    
    for key in sd:  ## Seek through sessiondata keys and replace in html template when matched
        value = sd[key] ## Value of key
        searchstring = "<*" + key + "*>" #String to search for in html template
        if searchstring in htmltp:
            #print('found searchstring ' + searchstring + ' in html template and replaced it with: ' + value)
            htmltp = htmltp.replace(searchstring, str(value)) ##Replace string with value
    
    tablerowobject = ""
    
    for obj in ds:  ##Loop though all recipients and create tableobject
        decimals = wexp
        recipient   = obj['recipient']
        amountwleds = obj['amount']
        #amountwaves = int(amountwleds)/pow(10, decimals)
        amountwaves = ('{:.' + str(int(decimals)) + 'f}').format(int(amountwleds)/pow(10, decimals))

        tablerowobject += "<tr><td>" + recipient + "</td><td>" + str(amountwaves) + "</td></tr>"

    searchstring = "<*distributionstats*>"
    
    if searchstring in htmltp:
            htmltp = htmltp.replace(searchstring, tablerowobject) ##Replace string with value
    
    
    for key in res: ## This searches for the results tags and replaces in mailtemplate file
        value = res[key]
        if key == 'assetcounters':
            for asset in value:
                #print(asset)
                for key in value[asset]:
                    counter = value[asset][key]
                    searchstring = "<*" + key + "*>" #String to search for in mailtemplate
                    replacestring = str(counter)
                    if searchstring in htmltp:
                        #print('found searchstring ' + searchstring + ' in mail template and replaced it with: ' + value)
                        htmltp = htmltp.replace(searchstring, replacestring) ##Replace string with value
       
        else:
            searchstring = "<*" + key + "*>" #String to search for in mailtemplate
            replacestring = str(value)
            if searchstring in htmltp:
                #print('found searchstring ' + searchstring + ' in mail template and replaced it with: ' + value)
                htmltp = htmltp.replace(searchstring, replacestring) ##Replace string with value
 
    
    return htmltp
    
## ===================== END write html report for leasers =====================



    
################################## START MAIN ################################
def lambda_handler(event, context):
    
    #print(context)
    #print(event)
    
    global sessionid, this_conf_settings, shared_conf_settings, trigger_details, lambdaname
    
    trigger_bucket          = event['Records'][0]['s3']['bucket']['name']
    trigger_file            = event['Records'][0]['s3']['object']['key']
    lambdaname              = context.function_name
    trigger_details         = {} 
    this_conf_settings      = {}
    shared_conf_settings    = {}
    
    
    ##GLOBAL vars
    try:
        trigger_details         = json.loads(read_s3_object(trigger_bucket, trigger_file))
        sessionid               = trigger_details['session']['sessionid']
        this_conf_settings      = json.loads(read_s3_object(my_script_bucket, my_script_settings))
        shared_conf_settings    = json.loads(read_s3_object(my_script_bucket, shared_script_settings))
    except:
        try:
            pp(trigger_details['errors'])
        except:
            triggers_details['errors'] = "json load error in one of the settings files?"
            
        terminate()
    else:
        pass

    
    ##LOCAL vars
    wallet                    = trigger_details['session']['myleasewallet']
    s3_wallet_folder          = trigger_details['session']['s3_wallet_folder']
    leasedatafile             =  s3_wallet_folder + '/data/' + shared_conf_settings['toolbaseconfig']['collectorfilesprefix']+sessionid+'.json'
    leasedata                 = json.loads( read_s3_object( my_data_bucket, leasedatafile ) )
    payprocessorfile          = s3_wallet_folder + '/data/' + shared_conf_settings['paymentconfig']['wldaas_s3_payprocessor_prefix']+sessionid+'.json'
    download_packagefile      = 'devpackage-' + sessionid + '.json'
    leasereport_htmlfile      = 'leasereport-' + sessionid + '.html'
    leasereport_template_file = my_script_path + my_default_lease_report_template   ##located in my_script_bucket
    leasereport_template      = read_s3_object ( my_script_bucket, leasereport_template_file )  ##Read HTML report template
    leasereport_bucket        = shared_conf_settings['paymentconfig']['wldaas_s3_lease_reports']
    
    print('Pre payment processing started, sessionid ' + sessionid)
    
    if len(leasedata) == 0:
        print('Empty leasedata file. No payments applicable.')
        result = []
        trigger_details['results']['zerosharing'] = True
        collection_results_download_package = trigger_details
        collection_results_download_package["distributionstats"] = result   ##Add zero collection results for dev package

    else:
        result  = cleanup_leasedata_list(leasedata) #returns transfer array with all recipients, assets & amounts
        collection_results_download_package = trigger_details
        collection_results_download_package["distributionstats"] = result   ##Add raw collection results for dev package
        result  = create_masstransfer_limitted_list(result) #returns complete massTranfer object array, maximized to Waves masstransfer limit
    
    
    ##create HTML report from template with collector results
    leasereport = create_html_lease_report(leasereport_template, collection_results_download_package)
    
    
    try:
        write_s3_object(my_data_bucket, payprocessorfile, result) ##Write payment transaction data to data bucket
        write_s3_object(data_package_download_bucket, download_packagefile, collection_results_download_package, contenttype='binary/octet-stream') ##Write downloadable data sharing bucket
        write_s3_object(leasereport_bucket, leasereport_htmlfile, leasereport, datatype='text/html', contenttype='text/html')  ##Wrire HTML report to s3 leasing report bucket
    except:
        pp(trigger_details['errors'])
        terminate()
    else:   ## Construct presigned urls & download links
        s3_region            = shared_conf_settings['paymentconfig']['wld_s3_region']
        
        if len(leasedata) != 0:
            expiretime           = this_conf_settings['presigned_url_valid_secs']
            s3_presigned_url     = create_s3_presigned_url ( my_data_bucket, payprocessorfile,
                                                             expiration=expiretime,
                                                             region=s3_region )
            s3_presigned_url_b64 = create_base64_string ( s3_presigned_url )
            
            trigger_details['results']['s3_presigned_urls_base64'] = \
                    {
                        "wavespaylink" : {
                                            "link" : s3_presigned_url_b64,
                                            "displaytext" : "Use this link to execute the payment to your leasers"
                                         }
                    }
        
        ## Collector dev data bundle
        expiretime           = this_conf_settings['presigned_url_package_download_valid_secs']

        s3_presigned_url     = create_s3_presigned_url ( data_package_download_bucket, download_packagefile,
                                                             expiration=expiretime,
                                                             region=s3_region )
        #s3_presigned_url_b64 = create_base64_string ( s3_presigned_url )
        print('s3 presigned url to download package : ' + s3_presigned_url  )
        
        try:
            trigger_details['results']['s3_presigned_urls']
        except:
            trigger_details['results']['s3_presigned_urls'] = {}
        
        trigger_details['results']['s3_presigned_urls']['wavescollectorresultsbundlelink'] = \
                    {
                            "link" : s3_presigned_url,
                            "displaytext" : "Use this link to download the distribution results selfservice package",
                            "expiresecs" : expiretime
                    }

        ## Leasereport url
        expiretime           = this_conf_settings['presigned_url_leasereport_valid_secs']
        #s3_presigned_url     = create_s3_presigned_url ( data_package_download_bucket, download_packagefile,
                                                        #     expiration=expiretime,
                                                       #      region=s3_region )
        s3_url               = "http://" + leasereport_bucket + '.s3-website.' + s3_region + '.amazonaws.com/' + leasereport_htmlfile
        print('s3 url to lease report : ' + s3_url  )
        #print('s3 presigned url to lease report : ' + s3_presigned_url  )
            
        trigger_details['results']['s3_presigned_urls']['leasereportlink'] = \
                    {
                            "link" : s3_url,
                            "displaytext" : "Use this link to download the fees distribution report.",
                            "expiresecs" : expiretime
                    }
        
    
    try:
        write_end_result_trigger_file() ## Write s3 triggerfile to be picked up by email lambda function
    except:
        pp(trigger_details['errors'])
        terminate()
    else:
        print('Finished prepayment processing.')
        
        
    #print(resultmaxed) 
    #print('trigger details send to email notifier:')
    #pp(trigger_details)
    
    
    return {
        'statusCode': 200,
        'body': json.dumps('Finished Waves pre processor')
    }
################################# END main ##################################



