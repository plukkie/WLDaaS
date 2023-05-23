//////////////////////////////////////////////////
// Some comments
// Transaction type  8 : Lease
// Transaction type  9 : LeaseCancel
// Transaction type 16 : Invoke script
//                       - stateChanges
//                         - leases
//                         - leaseCancels
//                         - invokes
//                           - stateChanges
//                             - leases
//                             - leaseCancels
//////////////////////////////////////////////////

const configfile = 'config.json' //json file with appng.js settings
const s3_config_bucket = '<<AWS s3 bucket>>' //aws s3 bucket where configfile is stored
const s3_settings_path = '<<AWS s3 subpath>>' //sub path for configfile object
const s3_config_object = s3_settings_path + configfile //full aws s3 object
const appngrunfile = 'appng.run' 
const nopaytriggerfileprefix	= 'collected_'
const paytriggerfileprefix	= 'payjob_'
const http = require('http')
const rewarddevider = 3

var request = require('sync-request');
var fs = require('fs');
var AWS = require('aws-sdk')
var datetime = (new Date())
var date = datetime.getDate()+"-" + (datetime.getMonth()+1) +"-"+datetime.getFullYear()
var time = datetime.getHours()+"h"+datetime.getMinutes()+"m"+datetime.getSeconds()+"s"
var myAliases = [];
var config = {}
var currentStartBlock;
var myLeases = {}; //object, gets all active lease transactions
var myCanceledLeases = {}; //object, gets all cancelled lease transactions
var prevleaseinfofile; //File with all block leaser info from previous collector batch
var payments = [];
var mrt = [];
var BlockCount = 0;
var LastBlock = {};
var myForgedBlocks = []; //Array with all blocks that my node forged
var servicename;
var mailto;
var myquerynode
var feedistributionpercentage
var mrtperblock
var myleasewallet
var attachment = 'none'
var startscanblock
var paymentstartblock
var paymentstopblock
var blockwindowsize
var nofeearray
var blockrewardsharingpercentage
//define all vars related to the tool settings
var collectorfilesprefix
var minscfee
var mintxfee 
var balancesuri
var datadir
var batchinfofile
var s3_batchinfofile
var payqueuefile
var generatingbalance
var batchinfo = {}
var mybatchdata = {}
var wld_s3_bucket; //aws s3 bucket where payment processor output it stored
var lastblockleasersfile; //file which stores active leasers at lastblock scanned in batch (scanstopblock)
var payid //The collector batch of current session
var nextpayid //The collector batchid of the next session
var argobj = {} //dictionary with override cli values
var reset //boolean to indicate of previous batchinfo data should be overwritten
var force_collector_start //Indicates if the stopblock should be lowered to current height if it is set in the future
var dopayments  //Boolean, Should we excute payment after collection
var reportingobject = {} //object to store some reporting stats for client (used in lambda trigger file (notify or payprocessor)
var activeleasesstart //How many active leasers when the collector job starts
var activeleasesend //How many active lease transactions at end
var wavesFeesfull = 0 //total waves fees collected 100%
var wavesFeesshared = 0  //Waves fees shared
var wldaas_s3_trigger_bucket //Bucket where result output file is written that triggers lambda followup (notify or payprocessor)
var wldaas_s3_payprocessor_trigger_bucket //Bucket that will trigger the payment processor lambda function (only if dopayments is true)
var collectormail //object with mailheaders to send email to client 
var accountmail //Mail that should receive the collector tasks (the signup mail)
let sessionid //sessionid used for the job (got it from lambda)
var wavesnopayaddresscnt = 0
var wavespayaddresscnt = 0
var wavespayaddressamount = 0
var wavesnopayaddressamount = 0
var ecs_statefile__mybody = {}
let connect_retries
let connect_retry_delay
let get_collect_batch_delay
let request_open_sockets
let collect_batch_size
var errorobject = {}
let uniqueleasersend = 0
let startblocktime = ""
let stopblocktime = ""





/* Method that collects CLI arguments
 * args
 * - cli_key_array : array with possible keys from config.json
 *
 * On AWS cloud when used as a container, if additional commands
 * are send along, all commands are received as one string.
 * i.e.: commands : a=1 b=2 c=3 => 'a=1 b=2 c=3'
 * Thats why the myargs need extra modding to break at spaces
 */
function get_cli_args (cli_key_array) {

	const space=' '
	const breaker = '='
	const nopaytext = 'nopayoutaddresses'
	
	//Set array with all cli args given (strip 'node appng')
	//Items are devided by space delimiter
	//Values that contain spaces needs therefore contained in quotes
	//i.e. key="my value"
	let myargs = process.argv.slice(2)
	//console.log('Array with cli arguments received from lambda:', myargs)

	if ( myargs.length != 0 ) { //Found cli args

		//First sanetize the arguments given
		console.log('\nCLI arguments as received from lambda call: ' + myargs)
		
		myargs.forEach(function(myarg) {

			//If key is not defined in config.json, it will not be used
			cli_key_array.forEach(function(key) { //For all possible argument keys that are from config.json

				let key_in_key = myarg.indexOf(key) //If key not found, value is -1, else a cli arg was given, found at pos 0

				if ( key_in_key === 0 ) { //use argument from cli

					let keylength = key.length + breaker.length //get length of key to strip off
					let keyvalue = myarg.slice(keylength) //get value of argument
					let keyname = key

					//Next 4 lines are needed to check if the values contain double quotes
					//This is the case when the arguments are passsed from lambda
					//These need to be removed before added to dictionary object
					//NOTE
					//This is not needed when it would be started in node.js directly with the arguments
					//added on the command line.
					const firstchar = keyvalue.slice(0,1)
					const lastchar = keyvalue.slice(-1)
					if ( firstchar == '"' ) { keyvalue = keyvalue.substring(1) }
					if ( lastchar == '"' ) { keyvalue = keyvalue.substring(0, keyvalue.length - 1 ) }

					if ( keyname == nopaytext && keyvalue.length != 0 ) { //This is the nopayout address array
						let splitarray = keyvalue.split(space) //split string on space and create array of items
						keyvalue = splitarray
					} else if ( keyname == nopaytext ) { argobj[keyname] = [] }

					if ( keyvalue.length != 0 ) { //Found argument value, set var and value dynamically
					
						argobj[keyname] = keyvalue //Object with all key/values pushed by the API/Lambda user request

						//console.log('  - ' + keyname + ' : ' + keyvalue) //Print which values are used
					}
				}
			});
		});
		sessionid = argobj['sessionid']
		if ( !argobj[nopaytext] ) { argobj[nopaytext] = [] }
		console.log('dict argobj{}:')
		console.log(argobj)
	}
}


function delete_s3_object (bucket, key) {

	let s3 = new AWS.S3();
	const params = {  Bucket: bucket, Key: key };

	s3.deleteObject(params, function(err, data) {
		if (err) console.log(err, err.stack);  // error
  		else console.log();                 // deleted
	});
}



/* Promise to GET an S3 JSON object
 * arguments;
 * - aws_s3_bucket : name of S3 bucket
 * - aws_s3_object : name of S3 object
 */
function get_s3_object_promise (aws_s3_bucket, aws_s3_object) {

	return new Promise(function(resolve, reject) {
	
		let s3_params = { Bucket: aws_s3_bucket, Key: aws_s3_object };
		s3 = new AWS.S3({apiVersion: '2006-03-01'}); // Create S3 service object

		s3.getObject(s3_params, function(err,data) {
 			if(err) {
  				console.log(err,err.stack);
				reject(err)
 			}
 			else {
  				//console.log(data.Body.toString('utf-8'));
				resolve(data.Body.toString('utf-8'))
 			}
		});
	}); //End promise
}


/* Promise to POST an object to S3
 * arguments;
 * - aws_s3_bucket : name of S3 bucket
 * - aws_s3_object : name of S3 object
 * - type : html/text OR json
 */
function upload_s3_object_promise (aws_s3_bucket, aws_s3_object, object_body, type) {

	if (!object_body) { //No body given
		object_body = '' //Set empty body
	} else if (type === 'text' || type === 'html') {
		type = 'text/html'
	} else {
		type = 'json'
		object_body = JSON.stringify(object_body)
	}

	return new Promise(function(resolve, reject) {

		let uploadParams = { Bucket: aws_s3_bucket, Key: aws_s3_object, Body: object_body, ContentType: type };
		s3 = new AWS.S3({apiVersion: '2006-03-01'}); // Create S3 service object
		
		s3.upload (uploadParams, function (err, data) {

                        if (err) {
                                console.log("Error uploading to AWS! Object: s3://" + aws_s3_bucket + "/" + aws_s3_object)
				console.log(err)
				reject(err)
                        }
                        if (data) {
				resolve(data)
                        }
                })
	});
}


/* Promise to check if an S3 object exists
 * arguments;
 * - s3bucket : name of S3 bucket
 * - s3object : name of S3 object
 */
function check_s3_object_exists_promise (s3bucket, s3object) {

	let params = {
    		Bucket: s3bucket,
    		Key: s3object
	};	

	return new Promise(function(resolve, reject) {

		s3.headObject(params, function (err, metadata) {
  			if (err && err.code === 'NotFound') {
    				// Handle no object on cloud here
				reject(err)
  			} else {
    				//s3.getSignedUrl('getObject', params, callback);

				resolve(metadata)
  			}
		});
	});
}







/* Method to create a folder
 * arguments;
 * - dir : directory to check
 */
function foldercheck ( dir ) {

	if (!fs.existsSync(dir)) { //folder does not exist
    		fs.mkdir(dir, (err) => { //create folder
    			if (err) {
				console.log("Error creating folder '" + dir + "'")
        			throw err;
				console.log('Will stop now. Check folder permissions.')
				process.exit()
    			}
		});
	}
}


function get_api_json_request (url) {

	let response = {}

	if (url != '' && url != undefined) {
		response = JSON.parse(request('GET', url, { json: true } ).body)
	} else {
		response = { "container_run" : "local run" }
	}

	return response;
}


/**
 * Method that returns all aliases for address.
 *
 * @returns {Array} all aliases for address
 */
function getAllAlias () {
						var AliasArr = [];
            var Aliases = JSON.parse(request('GET', config.node + '/alias/by-address/' + config.address, {
                'headers': {
                    'Connection': 'keep-alive'
                }
            }).getBody('utf8'));

        Aliases.forEach(function(alias)
        {
						 AliasArr.push(alias);
						 console.log(alias);
        });
    return AliasArr;
}


/**
  * This method starts the overall process by first downloading the blocks,
  * preparing the necessary datastructures and finally preparing the payments
  * and serializing them into a file that could be used as input for the
  * masspayment tool.
 */
function start () {
  console.log('get aliases');
  myAliases = getAllAlias();
    console.log('Retreive blocks and collecting lease info and transaction fees...');

	var blocks = getAllBlocks(); //array with all blocks and blockdata of current batch
	blocks.then ( function (result) {

		if (Object.keys(errorobject).length != 0 ) {
			console.log('******************************')
			console.log(' There were errors collecting blocks !')
			console.log(' content error object:\n', errorobject)
			console.log('******************************')
		}

		console.log('preparing payments...');

    		myForgedBlocks.forEach(function(block) {

        		if (block.height >= config.startBlockHeight && block.height <= config.endBlock) {

            			var blockLeaseData = getActiveLeasesAtBlock(block);
            			var activeLeasesForBlock = blockLeaseData.activeLeases;
            			var amountTotalLeased = blockLeaseData.totalLeased;

            			distribute(activeLeasesForBlock, amountTotalLeased, block);
            			BlockCount++;
        		}
    		});

    		pay();
    		console.log("blocks forged: " + BlockCount);
    		write_end_result_trigger_file();
	})
	.catch ( function (result) {

		}
	)
};


//request function to receive the blocks
//
function get_blocks_promise (msg, url, connectionpool)	{

	let failurecnt = 0

	//url = url + 'a' //FOR ERROR TESTING

	return new Promise ( function ( resolve, reject) {

		//console.log('GET request to ' + url)

		function get_request ( url , failurecnt) {	

			console.log(msg)
			//console.log(failurecnt)

			http.get ( url, {agent:connectionpool}, res => {
				let body = "";
				res.on("data", (chunk) => {
        				body += chunk;
    					}
				);
				//console.log('initiated http.get in function promise get_blocks_promise, function get_request..')

				res.on("end", () => {
        				try {
            					let jsonbody = JSON.parse(body);
						console.log('http request to ' + url + ' successful')
						resolve(jsonbody)
        				} catch (error) {
						console.log('catch error from parsing body from result, try JSON.parse(body)')
            					console.error(error.message);
        				};
				});
			})
			.on('error', err => {
				failurecnt++
				console.log('http request to ' + url + ' failed')

				if (failurecnt < connect_retries) {
					
					setTimeout ( function () {
						console.log('RETRY : ' + msg)
						get_request(url, failurecnt)
					}, connect_retry_delay)

				}
				if (failurecnt == connect_retries) { 
					console.log('ALL RETRIES FAILED : ' + url)
					reject(err)
				}
			})
		}

		get_request(url, failurecnt)
	})
}



function write_end_result_trigger_file() {

	let s3object
	let s3bucket
	let s3body = {}
	let activeleasesend = Object.keys(myLeases).length
	let leaseschange = activeleasesend - activeleasesstart
	let wavesnodeprofit = wavesFeesfull-wavesFeesshared
	let effectivewavesnodeprofit = wavesnodeprofit+wavesnopayaddressamount
	let sessiondescription = "no description"

	reportingobject = {
				"myblocks" : myForgedBlocks.length,
				"blocksscanned" : paymentstopblock-paymentstartblock+1,
				"assetcounters" : {
							"Waves" : {
								"totalfees" : (wavesFeesfull/100000000).toFixed(8),
								"feesshared" : (wavesFeesshared/100000000).toFixed(8),
								"nopayaddresscnt" : wavesnopayaddresscnt,
								"payaddresscnt" : wavespayaddresscnt,
								"payaddressamount" : (wavespayaddressamount/100000000).toFixed(8),
								"nopayaddressamount" : (wavesnopayaddressamount/100000000).toFixed(8),
								"nodeprofit" : (wavesnodeprofit/100000000).toFixed(8),
								"effectivenodeprofit" : (effectivewavesnodeprofit/100000000).toFixed(8)
							}
				},
				"generatingbalance" : Math.round(generatingbalance / Math.pow(10, 8)),
				"activeleases" : activeleasesend,
				"leaseschange" : leaseschange,
				"uniqueleasersend" : uniqueleasersend
			  }

	if ( dopayments == 'true' ) {
		s3bucket = wldaas_s3_payprocessor_trigger_bucket //Write trigger to payprocessor bucket, payments are requested
		s3object = paytriggerfileprefix + sessionid + "_" + date + "_" + time + ".json"
		sessiondescription = "Collect and transact payments"
	}
	else if ( dopayments == 'false' ) {
		s3bucket = wldaas_s3_trigger_bucket //Write trigger to email bucket, no payments requested
		s3object = nopaytriggerfileprefix + sessionid + "_" + date + "_" + time + ".json"
		sessiondescription = "Collect only, no payments"
	}

	s3body['session'] = argobj //Add session parameters to object, used for reporting to client
	s3body['session']['sessiondescription'] = sessiondescription
	s3body['session']['date'] = date
	s3body['session']['startblocktime'] = startblocktime
	s3body['session']['stopblocktime'] = stopblocktime
	s3body['results'] = reportingobject  //Add summary as client reporting output
	s3body['mailheaders'] = mailheaders
	s3body['mailheaders']['receivers'] = [ accountmail ]
	s3body['mailheaders']['receiver'] = accountmail

        //upload_s3_object_promise (wldaas_s3_trigger_bucket, s3object, s3body, 'json').then (function (result) { //Upload file to S3
        upload_s3_object_promise (s3bucket, s3object, s3body, 'json').then (function (result) { //Upload file to S3

                console.log(' - End result written to s3 (triggerfile):              / ' + s3bucket + ' / ' + s3object);
        })
	console.log(JSON.stringify(s3body, null, 2))

        const s3_ecs_queue = toolconfigdata['s3_ecs_queue']     //s3 object prefix where container starts create json state file
        const ecs_queue_prefix = s3_ecs_queue + sessionid
        const ecs_startfile = ecs_queue_prefix + '_task-started.json'
	const ecs_finishfile = ecs_queue_prefix + '_task-finished.json'

        upload_s3_object_promise (wld_s3_bucket, ecs_finishfile, ecs_statefile__mybody, 'json').then (function (result) { //Upload file to S3
                console.log(' - finishfile created on s3: /' + wld_s3_bucket + '/' + ecs_finishfile);
        })

	delete_s3_object (wld_s3_bucket, ecs_startfile)
}




/**
 * Method to find all lease and leasecancels in transaction type16 statechanges
 * params:
 * - type16txs : transaction object (JSON)
 */
var get_type16_invoke_leases = function (type16txs) {
	
	//NOTE: prop is the key name
	//NOTE: type16txs[prop] is the value
	for ( prop in type16txs) {

		if (prop == 'stateChanges' && prop.length > 0) { //Check leases, leasecancels and invokes

			let la = type16txs[prop]['leases'] //lease array
			let lca = type16txs[prop]['leaseCancels'] //leasecancel array
			let ia = type16txs[prop]['invokes'] //invoke script array

			if ( la.length > 0 ) { //Lease transactions found

				// For every lease activation found in array leases, add lease to myLeases array
				la.forEach(function(lease) {
					if ( (lease.recipient === config.address) || (myAliases.indexOf(lease.recipient) > -1) ) {
						lease.block = lease.height
						lease.type = 16 //Add type 16 key informational, cause that info is missing in lease object
						myLeases[lease.id] = lease; //Add transaction id with transaction data to mylease array
					}
				});
			} 
			if ( lca.length > 0 ) { //Lease cancel transactions found

				// For every lease cancel found in array leaseCancel, add leasecancel to myCancelledLeases array
				lca.forEach(function(leasecancel) {
					if ( myLeases[leasecancel.id] ) { //Leasecancel id found in active lease array
						leasecancel.block = leasecancel.height
						leasecancel.type = 16//Add type 16 key informational, cause that info is missing in lease object
						myCanceledLeases[leasecancel.id] = leasecancel; //Add transaction id with transaction data to mycancel lease array
					}
				});
			}

			if (ia.length > 0) { //Found invokes data, check repeat function with new object data

				ia.forEach(function(object,i) { //Loop through invoke array to find 'stateChanges' object

					if ( 'stateChanges' in ia[i] ) {
						get_type16_invoke_leases(ia[i]); //start function again with new invoke json object
					}
					
				});
			}
		}
	}
}





/*
 * Method that returns all relevant blocks in batches of 100.
 * One batch is scanned for lease activations, lease cancels and if my node forged the block
 * My forged blocks are pushed to array myforgedBlocks[] for later usage and waves fees
 * are collected for transactions that are needed for lease sharing.
 * The fees in the previous block are also needed related to the forged block
 * New leases are added to array myLeases[], with block height and transaction data
 * Cancelled leases are added to array myCanceledLeases[], with block height and transaction data
 *
 * @returns {Array} all relevant blocks
 */

var getAllBlocks = function() { //Promise

	// leases have been resetted in block 462000, therefore, this is the first relevant block to be considered
	var cnt = 0; //batch counter, after a batch request resolves, increase counter
	var delaycounter = 0 //Used for pause between requests & its the While loop counter
	let lastblockarray = []
	//var checkprevblock = false;
	//var keeplastblock = {};

	const connectionpool = new http.Agent()
        connectionpool.maxSockets = Number(request_open_sockets) //Maximum open sockets to avoid client resource depletion (on container)
	connectionpool.keepAlive = true
	const startbl = currentStartBlock //Keep copy of collector run startblock
	const stopbl  = config.endBlock //Keep copy of collector run endblock 
	const prevbl = currentStartBlock-1 //Needed to collect fees for last block of previous session if start is myblock
	const batchsize = Number(collect_batch_size)
	const totalbatches = Math.ceil ( (stopbl - prevbl) / batchsize )
	const blockcount = batchsize-1 //+relative endblock of every batch

	return new Promise ( function(resolve, reject) { //If resolve, then we are done collecting all blocks

		//Grab blocks in batches of 100
		//start from currentstartblock (defined in batchinfo.json)
		//stop at endblock (defined in batchinfo.json)
		while (currentStartBlock <= stopbl) {	// START loop to get all blocks
	    							// The loop runs instant, counter cnt represents how many batches
	    							// For every batch of 100 blocks, promise function get_blocks_promise
	    							// is delayed a timer, to not overwhelm the api node

			let msg = 'getting blocks '
			let link = config.node + '/blocks/seq/'
			let timeout = Number(get_collect_batch_delay) * delaycounter //How long to wait for every batch collection to start
			
			if (delaycounter == 0) { //This is the start batch 
				link += prevbl + '/'
				msg += prevbl + ' to '
			} else {
				link += currentStartBlock + '/' //This is for followup batches
				msg += currentStartBlock + ' to '
			}

        		if (currentStartBlock + blockcount < stopbl) { //Start a batch and there will be next one

				msg += currentStartBlock + blockcount
				link += (currentStartBlock + blockcount)

			} else { //This will be the last batch to collect if not exact 100

				msg += stopbl
				link += stopbl
			}
			const batchstartblock = currentStartBlock //This is the blockheight of the first block to add to lastblockarray

			setTimeout ( function () {  	// Request a batch of 100 blocks from node
							// push them to array currentBlocks
							// delay between every request call

					const errorkey = 'batch_' + cnt

					get_blocks_promise ( msg, link, connectionpool) //request batch of blocks (promise), resolve is array with blockdata
                                		.then ( function (result) {

							let thiserrorobject = {}
                                        		//console.log('OK')
                                        		//console.log(result[1])
							let thislastbatchblockheight = 0 //blockheight of last block in current batch
							let thislastbatchblock //last block of this batch
							for (index in result) { //batchblock returns the index nr of the block in array
								let thisbatchblockheight = result[index].height
								if (thisbatchblockheight > thislastbatchblockheight) { //find highest block
									thislastbatchblock = result[index] //The last block of this batch, to be used if first block of next batch is myblock
								}
								
							}

							lastblockarray.push(thislastbatchblock) //Add block to array as object "blockheight" : { blockdata }
							
							const myprevsessionblock = result.findIndex(o => o.height === prevbl) //Find blockdata of previous session block
							if (myprevsessionblock != undefined && myprevsessionblock > -1) { lastblockarray.push(myprevsessionblock) } //Add block to array as object "blockheight" : { blockdata }
							try {
								result.forEach(function(block, index) { //For each block within the batch of blocks

									var checkprevblock = false;
									var myblock = false;
        								var wavesFees = 0;
									var blockrewards = 0;
									var blockwavesfees=0;

            								if (block.height <= stopbl) { //Block height falls within collect range

										if (block.generator === config.address) { //My node is the generator of the block
											checkprevblock = true
											myblock = true;
											console.log(' ***** Hurray! Generated block : ' + block.height + ' *****')

											if (block.height == startbl) { //Need to get previous block
												console.log('First session block generated by my node. Collect also previous session block ' + prevbl)

											} //END else if block.height == start

										}
										
										if (block.height == startbl) { //if we hit startblock, keep timestamp
											let datetime = new Date(block.timestamp)
											startblocktime = ('0'+datetime.getDate()).slice(-2)+"/" +
													 ('0'+(datetime.getMonth()+1)).slice(-2)+"/" +
													 datetime.getFullYear() + " " +
			  										 ('0'+datetime.getHours()).slice(-2)+":" +
													 ('0'+datetime.getMinutes()).slice(-2)+":" +
													 ('0'+datetime.getSeconds()).slice(-2)

										} else if (block.height == stopbl) { //If we hit last block, keep for Lastblockleaser reference later
											LastBlock = block 
											console.log('LastBlock hit : ' + LastBlock.height)
											let datetime = new Date(block.timestamp)
											stopblocktime = ('0'+datetime.getDate()).slice(-2)+"/" +
													('0'+(datetime.getMonth()+1)).slice(-2)+"/" +
													datetime.getFullYear() + " " +
			  										('0'+datetime.getHours()).slice(-2)+":" +
													('0'+datetime.getMinutes()).slice(-2)+":" +
													('0'+datetime.getSeconds()).slice(-2)
										}

										catch_relevant_blocks ( //Catch new lease, cancels and fees
											startbl,
											index,
											block,
											myblock,
											wavesFees,
											blockwavesfees,
											checkprevblock,
											result,
											thislastbatchblock,
											lastblockarray
										);
										
									} //END IF block.height <= config.endBlock

								});
							} catch (error) {
								console.log('Maximum retry limit reached for ' + link + '. Missed blocks.')
								console.log(error)
								if (errorobject.hasOwnProperty(errorkey) == false) { errorobject[errorkey] == {} }

								errorobject[errorkey]['missed_blocks'] = {
										"link" : link,
										"error" : error
												}
							}		

							const previouslastblockheight = batchstartblock-1
      							const previouslastblockindex = lastblockarray.findIndex(o => o.height === previouslastblockheight)					

							if (previouslastblockindex > -1) { //Found index for block
  								lastblockarray.splice(previouslastblockindex, 1);
								//console.log('removed previous lastblock :' + previouslastblockheight)
							}

							cnt++
							
							if (cnt == totalbatches) { //We reached the end of collecting all batches
								console.log('Finished collecting all blocks : ' + prevbl + ' -- ' + stopbl)
								//LastBlock = result.slice(-1)[0] //Save last block content
                                                                resolve()
							}

						} //END then

                                	).catch ( function (result) {
                                        	console.log('Error connecting to ' + link + '. This was captured by a catch clause in promise "get_blocks_promise"')
                                        	console.log(result)

						if (errorobject.hasOwnProperty(errorkey) == false) { errorobject[errorkey] == {} }

							errorobject[errorkey]['link_connect_errors'] = {
                                                        	"link" : link,
                                                                "error" : result
                                                                                                }
                                        })

			}, Number(timeout)) //END setTimeout
					
			delaycounter++ //Used to multiply the pause timer between the subsequent request batch
           		currentStartBlock += batchsize; //Increase with batchsize to start next collection

    		} //END WHILE loop to get all blocks

	}); //End promise

}; //END function getAllBlocks








/**
 * Method that scans the block for lease activations and cancellations
 * It adds some data to the block and pushes it to relevant block array
 * global var : myForgedBlocks (this gets all blocks forged by my node)
 */
var catch_relevant_blocks = function (startbl, index, block, myblock, wavesFees, blockwavesfees, checkprevblock, currentblockarray, keeplastblock, lastblockarray) {

	// Scan through all transactions in a block and catch lease activations, cancellations and waves fees
	// 1.  grep type8 lease transactions that are targetted to my node address
	// 2.  grep type9 leaseCancel transactions that are matched in my node lease array with active lease transactions
	// 3.  grep type16 transactions
	// 3.1  - grep statechanges -> lease that are targetted to my node address
	// 3.2  - grep statechanges -> invokes -> statechanges -> lease  that are targetted to my node address
	// 3.3  - grep statechanges -> leaseCancel that are matched in my node lease array with active lease transactions
	// 3.4  - grep statechanges -> invokes -> statechanges -> leaseCancel that are matched in my node lease array with active lease transactions
	//
	// NOTE
	// - All blocks need to be scanned for lease/leasecancel transactions to your node
	// - Only blocks that mynode secured need to be scanned for fees
	//

	block.transactions.forEach(function(transaction) {

            		// type 8 is leasing tx
			// AND if the node address (recipient) is my node or the alias is used and is mynode's name
            		if (transaction.type === 8 && ((transaction.recipient === config.address)|| (myAliases.indexOf(transaction.recipient) > -1) )){
                		transaction.block = block.height; //Add key block and set blockheight
                		myLeases[transaction.id] = transaction; //Add transaction id to mylease array

			// type 9 is leaseCancel tx
			// AND the lease transaction is found in my array of active leases
            		} else if (transaction.type === 9 && myLeases[transaction.leaseId]) {
                		transaction.block = block.height; //Add key block and set blockheight
                		myCanceledLeases[transaction.leaseId] = transaction; //Add transaction leaseid to array with cancelled leases

			// type 16 with lease and leasecancels by invocation script execution with stateChanges
            		} else if (transaction.type === 16 && transaction.hasOwnProperty('stateChanges')) { //Type16 and toplevel key 'stateChanges' is present

					get_type16_invoke_leases(transaction); //Get all lease & leasecancel transactions from stateChanges & invoke dApps
			}

			if(myblock == true) { //The collected block is generated by my node, collect the fees for the transactions

                		// considering Waves fees
                		if (!transaction.feeAsset || transaction.feeAsset === '' || transaction.feeAsset === null) { //This is a Waves transaction
                    			if(transaction.fee < 200000000)  { // if tx waves fee is more dan 2 waves, filter it. probably a mistake by someone
                        			//wavesFees += (transaction.fee*0.4);
                        			blockwavesfees += transaction.fee; //Add up all the Waves transaction fees
                    			} else {
                        			console.log("Filter TX at block: " + block.height + " Amount: " +  transaction.fee) //Do not add up waves fees
                    			}
                		} else if (block.height > 1090000 && transaction.type === 4) { //Waves Transfer transaction
                				blockwavesfees += mintxfee; //Add up Waves minimum fee
		  		}
			}

	});

      wavesFees += Math.round(parseInt(blockwavesfees / 5) * 2); //Total Waves fees for the block
      blockwavesfees=0; //Reset fee counter for the block

      const previousblockheight = block.height-1

      if (checkprevblock == true) { //Need to collect fees from previous block
	
		let prevblock

		if (index === 0 || block.height == startbl) { //Check fees from old copy, that was kept from previous cycle of blocks
			//prevblock = keeplastblock;
			prevblock = lastblockarray.find(o => o.height == previousblockheight) //get previous block from this batch
			console.log('Get block fees from previous block in previous batch [block ' + previousblockheight + ']')
			//console.log(prevblock)
			//console.log('Previous block needed for fee collection.\n - current block: ' + block.height + '\n - previous block: ' + prevblock.height)
		} else { //The previous block is just in this batch
			console.log('Get block fees from previous block in this batch [block ' + previousblockheight + ']')
			prevblock = currentblockarray.find(o => o.height == previousblockheight) //get previous block from this batch
		}	

            	prevblock.transactions.forEach(function(transaction) {
                	// considering Waves fees
                	if (!transaction.feeAsset || transaction.feeAsset === '' || transaction.feeAsset === null) {
              			if(transaction.fee < 200000000) // if tx waves fee is more dan 2 waves, filter it. probably a mistake by someone
         				{
                  			//wavesFees += (transaction.fee*0.6);
                  			blockwavesfees += transaction.fee;
                		} else {
  		        		console.log("Filter TX at block: " + block.height + " Amount: " +  transaction.fee)
  		       		}
            		} else if (block.height > 1090000 && transaction.type === 4) {
                		blockwavesfees += mintxfee;
	      		}
            	});

      		wavesFees += (blockwavesfees - Math.round(parseInt(blockwavesfees / 5) * 2));
      }
      


      wavesFeesfull += wavesFees //global amount of 100% wavesfees
      wavesFees = ( wavesFees * config.percentageOfFeesToDistribute / 100 ) //These are the Txs fees with sharing % applied from configfile

      if (myblock == true) {  //This block is written by my waves node
	        // This is the blockreward amount with sharing % applied from configfile and the 100% amount
		if (block.height >= 1740000) { 
			let myreward = block.reward / rewarddevider
                        wavesFeesfull += myreward
                        wavesFees += ( myreward * blockrewardsharingpercentage ) / 100
		} //Feature 14 activated at 1740000
      }
      
      block.wavesFees = wavesFees; //Set sum of all transaction fees for this block

      if (myblock == true) { myForgedBlocks.push(block) } //Push my forged block to array which has all my forged blocks

}




/**
 * This method distributes either Waves fees and MRT to the active leasers for
 * the given block.
 *
 * @param activeLeases active leases for the block in question
 * @param amountTotalLeased total amount of leased waves in this particular block
 * @param block the block to consider
 */
var distribute = function(activeLeases, amountTotalLeased, block) {

    var fee = block.wavesFees; //total waves fee amount + blockreward with sharing % from configfile applied


    if ( activeLeases.length != 0 ) {

    for (var address in activeLeases) {

	if ( nofeearray.indexOf(address) == -1 ) {	// leaseaddress is not marked as 'no pay address'
		var share = (activeLeases[address] / amountTotalLeased); //what is the share ratio for this address
		var payout = true;
	} else {					//this address will not get payed
		var share = (activeLeases[address] / amountTotalLeased); //what is the share ratio for this address
		var payout = false;
	  }

        var amount = fee * share; //The Waves amount per address according ratio

        var assetamounts = [];


        var amountMRT = share * config.distributableMrtPerBlock; //How many Mrt will the address get

       	if (address in payments) { //Address already in array, add to amount
       		payments[address] += amount //How many Waves fees leaser gets
       		mrt[address] += amountMRT; //How many Mrt leaser gets
	} else { //Address not yet in array, add entry
		payments[address] = amount; //How many Waves fees leaser gets
		mrt[address] = amountMRT; //How many Mrt leaser gets
	}

	if ( payout == true ) {
        	console.log(address + ' will receive ' + amount + ' of ' + fee + ' Waves and ' + amountMRT + ' MRT for block: ' + block.height + ' share: ' + share);
	} else if ( payout == false ) {
		console.log(address + ' marked as NOPAYOUT: ' + amount + ' of(' + fee + ') and ' + amountMRT + ' MRT for block: ' + block.height + ' share: ' + share);
	}
    }
    }
};


/**
 * Method that creates the concrete payment tx and writes it to the file
 * configured in the config section.
 */
var pay = function() {

	let s3bucket = wld_s3_bucket
	let s3object;
	let s3body;

    var transactions = [];
    var totalMRT = 0;
    var totalfees =0;
    var nopaywaves = 0
    var nopaymrt = 0

    var html = "";

    var html = "<!DOCTYPE html>" +
"<html lang=\"en\">" +
"<head>" +
"  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">" +
"  <link rel=\"stylesheet\" href=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css\">" +
"  <script src=\"https://ajax.googleapis.com/ajax/libs/jquery/3.2.1/jquery.min.js\"></script>" +
"  <script src=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js\"></script>" +
"</head>" +
"<body>" +

"<div class=\"container\">" +
"  <h3>Fees between blocks " + config.startBlockHeight + " - " + config.endBlock + ", Payout #" + config.paymentid + ", (Share Tx fees " + config.percentageOfFeesToDistribute + "% / Blockreward " + config.percentageOfBlockrewardToDistribute + "%)</h3>" +
"  <h4>(LPOS address: " + config.address + ")</h4>" +
"  <h5>[ " + date + " ]: Hi all, again a short update of the fee's earned by the waves service '" + servicename + "'. Greetings!</h5> " +
"  <h5>You can always contact me by <a href=\"mailto:" + mailto + "\">E-mail</a></h5>" +
"  <h5>Blocks forged: " + BlockCount + "</h5>" +
"  <table class=\"table table-striped table-hover\">" +
"    <thead> " +
"      <tr>" +
"        <th>Address</th>" +
"        <th>Waves</th>" +
"        <th>MRT</th>" +

"      </tr>" +
"    </thead>" +
"    <tbody>";

    for (var address in payments) { //Start for all addresses in payments array
        var payment = (payments[address] / Math.pow(10, 8));

	if ( nofeearray.indexOf(address) == -1 ) { //This address will get payed (it's not found in nopay array)

		payout = true
		wavespayaddresscnt ++

		console.log(address + ' will receive ' + parseFloat(payment).toFixed(8) + ' Waves and ' + parseFloat(mrt[address]).toFixed(2) + ' MRT in total!')

		//send Waves fee
		if (Number(Math.round(payments[address])) > 0) {
			transactions.push({
				"amount": Number(Math.round(payments[address])),
				"fee": config.feeAmount,
				//"feeAssetId": config.assetFeeId,
				"sender": config.address,
				"attachment": config.paymentAttachment,
				"recipient": address,
				"pay" : "yes"
			});
			wavespayaddressamount += Number(Math.round(payments[address]))
		}

		//send MRT
		if (Number(Math.round(mrt[address] * Math.pow(10, 2))) > 0) {
			transactions.push({
				"amount": Number(Math.round(mrt[address] * Math.pow(10, 2))),
				"fee": config.feeAmount,
				//"feeAssetId": config.assetFeeId,
				"assetId": "4uK8i4ThRGbehENwa6MxyLtxAjAo1Rj9fduborGExarC",
				"sender": config.address,
				"attachment": config.paymentAttachment,
				"recipient": address,
				"pay" : "yes"
			});
		}

	} else { //NOPAYOUT address, will not get payed

		payout = false
		wavesnopayaddresscnt ++

		console.log(address + ' marked as NOPAYOUT, will not receive ' + parseFloat(payment).toFixed(8) + ' and ' + parseFloat(mrt[address]).toFixed(2) + ' MRT!')

		//send Waves fee
                if (Number(Math.round(payments[address])) > 0) {
			nopaywaves += payments[address]
                        transactions.push({
                                "amount": Number(Math.round(payments[address])),
                                "fee": config.feeAmount,
                                //"feeAssetId": config.assetFeeId,
                                "sender": config.address,
                                "attachment": config.paymentAttachment,
                                "recipient": address,
				"pay" : "no"
                        });
                	wavesnopayaddressamount += Number(Math.round(payments[address]))
                }

                //send MRT
                if (Number(Math.round(mrt[address] * Math.pow(10, 2))) > 0) {
			nopaymrt += mrt[address]
                        transactions.push({
                                "amount": Number(Math.round(mrt[address] * Math.pow(10, 2))),
                                "fee": config.feeAmount,
                                //"feeAssetId": config.assetFeeId,
                                "assetId": "4uK8i4ThRGbehENwa6MxyLtxAjAo1Rj9fduborGExarC",
                                "sender": config.address,
                                "attachment": config.paymentAttachment,
                                "recipient": address,
				"pay" : "no"
                        });
                }

	  }

        totalMRT += mrt[address];
        totalfees += payments[address];


        html += "<tr><td>" + address + "</td><td>" + 							 	//address column
				((payments[address]/100000000).toFixed(8)) + "</td><td>" + 	//Waves fee's
				mrt[address].toFixed(2) + "</td><td>"                      //MRT
	
	if (payout == false) { html += "* NO PAYOUT *" }
	
	html += "\r\n";

    }	//End for all addresses in payments array

    html += "<tr><td><b>Total amount</b></td><td><b>" + ((totalfees/100000000).toFixed(8)) +
		 "</b></td><td><b>" + totalMRT.toFixed(2) + "</b></td><td><b>" +
			"\r\n";

    if (nopaywaves != 0) { //Write no payout row
    	html += "<tr><td><b>No Payout amount (" + wavesnopayaddresscnt + " recipients)</b></td><td><b>" + ((nopaywaves/100000000).toFixed(8)) +
		"</b></td><td><b>" + nopaymrt.toFixed(2) + "</b></td><td><b>" +
			"\r\n";
    }

    html += "</tbody>" +
"  </table>" +
"</div>" +

"</body>" +
"</html>";


    console.log("total Waves shared (fees + blockrewards): " + (totalfees/100000000).toFixed(8) + " (" + config.percentageOfFeesToDistribute + "%/" + config.percentageOfBlockrewardToDistribute + "%) + total MRT: " + totalMRT );
    var paymentfile = config.filename + sessionid + ".json";
    var htmlfile = config.filename + sessionid + ".html";

//if ( !BlockCount == 0 ) { transactions.push( { "forgedblocks:": BlockCount } ) }

	const s3_wallet_folder = argobj['s3_wallet_folder']
	let s3object_payoutfile = s3_wallet_folder + '/'+ datadir+paymentfile
	let s3body_transactions = transactions
	
	upload_s3_object_promise (s3bucket, s3object_payoutfile, s3body_transactions, 'json').then (function (result) { //Upload file to S3

		console.log(' - payment data written to s3:                          / ' + s3bucket + ' / ' + s3object_payoutfile);
	})

	let s3object_payreportfile = s3_wallet_folder + '/' + datadir+htmlfile
	let s3body_html = html
	
	upload_s3_object_promise (s3bucket, s3object_payreportfile, s3body_html, 'text').then (function (result) { //Upload file to S3

		console.log(' - payreport written to s3:                             / ' + s3bucket + ' / ' + s3object_payreportfile);
	})

	let s3object_logfile = s3_wallet_folder + '/' + datadir + config.filename + sessionid + '.log'
	let s3body_logdata = 	  "total Waves fees: " + (totalfees/100000000).toFixed(8) + " total MRT: " + totalMRT + "\n"
				+ "Total blocks forged: " + BlockCount + "\n"
				+ "Active leasers: " + Object.keys(myLeases).length + "\n"
				+ "Generating balance: " + Math.round(generatingbalance / Math.pow(10, 8)) + "\n"
				+ "NO PAYOUT Waves: " + (nopaywaves/100000000).toFixed(8) + "\n"
				+ "NO PAYOUT MRT: " +  nopaymrt.toFixed(2) + "\n"
				+ "Payment ID of batch session: " + config.paymentid + "\n"
				+ "Payment startblock: " + paymentstartblock + "\n"
				+ "Payment stopblock: " + paymentstopblock + "\n"
				+ "Distribution: " + paymentconfigdata.feedistributionpercentage + "%\n"
				+ "Blockreward sharing: " + blockrewardsharingpercentage + "%\n"
				+ "Following addresses are skipped for payment; \n"
				+ JSON.stringify(nofeearray) + "\n"


	wavesFeesshared = totalfees

	upload_s3_object_promise (s3bucket, s3object_logfile, s3body_logdata, 'text').then (function (result) { //Upload file to S3

		console.log(' - logfile written to s3:                               / ' + s3bucket + ' / ' + s3object_logfile);
	});

	const nextstartblock = config.endBlock+1
    var latestblockinfo = {};
    latestblockinfo["leases"] = myLeases; //All last known active leases, used when next collection batch starts
    latestblockinfo["canceledleases"] = myCanceledLeases; //All last known cancelled leases, used when next collection batch starts
    var blockleases = 'prevleaseinfo_startblock_' + nextstartblock + '.json';

	let s3object_blockleases = s3_wallet_folder + '/' + datadir + blockleases
	let s3body_blockinfo = latestblockinfo
	
	upload_s3_object_promise (s3bucket, s3object_blockleases, s3body_blockinfo, 'json').then (function (result) { //Upload file to S3

		console.log(' - blockinfo with leasers for next batch written to s3: / ' + s3bucket + ' / ' + s3object_blockleases);
	})


    var ActiveLeaseData = getActiveLeasesAtBlock(LastBlock); //Get all lease recipients with amount, active at Lastblock (paystopblock in batchinfo.json) 
	
	let s3object_lastblockleasers = s3_wallet_folder +'/' + datadir + lastblockleasersfile
	let s3body_activeleasedata = ActiveLeaseData

	upload_s3_object_promise (s3bucket, s3object_lastblockleasers, s3body_activeleasedata, 'json').then (function (result) { //Upload file to S3

		console.log(' - lastblockleasersfile written to s3:                  / ' + s3bucket + ' / ' + s3object_lastblockleasers + ' [ block ' + LastBlock.height + ' ]');
	})

	uniqueleasersend = Object.keys(ActiveLeaseData.activeLeases).length //Set total unique leasers, global var

   // Write the current payid of the batch to the payment queue file. This is used by the masspayment tool
   let paymentqueue = function (callback) {

        payarray = [ ];

	let s3object_payqueuefile = s3_wallet_folder + '/' + datadir + payqueuefile

	check_s3_object_exists_promise (wld_s3_bucket, s3object_payqueuefile). //Check if we found a previous payqueue file

                then (function (result) { //Promise succesfull, found payqueuefile on s3 object exists

			const rawpayqueue = get_s3_object_promise(wld_s3_bucket, s3object_payqueuefile) //Get payqueuefile 

			rawpayqueue.then (function (pendingpayments) {

				console.log()

				if ( reset === false ) {
					
					console.log('Reading queuefile with payjobs...')
					payarray = JSON.parse(pendingpayments)

				} else { //Do not get payqueue (reset true)
					console.log('Reset requested by user, payqueue will start empty.')
				}
			
				if ( payarray.length == 0 ) { //No pending payments
					console.log('No pending payments yet. Add \'' + payid + '\' to queue.')
					payarray = [ payid ]
				} else if ( payarray.includes (payid) == true ) { //Batch already in queue
					console.log('WARNING: Payid \'' + payid + '\' already pending in queue. Payfiles overwritten. Is this a valid collector run?')
				} else {
					console.log('There are pending payjobs in the queue already. Adding \'' + payid + '\' to queue.')
					payarray.push(payid)
				}
				
				console.log("The next batch session will be '" + nextpayid + "'\n");
	
				let s3body_batch_ids = payarray
	
				upload_s3_object_promise (s3bucket, s3object_payqueuefile, s3body_batch_ids, 'json').then (function (result) { //Upload file to s3

					console.log(' - payqueuefile written to s3:                          / ' + s3bucket + ' / ' + s3object_payqueuefile);
					console.log('   pending payments in payqueue:                        / [' + payarray + ']')
				})
			})

		}).

		catch (function () { //Payqueue file does not exist
			
			payarray.push(payid) //Add payid
			console.log('No pending payments yet. Add \'' + payid + '\' to queue.')
			console.log("The next batch session will be '" + nextpayid + "'\n");
	
			let s3body_batch_ids = payarray
	
			upload_s3_object_promise (s3bucket, s3object_payqueuefile, s3body_batch_ids, 'json').then (function (result) { //Upload file to s3

				console.log(' - payqueuefile written to s3:                          / ' + s3bucket + ' / ' + s3object_payqueuefile);
				console.log('   pending payments in payqueue:                        / [' + payarray + ']')
			})

		})

   	callback();

   }; //END let payment queue


   // update json batchdata for next collection round
   // The next start block needs to be endblock +1 because
   // the endblock is also taken into account
   let nextbatchdata = function () {

	let newbatchdata = {}
	mybatchdata["paymentid"] = (payid + 1).toString()
	mybatchdata["paystartblock"] = (paymentstopblock+1).toString()
	mybatchdata["paystopblock"] = (paymentstopblock + blockwindowsize).toString()	
	//mybatchdata["scanstartblock"] = (paymentstopblock).toString()
	mybatchdata["scanstartblock"] = (startscanblock).toString() //First leaser block
	newbatchdata["batchdata"] = mybatchdata
	
	let s3bucket = wld_s3_bucket
	let s3object = s3_wallet_folder + '/' + datadir + batchinfofile
	let s3body = newbatchdata
	
	let s3upload = upload_s3_object_promise (s3bucket, s3object, s3body, 'json') //Upload file to s3

	s3upload.then (function (result) {

		console.log(' - batchinfofile for next batch written to s3:          / ' + s3bucket + ' / ' + s3object);


/*
		fs.unlink(datadir+appngrunfile, (err) => { //All done, remove run file which is checked during startup
               		if (err) {
                       		console.error(err)
                       		return
               		}
       		})
*/


	})
    };

    // update the paymentqueue and callback update batchdata function
    paymentqueue(nextbatchdata); //Execute updating the payment queue file and then update next batchdata and write it to batchinfofile on s3
};


/**
 * This method returns (block-exact) the active leases and the total amount
 * of leased Waves for a given block.
 *
 * @param block the block to consider
 * @returns {{totalLeased: number, activeLeases: {}}} total amount of leased waves and active leases for the given block
 */
var getActiveLeasesAtBlock = function(block) {

    var activeLeases = []; //array with all leases that are active and possibly accountable for this block
    var totalLeased = 0;
    var activeLeasesPerAddress = {};

    for (var leaseId in myLeases) { //Scan through all last known active leases
        var currentLease = myLeases[leaseId];

        if (!myCanceledLeases[leaseId] || myCanceledLeases[leaseId].block > block.height) { //Lease is not cancelled or was set later then current block
            activeLeases.push(currentLease); //Push lease data to activeLeases array
        }
    }
    activeLeases.forEach(function (lease, index) { //Check if active leases are accountable for sharing

        if (block.height > lease.block + 1000) { //If the lease was at least activated 1000 blocks ago

            if (!activeLeasesPerAddress[lease.sender]) { //If leaser not in activeLeasesPerAddress yet
                activeLeasesPerAddress[lease.sender] = lease.amount; //Add the lease amount
            } else {
                activeLeasesPerAddress[lease.sender] += lease.amount; //Sum up the lease amounts
            }

            totalLeased += lease.amount; //total leased of all leasers for this block
        }
    });
//console.log(totalLeased)
    return { totalLeased: totalLeased, activeLeases: activeLeasesPerAddress };
};




/***********************************/
/******* START MAIN PGROGRAM *******/
/***********************************/

const rawconfiguration = get_s3_object_promise(s3_config_bucket, s3_config_object) //Get app config key/values from s3 
rawconfiguration.then ( function (rawdata) { //When finished reading config items


	const jsonconfiguration = JSON.parse(rawdata)
	toolconfigdata = jsonconfiguration['toolbaseconfig']
	paymentconfigdata = jsonconfiguration['paymentconfig']

	//If no override values are given @program start or from batchinfo.json, below values are set and used
	//myleasewallet 	  = paymentconfigdata['leasewallet']			//Default node wallet
	//blockwindowsize   = parseInt(paymentconfigdata['blockwindowsize']) 	//How many blocks to collect
	//startscanblock 	  = parseInt(paymentconfigdata['firstleaserblock'])	//Where to start scanning
	//paymentstopblock  = startscanblock + blockwindowsize 			//Scan till block
	//paymentstartblock = parseInt(paymentconfigdata['paystartblock']) 	//First block from which to take fee sharing into account

	const cli_keys = toolconfigdata['clikeys'] //All possible cli argument keys that can be overwritten
	get_cli_args(cli_keys); //If cli arguments are given, use these
	
	//console.log('\nCLI arguments that will be used [dict argobj]:')
	//setTimeout ( function () {
	//	console.log(argobj)
	//	console.log()
	//}, 500 )
	
	//Set all global vars specific to  collector session
	s3_wallet_folder		= argobj['s3_wallet_folder']
	myleasewallet			= argobj['myleasewallet']
  	blockwindowsize			= parseInt(argobj['blocks'])
  	startscanblock			= parseInt(argobj['startblock'])
	paymentstartblock		= parseInt(argobj['payblock'])
	paymentstopblock		= parseInt(argobj['stopblock'])
	feedistributionpercentage	= parseInt(argobj['feeshare'])
	blockrewardsharingpercentage 	= parseInt(argobj['rewardshare'])
	nofeearray 			= argobj['nopayoutaddresses']
	dopayments			= argobj['dopayments']
	reset 				= argobj['reset']
	servicename 			= argobj['servicename']
	accountmail			= argobj['email']
	if (argobj['transactionattachment']) { attachment = argobj['transactionattachment'] } else { argobj['transactionattachment'] = attachment }
	
	if ( dopayments == 'false' ) {
		mailheaders = jsonconfiguration['collectormail']
	} else { mailheaders = jsonconfiguration['paymentmail'] } 


	//define all vars that could be overwritten on cli at start. argobj = list with all arguments (sanitized) 

	if ( !argobj['force'] ) { force_collector_start = 'no' } else if ( argobj['force'] === 'true' || argobj['force'] === 'yes' ) { force_collector_start = 'yes' } else { force_collector_start = 'no' }

		 
	//define all vars related to the payment settings
	apiuris = jsonconfiguration['api_uris']
	myquerynode = paymentconfigdata['querynode_api']
	mrtperblock = paymentconfigdata['mrtperblock']
	//attachment = paymentconfigdata['transactionattachment']
	mailto = paymentconfigdata['mail']
	//define all vars related to the tool settings
	collectorfilesprefix = toolconfigdata['collectorfilesprefix']
	minscfee = parseInt(toolconfigdata['txscfee'])
	mintxfee = parseInt(toolconfigdata['txfee']) 
	balancesuri = (apiuris['balances']).replace('{address}', myleasewallet)
	datadir = toolconfigdata['datadir']; if (datadir.slice(-1) != '/') { datadir = datadir+'/' }
	batchinfofile = toolconfigdata['batchinfofile']
	payqueuefile = toolconfigdata['payqueuefile']
	wld_s3_bucket = paymentconfigdata['wld_s3_bucket']
	lastblockleasersfile = toolconfigdata['lastblockleasersfile']
	wldaas_s3_trigger_bucket = paymentconfigdata['wldaas_s3_trigger_bucket']
	wldaas_s3_payprocessor_trigger_bucket = paymentconfigdata['wldaas_s3_payprocessor_trigger_bucket']
	connect_retries = toolconfigdata['node_connect_retries'] //How many times to reconnect to the node to collect blocks 
	connect_retry_delay = toolconfigdata['node_connect_retry_delay_msecs'] //Waiting time between connect retries when failures occur
	get_collect_batch_delay = toolconfigdata['node_get_collect_delay'] //Waiting time between collecting block batches
	request_open_sockets = toolconfigdata['open_request_client_sockets'] //Waiting time between collecting block batches
	collect_batch_size = toolconfigdata['collect_batch_size'] //how many blocks to collect in one batch

	s3_batchinfofile = s3_wallet_folder + '/' + datadir + batchinfofile

	//Create task start file for reference if there are problems with crashed containers
	const ecs_metadata_env = process.env.ECS_CONTAINER_METADATA_URI_V4
	const ecs_metadata = get_api_json_request (ecs_metadata_env)
	const s3_ecs_queue = toolconfigdata['s3_ecs_queue']	//s3 object prefix where container starts create json state file
	const ecs_queue_prefix = s3_ecs_queue + sessionid
	const ecs_startfile = ecs_queue_prefix + '_task-started.json'

	ecs_statefile__mybody = { "container_metadata" : ecs_metadata,
	  	   		  "paramstring_received" : process.argv.slice(2),
		   		  "paramstring_processed" : argobj }

	upload_s3_object_promise (wld_s3_bucket, ecs_startfile, ecs_statefile__mybody, 'json').then (function (result) { //Upload file to S3
                console.log(' - startfile created on s3: /' + wld_s3_bucket + '/' + ecs_startfile);
        })
/*
	if ( fs.existsSync(datadir+appngrunfile) ) { //Found app crashfile, alert and exit
		console.log(	"\nALERT:\n" +
                    		"Found appng interruptionfile. Apparently appng was interupted abnormally last time!\n" +
                    		"Normally if collector sessions run 100% fine, this alert should not be given.\n" +
                    		"Check your logs and if everything is fine, delete the crashfile: '" + appngrunfile + "'\n" +
                    		"\nGoodbye now!\n")

        	process.exit() //Terminate

	} else { //No crashfile found, proceed

		foldercheck ( datadir ); //function to create data folder if needed

		let dir = false

		while ( dir === false ) { //This loop is needed to wait for the function finish that creates the 'datadir' folder

			if ( fs.existsSync(datadir)) { 
				fs.closeSync(fs.openSync(datadir + appngrunfile, 'w')) //Touch runfile to detect crashes
				dir = true
			}
		}
	}
*/


	generatingbalance = JSON.parse(request ( "GET", myquerynode + balancesuri, { json: true } ).body).generating //GET generating balance of wallet


	check_s3_object_exists_promise (wld_s3_bucket, s3_batchinfofile). //Check if we found a previous batchinfo file (so we know the block heights)
		
		then (function (result) { //Promise succesfull, found batchinfofile on s3 object exists

			const rawbatchinfo = get_s3_object_promise(wld_s3_bucket, s3_batchinfofile) //Get batchinfo data from s3 


			rawbatchinfo.then ( function (rawdata) { //When async request has finished, do..

				console.log()

				if ( reset === false ) { //Use previous batchinfo data

   					batchinfo = JSON.parse(rawdata);
   					mybatchdata = batchinfo["batchdata"];
   					startscanblock = parseInt(mybatchdata["scanstartblock"]);
   					paymentstartblock = parseInt(mybatchdata["paystartblock"]); //block where to start payments
   					if ( argobj['blocks'] ) {
						paymentstopblock = startscanblock + parseInt(argobj['blocks'])
					} else {
						paymentstopblock = parseInt(mybatchdata["paystopblock"]); //block UP UNTIL (tm) to get payments
					}
   					payid = parseInt(mybatchdata["paymentid"]); 
					nextpayid = payid + 1

					console.log('Found existing batchinfofile...done reading...current batchid is \'' + payid + '\'')
					console.log('Values used for this run;')
					console.log(' - 1st leaser block : ' + startscanblock)
					console.log(' - start scan       : ' + paymentstartblock)
					console.log(' - stop scan        : ' + paymentstopblock)

				} else { //Reset is true, remove previous batchinfo data
					console.log('Overwrite requested. Values used for this run;')
                                        console.log(' - 1st leaser block : ' + startscanblock)
                                        console.log(' - start scan       : ' + paymentstartblock)
                                        console.log(' - stop scan        : ' + paymentstopblock)
					payid = 1
					nextpayid = payid + 1
					mybatchdata = {}
				}

   				// Collect height of last block in waves blockchain
   				let options = {
					uri: "/blocks/height",
					baseUrl: myquerynode,
					method: "GET",
					headers: {
						json: true
					}
   				};
   
   				let blockchainresponse = request(options.method, options.baseUrl + options.uri, options.headers)
   				let lastblockheight = parseInt(JSON.parse(blockchainresponse.body).height) - 1 //Current blockchain height 

   				if (paymentstopblock > lastblockheight && force_collector_start === 'no' ) { //Stopblock  not reached yet, exit

					let blocksleft = paymentstopblock - lastblockheight

        				console.log("\n Current blockheight is " + lastblockheight + ". Waiting to reach " + paymentstopblock + " for next collector round.")
        				console.log(" This is approximaly in ~" + Math.round((blocksleft)/60) + " hrs (" + (Math.round((blocksleft/60/24)*100))/100 + " days).\n")
					console.log(" You can safely force collection start with argument '/now', i.e. 'node appng /now' if you do")
					console.log(" not want to wait. This will use lastblockheight " + lastblockheight + " as paymentstopblock.\n")
	

/*
					fs.unlink(datadir+appngrunfile, (err) => { //All done, remove run file which is checked during startup
						if (err) {
							console.error(err)
                        				return
                				}
        				})
*/


        				return;

   				} else if (paymentstopblock > lastblockheight && force_collector_start === 'yes' ) { //Force collector start with current blockchain height

	   				paymentstopblock = lastblockheight -1 //Start collector with current blockheight as stop block

   				}

				upload_s3_object_promise (wld_s3_bucket, s3_batchinfofile + '.bak', batchinfo, 'json').then (function (result) { }) //Upload batchinfo.bak file to S3

				config = {
    					address: myleasewallet,
    					startBlockHeight: paymentstartblock,
    					endBlock: paymentstopblock,
    					distributableMrtPerBlock: mrtperblock,  //MRT distribution stopped
    					filename: collectorfilesprefix, //.json, html, log  added automatically
    					paymentid: payid,
    					node: myquerynode,
    					//node: 'http://nodes.wavesnodes.com',
    					assetFeeId: null, //not used anymore with sponsored tx
    					feeAmount: parseInt(toolconfigdata.txbasefee),
    					paymentAttachment: attachment, 
    					percentageOfFeesToDistribute: feedistributionpercentage,
    					percentageOfBlockrewardToDistribute: blockrewardsharingpercentage
				}

				currentStartBlock = startscanblock; //Which block to start scanning 
				s3_prevleaseinfofile = s3_wallet_folder + '/' + datadir + 'prevleaseinfo_startblock_' + config.startBlockHeight + '.json'; //Previous leasers file	

				check_s3_object_exists_promise (wld_s3_bucket, s3_prevleaseinfofile). //Check if we found a previous leaseinfo file

                			then (function (result) { //Promise succesfull, found prevleaseinfofile on s3 object exists

						console.log('\nFound previous leaseinfo file, ' + s3_prevleaseinfofile + ', read content...')

						const rawprevleaseinfo = get_s3_object_promise(wld_s3_bucket, s3_prevleaseinfofile) //Get previous leaseinfo 
						rawprevleaseinfo.then (function (leasedata) {
							var prevleaseinfo=JSON.parse(leasedata);
							myLeases = prevleaseinfo["leases"]; //All lease transactions (type8, type16), can be multiple for one sender
							myCanceledLeases = prevleaseinfo["canceledleases"]; //All leasecancels (type9), can be multiple for one sender
							currentStartBlock = config.startBlockHeight;

							//do some cleaning
							//After this, var myLeases has the active leasers left from our startblock
							//All leasers that cancelled their lease are removed
							var cleancount = 0;
	
							for(var cancelindex in myCanceledLeases) {
    								if (myCanceledLeases[cancelindex].leaseId in myLeases) {

        								//remove from both arrays, we don't need them anymore
        								delete myLeases[cancelindex];
        								delete myCanceledLeases[cancelindex];
        								cleancount++;
    								}
							}

							console.log("done cleaning, removed: " + cleancount);
							activeleasesstart = Object.keys(myLeases).length

							start()
						})

					}). //END when prevleaseinfo was found and read
					catch (function (result) { //No prevleasinfo file found
						console.log("\nNo previous leasefile found,  starting session without leaseinfo.")
						if (reset == 'true') {
							currentStartBlock = paymentstartblock 
							console.log('Will start forced scan from block : ' + currentStartBlock)
						} else {
							console.log('Will start scan from block : ' + currentStartBlock)
						}
						//NOTE
						//If no prev leaseinfo file found of the startblock (payblock) then the active leasers
						//are not found and nothing will be shared.
						start()
					})

			}); //END rawbatchinfo.then 


		}). //END check_s3_object_exists_promise.then...(for batchinfo file)

		catch( function (result) { //s3 batchinfo object does not exist, result.errno = -2
   				
			// Collect height of last block in waves blockchain
   			let options = {
				uri: "/blocks/height",
				baseUrl: myquerynode,
				method: "GET",
				headers: {
					json: true
				}
   			};
   				
			let blockchainresponse = request(options.method, options.baseUrl + options.uri, options.headers)
   			let lastblockheight = parseInt(JSON.parse(blockchainresponse.body).height) - 1 //Current blockchain height 

			if ( paymentstartblock > lastblockheight ) { //Can not collect in the future
				console.log('Startblock ' + paymentstartblock + ' is greater then current blockheight ' + lastblockheight + '. Will terminate.')
				process.exit()
			} else if ( paymentstopblock > lastblockheight && force_collector_start === 'no' ) {
				console.log('Stopblock ' + paymentstopblock + ' is greater then current blockheight ' + lastblockheight + '. Will terminate.')
				process.exit()
			} else if ( paymentstopblock > lastblockheight ) {
				paymentstopblock = lastblockheight - 1
			}

			payid = 1
			nextpayid = payid + 1
			//paymentstopblock = startscanblock + blockwindowsize (already declared, can be removed if tested succesfully)

			batchinfo = { "batchdata" :
					{
						"paymentid" : payid,
						"scanstartblock" : startscanblock,
						"paystartblock" : paymentstartblock,
						"paystopblock" : paymentstopblock
					}
			}
	
			mybatchdata = batchinfo["batchdata"]

			console.log(	"\n Batchfile '" + batchinfofile + "' is missing. This seems to be the first collector session." +
		    			"\n The collector will start with the following batch details:\n" +
		    			"\n  - paymentID: " + payid +
		    			"\n  - Start scanning from block: " + startscanblock +
		    			"\n  - Scan till block: " + paymentstopblock +
		    			"\n  - Blockwindowsize: " + blockwindowsize + " blocks" +
		    			"\n  - First relevant payoutblock: " + paymentstartblock + "\n" +
		    			" =============================================================================================\n");
	
			config = {
    				address: myleasewallet,
    				startBlockHeight: paymentstartblock,
    				endBlock: paymentstopblock,
    				distributableMrtPerBlock: mrtperblock,  //MRT distribution stopped
    				filename: collectorfilesprefix, //.json added automatically
    				paymentid: payid,
    				node: myquerynode,
    				//node: 'http://nodes.wavesnodes.com',
    				assetFeeId: null, //not used anymore with sponsored tx
    				feeAmount: parseInt(toolconfigdata.txbasefee),
    				paymentAttachment: attachment, 
    				percentageOfFeesToDistribute: feedistributionpercentage,
    				percentageOfBlockrewardToDistribute: blockrewardsharingpercentage
			}
	
			currentStartBlock = startscanblock; //Which block to start scanning 

			start();

		}); //END catch & check_s3_object_exists_promise function




}); //End rawconfiguration.then

