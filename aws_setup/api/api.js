
var AWS = require("aws-sdk");
AWS.config.update({
    region: "us-east-1"
});
const fetch = require('node-fetch');
const qs = require('querystring');
const debug = require('debug')('datafn');
debug.enabled = true;
debug(debug.extend);

const qualifiedSearchString = query => (query.trim().startsWith('|') ? query : `search ${query}`);
const sleep = ms => new Promise(r => setTimeout(r, ms));

const MIN_REFRESH_TIME = 30;

exports.handler =  async function(event, context, callback) {
    const request = event.Records[0].cf.request;
    if (request.uri.startsWith("/api/data/") != true)  {
        return {
            status: '404',
            statusDescription: 'OK',
            headers: {
                'cache-control': [{
                    key: 'Cache-Control',
                    value: 'max-age=3600, public'
                }],
                'content-type': [{
                    key: 'Content-Type',
                    value: 'text/html'
                }],
                'content-encoding': [{
                    key: 'Content-Encoding',
                    value: 'UTF-8'
                }],
                'expires': [{
                    key: 'Expires',
                    value: '300'
                }],
            },
            body: "40h4",
        };
    }
    const id = request.uri.substring(request.uri.lastIndexOf('/')+1)
    debug('Looking up datasource ID %o', id);

    var dynamodb =  new AWS.DynamoDB({apiVersion: '2012-08-10'});
    var params = {
        Key: {
            "searchid": {"S": id}
        },
        TableName: "splunk-collections"
    };
    var result = await dynamodb.getItem(params).promise()
    var json_result = AWS.DynamoDB.Converter.unmarshall(result.Item);
    debug(json_result)
    debug(result)
    if (!result.Item) {
        debug('ERROR: No datasource with ID %o found', id);
        callback(null, {
            status: '500',
            body: { error: 'Datasource not found' },
            headers: {
                'Content-Type': [{
                    key: 'Content-Type',
                    value: 'text/plain'
                }],
                'Access-Control-Allow-Origin': [{
                    key: 'Access-Control-Allow-Origin',
                    value: '*'
                }],
                'cache-control': [{
                    key: 'Cache-Control',
                    value: 's-maxage=3600'
                }]
            },
        });
    }

    var search = json_result['search'];
    var app = json_result['app'];
    var servername = json_result['splunk_server']
    console.log(`/splunkdash/${servername}/url`);
    var secretsmanager = new AWS.SecretsManager();
    var splunkd_urisecret = await secretsmanager.getSecretValue({"SecretId":`/splunkdash/${servername}/url`}).promise();
    var splunkd_usersecret = await secretsmanager.getSecretValue({"SecretId":`/splunkdash/${servername}/username`}).promise();
    var splunkd_passsecret = await secretsmanager.getSecretValue({"SecretId":`/splunkdash/${servername}/password`}).promise();
    console.log(splunkd_passsecret);
    const SPLUNKD_URL = splunkd_urisecret.SecretString;
    const SPLUNKD_PASSWORD = splunkd_passsecret.SecretString;
    const SPLUNKD_USER = splunkd_usersecret.SecretString;
    const agent = SPLUNKD_URL.startsWith('https')
        ? new (require('https').Agent)({
            rejectUnauthorized: false,
        })
        : undefined;
    const log = require('debug')(`debug:${id}`);
    log.enabled = true;
    const refresh = Math.min(MIN_REFRESH_TIME, search.refresh || 0);

    try {
        log('Executing search for data fn', id);
        const SERVICE_PREFIX = `servicesNS/${encodeURIComponent(SPLUNKD_USER)}/${encodeURIComponent(app)}`;
        const r = await fetch(`${SPLUNKD_URL}/${SERVICE_PREFIX}/search/jobs`, {
            method: 'POST',
            headers: {
                Authorization: `Basic ${Buffer.from([SPLUNKD_USER, SPLUNKD_PASSWORD].join(':')).toString(
                    'base64'
                )}`,
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: qs.stringify({
                output_mode: 'json',
                earliest_time: (search.queryParameters || {}).earliest,
                latest_time: (search.queryParameters || {}).latest,
                search: qualifiedSearchString(search.query),
                reuse_max_seconds_ago: refresh,
                timeout: refresh * 2,
            }),
            agent,
        });

        if (r.status > 299) {
            throw new Error(`Failed to dispatch job, splunkd returned HTTP status ${r.status}`);
        }
        const { sid } = await r.json();
        log(`Received search job sid=${sid} - waiting for job to complete`);

        let complete = false;
        while (!complete) {
            const statusData = await fetch(
                `${SPLUNKD_URL}/${SERVICE_PREFIX}/search/jobs/${encodeURIComponent(sid)}?output_mode=json`,
                {
                    headers: {
                        Authorization: `Basic ${Buffer.from([SPLUNKD_USER, SPLUNKD_PASSWORD].join(':')).toString(
                            'base64'
                        )}`,
                    },
                    agent,
                }
            ).then(r => r.json());

            const jobStatus = statusData.entry[0].content;
            if (jobStatus.isFailed) {
                throw new Error('Search job failed');
            }
            complete = jobStatus.isDone;
            if (!complete) {
                await sleep(250);
            }
        }

        log('Search job sid=%s for data fn id=%s is complete', sid, id);

        const resultsQs = qs.stringify({
            output_mode: 'json_cols',
            count: 10000,
            offset: 0,
        });
        const data = await fetch(`${SPLUNKD_URL}/${SERVICE_PREFIX}/search/jobs/${sid}/results?${resultsQs}`, {
            method: 'GET',
            headers: {
                Authorization: `Basic ${Buffer.from([SPLUNKD_USER, SPLUNKD_PASSWORD].join(':')).toString(
                    'base64'
                )}`,
            },
            agent,
        }).then(r => r.json());

        log('Retrieved count=%d results from job sid=%s for data fn id=%s', data.columns.length, sid, id);
        const { columns, fields } = data;

        callback(null, {
            status: '200',
            statusDescription: 'OK',
            body: JSON.stringify({ fields, columns }),
            headers: {
                'Content-Type': [{
                    key: 'Content-Type',
                    value: 'text/plain'
                }],
                'Access-Control-Allow-Origin': [{
                    key: 'Access-Control-Allow-Origin',
                    value: '*'
                }],
                'cache-control': [{
                    key: 'Cache-Control',
                    value: 'public, maxage=3600'
                }],
                'expires': [{
                    key: 'Expires',
                    value: ('refresh' in json_result['search'] ? json_result['search']['refresh'] : '300')
                }],
            },
        });
    } catch (e) {
        log('Error fetching data for data fn %s', id, e);
        callback(null,{
            'status': '500',
            'body': { error: 'Failed to fetch data' },
            'headers': {
                'Content-Type': 'text/plain',
                'Access-Control-Allow-Origin' : 'cache-control',
            }
        });
    }
};