"""
aws-iam-lookup.py
Pulls in tags from iam users on AWS
"""
import livehybrid_udf_publisher_declare

import splunk.Intersplunk
#import splunk.rest
#from splunk.clilib import cli_common as cli

from splunk_aoblib.setup_util import Setup_Util

import json
import datetime
import logging as logger
import json
import os, sys
import csv
from decimal import Decimal
import hashlib
import boto3
import base64
from dotted_dict import DottedDict
#boto3.set_stream_logger('boto3.resources', logger.INFO)
# from botocore.exceptions import EndpointConnectionError
# from botocore.exceptions import ClientError


logger.basicConfig(level=logger.INFO,
                    format='%(asctime)s %(levelname)s %(message)s',
                    filename=os.path.join(os.getenv('SPLUNK_HOME','/opt/splunk'),'var','log','splunk','publisher_datasources.log'),
                    filemode='a'
                    )

class fakefloat(float):
    def __init__(self, value):
        self._value = value
    def __repr__(self):
        return str(self._value)

def defaultencode(o):
    if isinstance(o, Decimal):
        # Subclass float with custom repr?
        return fakefloat(o)
    raise TypeError(repr(o) + " is not JSON serializable")

def aws_session(session=None, role_arn=None, session_name='lookup_session'):
    """
    If role_arn is given assumes a role and returns boto3 session
    otherwise return a regular session with the current IAM user/role
    """
    if role_arn:
        if session == None:
            client = boto3.client('sts')
        else:
            client = session.client('sts')
        response = client.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
        creds = response.get("Credentials", None)
        if creds is not None:
            session = boto3.Session(
                aws_access_key_id=creds['AccessKeyId'],
                aws_secret_access_key=creds['SecretAccessKey'],
                aws_session_token=creds['SessionToken'])
        return session
    else:
        return boto3.Session()

if __name__ == "__main__":
    splunk_results, unused1, settings = splunk.Intersplunk.getOrganizedResults()
    keywords,options = splunk.Intersplunk.getKeywordsAndOptions()
    if 'collection' not in options or options['collection'] == "":
        logger.critical("Unknown Collection - Please specify a collection")
        exit(1)
    logger.warning(options)
#    logger.warning(splunk_results)
    session_key = settings.get("sessionKey")

    uri = "https://localhost:8089"
    setup_util = Setup_Util(uri, session_key, logger)

    aws_access_key = setup_util.get_customized_setting("aws_access_key")
    aws_secret_key = setup_util.get_customized_setting("aws_secret_key")
    iam_role_arn = setup_util.get_customized_setting("iam_role_arn")

    if aws_secret_key != None and aws_access_key != None:
        boto_session = boto3.session.Session(region_name="eu-west-2", aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key, aws_session_token=None)
    else:
        boto_session = None

    #boto_session = aws_session(session=boto_session, role_arn=iam_role_arn, session_name='splunk_publisher')
    logger.warning(splunk_results)
    datasources = {}
    print(",".join(["Name","SearchID","Status"]))

    for row in splunk_results:
        key = row['dsID']
        value = {row['dsField'] : row['fieldvalue']}
        try:
            datasources[key][row['dsField']] = row['fieldvalue'].encode('utf-8')
        except KeyError:
            datasources[key] = {}
            datasources[key][row['dsField']] = row['fieldvalue'].encode('utf-8')

    logger.info(datasources)
    dynamodb = boto_session.resource('dynamodb',region_name='us-east-1')
    table = dynamodb.Table("splunk-collections")

    for dsKey in datasources:
        ds = datasources[dsKey]
        h = hashlib.sha256()
        h.update(ds["options.query"])

        if 'options.queryParameters.earliest' in ds:
            h.update(ds['options.queryParameters.earliest'])
        if 'options.queryParameters.latest' in ds:
            h.update(ds['options.queryParameters.latest'])
        if 'options.refresh' in ds:
            h.update(ds['options.refresh'])
        if 'options.postprocess' in ds:
           h.update(ds['options.postprocess'])
        digest = h.hexdigest()
        ds_hash_id = digest[0:24]
        #logger.warning(ds_hash_id)
        #res = ""
        #for x in range(0, len(ds_hash_id),2):
        #    logger.warning(ds_hash_id[x:x+2])
        #    res += (str((int(ds_hash_id[x:x+2],16)) % 36))
        search = {}
        for item in ds :
            if 'options.' in item:
                key = item.replace("options.","")
                if '.' in key:
                    key_parts = key.split('.')
                    if len(key_parts) > 2:
                        logger.critical("This only supports single nested options")
                    if key_parts[0] not in search:
                        search[key_parts[0]] = {}
                    search[key_parts[0]][key_parts[1]] = ds[item].decode('utf-8')
                else:
                    search[key] = ds[item].decode('utf-8')
        dynamo_ds = {
          "app": "splunk-dashboard-app",
          "collection": options['collection'],
          "splunk_server" : row['server'],
          "id": ds_hash_id,
          "search": search,
          "searchid": ds_hash_id
        }

        print(",".join([dsKey, ds_hash_id,"Added/Updated"]))
        logger.warning(json.dumps(dynamo_ds,indent=4))
        res = table.put_item(Item=dynamo_ds)


