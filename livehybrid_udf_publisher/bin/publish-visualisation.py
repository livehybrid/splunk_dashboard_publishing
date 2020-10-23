"""
aws-iam-lookup.py
Pulls in tags from iam users on AWS
"""
import livehybrid_udf_publisher_declare

import splunk.Intersplunk
#import splunk.rest
#from splunk.clilib import cli_common as cli

from splunk_aoblib.setup_util import Setup_Util

#import json
import simplejson as sjson
import datetime
import logging as logger
import json
import os, sys
import csv
from decimal import Decimal
import hashlib
import boto3
import base64
import re
from dotted_dict import DottedDict
#boto3.set_stream_logger('boto3.resources', logger.INFO)
# from botocore.exceptions import EndpointConnectionError
# from botocore.exceptions import ClientError


logger.basicConfig(level=logger.INFO,
                    format='%(asctime)s %(levelname)s %(message)s',
                    filename=os.path.join(os.getenv('SPLUNK_HOME','/opt/splunk'),'var','log','splunk','publisher_visualization.log'),
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

def gen_ds_hash(ds):
    h = hashlib.sha256()
    logger.warning(ds)
    h.update(ds["options"]["query"].encode('utf-8'))
    if 'queryParameters' in ds['options']:
        if 'earliest' in ds['options']['queryParameters']:
            h.update(ds['options']['queryParameters']['earliest'].encode('utf-8'))
        if 'latest' in ds['options']['queryParameters']:
            h.update(ds['options']['queryParameters']['latest'].encode('utf-8'))
    if 'refresh' in ds['options']:
        h.update(ds['options']['refresh'].encode('utf-8'))
    if 'postprocess' in ds['options']:
        h.update(ds['options']['postprocess'].encode('utf-8'))
    digest = h.hexdigest()
    ds_hash_id = digest[0:24]
    return ds_hash_id

def slugify(val):
    non_url_safe = ['"', '#', '$', '%', '&', '+',
                    ',', '/', ':', ';', '=', '?',
                    '@', '[', '\\', ']', '^', '`',
                    '{', '|', '}', '~', "'"]
    translate_table = {ord(char): u'' for char in non_url_safe}
    text = val.translate(translate_table)
    text = u'_'.join(text.split())
    return text

def convert_json(value):
    if isinstance(value, dict):
        return {key: convert_json(val) for key, val in value.items()}
    elif isinstance(value, bool):
        return str(value).lower()
    elif isinstance(value, (int, long, float, complex)):
        return int(value)
    elif isinstance(value, Decimal):
#        return ast.literal_eval(value)
        return int(value)
    elif hasattr(value, '__iter__'):
        return map(convert_json, value)

    return value

if __name__ == "__main__":
    splunk_results, unused1, settings = splunk.Intersplunk.getOrganizedResults()
    keywords,options = splunk.Intersplunk.getKeywordsAndOptions()
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
        boto_session = aws_session(session=boto_session, role_arn=None  , session_name='splunk_publisher')
    logger.warning(splunk_results)
    dynamodb = boto_session.resource('dynamodb',region_name='us-east-1')
    table_ds = dynamodb.Table("splunk-collections")
    table_viz = dynamodb.Table("splunk-dashboards")

    for row in splunk_results:
        visualization = json.loads(row['_raw'])
        original = json.loads(row['_raw'])
#         for viz in visualization['visualizations'].keys():
#             pass

        for dsKey in visualization['dataSources'].keys():
            ds = visualization['dataSources'][dsKey]
            ds_hash_id = gen_ds_hash(ds)
            #logger.warning(ds_hash_id)
            #res = ""
            #for x in range(0, len(ds_hash_id),2):
            #    logger.warning(ds_hash_id[x:x+2])
            #    res += (str((int(ds_hash_id[x:x+2],16)) % 36))

            dynamo_ds = {
              "app": "splunk-dashboard-app",
              "collection": options['collection'],
              "id": ds_hash_id,
              "search": ds['options'],
              "splunk_server" : row['server'],
              "searchid": ds_hash_id
            }
            if visualization['dataSources'][dsKey]['type'] == "ds.chain":
                base = visualization['dataSources'][dsKey]['options']['extend']
                chain_query = dynamo_ds['search']['query']
                dynamo_ds['search'] = original['dataSources'][base]['options']['query'] + chain_query
                #dynamo_ds['search'] = visualization['dataSources']['base']['options']
                #dynamo_ds['search']['postprocess'] = chain_query

            visualization['dataSources'][dsKey] = {
                "type": "ds.cdn",
                "options" : {
                    "uri" : "/api/data/{}".format(ds_hash_id)
                }
            }
            res = table_ds.put_item(Item=dynamo_ds)

        logger.warning(convert_json(visualization))
        dynamo_viz = {
        "dashid": slugify(visualization['title'].lower()),

#        "config" : sjson.dumps(visualization, parse_float=Decimal)
#        "config" : json.dumps(convert_json(visualization))
        "config" : convert_json(visualization)
#        "config" : re.sub(r"\"(-*\d+(?:\.\d+)?)\"","\1", json.dumps(convert_json(visualization))
        }


#        logger.warning(json.dumps(dynamo_viz,indent=4))
        res2 = table_viz.put_item(Item=dynamo_viz)
            #logger.warning(res)
	print(",".join(["Name","Status"]))
	print(",".join([visualization['title'],"Done!"]))
