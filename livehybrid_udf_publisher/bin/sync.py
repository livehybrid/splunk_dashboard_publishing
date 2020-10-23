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

import boto3
#boto3.set_stream_logger('boto3.resources', logger.INFO)
# from botocore.exceptions import EndpointConnectionError
# from botocore.exceptions import ClientError


logger.basicConfig(level=logger.DEBUG,
                    format='%(asctime)s %(levelname)s %(message)s',
                    filename=os.path.join(os.getenv('SPLUNK_HOME','/opt/splunk'),'var','log','splunk','publisher_sync.log'),
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

    #   boto_session = aws_session(session=boto_session, role_arn=iam_role_arn, session_name='splunk_publisher')

    dynamodb = boto_session.resource('dynamodb',region_name='eu-west-2')
    table = dynamodb.Table("publishertest")

    items = table.scan()
#    print(",".join(items['Items'][0].keys()))
    for item in items['Items']:
#       item['search'] = 'test'
       try:
           item['search'] = json.dumps(item['search'])
       except:
     #      item['search'] = '
           logger.critical(item)
#        output = ",".join("" if isinstance(x, dict) else x for x in item.values())
    splunk.Intersplunk.outputResults(items['Items'])
    #    print(output)
    #logger.info(items)

#splunk.Intersplunk.getOrganizedResults    splunk.Intersplunk.outputResults(items)
    #
    #
    # for result in splunk_results:
    #     if 'username' in result:
    #         logger.info("Lookup sponsor for username={}".format(result['username']))
    #         try:#
    #             tags = client.list_user_tags(UserName=result['username'])
    #             logger.info(tags['Tags'])
    #             for tag in tags['Tags']:
    #                result[tag['Key']] = tag['Value']
    #         except Exception as e:
    #             logger.warning("Tags not found for username={}".format(result['username']))
    #
    # splunk.Intersplunk.outputResults(events)
