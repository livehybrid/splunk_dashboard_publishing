import re
import sys
import os
import fileinput
import boto3
import base64
from botocore.exceptions import ClientError
import subprocess, shlex

def get_secret(secret_name):
#    print "Finding secret={}".format(secret_name)
    region_name = "eu-west-2"

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

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
            print("secret={} not found in secretsmanager".format(secret_name))
            return ""
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            return get_secret_value_response['SecretString']
        else:
            return base64.b64decode(get_secret_value_response['SecretBinary'])

def replace_secret(value):
#    pprint.pprint(value.groups())
    print("Replacing secret={}".format(value.group(2)))
    secret = get_secret(value.group(2))
    return "{}{}{}".format(value.group(1),secret,value.group(3))

#APP_NAME="git-manager"
#TARGET_DIR="bin"
#filepath = os.path.join(os.environ['SPLUNK_HOME'], 'etc', 'apps', APP_NAME, TARGET_DIR, "pull-app-helper.sh")
def runGitCommand(command):
    kwargs = {}
    kwargs['stdout'] = subprocess.PIPE
    kwargs['stderr'] = subprocess.PIPE
    kwargs['cwd']  = '/opt/splunk/etc'
    proc = subprocess.Popen(shlex.split("git {}".format(command)), **kwargs)
    (stdout_str, stderr_str) = proc.communicate()
    return_code = proc.wait()
    #Git output
    print stdout_str
    print stderr_str

runGitCommand("reset --hard")
runGitCommand("pull origin {}".format(sys.argv[1]))

secret_files = os.popen("grep -Rl splunksecret /opt/splunk/etc/shcluster /opt/splunk/etc/master-apps /opt/splunk/etc/apps /opt/splunk/etc/deployment-apps").read()
for secret_file in iter(secret_files.splitlines()):
    print("Secrets found in file={}".format(secret_file))
    with open(secret_file) as f:
        buffer=f.read()
	output=re.sub(r"(.*)#splunksecret\:([^#]+)#(.*)", replace_secret, buffer)

    with open(secret_file, "w") as f:
         f.write(output)
