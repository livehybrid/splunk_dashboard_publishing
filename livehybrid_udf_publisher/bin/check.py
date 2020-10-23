import re
import sys
import os
import fileinput
import boto3
import base64
from botocore.exceptions import ClientError
import subprocess, shlex


#APP_NAME="git-manager"
#TARGET_DIR="bin"
#filepath = os.path.join(os.environ['SPLUNK_HOME'], 'etc', 'apps', APP_NAME, TARGET_DIR, "pull-app-helper.sh")
def checkVersion(binFile,suffix):
    try:
        kwargs = {}
        kwargs['stdout'] = subprocess.PIPE
        kwargs['stderr'] = subprocess.PIPE
     #   kwargs['cwd']  = '/opt/splunk/etc'

        proc = subprocess.Popen(shlex.split(binFile+" "+suffix), **kwargs)
        (stdout_str, stderr_str) = proc.communicate()
        return_code = proc.wait()
        #Git output
        print(binFile+","+stdout_str.decode().replace("\n",""))
    except:
       print(binFile+","+"error")

print("file,version")
checkVersion("node","-v")
checkVersion("npm", "-v")