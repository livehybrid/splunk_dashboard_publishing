#!/bin/sh

aws cloudformation deploy \
  --template-file dashboard.yaml \
  --stack-name splunk-dashboard-$RANDOM \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides Nonce=$RANDOM
