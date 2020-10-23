## Introduction
Demo available at https://energy.livehybrid.com  
This is an *EXPERIMENTAL* tool to help publish Splunk dashboard using AWS Serverless technology and is Work-In-Progress, however please feel free to contact me for more information or to contribute.  

For background information on this please see our recent SplunkConf talk "DEV1665B - Publishing entire Splunk dashboards online using the latest dashboard features" at https://conf.splunk.com/learn/session-catalog.html?search=DEV1665B#/

## Usage Instructions
We are just ironing out a couple of issues and will upload a new version the week following Splunk .conf20 (w/c 26th Oct! Check back soon!)


## Notes
The Lambda role is granted access to AWS secrets in /splunkdash/*

## Known issues
* Static images are not uploaded - This feature is being tested and will be added shortly.
* Searches containing certain HTML characters may be converted to their HTML entities. - This is being tested and fixed shortly.

This has been shared as a Proof of Concept, however I intend to iron out issues to make it more useful to external users. Please get in touch if you experience issues, or feel free to submit a Merge Request.
