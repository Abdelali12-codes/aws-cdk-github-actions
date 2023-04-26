import json
import base64
import gzip
import boto3
import requests
import os
from requests_aws4auth import AWS4Auth


region = 'us-west-2' # For example, us-west-1
service = 'es'
credentials = boto3.Session().get_credentials()
awsauth = AWS4Auth(credentials.access_key, credentials.secret_key, region, service, session_token=credentials.token)


host = os.environ['es_host'] # the OpenSearch Service domain, e.g. https://search-mydomain.us-west-1.es.amazonaws.com
index = 'lambda-index'
type = '_doc'
url = host + '/' + index + '/' + type


headers = { "Content-Type": "application/json" }


def handler(event, context):
    print('the event is ', event)
    # TODO implement
    for record in event['Records']:
        if 'kinesis' in record:
            data = record['kinesis']['data']
            decod = base64.b64decode(data)
            obj = json.loads(gzip.decompress(decod).decode('utf-8'))
            if 'logEvents' in obj:
                for logevent in obj['logEvents']:
                    if 'extractedFields' in logevent:
                        document = logevent['extractedFields']
                        r = requests.post(url, auth=awsauth, json=document, headers=headers)