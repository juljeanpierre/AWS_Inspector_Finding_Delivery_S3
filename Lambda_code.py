from __future__ import print_function
import boto3
import json
from datetime import datetime
import sys

sns = boto3.client('sns')
inspector = boto3.client('inspector')


def lambda_handler(event, context):
    print(event)
    message = event['Records'][0]['Sns']['Message']
    runArn = json.loads(message)['run']
    #print(runArn)

    response = inspector.get_assessment_report(
    assessmentRunArn=runArn,
    reportFileFormat='PDF',
    reportType='FINDING')
    print("Response is")
    print(response)
    message = response['status']
    while (message != 'COMPLETED'):
        response = inspector.get_assessment_report(
        assessmentRunArn=runArn,
        reportFileFormat='PDF',
        reportType='FINDING')
    response = sns.publish(
        TopicArn = 'arn:aws:sns:us-east-1:675597678277:Inspector-Finding-Delivery',
        Message = str(response),
        Subject = "Inspector_report_download_link "+str(datetime.now())
        )
    print('Report sent successfully')