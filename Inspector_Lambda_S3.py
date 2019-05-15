import boto3
import json
import re
import urllib.request
import ssl

clientInspector = boto3.client('inspector')


# Get Run ARN
def lambda_handler(event, context):
    records = event["Records"]
    for v in records:
        message = (v["Sns"]["Message"])
        create_dict = json.loads(message)
        run_arn = create_dict.get('run')
    obtain_findings(run_arn=run_arn)


# Upload Inspector findings to s3 bucket
def obtain_findings(run_arn):
    try:
        run_name = re.sub(r'.+/', "", run_arn)
        paginator = clientInspector.get_paginator('list_findings')
        response_iterator = paginator.paginate(assessmentRunArns=[run_arn])
        for response in response_iterator:
            for k, v in response.items():
                if k == "findingArns":
                    if v == []:
                        continue
                    else:
                        list_find = (v)
                        for idx, arn in enumerate(list_find):
                            finding_name = re.sub(r'.+/', "", arn)
                            response_describe_finding = clientInspector.describe_findings(findingArns=[arn],
                                                                                          locale='EN_US')
                            response_describe_finding = json.dumps(response_describe_finding, indent=4, default=str)
                            object_name = "Assessment_run_" + run_name + "/" + "Finding_" + finding_name + ".json"
                            upload_to_bucket(object_s3=response_describe_finding, key_s3=object_name)
                else:
                    continue
        obtain_report(run_arn=run_arn, run_name=run_name)
    except Exception as error:
        print (error)


def obtain_report(run_arn, run_name):
    try:
        response = clientInspector.get_assessment_report(assessmentRunArn=run_arn, reportFileFormat='HTML',
                                                         reportType='FULL')
        if response["status"] == "COMPLETED":
            filename = "Report_" + run_name + '.html'
            url = response["url"]
            context = ssl._create_unverified_context()
            report = urllib.request.urlopen(url, context=context)
            report_object = report.read()
            upload_to_bucket(object_s3=report_object, key_s3=filename)
        else:
            obtain_report(run_arn=run_arn, run_name=run_name)
    except Exception as error:
        print (error)


def upload_to_bucket(object_s3, key_s3):
    try:
        clientS3 = boto3.client('s3')
        response = clientS3.put_object(
            Body=object_s3,
            Bucket="<YOUR_BUCKET_NAME>",
            ContentEncoding='json',
            Key=key_s3,
        )
    except Exception as error:
        print (error)