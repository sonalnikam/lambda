import boto3
import botocore
import os
import time
import csv
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
from datetime import datetime
from collections import OrderedDict


# import logging
failReason = ""
result = True

access_key_name_alias=""
access_key_active=""
access_key_last_rotated=""

offenders_7_days = []
offenders_1_days = []
offenders_0_days = []
offenders_pwd_not_used = []
offenders_pwd_not_used_30_days = []
scored = True
userList_7_days = []
userList_1_days = []
userList_0_days = []
userList_pwd_30_days = []
userList_pwd_no_info = []

emailList_7_days = []
emailList_1_days = []
emailList_0_days = []
pwd_emailList_30_days = []
pwd_emailList_no_info = []
credential_report = ""


# Get current time
now = time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(time.time()))
frm = "%Y-%m-%dT%H:%M:%S+00:00"


"""
    Assumes a role in 'destination' AWS account
"""


iam_client = boto3.client('iam')

def assume_role_aua1(accountId):
    session = boto3.Session()
    sts_client = session.client('sts')
    assumed_role = sts_client.assume_role(
        RoleArn="arn:aws:iam::" + accountId + ":role/SR-AtosNotifyUser",
        RoleSessionName="CredentialReport"
    )

    return assumed_role['Credentials']


"""
    Generate the Credential Report for Atos User from AUA Account
"""


def get_credential_report_aua(assumed_role):
    iam_client = boto3.client(
        'iam',
        aws_access_key_id=assumed_role['AccessKeyId'],
        aws_secret_access_key=assumed_role['SecretAccessKey'],
        aws_session_token=assumed_role['SessionToken']
    )

    gen_cred_report_res = iam_client.generate_credential_report()
    gen_cred_report_state = gen_cred_report_res['State']

    if gen_cred_report_state == "COMPLETE":
        try:
            #print("Credential Report Generated...")
            get_cred_report_resp = iam_client.get_credential_report()
            get_cred_report_csv = get_cred_report_resp['Content']
            csv_file = get_cred_report_csv.decode()
            reader = csv.DictReader(csv_file.splitlines())
            credential_report = []
            for row in reader:
                credential_report.append(row)
            return credential_report
        except botocore.exceptions.ClientError as e:
            print("Unknown error getting Report: " + e)
    else:
        time.sleep(2)
        return get_credential_report_aua(assumed_role)


""" 
    Determines if valid datetime format 
"""


def validate_date(datetime_str, format):
    
    try:
        datetime.strptime(datetime_str, format)
        return True
    except ValueError:
        return False


"""
    Get Item from DynamoDB Table
"""

def get_item(table_name, list_values):
    
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(table_name)
    response = table.scan(
        TableName='MPAWS_IAMUsers_List',
        Select='SPECIFIC_ATTRIBUTES',
        AttributesToGet=['DAS_ID', 'Email']
    )
    return response['Items']

def iterate_over_multiple_list(listName, userListName):
    for i in listName:
        list1 = i.split('/', 2)[1]
        list2 = list1.split(':')[0]
        userListName.append(list2)
    return userListName


def get_emailList_from_dynamodb(dbUserListName, userListName, emailListName):
    i = 0
    while i < len(dbUserListName):
        if len(dbUserListName) != 0:
            dbDasId = dbUserListName[i]['DAS_ID']
            dbDasEmail = dbUserListName[i]['Email']
            for j in userListName:
                if ((j.lower() == dbDasId.lower()) 
                    & (dbDasEmail != 'NA')):
                    #print("DAS_ID: " + dbDasId + " Email: " + dbDasEmail)
                    emailListName.append(dbUserListName[i]['Email'])
            i = i + 1
    return emailListName

def send_message():
    boto3.client('ses').send_email(
    Source='no-reply@mpcaws.idm.atos.net',
    Destination={
        'ToAddresses': [
            'kamal.garg@atos.net'
        ]
    },
    Message={
        'Subject': {
            'Charset': 'UTF-8',
            'Data': 'Test email'
        },
        'Body': {
            'Html': {
                'Charset': 'UTF-8',
                'Data': 'This message body contains HTML formatting. It can, for example, contain links like this one: <a class="ulink" href="http://docs.aws.amazon.com/ses/latest/DeveloperGuide" target="_blank">Amazon SES Developer Guide</a>.'
            },
            'Text': {
                'Charset': 'UTF-8',
                'Data': 'This is the message body in text format.'
            }
        }
    }
    )
 
def lambda_handler(event, context):
    assumed_role = assume_role_aua1(os.environ['accountId'])
    #print("Temp creds generated: " + str(assumed_role))

    credential_report = get_credential_report_aua(assumed_role)
    #print("Credential Report: " + str(credential_report))


    for row in range(len(credential_report)):
        if credential_report[row]['access_key_1_active'] == "true":
            access_key_name_alias="Access Key 1"
            access_key_last_rotated="access_key_1_last_rotated"
        elif credential_report[row]['access_key_2_active'] == "true":
            access_key_name_alias="Access Key 2"
            access_key_last_rotated="access_key_2_last_rotated"
            
            print(access_key_name_alias)
            print(access_key_last_rotated)
            
            try:
                if validate_date(credential_report[row][access_key_last_rotated], frm):
                    delta = datetime.strptime(now, frm) - datetime.strptime(
                        credential_report[row][access_key_last_rotated], frm)
                    
                    # Verify access key1 aged more than 83 days
                    if delta.days >= 83:
                        result = False
                        failReason = "AccessKey1 will expire in 7 days."
                        offenders_7_days.append(str(credential_report[row]['arn']) + ":key1_7_days")
                        print(access_key_name_alias + " 7 Days: " + str(offenders_7_days))
                    
                    # Verify access key1 aged more than 89 days
                    elif delta.days >= 89:
                        result = False
                        failReason = "AccessKey1 will expire in 1 day."
                        offenders_1_days.append(str(credential_report[row]['arn']) + ":key1_1_days")
                        print(access_key_name_alias + "1 Day: " + str(offenders_1_days))

                    # Verify access key1 aged more than 90 days
                    elif delta.days == 90:
                        result = False
                        failReason = "AccessKey1 Now expired."
                        offenders_0_days.append(str(credential_report[row]['arn']) + ":key1_0_days")
                        print(access_key_name_alias+ "0 Day: " + str(offenders_0_days))
            except Exception as e:
                print('Exception while examinging access_key 1 last_used_date. Error: ' + str(e)) 
