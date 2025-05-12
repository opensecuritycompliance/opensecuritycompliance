import os
import re
import json
import time
import logging
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import List, Any, Dict, Tuple, Optional
from urllib.parse import urlparse
from dateutil import tz
import requests
import pytz
import pandas as pd
import numpy as np
import boto3
import botocore.exceptions
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
from applicationtypes.compliancecow import compliancecow
from compliancecowcards.utils import cowdictutils

RESOURCE_PLACEHOLDER         = '<<Resource>>'
REGION_PLACEHOLDER           = '<<Region>>'
RESOURCE_PARENT_PLACEHOLDER  = '<<ResourceParent>>'
RESOURCE_TYPE                = 'resource_type'
RESOURCE_FIELD               = 'Resource'
REGION_FIELD                 = 'Region'
RESOURCE_PARENT_FIELD        = 'ResourceParent'
# resourcetypes
CLOUDTRAIL                   = 'AwsCloudTrailTrail'  
CLOUDTRAIL_LIST              = 'AwsCloudTrailTrailList'
KMS                          = 'AwsKmsKey'
VPC                          = 'AwsEc2Vpc'
CLOUD_WATCH_METRIC_ALARM     = 'AwsCloudWatchMetricAlaram'
CLOUD_WATCH_METRIC_FILTER    = 'AwsCloudWatchMetricFilter'
IAM_USER                     = 'AwsIamUser'
IAM_USER_LIST                = 'AwsIamUserList'
IAM_ROLE                     = 'AwsIamRole'
IAM_GROUP                    = 'AwsIamGroup'
IAM_POLICY                   = 'AwsIamPolicy'
CLOUD_WATCH_LOG_GRP          = 'LogGroup'
S3_BUCKET                    = 'AwsS3Bucket'
BACKUP_VAULT                 = 'AwsBackupBackupVault'
BACKUP_RECOVERY_PT           = "AwsBackupRecoveryPoint"
CLOUD_WATCH_METRICS_LIST     = 'AwscloudWatchMetricList'
CLOUD_WATCH_ALARM_LIST       = 'AwscloudWatchAlarmList'
EC2_SECURITY_GROUP           = 'AwsEc2SecurityGroup'
RDS_DB_INSTANCE              = 'AwsRdsDbInstance'
EC2_INSTANCE                 = 'AwsEc2Instance'
ELASTIC_FILE_SYSTEM          = 'AwsEFS'
CLOUD_TRAIL_EVENT            = 'AwsCloudTrailEvent'
EC2_SUBNET                   = 'AwsEc2Subnet'
CLOUD_FORMATION_STACK        = 'AwsCloudFormationStack'
# urls
CLOUDTRAIL_URL               = 'https://<<Region>>.console.aws.amazon.com/cloudtrail/home?region=<<Region>>#/trails/<<Resource>>'
KMS_URL                      = 'https://<<Region>>.console.aws.amazon.com/kms/home?region=<<Region>>#/kms/defaultKeys/<<Resource>>'
VPC_URL                      = 'https://<<Region>>.console.aws.amazon.com/vpcconsole/home?region=<<Region>>#VpcDetails:VpcId=<<Resource>>'
CLOUD_WATCH_METRIC_ALARM_URL = 'https://<<Region>>.console.aws.amazon.com/cloudwatch/home?region=<<Region>>#alarmsV2:alarm/<<Resource>>'
CLOUD_WATCH_METRIC_FILER_URL = 'https://<<Region>>.console.aws.amazon.com/cloudwatch/home?region=<<Region>>#logsV2:log-groups/log-group/<<ResourceParent>>/edit-metric-filter/<<Resource>>'
IAM_USER_URL                 = 'https://us-east-1.console.aws.amazon.com/iamv2/home?region=us-east-1#/users/details/<<Resource>>'
IAM_ROLE_URL                 = 'https://us-east-1.console.aws.amazon.com/iamv2/home?region=1#/roles/details/<<Resource>>'
IAM_GROUP_URL                = 'https://us-east-1.console.aws.amazon.com/iamv2/home?region=1#/groups/details/<<Resource>>'
CLOUD_WATCH_LOG_GRP_URL      = 'https://<<Region>>.console.aws.amazon.com/cloudwatch/home?region=<<Region>>#logsV2:log-groups/log-group/<<Resource>>'
S3_BUCKET_URL                = 'https://s3.console.aws.amazon.com/s3/buckets/<<Resource>>?region=<<Region>>&bucketType=general'
BACKUP_VAULT_URL             = 'https://<<Region>>.console.aws.amazon.com/backup/home?region=<<Region>>#/backupvaults/details/<<Resource>>'
BACKUP_RECOVERY_PT_URL       = 'https://<<Region>>.console.aws.amazon.com/backup/home?region=<<Region>>#/backupvaults/details/<<ResourceParent>>/<<Resource>>'
IAM_POLICY_URL               = 'https://<<Region>>.console.aws.amazon.com/iamv2/home?region=<<Region>>#/policies/details/<<Resource>>'
CLOUD_WATCH_METRICS_LIST_URL = 'https://<<Region>>.console.aws.amazon.com/cloudwatch/home?region=<<Region>>#metricsV2'
CLOUD_WATCH_ALARM_LIST_URL   = 'https://<<Region>>.console.aws.amazon.com/cloudwatch/home?region=<<Region>>#alarmsV2'
CLOUDTRAIL_LIST_URL          = 'https://<<Region>>.console.aws.amazon.com/cloudtrailv2/home?region=<<Region>>#/trails'
IAM_USER_LIST_URL            = 'https://<<Region>>.console.aws.amazon.com/iamv2/home?region=<<Region>>#/users'
EC2_SECURITY_GROUP_URL       = 'https://<<Region>>.console.aws.amazon.com/ec2/home?region=<<Region>>#SecurityGroup:groupId=<<Resource>>'
RDS_DB_INSTANCE_URL          = 'https://<<Region>>.console.aws.amazon.com/rds/home?region=<<Region>>#database:id=<<Resource>>'
EC2_INSTANCE_URL             = "https://<<Region>>.console.aws.amazon.com/ec2/home?region=<<Region>>#Instances:instanceState=running;instanceId=<<Resource>>"
ELASTIC_FILE_SYSTEM_URL      = "https://<<Region>>.console.aws.amazon.com/efs/home?region=<<Region>>#/file-systems/<<Resource>>"
CLOUD_TRAIL_EVENT_URL        = "https://<<Region>>.console.aws.amazon.com/cloudtrailv2/home?region=<<Region>>#/events/<<Resource>>"
EC2_SUBNET_URL               = "https://<<Region>>.console.aws.amazon.com/vpcconsole/home?region=<<Region>>#SubnetDetails:subnetId=<<Resource>>"
CLOUD_FORMATION_STACK_URL    = "https://<<Region>>.console.aws.amazon.com/cloudformation/home?region=<<Region>>#/stacks/stackinfo?stackId=<<Resource>>"

class AWSRole:
    access_key: str
    secret_key: str
    role_arn: str

    def __init__(self, access_key: str, secret_key: str,
                 role_arn: str) -> None:
        self.access_key = access_key
        self.secret_key = secret_key
        self.role_arn = role_arn

    @staticmethod
    def from_dict(obj) -> 'AWSRole':
        access_key, secret_key, role_arn = "", "", ""
        if isinstance(obj, dict):
            access_key = obj.get("AccessKey", "")
            secret_key = obj.get("SecretKey", "")
            role_arn = obj.get("RoleARN", "")

        return AWSRole(access_key, secret_key, role_arn)

    def to_dict(self) -> dict:
        result: dict = {}
        result["AccessKey"] = self.access_key
        result["SecretKey"] = self.secret_key
        result["RoleARN"] = self.role_arn
        return result


class AWSIAM:
    access_key: str
    secret_key: str

    def __init__(self, access_key: str, secret_key: str) -> None:
        self.access_key = access_key
        self.secret_key = secret_key

    @staticmethod
    def from_dict(obj) -> 'AWSIAM':
        access_key, secret_key = "", ""
        if isinstance(obj, dict):
            access_key = obj.get("AccessKey", "")
            secret_key = obj.get("SecretKey", "")

        return AWSIAM(access_key, secret_key)

    def to_dict(self) -> dict:
        result: dict = {}
        result["AccessKey"] = self.access_key
        result["SecretKey"] = self.secret_key
        return result

    def validate_attributes(self) -> str:
        emptyAttrs = []
        if not self.access_key:
            emptyAttrs.append("AccessKey")

        if not self.secret_key:
            emptyAttrs.append("SecretKey")

        if not self.role_arn:
            emptyAttrs.append("RoleARN")

        return "Invalid Credentials: " + ", ".join(
            emptyAttrs) + " is empty" if emptyAttrs else ""


class LinkedApplications:
    compliance_cow_app: List[compliancecow.ComplianceCow]

    def __init__(
            self,
            compliance_cow_app: List[compliancecow.ComplianceCow]) -> None:
        self.compliance_cow_app = compliance_cow_app

    @staticmethod
    def from_dict(obj) -> 'LinkedApplications':
        compliance_cow_app = []
        if isinstance(obj, dict):
            compliance_cow_app = [
                compliancecow.ComplianceCow.from_dict(item)
                for item in obj.get("ComplianceCow", [])
            ]

        return LinkedApplications(compliance_cow_app)

    def to_dict(self) -> dict:
        result: dict = {}
        result["ComplianceCow"] = [
            item.to_dict() for item in self.compliance_cow_app
        ]
        return result


class UserDefinedCredentials:
    aws_role: AWSRole
    awsiam: AWSIAM

    def __init__(self, aws_role: AWSRole, awsiam: AWSIAM) -> None:
        self.aws_role = aws_role
        self.awsiam = awsiam

    @staticmethod
    def from_dict(obj) -> 'UserDefinedCredentials':
        aws_role, awsiam = None, None
        if isinstance(obj, dict):
            aws_role = AWSRole.from_dict(obj.get("AWSRole", None))
            awsiam = AWSIAM.from_dict(obj.get("AWSIAM", None))
        return UserDefinedCredentials(aws_role, awsiam)

    def to_dict(self) -> dict:
        result: dict = {}
        result["AWSRole"] = self.aws_role.to_dict()
        result["AWSIAM"] = self.awsiam.to_dict()
        return result


class AWSAppConnector:
    app_url: str
    app_port: int
    user_defined_credentials: UserDefinedCredentials
    linked_applications: LinkedApplications

    def __init__(self,
                 app_url: str = None,
                 app_port: int = None,
                 user_defined_credentials: UserDefinedCredentials = None,
                 region: list = None,
                 linked_applications: LinkedApplications = None) -> None:
        self.app_url = app_url
        self.app_port = app_port
        self.user_defined_credentials = user_defined_credentials
        self.region = region
        self.linked_applications = linked_applications

    @staticmethod
    def from_dict(obj) -> 'AWSAppConnector':
        app_url, app_port, user_defined_credentials, linked_applications = "", "", None, None
        if isinstance(obj, dict):
            app_url = obj.get("AppURL", "")
            if not app_url:
                app_url = obj.get("appURL", "")
            app_port = obj.get("AppPort", 0)
            if not app_port:
                app_port = obj.get("appPort", 0)
            user_defined_credentials_dict = obj.get("UserDefinedCredentials",
                                                    None)
            if user_defined_credentials_dict is None:
                user_defined_credentials_dict = obj.get(
                    "userDefinedCredentials", None)
            if bool(user_defined_credentials_dict):
                user_defined_credentials = UserDefinedCredentials.from_dict(
                    user_defined_credentials_dict)

            linked_applications_dict = obj.get("LinkedApplications", None)
            if linked_applications_dict is None:
                linked_applications_dict = obj.get("linkedApplications", None)
            if bool(linked_applications_dict):
                linked_applications = LinkedApplications.from_dict(
                    linked_applications_dict)
            region = obj.get("Region", [])

        return AWSAppConnector(app_url, app_port, user_defined_credentials, region,
                               linked_applications)

    def to_dict(self) -> dict:
        result: dict = {}
        result["AppURL"] = self.app_url
        result["AppPort"] = self.app_port
        result[
            "UserDefinedCredentials"] = self.user_defined_credentials.to_dict(
            )
        result["Region"] = self.region
        result["LinkedApplications"] = self.linked_applications.to_dict()
        return result

    def validate(self) -> bool and dict:
        if not self.is_empty_aws_role():
            return self.validate_aws_role()
        elif not self.is_empty_aws_iam():
            return self.validate_aws_iam()
        return False, {'Error': 'Not a valid input'}

    def is_empty_aws_role(self):
        role_creds = self.user_defined_credentials.aws_role
        return not all((role_creds.access_key, role_creds.secret_key, role_creds.role_arn))

    def create_aws_session_with_role(self, region=None, role_session_name='compliancecowsession', aws_service_name='sts'):
        aws_role = self.user_defined_credentials.aws_role
        iam_session = boto3.Session(
            region_name=region,
            aws_access_key_id=aws_role.access_key,
            aws_secret_access_key=aws_role.secret_key,
        )
        try:
            sts_client = iam_session.client(aws_service_name)
            assumed_role = sts_client.assume_role(
                RoleArn=aws_role.role_arn, 
                RoleSessionName=role_session_name
                )
            if cowdictutils.is_valid_key(assumed_role, 'Credentials') and \
               cowdictutils.is_valid_key(assumed_role['Credentials'], 'AccessKeyId') and \
               cowdictutils.is_valid_key(assumed_role['Credentials'], 'SecretAccessKey') and \
               cowdictutils.is_valid_key(assumed_role['Credentials'], 'SessionToken'):
                
                credentials = assumed_role['Credentials']
                session = boto3.Session(
                    aws_access_key_id=credentials['AccessKeyId'],
                    aws_secret_access_key=credentials['SecretAccessKey'],
                    aws_session_token=credentials['SessionToken'],
                    region_name=region,
                )
                return session, None
            return None, 'Unable to get the assumed role credentials.'    
        except botocore.exceptions.ClientError as error:
            error_message = 'An error occurred while trying to assume role.'
            if error.response and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message') and cowdictutils.is_valid_key(error.response['Error'], 'Code'):
                if error.response['Error']['Code']=='InvalidClientTokenId':
                    error_message='Invalid AccessKey'
                elif error.response['Error']['Code']=='SignatureDoesNotMatch':
                    error_message = 'Invalid SecretKey'
                elif error.response['Error']['Code']=='AccessDenied':
                    error_message = 'Invalid RoleARN'
                else:
                    error_message = error.response['Error']['Message']
            return None, error_message
        except botocore.exceptions.UnknownServiceError as error:
            return None, f"Unknown AWS Service Error: {error}"
        except botocore.exceptions.EndpointConnectionError as error:
            return None, f"Endpoint connection error: {error}. Check if AWS STS is enabled in region '{region}'."

    def validate_aws_role(self):
        _, error = self.create_aws_session_with_role()
        if error:
            return False, error
        return True, None

    def is_empty_aws_iam(self):
        iam_creds = self.user_defined_credentials.awsiam
        return not all((iam_creds.access_key, iam_creds.secret_key))

    def create_aws_session_with_accesskey(self, region=None):
        aws_iam = self.user_defined_credentials.awsiam
        iam_session = boto3.Session(
            region_name=region,
            aws_access_key_id=aws_iam.access_key,
            aws_secret_access_key=aws_iam.secret_key,
        )
        return iam_session

    def validate_aws_iam(self):
        iam_session = self.create_aws_session_with_accesskey()
        try:
            iam_client = iam_session.client('iam')
            iam_client.get_account_authorization_details()
            return True, None
        except botocore.exceptions.ClientError as error:
            error_message = 'An error occurred while getting account authorization details.'
            if error.response and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message') and cowdictutils.is_valid_key(error.response['Error'], 'Code'):
                if error.response['Error']['Code']=='InvalidClientTokenId':
                    error_message='Invalid AccessKey'
                elif error.response['Error']['Code']=='SignatureDoesNotMatch':
                    error_message = 'Invalid SecretKey'
                else:
                    error_message = error.response['Error']['Message']
            return False, error_message

    def create_aws_session(self, region=None):
        if not self.is_empty_aws_role():
            session, error = self.create_aws_session_with_role(region)
            if error:
                return None, error
        elif not self.is_empty_aws_iam():
            session = self.create_aws_session_with_accesskey(region)
        else:
            return None, 'Not a valid application'
        return session, None
    
    # https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetLoginProfile.html
    def get_user_login_profile(self, user_name: str):
        try:
            iam_session = self.create_aws_session_with_accesskey()
            
            iam_client = iam_session.client('iam')
            login_profile = iam_client.get_login_profile(UserName=user_name)
            return login_profile, None
        except iam_client.exceptions.NoSuchEntityException:
            # https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetLoginProfile.html#API_GetLoginProfile_Errors
		    # Ignore NoSuchEntity exception
            return None, None
        except botocore.exceptions.ClientError as error:
            return None, {'error': error.response['Error']['Message']}

    # https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVpcs.html
    def describe_vpcs(self):
        try:
            vpcs_df = pd.DataFrame()
            errors_list = []

            for region in self.region:
                session, error = self.create_aws_session(region)
                if error:
                    errors_list.append({'Region': region, 'Error': error})
                    continue

                ec2_client = session.client('ec2')
                paginator = ec2_client.get_paginator('describe_vpcs')

                try:
                    for page in paginator.paginate():
                        vpcs = page.get('Vpcs', [])
                        if len(vpcs) != 0:
                            vpcs_flat = pd.json_normalize(
                                vpcs)
                            vpcs_df = pd.concat(
                                [vpcs_df, pd.DataFrame(vpcs_flat)], ignore_index=True)
                except botocore.exceptions.ClientError as error:
                    error_msg = error.response['Error']['Message']
                    errors_list.append({'Region': region, 'Error': error_msg})
                    continue
                except Exception as error:
                    errors_list.append({'Region': region, 'Error': f"{error}"})
                    continue

            if not vpcs_df.empty:
                vpcs_df.columns = pd.Series(
                    vpcs_df.columns).apply(self.clean_column_names)

            return vpcs_df, errors_list

        except Exception as error:
            return None, [{'Error': f"{error}"}]

    # https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeFlowLogs.html
    def describe_flow_logs(self):
        try:
            flow_logs_df = pd.DataFrame()
            errors_list = []

            for region in self.region:
                session, error = self.create_aws_session(region)
                if error:
                    errors_list.append({'Region': region, 'Error': error})
                    continue

                ec2_client = session.client('ec2')
                paginator = ec2_client.get_paginator('describe_flow_logs')

                try:
                    for page in paginator.paginate():
                        flow_logs = page.get('FlowLogs', [])
                        if len(flow_logs) != 0:
                            flow_logs_flat = pd.json_normalize(
                                flow_logs)
                            flow_logs_df = pd.concat(
                                [flow_logs_df, pd.DataFrame(flow_logs_flat)], ignore_index=True)
                except botocore.exceptions.ClientError as error:
                    error_msg = error.response['Error']['Message']
                    errors_list.append({'Region': region, 'Error': error_msg})
                    continue
                except Exception as error:
                    errors_list.append({'Region': region, 'Error': f"{error}"})
                    continue

            if not flow_logs_df.empty and 'CreationTime' in flow_logs_df.columns:
                flow_logs_df['CreationTime'] = flow_logs_df['CreationTime'].apply(
                    self.convert_timestamp)
                flow_logs_df.columns = pd.Series(
                    flow_logs_df.columns).apply(self.clean_column_names)

            return flow_logs_df, errors_list

        except Exception as error:
            return None, [{'Error': f"{error}"}]

    # https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html
    def describe_security_groups(self):
        try:
            security_groups_df = pd.DataFrame()
            errors_list = []

            for region in self.region:
                session, error = self.create_aws_session(region)
                if error:
                    errors_list.append({'Region': region, 'Error': error})
                    continue

                ec2_client = session.client('ec2')
                paginator = ec2_client.get_paginator(
                    'describe_security_groups')

                try:
                    for page in paginator.paginate():
                        security_groups = page.get('SecurityGroups', [])
                        if len(security_groups) != 0:
                            security_groups_flat = pd.json_normalize(
                                security_groups)
                            security_groups_df = pd.concat(
                                [security_groups_df, pd.DataFrame(security_groups_flat)], ignore_index=True)
                except botocore.exceptions.ClientError as error:
                    error_msg = error.response['Error']['Message']
                    errors_list.append({'Region': region, 'Error': error_msg})
                    continue
                except Exception as error:
                    errors_list.append({'Region': region, 'Error': f"{error}"})
                    continue

            if not security_groups_df.empty:
                security_groups_df.columns = pd.Series(
                    security_groups_df.columns).apply(self.clean_column_names)

            return security_groups_df, errors_list

        except Exception as error:
            return None, [{'Error': f"{error}"}]

    # https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_DescribeTrails.html
    def describe_cloud_trails(self):
        cloud_trails_df = pd.DataFrame()
        errors_list = []

        for region in self.region:
            session, error = self.create_aws_session(region)
            if error:
                errors_list.append({'Region': region, 'Error': error})
                continue

            try:
                cloud_trail_client = session.client('cloudtrail')
                response = cloud_trail_client.describe_trails()
                if not cowdictutils.is_valid_array(response, 'trailList'):
                    errors_list.append({'Region': region, 'Error': 'Could not get trail list from response'})
                    continue
                trail_list = response['trailList']
                trail_list_flat = pd.json_normalize(
                    trail_list)
                cloud_trails_df = pd.concat(
                    [cloud_trails_df, pd.DataFrame(trail_list_flat)], ignore_index=True)
            except botocore.exceptions.ClientError as error:
                error_message = 'An error occurred while trying to fetch the response for the describe_cloud_trails operation.'
                if hasattr(error,'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                    error_message = error.response['Error']['Message']
                errors_list.append({'Region': region, 'Error': error_message})
                continue
            except botocore.exceptions.EndpointConnectionError as error:
                error_message = 'Could not connect to the CloudTrail endpoint URL'
                if hasattr(error,'kwargs') and isinstance(error.kwargs, dict) and cowdictutils.is_valid_key(error.kwargs, 'endpoint_url'):
                    endpoint_url = error.kwargs['endpoint_url']
                    error_message = f'Could not connect to the endpoint URL: "{endpoint_url}" in region "{region}" while attempting to access the CloudTrail service.'
                errors_list.append({'Region': region, 'Error': error_message})
                continue

        if not cloud_trails_df.empty and 'TrailARN' in cloud_trails_df.columns:
            cloud_trails_df.drop_duplicates('TrailARN', inplace=True)
            cloud_trails_df = self.standardize_column_names(cloud_trails_df)

        return cloud_trails_df, errors_list
        
    def get_event_selectors(self, trail_name, region):
        errors_list = []
        session, error = self.create_aws_session(region)
        if error:
            errors_list.append({'Region': region, 'Error': error})
            return None, errors_list    
        try:
            cloud_trail_client = session.client('cloudtrail')
            response = cloud_trail_client.get_event_selectors(TrailName=trail_name)
            return response, None
        except botocore.exceptions.ClientError as error:
            error_message = 'An error occurred while trying to fetch the response for the get_event_selectors operation.'
            if hasattr(error,'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                error_message = error.response['Error']['Message']
            errors_list.append({'Region': region, 'Error': error_message})
            return None, errors_list    
    
        
    def get_caller_identity(self):
        identity_details_df = pd.DataFrame()
        errors_list = []
        session, error = self.create_aws_session(region=None)
        if error:
            errors_list.append({'Error': error})
            return None, errors_list     
        try:
            client = session.client('sts')
            identity_details = client.get_caller_identity()
            identity_details_flat = pd.json_normalize(
                            identity_details)
            identity_details_df = pd.concat(
                            [identity_details_df, pd.DataFrame(identity_details_flat)], ignore_index=True)
            return identity_details_df, None
        except botocore.exceptions.ClientError as error:
            error_message = 'An error occurred while trying to fetch the response for the get_caller_identity operation.'
            if hasattr(error,'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                error_message = error.response['Error']['Message']
            errors_list.append({'Error': error_message})
            return None, errors_list



    # https://docs.aws.amazon.com/kms/latest/APIReference/API_ListKeys.html
    # https://docs.aws.amazon.com/kms/latest/APIReference/API_DescribeKey.html
    def describe_kms_key(self):
        kms_keys_df = pd.DataFrame()
        errors_list = []
        for region in self.region:
            session, error = self.create_aws_session(region)
            if error:
                errors_list.append({'Region': region, 'Error': error})
                continue
            kms_client = session.client('kms')
            marker = None
            try:
                while True:
                    if marker:
                        response = kms_client.list_keys(Marker=marker)
                    else:
                        response = kms_client.list_keys()
                    
                    if cowdictutils.is_valid_array(response, 'Keys'):
                        for key in response['Keys']:
                            if cowdictutils.is_valid_key(key, 'KeyId'):
                                key_id = key['KeyId']
                                key_details = kms_client.describe_key(KeyId = key_id)
                                if cowdictutils.is_valid_key(key_details, 'KeyMetadata'):
                                    key_rotation_details, err = self.get_key_rotation_status(
                                    key_id, kms_client)
                                    if err:
                                        errors_list.append(
                                            {'Region': region, 'Error': err})
                                        continue
                                    key_details_flat = pd.json_normalize(
                                        key_details['KeyMetadata'])
                                    
                                    # key_rotation_details - fields
                                    key_rotation_enabled = key_rotation_details['KeyRotationEnabled']
                                    rotation_period_in_days = key_rotation_details['RotationPeriodInDays']
                                    next_rotation_date = key_rotation_details['NextRotationDate']
                                    # Calculate LastRotationDate obj
                                    last_rotation_obj = next_rotation_date - timedelta(days=rotation_period_in_days)
            
                                    key_details_flat['KeyRotationEnabled'] = key_rotation_enabled
                                    key_details_flat['KeyLastRotatedDate'] = self.get_time_stamp(last_rotation_obj)
                                    key_details_flat['KeyNextRotatedDate'] = self.get_time_stamp(next_rotation_date)
                                    kms_keys_df = pd.concat(
                                        [kms_keys_df, pd.DataFrame(key_details_flat)], ignore_index=True)
                                else:
                                    errors_list.append({'Region': region, 'Error': 'Missing field: KeyMetaData'})
                                    continue
                            else:
                                errors_list.append({'Region': region, 'Error': 'Missing field: KeyId'})
                                continue
                    else:
                        errors_list.append({'Region': region, 'Error': 'Missing field: Keys'})
                        continue
                    if response.get('Truncated', False):
                        marker = response['Marker']
                    else:
                        break
            except botocore.exceptions.ClientError as error:
                error_message = 'An error occurred while trying to fetch the response for the describe_kms_key operation.'
                if hasattr(error,'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                    error_message = error.response['Error']['Message']
                errors_list.append({'Region': region, 'Error': error_message})
                continue
            except botocore.exceptions.EndpointConnectionError as error:
                error_message = 'Could not connect to the kms endpoint URL'
                if hasattr(error,'kwargs') and isinstance(error.kwargs, dict) and cowdictutils.is_valid_key(error.kwargs, 'endpoint_url'):
                    endpoint_url = error.kwargs['endpoint_url']
                    error_message = f'Could not connect to the endpoint URL: "{endpoint_url}" in region "{region}" while attempting to access the KMS service.'
                errors_list.append({'Region': region, 'Error': error_message})
                continue 
        if not kms_keys_df.empty and 'CreationDate' in kms_keys_df.columns:
                kms_keys_df['CreationDate'] = kms_keys_df['CreationDate'].apply(
                    self.convert_timestamp)
                kms_keys_df = self.standardize_column_names(kms_keys_df)
        return kms_keys_df, errors_list

    # https://docs.aws.amazon.com/kms/latest/APIReference/API_GetKeyRotationStatus.html
    def get_key_rotation_status(self, key_id, kms_client):
        try:
            response = kms_client.get_key_rotation_status(KeyId=key_id)
            if cowdictutils.is_valid_key(response, 'KeyRotationEnabled') and cowdictutils.is_valid_key(response, 'RotationPeriodInDays') and cowdictutils.is_valid_key(response, 'NextRotationDate'):
                return response, None
            else:
                return  None , f'KeyRotationEnabled is not enabled for key - {key_id}'
        except botocore.exceptions.ClientError as error:
            error_message = 'An error occurred while trying to fetch the response for the get_key_rotation_status operation.'
            if hasattr(error,'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                error_message = error.response['Error']['Message']
            return None, error_message
        except botocore.exceptions.EndpointConnectionError as error:
            error_message = 'Could not connect to the kms endpoint URL'
            if hasattr(error,'kwargs') and isinstance(error.kwargs, dict) and cowdictutils.is_valid_key(error.kwargs, 'endpoint_url'):
                endpoint_url = error.kwargs['endpoint_url']
                error_message = f'Could not connect to the endpoint URL: "{endpoint_url}" while attempting to access the KMS service.'
            return None, error_message

    # https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_DescribeMetricFilters.html
    def describe_metric_filters(self):
            metric_filters_df = pd.DataFrame()
            errors_list = []

            for region in self.region:
                session, error = self.create_aws_session(region)
                if error:
                    errors_list.append({'Region': region, 'Error': error})
                    continue

                logs_client = session.client('logs')
                paginator = logs_client.get_paginator(
                    'describe_metric_filters')
                
                try:
                    for page in paginator.paginate():
                        if cowdictutils.is_valid_array(page,'metricFilters') :
                            metric_filters = page["metricFilters"]
                            metric_filters_flat = pd.json_normalize(
                                metric_filters)
                            metric_filters_df = pd.concat(
                                [metric_filters_df, pd.DataFrame(metric_filters_flat)], ignore_index=True)
                except botocore.exceptions.ClientError as error:
                    error_message = 'An error occurred while trying to fetch the response for the describe_metric_filters operation.'
                    if hasattr(error,'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                        error_message = error.response['Error']['Message']
                    errors_list.append({'Region': region, 'Error': error_message})
                    continue
                except botocore.exceptions.EndpointConnectionError as error:
                    error_message = 'Could not connect to the CloudWatch endpoint URL'
                    if hasattr(error,'kwargs') and isinstance(error.kwargs, dict) and cowdictutils.is_valid_key(error.kwargs, 'endpoint_url'):
                        endpoint_url = error.kwargs['endpoint_url']
                        error_message = f'cCould not connect to the endpoint URL: "{endpoint_url}" in region "{region}" while attempting to access the CloudWatch service.'
                    errors_list.append({'Region': region, 'Error': error_message})
                    continue     
            if not metric_filters_df.empty and 'creationTime' in metric_filters_df.columns:
                
                metric_filters_df['creationTime'] = self.convert_timestamp(metric_filters_df['creationTime'], unit='ms')

                if 'metricTransformations' in metric_filters_df.columns:
                    # metricTransformations: fixed number of 1 item
                    try:
                        metric_transformations =  pd.DataFrame(metric_filters_df['metricTransformations'].tolist()[0])
                        metric_filters_df = pd.concat([metric_filters_df,  
                                metric_transformations],
                                axis=1)
                        metric_filters_df.drop(columns='metricTransformations', inplace=True)
                    except (IndexError, ValueError, TypeError) as error:
                        errors_list.append({'Error': f"{error}"})
                        return None, errors_list

                metric_filters_df.rename(columns={'creationTime': 'CreationTime',
                                                'filterName': 'FilterName',
                                                'filterPattern': 'FilterPattern',
                                                'logGroupName': 'LogGroupName',
                                                'metricName': 'MetricName',
                                                'metricNamespace': 'MetricNamespace',
                                                'metricValue': 'MetricValue',
                                                'defaultValue': 'DefaultValue',
                                                'dimensions': 'Dimensions',
                                                'unit': 'Unit'}, inplace=True)

            return metric_filters_df, errors_list

    # https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html
    def describe_db_instances(self):
        db_instances_df = pd.DataFrame()
        errors_list = []

        for region in self.region:
            session, error = self.create_aws_session(region)
            if error:
                errors_list.append({'Region': region, 'Error': error})
                continue

            rds_client = session.client('rds')
            paginator = rds_client.get_paginator(
                'describe_db_instances')

            try:
                for page in paginator.paginate():
                    if cowdictutils.is_valid_array(page, 'DBInstances'):
                        db_instances = page['DBInstances']
                        db_instances_flat = pd.json_normalize(
                            db_instances)
                        # 'Region' added because the DescribeDBInstances API lists only 'AvailabilityZone'
                        db_instances_flat['Region'] = region
                        db_instances_df = pd.concat(
                            [db_instances_df, db_instances_flat], ignore_index=True)
            except botocore.exceptions.ClientError as error:
                error_message = 'An error occurred while trying to fetch the response for the describe_db_instances operation.'
                if hasattr(error,'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                    error_message = error.response['Error']['Message']
                errors_list.append({'Region': region, 'Error': error_message})
                continue
            except botocore.exceptions.EndpointConnectionError as error:
                error_message = 'Could not connect to the RDS endpoint URL'
                if hasattr(error,'kwargs') and isinstance(error.kwargs, dict) and cowdictutils.is_valid_key(error.kwargs, 'endpoint_url'):
                    endpoint_url = error.kwargs['endpoint_url']
                    error_message = f'Could not connect to the endpoint URL: "{endpoint_url}" in region "{region}" while attempting to access the RDS service.'
                errors_list.append({'Region': region, 'Error': error_message})
                continue

        return db_instances_df, errors_list

    # https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_DescribeAlarms.html
    def describe_metric_alarms(self):
        metric_alarms_df = pd.DataFrame()
        errors_list = []

        for region in self.region:
            session, error = self.create_aws_session(region)
            if error:
                errors_list.append({'Region': region, 'Error': error})
                continue

            cloud_watch_client = session.client('cloudwatch')
            paginator = cloud_watch_client.get_paginator('describe_alarms')

            try:
                for page in paginator.paginate(AlarmTypes=['MetricAlarm']):
                    if cowdictutils.is_valid_array(page,'MetricAlarms') :
                        metric_alarms = page["MetricAlarms"]
                        metric_alarms_flat = pd.json_normalize(
                            metric_alarms)
                        metric_alarms_df = pd.concat(
                            [metric_alarms_df, pd.DataFrame(metric_alarms_flat)], ignore_index=True)
            except botocore.exceptions.ClientError as error:
                error_message = 'An error occurred while trying to fetch the response for the describe_alarms operation.'
                if hasattr(error,'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                    error_message = error.response['Error']['Message']
                errors_list.append({'Region': region, 'Error': error_message})
                continue
            except botocore.exceptions.EndpointConnectionError as error:
                error_message = 'Could not connect to the CloudWatch endpoint URL'
                if hasattr(error,'kwargs') and isinstance(error.kwargs, dict) and cowdictutils.is_valid_key(error.kwargs, 'endpoint_url'):
                    endpoint_url = error.kwargs['endpoint_url']
                    error_message = f'Could not connect to the endpoint URL: "{endpoint_url}" in region "{region}" while attempting to access the CloudWatch service.'
                errors_list.append({'Region': region, 'Error': error_message})
                continue    

        if not metric_alarms_df.empty:
            if 'AlarmConfigurationUpdatedTimestamp' in metric_alarms_df.columns:
                metric_alarms_df['AlarmConfigurationUpdatedTimestamp'] = self.convert_timestamp(metric_alarms_df['AlarmConfigurationUpdatedTimestamp'])
            if 'StateTransitionedTimestamp' in metric_alarms_df.columns:
                metric_alarms_df['StateTransitionedTimestamp'] = self.convert_timestamp(metric_alarms_df['StateTransitionedTimestamp'])
            if 'StateUpdatedTimestamp' in metric_alarms_df.columns:
                metric_alarms_df['StateUpdatedTimestamp'] = self.convert_timestamp(metric_alarms_df['StateUpdatedTimestamp'])
                
            metric_alarms_df = self.standardize_column_names(metric_alarms_df)

        return metric_alarms_df, errors_list
        
    def upload_file_to_s3(self,  file_content, file_name, bucket_name):
        try:
            session= self.create_aws_session_with_accesskey()
            if session:
                s3_client = session.client('s3')
                s3_client.head_bucket(Bucket=bucket_name)
                response = s3_client.put_object(
                    Bucket=bucket_name,
                    Key=file_name,
                    Body=file_content
                )
                if response['ResponseMetadata']['HTTPStatusCode'] != 200:
                    return None, f"Failed to upload file to S3. Status code: {response['ResponseMetadata']['HTTPStatusCode']}"
                return json.dumps(response), None
        except botocore.exceptions.ClientError as error:
            error_message = 'An error occurred while trying to upload file to S3'
            if hasattr(error, 'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message') and cowdictutils.is_valid_key(error.response['Error'], 'Code'):
                if error.response['Error']['Code'] == '403':
                    return None, f"User doesn't have write access for the given bucket {bucket_name}. Please check permissions."
                else:
                    error_message = error.response['Error']['Message']
            return None, error_message
        except botocore.exceptions.EndpointConnectionError as error:
            error_message = 'Could not connect to the S3 endpoint URL'
            if hasattr(error, 'kwargs') and isinstance(error.kwargs, dict) and cowdictutils.is_valid_key(error.kwargs, 'endpoint_url'):
                endpoint_url = error.kwargs['endpoint_url']
                error_message = f'Could not connect to the endpoint URL: "{endpoint_url}" while attempting to access the S3 service.'
            return None, error_message
        except Exception as e:
            return None, f"Exception while uploading file to S3: {e}"
        
    def get_bucket_region(self, bucket_name):
        try:
            session= self.create_aws_session_with_accesskey()
            if session:
                s3_client = session.client('s3')
                response = s3_client.get_bucket_location(Bucket=bucket_name)
                region = response['LocationConstraint']
                return region, None
        except botocore.exceptions.ClientError as error:
            if hasattr(error, 'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message') and cowdictutils.is_valid_key(error.response['Error'], 'Code'):
                if error.response['Error']['Code'] == 'NoSuchBucket':
                    return None, f"Bucket name: {bucket_name} is not found. Please provide a valid bucketname."
            return None, f"Error fetching bucket location: {error}"
        
    def clean_column_names(self, column):
        parts = column.split('.')
        cleaned_parts = [part[0].upper() + part[1:] for part in parts]
        return ''.join(cleaned_parts)

    def convert_timestamp(self, data, unit=None):
        # Check if data is a string or a Timestamp
        if isinstance(data, str):
            # If data is a string and unit is provided, convert using the specified unit
            if unit:
                return pd.to_datetime(data, unit=unit).dt.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            else:
                return pd.to_datetime(data).dt.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        elif isinstance(data, pd.Timestamp):
            # If data is a Timestamp, just format it directly
            return data.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    
    def get_time_stamp(self, data):
        data_utc = data.astimezone(pytz.utc)
        data_dt = data_utc.astimezone(tz.tzlocal())
        data_time_stamp = pd.Timestamp(data_dt)
        return self.convert_timestamp(data_time_stamp)

    def create_field_meta_data(self, data_df):
        if not data_df.empty:
            field_meta_data = {
                'srcConfig': []
            }
            src_config_list = []
            for index, (column_name, column_data) in enumerate(data_df.items()):
                if pd.api.types.is_string_dtype(column_data):
                    column_type = 'STRING'
                elif pd.api.types.is_bool_dtype(column_data):
                    column_type = 'BOOLEAN'
                elif pd.api.types.is_numeric_dtype(column_data):
                    if pd.api.types.is_integer_dtype(column_data):
                        column_type = 'INTEGER'
                    elif pd.api.types.is_float_dtype(column_data):
                        column_type = 'FLOAT'
                elif pd.api.types.is_datetime64_any_dtype(column_data):
                    column_type = 'TIMESTAMP'
                else:
                    column_type = 'RECORD'

                src_config_entry = {
                    'mode': 'NULLABLE',
                    'name': column_name,
                    'type': column_type,
                    'fieldName': column_name,
                    'fieldDisplayName': column_name,
                    'isFieldIndexed': True,
                    'isFieldVisible': True,
                    'isFieldVisibleForClient': True,
                    'canUpdate': False,
                    'isRequired': True,
                    'isRepeated': False,
                    'htmlElementType': column_type,
                    'fieldDataType': column_type,
                    'fieldOrder': index
                }
                src_config_list.append(src_config_entry)

            field_meta_data['srcConfig'] = src_config_list
            return field_meta_data
        return {}

    def calculate_compliance_score(self, total_record, failed_record):
        compliance_pct, compliance_status = 100, "COMPLIANT"
        if failed_record > 0:
            compliance_pct = int(100 - (failed_record * 100) / total_record)
            compliance_status = "NON_COMPLIANT"
        if total_record == 0:
            compliance_pct = 0
            compliance_status="NOT_DETERMINED"
        return compliance_pct, compliance_status
    
    '''
       resource_info = {
         'resource_type'  : 'AwsIamUser',
         'Resource'       : 'user_name',
         'Region'         : 'user_region',
         'ResourceParent' : 'main resource under which this sub-resource is found.
         }

        other than "resource_type," all other fields are optional unless the specific URL requires these fields.
    '''
    def get_resource_url(self, resource_info: dict):

       # Mapping of resource types to their respective URL templates
        resource_url_dict = {
            CLOUDTRAIL: CLOUDTRAIL_URL,
            CLOUDTRAIL_LIST: CLOUDTRAIL_LIST_URL,
            KMS: KMS_URL,
            CLOUD_WATCH_METRIC_ALARM: CLOUD_WATCH_METRIC_ALARM_URL,
            CLOUD_WATCH_METRIC_FILTER: CLOUD_WATCH_METRIC_FILER_URL,
            IAM_USER: IAM_USER_URL,
            IAM_USER_LIST: IAM_USER_LIST_URL,
            IAM_ROLE: IAM_ROLE_URL,
            IAM_GROUP: IAM_GROUP_URL,
            IAM_POLICY: IAM_POLICY_URL,
            CLOUD_WATCH_LOG_GRP: CLOUD_WATCH_LOG_GRP_URL,
            S3_BUCKET: S3_BUCKET_URL,
            BACKUP_VAULT: BACKUP_VAULT_URL,
            BACKUP_RECOVERY_PT: BACKUP_RECOVERY_PT_URL,
            CLOUD_WATCH_METRICS_LIST: CLOUD_WATCH_METRICS_LIST_URL,
            CLOUD_WATCH_ALARM_LIST: CLOUD_WATCH_ALARM_LIST_URL,
            EC2_SECURITY_GROUP: EC2_SECURITY_GROUP_URL,
            RDS_DB_INSTANCE:RDS_DB_INSTANCE_URL,
            VPC:VPC_URL, 
            EC2_INSTANCE:EC2_INSTANCE_URL,
            ELASTIC_FILE_SYSTEM:ELASTIC_FILE_SYSTEM_URL,
            CLOUD_TRAIL_EVENT:CLOUD_TRAIL_EVENT_URL,
            EC2_SUBNET:EC2_SUBNET_URL,
            CLOUD_FORMATION_STACK:CLOUD_FORMATION_STACK_URL,
        }

        if cowdictutils.is_valid_key(resource_info, RESOURCE_TYPE) :
            resource_type = resource_info[RESOURCE_TYPE]
            if cowdictutils.is_valid_key(resource_url_dict, resource_type) :
                url, error = self.modify_url(resource_url_dict[resource_type], resource_info)
                if error:
                    return None, error
                return url, None
            else:
                return None, f'Invalid resource type :: {resource_type}'
        else:
            return None, "Errror while fetching resource url - resource type is missing"
        
    
    def modify_url(self, url, resource_info):
        # sample urls have placeholders with special characters - "<< >>"
        placeholder_pattern = r'<<([^>]*)>>'
        matches = self.extract_placeholders(url, placeholder_pattern)

        placeholders = [f'<<{match}>>' for match in matches]
 
        # Mapping placeholders to the corresponding field in resource_info
        placeholder_map = {
            REGION_PLACEHOLDER: REGION_FIELD,
            RESOURCE_PLACEHOLDER: RESOURCE_FIELD,
            RESOURCE_PARENT_PLACEHOLDER: RESOURCE_PARENT_FIELD
        }

        # Replace each placeholder with the actual value from resource_inf
        for placeholder in placeholders:
            if cowdictutils.is_valid_key(placeholder_map, placeholder):
                field = placeholder_map.get(placeholder)    
                if field:
                    if cowdictutils.is_valid_key(resource_info, field) and resource_info[field] != '':
                        url = url.replace(placeholder, resource_info[field])
                    else:
                        return None, f'Required field {field} not found or empty in input dict'           
        return url, None

    def extract_placeholders(self, input_str, pattern):
        matches = re.findall(pattern, input_str)
        return matches

    def get_current_datetime(self):       
        current_time = datetime.now(timezone.utc)
        formatted_time = current_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        return formatted_time

    def replace_empty_dicts_with_none(self, json_obj):
        if isinstance(json_obj, dict):
            for key, value in json_obj.items():
                if isinstance(value, dict):
                    if not value:
                        json_obj[key] = None
                    else:
                        self.replace_empty_dicts_with_none(value)
                elif isinstance(value, list):
                    if not value:
                        json_obj[key] = None
                    for item in value:
                        self.replace_empty_dicts_with_none(item)
        elif isinstance(json_obj, list):
            if not value:
                json_obj[key] = None
            for item in json_obj:
                self.replace_empty_dicts_with_none(item)
        return json_obj
    
    def flatten_json(self, json_obj, parent_key='', level=0):
        flattened_dict = {}
        for key, value in json_obj.items():
            key = key[0].upper() + key[1:]
            if key == "Id":
                key = "ResourceID"
            parent_key = parent_key.capitalize()
            new_key = f"{parent_key}{key}" if parent_key else key
            if isinstance(value, dict) and level != 1:
                flattened_dict.update(self.flatten_json(
                    value, new_key, level=level+1))
            else:
                flattened_dict[new_key] = value
        return flattened_dict
    
    def audit_manager_get_evidence_folder(self,param):
            
        errors_list = []
        evidence = []
        input_region = []

        if isinstance(self.region , str) :
            input_region = self.region.split()
        else:
            input_region = self.region

        for region in input_region :
            session, error = self.create_aws_session(region)
            if error:
                errors_list.append({'Region': region, 'Error': error})
                continue
            
            resp = None
            try:
                auditmanager_client = session.client('auditmanager')
                resp = auditmanager_client.get_evidence_by_evidence_folder(
                        assessmentId= str(param["AssessmentId"]),
                        controlSetId= str(param["ControlSetId"]),
                        evidenceFolderId= str(param["Id"])
                    )
            except botocore.exceptions.ClientError as error:
                errors_list.append(error.response['Error']['Message'])
                return None, errors_list
            except botocore.exceptions.EndpointConnectionError as error :
                errors_list.append(error)
                return None, errors_list
            
            if cowdictutils.is_valid_key(resp ,"evidence") :
                evidence.append(resp["evidence"])

        evidence_array = np.array(evidence)
        flat_arr = evidence_array.flatten()

        return flat_arr.tolist() , errors_list
    
# Standardizes the column names of the DataFrame by capitalizing the first letter of each word and removing spaces.
    def standardize_column_names(self, df):
        df.columns = df.columns.map(lambda x: ''.join([w[0].upper(
        ) + w[1:] if len(w) >= 1 else w.upper() for w in x.split('.')])).str.replace(' ', '')
        return df    
    

    def get_file_uris_from_s3_objects(self, objects, bucket_name):
        if not objects:
            return None, "Object info is empty."
        if not bucket_name:
            return None, "'Bucket Name' is empty."
        try:
            s3_file_uris = []
            for object in objects:
                if 'Key' in object and "." in object['Key']:
                   s3_file_uri = f"s3://{bucket_name}/{object['Key']}"
                   s3_file_uris.append(s3_file_uri)
            if not s3_file_uris:
                return None, "Failed to generate s3 uri(s) for provided object(s)"
            return s3_file_uris, None
        except Exception as e:
            return None, f"Exception occured while generating s3 uri(s) for provided object(s). {str(e)}"
        

    def get_all_file_content_from_s3_bucket(self, bucket_name, folder_path=None):
        if not bucket_name:
            return None, "'Bucket Name' is empty."
        try:
            session, error = self.create_aws_session(region=None)
            if error:
                return None, error
            s3_client = session.client('s3')
            response = s3_client.list_objects_v2(
                Bucket=bucket_name,
                Prefix=folder_path,
            )
            if 'Contents' in response:
               if len(response['Contents']) == 0:
                   return None, f"No file content found in bucket {bucket_name}"
               objects = response['Contents']
               if folder_path == '' or folder_path is None:
                   req_objects = []
                   for object in objects:
                       # Filtering file contents alone
                       if 'Key' in object and '/' not in object['Key']:
                           req_objects.append(object)
                   return req_objects, None
               return objects, None
            return None, f"Failed to fetch file content from AWS bucket {bucket_name}. Please contact support and review logs for further details."
        except botocore.exceptions.ClientError as error:
            error_message = f'ClientError occurred while trying to fetch file content from the AWS bucket {bucket_name}. '
            if hasattr(error,'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                msg = error.response["Error"]["Message"]
                error_message += f'{msg}.'
                logging.exception(f"ClientError exception occurred: {error_message}")    
            else:
                logging.exception(f"ClientError exception occurred: {error}")    
            return None, error_message
        except botocore.exceptions.EndpointConnectionError as error:
            error_message = f'EndpointConnectionError occurred while trying to fetch file content from the AWS bucket {bucket_name}. '
            if hasattr(error,'kwargs') and isinstance(error.kwargs, dict) and cowdictutils.is_valid_key(error.kwargs, 'endpoint_url'):
                endpoint_url = error.kwargs['endpoint_url']
                error_message += f'Could not connect to the endpoint URL: "{endpoint_url}". Failed to fetch file content from aws.'
                logging.exception(error_message)
            else:
                logging.exception(f"EndpointConnectionError exception occurred: {error}")   
            return None, error_message
        except Exception as e:
            return None, f"Exception occured while trying to fetch file content from AWS bucket {bucket_name}. {str(e)}"
        
    
    def download_file_from_s3(self, s3_file_uri):
        if not s3_file_uri:
            return None, "'s3_file_uri' is empty. Please try with valid 's3_file_uri'"
        parsed_uri = urlparse(s3_file_uri)
        if not parsed_uri.scheme == 's3' or not parsed_uri.netloc:
            return None, "Invalid 's3_file_uri'. Please try with valid 's3_file_uri'"
        bucket_name = parsed_uri.netloc
        file_name = parsed_uri.path.lstrip('/')
        err_msg = "Failed to download file from AWS. Please contact support and review logs for further details."
        try:
            session, error = self.create_aws_session(region=None)
            if error:
                return None, error
            s3_client = session.client('s3')
            response = s3_client.get_object(
                Bucket=bucket_name,
                Key=file_name
            )
            if "Body" in response:
                file_content = response["Body"].read()
                return file_content, None
            logging.info(f"AWS download response info: {str(response)}")    
            return None, err_msg
        except botocore.exceptions.ClientError as error:
            error_message = f'ClientError occurred while trying to download files from the AWS bucket - {s3_file_uri}. FileName - {file_name}'
            if hasattr(error,'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                msg = error.response["Error"]["Message"]
                error_message = f'{msg}. BucketName: {bucket_name}. FileName: {file_name}'
                logging.exception(f"ClientError exception occurred: {error_message}")    
            else:
                logging.exception(f"ClientError exception occurred: {error}")    
            return None, error_message
        except botocore.exceptions.EndpointConnectionError as error:
            error_message = f'EndpointConnectionError occurred while trying to download files from the AWS bucket - {s3_file_uri}. FileName - {file_name}'
            if hasattr(error,'kwargs') and isinstance(error.kwargs, dict) and cowdictutils.is_valid_key(error.kwargs, 'endpoint_url'):
                endpoint_url = error.kwargs['endpoint_url']
                error_message = f'Could not connect to the endpoint URL: "{endpoint_url}". Failed to download file from aws. BucketName: {bucket_name}. FileName: {file_name}'
                logging.exception(error_message)
            else:
                logging.exception(f"EndpointConnectionError exception occurred: {error}")   
            return None, error_message
        
        
        
    #https://docs.aws.amazon.com/efs/latest/ug/API_DescribeFileSystems.html
    def list_efs_file_systems(self):
        
        efs_list = []
        errors_list = []

        for region in self.region:
            try:
                session, error = self.create_aws_session(region)
                if error:
                    errors_list.append(f'Error while creating session in {region}. {error}')
                    continue

                efs_client = session.client('efs')
                response = efs_client.describe_file_systems()
                if 'FileSystems' in response:
                    for file_system in response['FileSystems']:
                        file_system['Region'] = region
                        efs_list.append(file_system)
                else:
                    errors_list.append(f'Failed to fetch EFS list in {region}. Please contact support for further details')

            except botocore.exceptions.ClientError as error:
                error_message = f'An error occurred while trying to fetch the response EFS list in {region}'
                if hasattr(error,'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                    exp_message = error.response['Error']['Message']
                    error_message = f'{error_message}. {exp_message}'
                errors_list.append(error_message)
                continue
            except botocore.exceptions.EndpointConnectionError as error:
                error_message = f'Could not connect to the EFS endpoint URL in {region}'
                if hasattr(error,'kwargs') and isinstance(error.kwargs, dict) and cowdictutils.is_valid_key(error.kwargs, 'endpoint_url'):
                    endpoint_url = error.kwargs['endpoint_url']
                    error_message = f'Could not connect to the endpoint URL: "{endpoint_url}" in region "{region}" while attempting to fetch EFS list'
                errors_list.append(error_message)
                continue

        return efs_list, errors_list
    
    # https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html
    def look_up_events(self, from_date, to_date, look_up_attributes=None):
        events = [] 
        errors_list = []

        for region in self.region:
            try:
                session, error = self.create_aws_session(region)
                if error:
                    errors_list.append(f'Error while creating session in {region}. {error}')
                    continue
                client = session.client('cloudtrail')
                paginator = client.get_paginator("lookup_events")
                for page in paginator.paginate(LookupAttributes=look_up_attributes, StartTime=from_date, EndTime=to_date):
                    if 'Events' in page:
                       self.add_field_in_list(page['Events'], 'Region', region)
                       events.extend(page['Events'])
            except botocore.exceptions.ClientError as error:
                error_message = self._get_client_error_message(error, region)
                errors_list.append(error_message)
                continue
            except botocore.exceptions.EndpointConnectionError as error:
                error_message = self._get_endpoint_error_message(error, region)
                errors_list.append(error_message)
                continue

        return events, errors_list
    
    # generic method to get client error msg
    def _get_client_error_message(self, error, region):
        error_message = f'Client error occurred. Region: "{region}"'
        try:
            exp_message = error.response['Error']['Message']
            return f'{error_message}. {exp_message}'
        except (AttributeError, KeyError):
            return error_message

    # generic method to get endpoint error msg
    def _get_endpoint_error_message(self, error, region):
        if hasattr(error, 'kwargs') and isinstance(error.kwargs, dict) and 'endpoint_url' in error.kwargs:
            endpoint_url = error.kwargs['endpoint_url']
            return f'Could not connect to the endpoint URL: "{endpoint_url}" in region "{region}".'
        return f'Endpoint connection error occured. Region: "{region}"'
    
    # generic method to add field in list
    def add_field_in_list(self, data_list, field_name, field_value):
        if isinstance(data_list, list) and data_list:
            for data in data_list:
                data[field_name] = field_value
        return data_list

    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam/client/list_users.html#
    def list_users(self):

        session, error = self.create_aws_session()
        if error:
            return [], [{"Error": f"Error while creating a session to fetch AWS user list. {str(error)}"}]
        try:
            iam_client = session.client('iam')
            paginator = iam_client.get_paginator('list_users')
            user_list = []
            for page in paginator.paginate():
                users = page.get('Users', [])
                if users:
                    user_list.extend(users)
            if not user_list:
                return user_list, [{"Error": "Failed to fetch user(s) for the provided AWS credentials."}]
            return user_list, []
        except iam_client.exceptions.ServiceFailureException as error:
            # https://botocore.amazonaws.com/v1/documentation/api/latest/reference/services/iam/client/exceptions/ServiceFailureException.htmlHandle ServiceFailureException
            error_message = 'ServiceFailureException occurred while fetching AWS user list.'
            if hasattr(error,'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                error_message = f"{error_message} {error.response['Error']['Message']}"
            return [], [{"Error": error_message}]
        except botocore.exceptions.ClientError as error:
            error_message = 'Client error occurred while fetching the AWS user list.'
            if hasattr(error,'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                error_message = f"{error_message} {error.response['Error']['Message']}"
            return [], [{"Error": error_message}]
        except botocore.exceptions.EndpointConnectionError as error:
                error_message = 'Could not connect to the AWS fetch users(list_users) endpoint URL'
                if hasattr(error,'kwargs') and isinstance(error.kwargs, dict) and cowdictutils.is_valid_key(error.kwargs, 'endpoint_url'):
                    endpoint_url = error.kwargs['endpoint_url']
                    error_message = f'Could not connect to the endpoint URL: "{endpoint_url}" while attempting to AWS fetch user list'
                return [], [{"Error": error_message}]
    
    def get_user_names(self):
        users, error = self.list_users()
        if error:
            return []
        return [user.get('UserName', '') for user in users if user.get('UserName')]    
    
    # https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAttachedUserPolicies.html 
    # ( aws managed policies - only directly attached not via groups or roles )
    def list_attached_user_policies(self, user_name, iam_client=None):

        if not user_name:
            return [], [{"Error" : "UserName is mandatory to fetch user attached policies"}]
        if iam_client is None:
            session, error = self.create_aws_session()
            if error:
                return [], [{"Error" : f"Failed to create session while fetching user attached policies. {error}"}]
            iam_client = session.client('iam')
        try:
            paginator = iam_client.get_paginator('list_attached_user_policies')
            aws_managed_policies = [] 
            for page in paginator.paginate(UserName=user_name):
                if 'AttachedPolicies' in page and isinstance(page['AttachedPolicies'], list):
                    aws_managed_policies.extend(page['AttachedPolicies'])
            if not aws_managed_policies:
                return [], [{"Error" : f"No attached policies found for user - {user_name}"}]
            return aws_managed_policies, []
        except iam_client.exceptions.NoSuchEntityException:
            return [], [{"Error" : f"User '{user_name}' does not exist."}]
        except iam_client.exceptions.InvalidInputException:
            return [], [{"Error" : f"Invalid input provided for user '{user_name}'."}]
        except iam_client.exceptions.ServiceFailureException as error:
            # https://botocore.amazonaws.com/v1/documentation/api/latest/reference/services/iam/client/exceptions/ServiceFailureException.htmlHandle ServiceFailureException
            error_message = f'ServiceFailureException occurred while fetching attached policies for user - {user_name}.'
            if hasattr(error,'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                error_message = f"{error_message} {error.response['Error']['Message']}"
            return [], [{"Error": error_message}]
        except botocore.exceptions.ClientError as error:
            error_message = f'Client error occurred while fetching attached policies for user - {user_name}.'
            if hasattr(error,'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                error_message = f"{error_message} {error.response['Error']['Message']}"
            return [], [{"Error": error_message}]
        except botocore.exceptions.EndpointConnectionError as error:
                error_message = 'Could not connect to the AWS fetch user attached policies(list_attached_user_policies) endpoint URL'
                if hasattr(error,'kwargs') and isinstance(error.kwargs, dict) and cowdictutils.is_valid_key(error.kwargs, 'endpoint_url'):
                    endpoint_url = error.kwargs['endpoint_url']
                    error_message = f'Could not connect to the endpoint URL: "{endpoint_url}" while attempting to AWS fetch user attached policies(list_attached_user_policies) endpoint URL'
                return [], [{"Error": error_message}]
    
    # https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListUserPolicies.html 
    # ( inline policies - only directly attached not via groups or roles )
    def list_user_policies(self, user_name, iam_client):

        if not user_name:
            return [], [{"Error" : "UserName is mandatory to fetch user policies"}]
        if iam_client is None:
            session, error = self.create_aws_session()
            if error:
                return [], [{"Error" : f"Failed to create session while fetching user policies. {error}"}]
            iam_client = session.client('iam')
        try:
            paginator = iam_client.get_paginator('list_user_policies')
            aws_inline_policies = [] 
            for page in paginator.paginate(UserName=user_name):
                for policy in page['PolicyNames']:
                    aws_inline_policies.extend(policy['PolicyName'])
            if not aws_inline_policies:
                return [], [{"Error" : f"No policies found for user - {user_name}"}]
            return aws_inline_policies, []        
        except iam_client.exceptions.NoSuchEntityException:
            return [], [{"Error" : f"User '{user_name}' does not exist."}]
        except iam_client.exceptions.ServiceFailureException as error:
            # https://botocore.amazonaws.com/v1/documentation/api/latest/reference/services/iam/client/exceptions/ServiceFailureException.htmlHandle ServiceFailureException
            error_message = f'ServiceFailureException occurred while fetching policies for user - {user_name}.'
            if hasattr(error,'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                error_message = f"{error_message} {error.response['Error']['Message']}"
            return [], [{"Error": error_message}]
        except botocore.exceptions.ClientError as error:
            error_message = f'Client error occurred while fetching policies for user - {user_name}.'
            if hasattr(error,'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                error_message = f"{error_message} {error.response['Error']['Message']}"
            return [], [{"Error": error_message}]
        except botocore.exceptions.EndpointConnectionError as error:
                error_message = 'Could not connect to the AWS fetch user policies(list_user_policies) endpoint URL'
                if hasattr(error,'kwargs') and isinstance(error.kwargs, dict) and cowdictutils.is_valid_key(error.kwargs, 'endpoint_url'):
                    endpoint_url = error.kwargs['endpoint_url']
                    error_message = f'Could not connect to the endpoint URL: "{endpoint_url}" while attempting to AWS fetch user policies(list_user_policies) endpoint URL'
                return [], [{"Error": error_message}]
        

    # fetch aws managed and inline policies of user ( only directly attached not via groups or roles)
    def list_user_policy_names(self, user_name):

        try:
            policies = []
            # AWS managed policies
            aws_managed_policies, error_list = self.list_aws_managed_user_policy_names(user_name)
            if error_list:
                return [], error_list
            policies.extend(aws_managed_policies)
            # Inline policies
            inline_policies, error_list = self.list_user_inline_policy_names(user_name)
            if error_list:
                return [], error_list
            policies.extend(inline_policies)
            return policies, []
        except botocore.exceptions.ClientError as error:
            error_message = f"Client Exception occured while fetching directly attached policy names for user - {user_name}."
            if hasattr(error,'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                error_message = f"{error_message} {error.response['Error']['Message']}"
            return [], [{"Error" : error_message}]
        
    
    def list_aws_managed_user_policy_names(self, user_name):

        try:
            policies = []
            aws_managed_policies, error_list = self.list_attached_user_policies(user_name)
            if error_list:
                return [], error_list
            policies = [policy['PolicyName'] for policy in aws_managed_policies if 'PolicyName' in policy]    
            return policies, []
        except botocore.exceptions.ClientError as error:
            error_message = f"Client Exception occured while fetching aws managed policies for user - {user_name}."
            if hasattr(error,'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                error_message = f"{error_message} {error.response['Error']['Message']}"
            return [], [{"Error" : error_message}]
        
    
    def list_user_inline_policy_names(self, user_name):

        try:
            policies = []
            inline_policies, error_list = self.list_user_policies(user_name)
            if error_list:
                return [], error_list
            policies.extend(inline_policies)
            return policies, []
        except botocore.exceptions.ClientError as error:
            error_message = f"Client Exception occured while fetching inline policies for user - {user_name}."
            if hasattr(error,'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                error_message = f"{error_message} {error.response['Error']['Message']}"
            return [], [{"Error" : error_message}]
    
    
   # https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListPolicies.html
    def list_policies(self, scope=None):

        if scope is None:
            scope = "All"
        # scope :
        # Local - customer managed policies 
        # AWS   - Amazon Web Services managed policies
        # All   - All policies
        session, error = self.create_aws_session()
        if error:
                return [], [{"Error" : f"Failed to create a session while fetching AWS policy list: {str(error)}"}]
        iam_client = session.client('iam')
        try:
            paginator = iam_client.get_paginator('list_policies')
            policies = [] 
            error_list = []
            for page in paginator.paginate(Scope=scope):
                policies.extend(page.get('Policies', []))
            if not policies:
                return [], [{"Error" : f"No policies found for provided AWS credentials."}]
            if policies:
                for policy in policies:
                    groups = []
                    roles = []
                    users = []
                    policy_arn = policy.get("Arn", "")
                    policy_groups, policy_roles, policy_users, pol_ent_err_list = self.list_entities_for_policy(policy_arn, iam_client)
                    if pol_ent_err_list:
                        error_list.extend(pol_ent_err_list)
                    if policy_groups:
                        for group in policy_groups:
                            groups.append(group.get('GroupName', ''))
                    policy['PolicyGroups'] = groups
                    if policy_roles:
                        for role in policy_roles:
                            roles.append(role.get('RoleName', ''))
                    policy['PolicyRoles'] = roles
                    if policy_users:
                        for user in policy_users:
                            users.append(user.get('UserName', ''))
                    policy['PolicyUsers'] = users  
            return policies, error_list
        except iam_client.exceptions.ServiceFailureException as error:
            # https://botocore.amazonaws.com/v1/documentation/api/latest/reference/services/iam/client/exceptions/ServiceFailureException.htmlHandle ServiceFailureException
            error_message = 'ServiceFailureException occurred while fetching AWS policies.'
            if hasattr(error,'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                error_message = f"{error_message} {error.response['Error']['Message']}"
            return [], [{"Error": error_message}]
        except botocore.exceptions.EndpointConnectionError as error:
            error_message = "EndpointConnectionError occured while fetching AWS policies."
            if hasattr(error,'kwargs') and isinstance(error.kwargs, dict) and cowdictutils.is_valid_key(error.kwargs, 'endpoint_url'):
                endpoint_url = error.kwargs['endpoint_url']
                error_message = f"Could not connect to the endpoint URL: '{endpoint_url}  while attempting to fetch AWS policies"
            return [], [{"Error" : error_message}]
        except botocore.exceptions.ClientError as error:
            error_message = "Client Exception occured while fetching AWS policies."
            if hasattr(error,'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                error_message = f"{error_message} {error.response['Error']['Message']}"
            return [], [{"Error" : error_message}]


    def list_entities_for_policy(self, policy_arn, iam_client=None):

        if not policy_arn:
            return [], [], [], [{"Error" : "PolicyARN is mandatory to fetch policy entities"}]
        if iam_client is None:
            session, error = self.create_aws_session()
            if error:
                return [], [], [], [{"Error" : f"Failed to create a session while fetching policy entities for policy - {policy_arn}. {str(error)}"}]
            iam_client = session.client('iam')
        try:
            policy_groups = []
            policy_roles = []
            policy_users = []
            paginator = iam_client.get_paginator('list_entities_for_policy')
            for page in paginator.paginate(PolicyArn=policy_arn):
                policy_groups.extend(page.get('PolicyGroups', []))
                policy_roles.extend(page.get('PolicyRoles', []))
                policy_users.extend(page.get('PolicyUsers', []))
            return policy_groups, policy_roles, policy_users, []
        except iam_client.exceptions.ServiceFailureException as error:
            error_message = f'ServiceFailureException occurred while fetching policy entities for policy - {policy_arn}.'
            if hasattr(error,'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                error_message = f"{error_message} {error.response['Error']['Message']}"
            return [], [], [], [{"Error": error_message}]
        except botocore.exceptions.EndpointConnectionError as error:
            error_message = f"EndpointConnectionError occured while fetching policy entities for policy - {policy_arn}."
            if hasattr(error,'kwargs') and isinstance(error.kwargs, dict) and cowdictutils.is_valid_key(error.kwargs, 'endpoint_url'):
                endpoint_url = error.kwargs['endpoint_url']
                error_message = f"Could not connect to the endpoint URL: '{endpoint_url}  while attempting to fetching policy entities for policy - {policy_arn}"
            return [], [], [], [{"Error" : error_message}]
        except botocore.exceptions.ClientError as error:
            error_message = f"Client Exception occured while fetching fetching policy entities for policy - {policy_arn}."
            if hasattr(error,'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                error_message = f"{error_message} {error.response['Error']['Message']}"
            return [], [], [], [{"Error" : error_message}]
    
    
    def get_policy_version(self, policy_arn, version_id, iam_client=None):
        
        if not policy_arn:
            return [], [{"Error" : "Policy ARN is mandatory to fetch policy version"}]
        if not version_id:
            return [], [{"Error" : "Policy Version ID is mandatory to fetch policy version"}]
        if iam_client is None:
            session, error = self.create_aws_session()
            if error:
                return [], [{"Error" : f"Failed to create a session while fetching policy version for policy - {policy_arn}"}]
            iam_client = session.client('iam')
        try:
            actions = []
            response = iam_client.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=version_id)
            if (response and isinstance(response, dict) and 'PolicyVersion' in response and response['PolicyVersion'] and
                isinstance(response['PolicyVersion'], dict) and 'Document' in response['PolicyVersion'] and response['PolicyVersion']['Document'] 
                and isinstance(response['PolicyVersion']['Document'], dict) and 'Statement' in response['PolicyVersion']['Document'] and 
                isinstance(response['PolicyVersion']['Document']['Statement'], list)):
                statements = response['PolicyVersion']['Document']['Statement']
                for statement in statements:
                    if 'Action' in statement:
                        if isinstance(statement['Action'], list):
                            actions.extend(statement['Action'])
                        if isinstance(statement['Action'], str):
                            actions.append(statement['Action'])
            return actions, []
        except iam_client.exceptions.ServiceFailureException as error:
            error_message = f'ServiceFailureException occurred while fetching policy version for policy - {policy_arn}.'
            if hasattr(error,'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                error_message = f"{error_message} {error.response['Error']['Message']}"
            return [], [{"Error": error_message}]
        except botocore.exceptions.EndpointConnectionError as error:
            error_message = f"EndpointConnectionError occured while fetching policy version for policy - {policy_arn}."
            if hasattr(error,'kwargs') and isinstance(error.kwargs, dict) and cowdictutils.is_valid_key(error.kwargs, 'endpoint_url'):
                endpoint_url = error.kwargs['endpoint_url']
                error_message = f"Could not connect to the endpoint URL: '{endpoint_url}  while attempting to fetch AWS policies"
            return [], [{"Error" : error_message}]
        except botocore.exceptions.ClientError as error:
            error_message = f"Client Exception occured while fetching policy version for policy - {policy_arn}."
            if hasattr(error,'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                error_message = f"{error_message} {error.response['Error']['Message']}"
            return [], [{"Error" : error_message}]
        
    
    # filter the user policies from the aws policies
    def list_user_policy_names(self, user_name, policy_list):

        try:
            if not user_name or not policy_list:
                return [], [{"Error": "Mandatory parameter missing: UserName or PolicyList"}]
            df = pd.DataFrame(policy_list)
            if 'PolicyUsers' not in df.columns:
                return [], [{"Error": "Invalid policy list. 'PolicyUsers' column is missing"}]
            df_filtered = df[df['PolicyUsers'].apply(lambda users: user_name in users)]
            policies = df_filtered['PolicyName'].tolist()
            return policies, []
        except (ValueError,KeyError) as e:
            return [], [{"Error": f"Failed to fetch user policy details for user {user_name}. {str(e)}"}]


    # https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListGroupsForUser.html
    def list_groups_for_user(self, user_name, iam_client=None):

        if iam_client is None:
            session, error = self.create_aws_session()
            if error:
                return [], [{"Error" : f"Failed to create a session while fetching groups for user - {user_name}"}]
            iam_client = session.client('iam')
        try:
            groups = []
            paginator = iam_client.get_paginator("list_groups_for_user")
            for page in paginator.paginate(UserName=user_name):
                group_info = page['Groups']
                for group in group_info:
                    groups.append(group['GroupName'])
            return groups, []
        except botocore.exceptions.EndpointConnectionError as error:
            error_message = f"EndpointConnectionError occured while fetching groups(list_groups_for_user) for user - {user_name}."
            if hasattr(error,'kwargs') and isinstance(error.kwargs, dict) and cowdictutils.is_valid_key(error.kwargs, 'endpoint_url'):
                endpoint_url = error.kwargs['endpoint_url']
                error_message = f"Could not connect to the endpoint URL: '{endpoint_url}  while fetching groups for user - {user_name}."
            return [], [{"Error" : error_message}]
        except botocore.exceptions.ClientError as error:
            error_message = f"Client Exception occured while etching groups for user - {user_name}."
            if hasattr(error,'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                error_message = f"{error_message} {error.response['Error']['Message']}"
            return [], [{"Error" : error_message}]
        except iam_client.exceptions.ServiceFailureException as error:
            error_message = f'ServiceFailureException occurred while fetching groups for user - {user_name}.'
            if hasattr(error,'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                error_message = f"{error_message} {error.response['Error']['Message']}"
            return [], [{"Error": error_message}]
        except iam_client.exceptions.NoSuchEntityException:
            return [], [{"Error" : f"User '{user_name}' does not exist."}]
        
    
    # filter the group policies from the aws policies
    def list_group_policies(self, groups, policy_list):
        try:
            if not groups or not policy_list:
                return [], [{"Error": "Mandatory parameter missing: GroupName(s) or PolicyList"}]
            if not isinstance(groups, list):
                return [], [{"Error": "Invalid type: 'group_names'. Supported type list"}]
            policies = []
            df = pd.DataFrame(policy_list)
            if 'PolicyGroups' not in df.columns:
                return [], [{"Error": "Invalid policy list. 'PolicyGroups' column is missing"}]
            # Create a boolean mask for rows where any of the provided groups is in 'PolicyGroups'
            df['GroupInPolicy'] = df['PolicyGroups'].apply(lambda groups_list: any(group in groups for group in groups_list))
            # Filter the DataFrame where the boolean mask is True
            df_filtered = df[df['GroupInPolicy']]
            # Extract unique policy names
            policies = df_filtered['PolicyName'].tolist()
            return policies, []
        except (ValueError,KeyError) as e:
            return [], [{"Error": f"Failed to fetch group policy details for group(s) - {', '.join(groups)}. {str(e)}"}]
        
    
    def list_user_roles(self, user_name, iam_client=None):

        if iam_client is None:
            session, error = self.create_aws_session()
            if error:
                return [], [{"Error" : f"Failed to create a session while fetching roles for user - {user_name}"}]
            iam_client = session.client('iam')
        try:
            paginator = iam_client.get_paginator("list_roles")
            roles = []
            for page in paginator.paginate():
                if 'Roles' in page:
                    roles_info = page['Roles']
                    for role in roles_info:
                        if 'AssumeRolePolicyDocument' in role:
                            doc = role['AssumeRolePolicyDocument']
                            if 'Statement' in doc:
                                statements = doc['Statement']
                                for statement in statements:
                                    if 'Principal' in statement:
                                        principal = statement['Principal']
                                        if 'AWS' in principal:
                                            arn = principal['AWS'].split("/")[-1]
                                            if user_name == arn:
                                                if 'RoleName' in role:
                                                    roles.append(role['RoleName'])
            return roles, []
        except (KeyError,ValueError) as error:
            return [], [{"Error" : f"Failed to fetch roles for user - {user_name}. {str(error)}"}]
        except botocore.exceptions.EndpointConnectionError as error:
            error_message = f"EndpointConnectionError occured while fetching roles(list_roles) for user - {user_name}."
            if hasattr(error,'kwargs') and isinstance(error.kwargs, dict) and cowdictutils.is_valid_key(error.kwargs, 'endpoint_url'):
                endpoint_url = error.kwargs['endpoint_url']
                error_message = f"Could not connect to the endpoint URL: '{endpoint_url}  while fetching role(s) for user - {user_name}."
            return [], [{"Error" : error_message}]
        except botocore.exceptions.ClientError as error:
            error_message = f"Client Exception occured while etching role(s) for user - {user_name}."
            if hasattr(error,'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                error_message = f"{error_message} {error.response['Error']['Message']}"
            return [], [{"Error" : error_message}]
        except iam_client.exceptions.ServiceFailureException as error:
            error_message = f'ServiceFailureException occurred while fetching role(s) for user - {user_name}.'
            if hasattr(error,'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                error_message = f"{error_message} {error.response['Error']['Message']}"
            return [], [{"Error": error_message}]
    

    # filter the role policies from the aws policies
    def list_role_policies(self, roles, policy_list):
        try:
            if not roles or not policy_list:
                return [], [{"Error": "Mandatory parameter missing: Role(s) or PolicyList"}]
            if not isinstance(roles, list):
                return [], [{"Error": "Invalid type: 'roles'. Supported type list"}]
            policies = []
            df = pd.DataFrame(policy_list)
            if 'PolicyRoles' not in df.columns:
                return [], [{"Error": "Invalid policy list. 'PolicyRoles' column is missing"}]
            # Create a boolean mask for rows where any of the provided roles is in 'PolicyRoles'
            df['RoleInPolicy'] = df['PolicyRoles'].apply(lambda role_list: any(role in roles for role in role_list))
            # Filter the DataFrame where the boolean mask is True
            df_filtered = df[df['RoleInPolicy']]
            # Extract unique policy names
            policies = df_filtered['PolicyName'].tolist()
            return policies, []
        except (ValueError,KeyError) as e:
            return [], [{"Error": f"Failed to fetch role policy details for role(s) - {', '.join(roles)}. {str(e)}"}]
        

    # list actions for input policy names. 
    # aws_policies - This is used to fetch the policy version id
    def list_action_for_polcies(self, policy_name_list, aws_policies=None):

        try:
            if not policy_name_list:
                return [], [{"Error": "Policy name list empty"}]
            if aws_policies is None:
                aws_policies, error = self.list_policies("All")
                if error:
                    return [], [{"Error": f"Error while fetching policy actions. {error}"}]
            aws_policies_df = pd.DataFrame(aws_policies)
            filtered_policies = aws_policies_df[aws_policies_df['PolicyName'].isin(policy_name_list)]
            action_list = []
            filtered_policies_list = filtered_policies.to_dict(orient='records')
            for aws_policy in filtered_policies_list:
                policy_version_id = aws_policy['DefaultVersionId']
                policy_arn = aws_policy['Arn']
                actions, error = self.get_policy_version(policy_arn=policy_arn, version_id=policy_version_id)
                if error:
                    return [], [{"Error": f"Error while fetching policy actions for policy {aws_policy['PolicyName']}. {error}"}]
                if actions:
                    action_list.extend(actions)
            return action_list, []
        except (KeyError,ValueError) as e:
            return action_list, [{"Error": f"Failed to fetch action list for input policy list. {str(e)}"}]

    
    # https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_ListAnalyzers.html
    def list_analyzers(self, region, analyzer_type=None):

        analyzers = []
        error_list = []
        try:
            session, error = self.create_aws_session(region)
            if error:
                return [], ([{'Error': f'Error while creating session in {region}. {error}'}])
            client = session.client('accessanalyzer')
            try:
                paginator = client.get_paginator("list_analyzers")
                if analyzer_type is None:
                    analyzer_type = ''
                for page in paginator.paginate(type=analyzer_type):
                    analyzers.extend(page.get('analyzers', []))
            except client.exceptions.ValidationException as error:
                msg = f"ValidationException occured while fetching analyzer details in {region}"
                if  isinstance(error, dict)  and cowdictutils.is_valid_key(error, 'message'):
                    error_list.append({"Error" : f"{msg}. {error.get('message')}"})
                else:
                    error_list.append({"Error" : f"{msg}. {str(error)}"})
            except client.exceptions.InternalServerException as error:
                msg = f"InternalServerException occured while fetching analyzer details in {region}"
                if  isinstance(error, dict)  and cowdictutils.is_valid_key(error, 'message'):
                    error_list.append({"Error" : f"{msg}. {error.get('message')}"})
                else:
                    error_list.append({"Error" : f"{msg}. {str(error)}"})
            except client.exceptions.ThrottlingException as error:
                msg = f"ThrottlingException occured while fetching analyzer details in {region}"
                if  isinstance(error, dict)  and cowdictutils.is_valid_key(error, 'message'):
                    error_list.append({"Error" : f"{msg}. {error.get('message')}"})
                else:
                    error_list.append({"Error" : f"{msg}. {str(error)}"})
            except client.exceptions.AccessDeniedException as error:
                msg = f"AccessDeniedException occured while fetching analyzer details in {region}"
                if  isinstance(error, dict)  and cowdictutils.is_valid_key(error, 'message'):
                    error_list.append({"Error" : f"{msg}. {error.get('message')}"})
                else:
                    error_list.append({"Error" : f"{msg}. {str(error)}"})
        except botocore.exceptions.EndpointConnectionError as error:
            error_message = f"EndpointConnectionError occured while fetching analyzer details in {region}"
            if hasattr(error,'kwargs') and isinstance(error.kwargs, dict) and cowdictutils.is_valid_key(error.kwargs, 'endpoint_url'):
                endpoint_url = error.kwargs['endpoint_url']
                error_message = f"Could not connect to the endpoint URL: '{endpoint_url}."
            error_list.append({"Error" : error_message})
        except botocore.exceptions.ClientError as error:
            error_message = f"Client Exception occured while fetching analyzer details in {region}"
            if hasattr(error,'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                error_message = f"{error_message} {error.response['Error']['Message']}"
            error_list.append({"Error" : error_message})
        return analyzers, error_list
    

    # https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_ListFindingsV2.html
    def list_findings_v2(self, analyzer_type):

        if not self.region:
            return [], [{'Error' : 'Region is mandatory'}]
        data = []
        error_list = []
        invalid_regions = []
        for region in self.region:
            analyzers, error_list = self.list_analyzers(region, analyzer_type)
            if not analyzers:
                invalid_regions.append(region)
            if error_list:
                return data, error_list
            try:
                session, error = self.create_aws_session(region)
                if error:
                    error_list.append({'Error': f'Error while creating session in {region}. {error}'})
                    continue
                client = session.client('accessanalyzer')
                for analyzer in analyzers:
                    arn = analyzer.get('arn')
                    try:
                        # Using paginator for list_findings_v2
                        paginator = client.get_paginator('list_findings_v2')
                        for page in paginator.paginate(analyzerArn=arn):
                            findings = page.get('findings', [])
                            for finding in findings:
                                finding_id = finding.get('id')
                                if finding_id:
                                    try:
                                        # https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_GetFindingV2.html
                                        finding_info = client.get_finding_v2(
                                            id=finding_id,
                                            analyzerArn=arn
                                        )
                                        data.append(finding_info)
                                    except client.exceptions.ValidationException as error:
                                        msg = f"ValidationException occured while fetching finding details. Analyzer - {arn}. Finding - {finding_id}"
                                        if  isinstance(error, dict)  and cowdictutils.is_valid_key(error, 'message'):
                                            error_list.append({"Error" : f"{msg}. {error.get('message')}"})
                                        else:
                                            error_list.append({"Error" : f"{msg}. {str(error)}"})
                                    except client.exceptions.InternalServerException as error:
                                        msg = f"InternalServerException occured while fetching finding details. Analyzer - {arn}. Finding - {finding_id}"
                                        if  isinstance(error, dict)  and cowdictutils.is_valid_key(error, 'message'):
                                            error_list.append({"Error" : f"{msg}. {error.get('message')}"})
                                        else:
                                            error_list.append({"Error" : f"{msg}. {str(error)}"})
                                    except client.exceptions.ThrottlingException as error:
                                        msg = f"ThrottlingException occured while fetching finding details. Analyzer - {arn}. Finding - {finding_id}"
                                        if  isinstance(error, dict)  and cowdictutils.is_valid_key(error, 'message'):
                                            error_list.append({"Error" : f"{msg}. {error.get('message')}"})
                                        else:
                                            error_list.append({"Error" : f"{msg}. {str(error)}"})
                                    except client.exceptions.AccessDeniedException as error:
                                        msg = f"AccessDeniedException occured while fetching finding details. Analyzer - {arn}. Finding - {finding_id}"
                                        if  isinstance(error, dict)  and cowdictutils.is_valid_key(error, 'message'):
                                            error_list.append({"Error" : f"{msg}. {error.get('message')}"})
                                        else:
                                            error_list.append({"Error" : f"{msg}. {str(error)}"})
                                    except client.exceptions.ResourceNotFoundException as error:
                                        msg = f"ResourceNotFoundException occured while fetching finding details. Analyzer - {arn}. Finding - {finding_id}"
                                        if  isinstance(error, dict)  and cowdictutils.is_valid_key(error, 'message'):
                                            error_list.append({"Error" : f"{msg}. {error.get('message')}"})
                                        else:
                                            error_list.append({"Error" : f"{msg}. {str(error)}"})
                    except client.exceptions.ValidationException as error:
                        msg = f"ValidationException occured while fetching Analyzer finding details. Analyzer - {arn}."
                        if  isinstance(error, dict)  and cowdictutils.is_valid_key(error, 'message'):
                            error_list.append({"Error" : f"{msg}. {error.get('message')}"})
                        else:
                            error_list.append({"Error" : f"{msg}. {str(error)}"})
                    except client.exceptions.InternalServerException as error:
                        msg = f"InternalServerException occured while fetching Analyzer finding details. Analyzer - {arn}."
                        if  isinstance(error, dict)  and cowdictutils.is_valid_key(error, 'message'):
                            error_list.append({"Error" : f"{msg}. {error.get('message')}"})
                        else:
                            error_list.append({"Error" : f"{msg}. {str(error)}"})
                    except client.exceptions.ThrottlingException as error:
                        msg = f"ThrottlingException occured while fetching Analyzer finding details. Analyzer - {arn}."
                        if  isinstance(error, dict)  and cowdictutils.is_valid_key(error, 'message'):
                            error_list.append({"Error" : f"{msg}. {error.get('message')}"})
                        else:
                            error_list.append({"Error" : f"{msg}. {str(error)}"})
                    except client.exceptions.AccessDeniedException as error:
                        msg = f"AccessDeniedException occured while fetching Analyzer finding details. Analyzer - {arn}."
                        if  isinstance(error, dict)  and cowdictutils.is_valid_key(error, 'message'):
                            error_list.append({"Error" : f"{msg}. {error.get('message')}"})
                        else:
                            error_list.append({"Error" : f"{msg}. {str(error)}"})
                    except client.exceptions.ResourceNotFoundException as error:
                        msg = f"ResourceNotFoundException occured while fetching Analyzer finding details. Analyzer - {arn}."
                        if  isinstance(error, dict)  and cowdictutils.is_valid_key(error, 'message'):
                            error_list.append({"Error" : f"{msg}. {error.get('message')}"})
                        else:
                            error_list.append({"Error" : f"{msg}. {str(error)}"})      
            except botocore.exceptions.EndpointConnectionError as error:
                error_message = f"EndpointConnectionError occured while fetching analyzer details in {region}"
                if hasattr(error,'kwargs') and isinstance(error.kwargs, dict) and cowdictutils.is_valid_key(error.kwargs, 'endpoint_url'):
                    endpoint_url = error.kwargs['endpoint_url']
                    error_message = f"Could not connect to the endpoint URL: '{endpoint_url}."
                error_list.append({"Error" : error_message})
            except botocore.exceptions.ClientError as error:
                error_message = f"Client Exception occured while fetching analyzer details in {region}"
                if hasattr(error,'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                    error_message = f"{error_message} {error.response['Error']['Message']}"
                error_list.append({"Error" : error_message})             
        
        if invalid_regions:
            error_list.append({"Error" : f"Failed to fetch analyzer finding details for the following region(s): {', '.join(invalid_regions)}"})

        return data, error_list


    def get_unused_permissions_for_user_using_access_analyzer(self, finding_info, user_name):

        try:
            permission_details = []
            df = pd.DataFrame(finding_info)
            df['resource_name'] = df['resource'].str.split('/').str.get(-1)
            filtered_df = df[(df['findingType'] == "UnusedPermission") & (df['resource_name'] == user_name) & (df['status'] == 'ACTIVE')]
            if not filtered_df.empty:
                findings =  filtered_df.to_dict('records')
                for finding in findings: 
                    un_used_permission_list = finding.get('findingDetails')
                    for un_used_permission in un_used_permission_list:
                        info = un_used_permission.get('unusedPermissionDetails')
                        service_name_space = info.get('serviceNamespace')
                        if "actions" in info:
                            action_list = info.get('actions')
                            if action_list is not None:
                                for action in action_list:
                                    permission_details.append(f"{service_name_space}:{action.get('action')}")
                        else:
                            permission_details.append(f"{service_name_space}:*")
            return permission_details, []
        except (KeyError,ValueError,AttributeError) as e:
            return [], [{"Error": f"Error occured while fetching access analyzer findings for user - {user_name}"}]
        
    
    # Used to get all "*" level permissions
    def modify_user_permissions(self, permission_df, user_permissions):
        
        if not isinstance(permission_df, pd.DataFrame) or permission_df.empty:
            return [], [{"Error": "Invalid master permission data"}]
        if not isinstance(user_permissions, list) or not user_permissions:
            return [], [{"Error": "Invalid user permission data"}]
        required_columns = {"Service", "AccessLevel", "Permission"}
        missing_columns = required_columns - set(permission_df.columns)
        if missing_columns:
            return [], [{"Error": f"Invalid master permission data. Missing column(s): {', '.join(missing_columns)}"}]
        modified_permissions = []
        all_permissions_included = {}
        try:
            for permission in user_permissions:
                if ":" not in permission:
                    modified_permissions.append(permission)
                    continue
                service, action = permission.split(":", 1)
                if service not in all_permissions_included:
                    filtered_df = permission_df[permission_df['Service'] == service.upper()] 
                    # if service is not available in permission master data
                    if filtered_df.empty:
                        modified_permissions.append(permission)
                    elif action == "*":
                        permission_list = filtered_df['Permission'].tolist()
                        for perm in permission_list:
                            modified_permissions.append(f"{service}:{perm}")
                        all_permissions_included[service] = True
                    elif "*" in action:
                        access_level = action.replace("*", "")
                        if access_level:
                            access_filtered_df = filtered_df[filtered_df['AccessLevel'] == access_level] 
                            if access_filtered_df.empty:
                                permission_list = filtered_df['Permission'].tolist()
                                filtered_permissions = [perm for perm in permission_list if perm.lower().startswith(access_level)]
                                for perm in filtered_permissions:
                                    modified_permissions.append(f"{service}:{perm}")
                                continue
                            for perm in access_filtered_df.to_dict(orient="records"):
                                modified_permissions.append(f"{service}:{perm['Permission']}")
                    else:
                        modified_permissions.append(permission)
        except (AttributeError,KeyError,ValueError) as error:
            return [], [{"Error": f"Failed to modify user permission from master permission list. {str(error)}"}]
        if modified_permissions:
            modified_permissions = list(set(modified_permissions))
        return modified_permissions, []
    
    # Below method are created for Workload Federal Identity Integration for GCP with AWS
    # Method 1: Sign AWS Request (SigV4)
    def sign_aws_request(self, aws_session_token: str, region: Optional[str] = None) -> Tuple[Optional[Dict[str, str]], Optional[str]]:
        try:
            aws_role = self.user_defined_credentials.aws_role
            url = "https://sts.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15"
            headers = {"host": "sts.amazonaws.com"}
            
            if not aws_role.access_key or not aws_role.secret_key:
                raise NoCredentialsError("AWS credentials are missing.")
            
            credentials = Credentials(aws_role.access_key, aws_role.secret_key, aws_session_token)
            request = AWSRequest(method="POST", url=url, headers=headers, data="")
            
            SigV4Auth(credentials, "sts", region).add_auth(request)
            return dict(request.headers), None
        except (NoCredentialsError, PartialCredentialsError) as e:
            return None, f"AWS Credentials Error: {e}"
    
    # Method 2: Generate Subject Token
    def generate_subject_token(self, signed_headers: Dict[str, str], gcp_creds: Dict[str, Any], aws_session_token: str) -> Tuple[Optional[str], Optional[str]]:
        try:
            if not signed_headers:
                raise ValueError("Signed headers are missing.")
            
            subject_token_json = {
                "headers": [
                    {"key": "x-amz-date", "value": signed_headers["X-Amz-Date"]},
                    {"key": "Authorization", "value": signed_headers["Authorization"]},
                    {"key": "host", "value": "sts.amazonaws.com"},
                    {
                        "key": "x-goog-cloud-target-resource",
                        "value": f"//iam.googleapis.com/projects/{gcp_creds.get('project_number')}/locations/global/workloadIdentityPools/{gcp_creds.get('pool_id')}/providers/{gcp_creds.get('provider_id')}",
                    },
                    {"key": "x-amz-security-token", "value": aws_session_token}
                ],
                "method": "POST",
                "url": "https://sts.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15",
            }

            subject_token_str = json.dumps(subject_token_json)

            return urllib.parse.quote(subject_token_str, safe=""), None
        except ValueError as e:
            return None, f"Invalid input error: {e}"

    # Method 3: Exchange for GCP Token
    def exchange_for_gcp_token(self, subject_token_encoded: str, gcp_creds: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        try:
            google_sts_url = "https://sts.googleapis.com/v1/token"
            sts_request_body = {
                "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
                "audience": f"//iam.googleapis.com/projects/{gcp_creds.get('project_number')}/locations/global/workloadIdentityPools/{gcp_creds.get('pool_id')}/providers/{gcp_creds.get('provider_id')}",
                "scope": "https://www.googleapis.com/auth/cloud-platform",
                "requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
                "subjectTokenType": "urn:ietf:params:aws:token-type:aws4_request",
                "subjectToken": subject_token_encoded,
            }
            
            response = requests.post(google_sts_url, headers={"Content-Type": "application/json"}, json=sts_request_body)
            response.raise_for_status()
            return response.json(), None
        except requests.exceptions.HTTPError as e:
            return None, f"HTTP error while exchanging for GCP token: {e}"
        except requests.exceptions.ConnectionError as e:
            return None, f"Connection error: {e}"
        except requests.exceptions.RequestException as e:
            return None, f"Request error while exchanging for GCP token: {e}"

    # Method 4: Generate Service Account Token
    def generate_service_account_token(self, gcp_access_token: str, gcp_creds: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        try:
            service_account_url = f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{gcp_creds.get('service_account')}:generateAccessToken"
            service_account_headers = {
                "Authorization": f"Bearer {gcp_access_token}",
                "Content-Type": "application/json"
            }
            service_account_body = {
                "scope": "https://www.googleapis.com/auth/cloud-platform"
            }
            
            response = requests.post(service_account_url, headers=service_account_headers, json=service_account_body)
            response.raise_for_status()
            return response.json(), None
        except requests.exceptions.HTTPError as e:
            return None, f"HTTP error while generating service account token: {e}"
        except requests.exceptions.ConnectionError as e:
            return None, f"Connection error: {e}"
        except requests.exceptions.RequestException as e:
            return None, f"Request error while generating service account token: {e}"
        
    # Below methods are API calls for GCPBigQuery using the created service account token
    def create_bigquery_job(self, service_account_token: str, query_payload: Dict[str, Any], gcp_table_config: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        try:
            bigquery_url = f"https://bigquery.googleapis.com/bigquery/v2/projects/{gcp_table_config.get('project_id')}/jobs"
            bigquery_headers = {
                "Authorization": f"Bearer {service_account_token}",
                "Content-Type": "application/json"
            }
            
            response = requests.post(bigquery_url, headers=bigquery_headers, json=query_payload)
            response.raise_for_status()
            
            return response.json(), None
        except requests.exceptions.HTTPError as e:
            return None, f"HTTP error querying BigQuery: {e}"
        except requests.exceptions.ConnectionError as e:
            return None, f"Connection error querying BigQuery: {e}"

    def check_query_job_status(self, job_query_response: Dict[str, Any], toml_data: Dict[str, Any], service_account_token: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        try:
            condition_field = toml_data.get("ConditionField", "")
            condition_value = toml_data.get("ConditionValue", "").split("|")
            time_interval = int(toml_data.get("TimeInterval", 5))
            max_retries = int(toml_data.get("MaxRetries", 5))

            if not condition_field:
                return None, "ConditionField is missing in TOML file."
            
            condition_field = condition_field.strip("<<>>")
            
            job_status_url = "https://bigquery.googleapis.com/bigquery/v2/projects/<<jobReference.projectId>>/jobs/<<jobReference.jobId>>"
            final_job_status_url = self.replace_placeholders_in_url(job_status_url, job_query_response)

            headers = {
                "Authorization": f"Bearer {service_account_token}",
                "Content-Type": "application/json"
            }

            retries = 0
            while retries < max_retries:
                response = requests.get(final_job_status_url, headers=headers)
                if response.status_code != 200:
                    return None, f"Error fetching job status: {response.text}"

                job_status_response = response.json()
                job_state = self.extract_value_from_json(job_status_response, condition_field)

                if job_state in condition_value:
                    # print(f"Job is {job_state}, retrying in {time_interval} seconds...")
                    time.sleep(time_interval)
                    retries += 1
                else:
                    return job_status_response, None

            return None, f"Max retries reached. Last job state: {job_state}"
        
        except KeyError as e:
            return None, f"KeyError: {e}"
        except requests.exceptions.RequestException as e:
            return None, f"RequestException: {e}"
        except ValueError as e:
            return None, f"Invalid TOML configuration value: {e}"

    def fetch_query_response_using_job_id(self, job_query_response: Dict[str, Any], service_account_token: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        try:
            query_results_url_template = "https://bigquery.googleapis.com/bigquery/v2/projects/<<jobReference.projectId>>/queries/<<jobReference.jobId>>"
            final_query_results_url = self.replace_placeholders_in_url(query_results_url_template, job_query_response)

            headers = {
                "Authorization": f"Bearer {service_account_token}",
                "Content-Type": "application/json"
            }

            response = requests.get(final_query_results_url, headers=headers)
            if response.status_code != 200:
                return None, f"Error fetching BigQuery query results: {response.text}"

            return response.json(), None

        except KeyError as e:
            return None, f"KeyError: {e}"
        except requests.exceptions.RequestException as e:
            return None, f"RequestException: {e}"

    def extract_value_from_json(self, response_json: Dict[str, Any], placeholder: str) -> str:
        try:
            keys = placeholder.split(".")
            value = response_json
            for key in keys:
                if isinstance(value, dict) and key in value:
                    value = value[key]
                else:
                    raise KeyError(f"Key '{key}' not found in response JSON.")
            return str(value)
        except KeyError as e:
            return f"Error: {e}"

    def replace_placeholders_in_url(self, url_template: str, response_json: Dict[str, Any]) -> str:
        """Replaces placeholders in URL with values from the response JSON."""
        return re.sub(r"<<(.+?)>>", lambda match: self.extract_value_from_json(response_json, match.group(1)), url_template)