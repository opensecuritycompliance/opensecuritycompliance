from typing import List
import boto3
import botocore.exceptions
import pandas as pd
from datetime import datetime
from compliancecowcards.utils import cowdictutils
from datetime import datetime, timedelta, timezone
import re
import pytz
from dateutil import tz

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
CLOUD_WATCH_ALARM_LIST_URL   =  'https://<<Region>>.console.aws.amazon.com/cloudwatch/home?region=<<Region>>#alarmsV2'
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
    region: list

    def __init__(
            self,
            app_url: str = None,
            app_port: int = None,
            user_defined_credentials: UserDefinedCredentials = None,
            region: list = None) -> None:
        self.app_url = app_url
        self.app_port = app_port
        self.user_defined_credentials = user_defined_credentials
        self.region = region

    @staticmethod
    def from_dict(obj) -> 'AWSAppConnector':
        app_url, app_port, user_defined_credentials, region = "", "", None, []
        if isinstance(obj, dict):
            app_url = obj.get("AppURL", "")
            if not app_url:
                app_url = obj.get("appURL", "")
            app_port = obj.get("AppPort", 0)
            if not app_port:
                app_port = obj.get("appPort", 0)
            user_defined_credentials_dict = obj.get(
                "UserDefinedCredentials", None)
            if user_defined_credentials_dict is None:
                user_defined_credentials_dict = obj.get(
                    "userDefinedCredentials", None)
            if bool(user_defined_credentials_dict):
                user_defined_credentials = UserDefinedCredentials.from_dict(
                    user_defined_credentials_dict)
            region = obj.get("Region", [])

        return AWSAppConnector(app_url, app_port, user_defined_credentials, region)

    def to_dict(self) -> dict:
        result: dict = {}
        result["AppURL"] = self.app_url
        result["AppPort"] = self.app_port
        result[
            "UserDefinedCredentials"] = self.user_defined_credentials.to_dict(
        )
        result["Region"] = self.region
        return result

    def validate(self) -> bool and dict:
        if not self.is_empty_aws_role():
            return self.validate_aws_role()
        elif not self.is_empty_aws_iam():
            return self.validate_aws_iam()
        return False, {'error': 'not a valid input'}

    def is_empty_aws_role(self):
        role_creds = self.user_defined_credentials.aws_role
        return not all((role_creds.access_key, role_creds.secret_key, role_creds.role_arn))

    def create_aws_session_with_role(self, region=None):
        aws_role = self.user_defined_credentials.aws_role
        iam_session = boto3.Session(
            region_name=region,
            aws_access_key_id=aws_role.access_key,
            aws_secret_access_key=aws_role.secret_key,
        )
        try:
            sts_client = iam_session.client('sts')
            assumed_role = sts_client.assume_role(
                RoleArn=aws_role.role_arn, RoleSessionName='compliancecowsession')
            if cowdictutils.is_valid_key(assumed_role,'Credentials') and cowdictutils.is_valid_key(assumed_role['Credentials'],'AccessKeyId') and cowdictutils.is_valid_key(assumed_role['Credentials'],'SecretAccessKey') and cowdictutils.is_valid_key(assumed_role['Credentials'],'SessionToken') :    
                credentials = assumed_role['Credentials']
                session = boto3.Session(
                    aws_access_key_id=credentials['AccessKeyId'],
                    aws_secret_access_key=credentials['SecretAccessKey'],
                    aws_session_token=credentials['SessionToken'],
                    region_name=region,
                )
                return session, None
            return None, 'unable to get the assumed role credentials.'    
        except botocore.exceptions.ClientError as error:
            error_message = 'an error occurred while trying to assume role.'
            if error.response and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                error_message = error.response['Error']['Message']
            return None, error_message

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
            error_message = 'an error occurred while getting account authorization details.'
            if error.response and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                error_message = error.response['Error']['Message']
            return False, error_message

    def create_aws_session(self, region):
        if not self.is_empty_aws_role():
            session = self.create_aws_session_with_role(region)
        elif not self.is_empty_aws_iam():
            session = self.create_aws_session_with_accesskey(region)
        else:
            return None, 'not a valid application'
        return session, None

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
                error_message = 'an error occurred while trying to fetch the response for the describe_alarms operation.'
                if hasattr(error,'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                    error_message = error.response['Error']['Message']
                errors_list.append({'Region': region, 'Error': error_message})
                continue
            except botocore.exceptions.EndpointConnectionError as error:
                error_message = 'could not connect to the CloudWatch endpoint URL'
                if hasattr(error,'kwargs') and isinstance(error.kwargs, dict) and cowdictutils.is_valid_key(error.kwargs, 'endpoint_url'):
                    endpoint_url = error.kwargs['endpoint_url']
                    error_message = f'could not connect to the endpoint URL: "{endpoint_url}" in region "{region}" while attempting to access the CloudWatch service.'
                errors_list.append({'Region': region, 'Error': error_message})
                continue    

        if not metric_alarms_df.empty:
            if 'AlarmConfigurationUpdatedTimestamp' in metric_alarms_df.columns:
                metric_alarms_df['AlarmConfigurationUpdatedTimestamp'] = self.convert_timestamp(metric_alarms_df['AlarmConfigurationUpdatedTimestamp'], unit='ms')
            if 'StateTransitionedTimestamp' in metric_alarms_df.columns:
                metric_alarms_df['StateTransitionedTimestamp'] = self.convert_timestamp(metric_alarms_df['StateTransitionedTimestamp'], unit='ms')
            if 'StateUpdatedTimestamp' in metric_alarms_df.columns:
                metric_alarms_df['StateUpdatedTimestamp'] = self.convert_timestamp(metric_alarms_df['StateUpdatedTimestamp'], unit='ms')
                
            metric_alarms_df = self.standardize_column_names(metric_alarms_df)

        return metric_alarms_df, errors_list

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
                    error_message = 'an error occurred while trying to fetch the response for the describe_metric_filters operation.'
                    if hasattr(error,'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                        error_message = error.response['Error']['Message']
                    errors_list.append({'Region': region, 'Error': error_message})
                    continue
                except botocore.exceptions.EndpointConnectionError as error:
                    error_message = 'could not connect to the CloudWatch endpoint URL'
                    if hasattr(error,'kwargs') and isinstance(error.kwargs, dict) and cowdictutils.is_valid_key(error.kwargs, 'endpoint_url'):
                        endpoint_url = error.kwargs['endpoint_url']
                        error_message = f'could not connect to the endpoint URL: "{endpoint_url}" in region "{region}" while attempting to access the CloudWatch service.'
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
                    errors_list.append({'Region': region, 'Error': 'could not get trail list from response'})
                    continue
                trail_list = response['trailList']
                trail_list_flat = pd.json_normalize(
                    trail_list)
                cloud_trails_df = pd.concat(
                    [cloud_trails_df, pd.DataFrame(trail_list_flat)], ignore_index=True)
            except botocore.exceptions.ClientError as error:
                error_message = 'an error occurred while trying to fetch the response for the describe_cloud_trails operation.'
                if hasattr(error,'response') and isinstance(error.response, dict) and cowdictutils.is_valid_key(error.response, 'Error') and cowdictutils.is_valid_key(error.response['Error'], 'Message'):
                    error_message = error.response['Error']['Message']
                errors_list.append({'Region': region, 'Error': error_message})
                continue
            except botocore.exceptions.EndpointConnectionError as error:
                error_message = 'could not connect to the CloudTrail endpoint URL'
                if hasattr(error,'kwargs') and isinstance(error.kwargs, dict) and cowdictutils.is_valid_key(error.kwargs, 'endpoint_url'):
                    endpoint_url = error.kwargs['endpoint_url']
                    error_message = f'could not connect to the endpoint URL: "{endpoint_url}" in region "{region}" while attempting to access the CloudTrail service.'
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
            error_message = 'an error occurred while trying to fetch the response for the get_event_selectors operation.'
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
    
    #https://docs.aws.amazon.com/efs/latest/ug/API_DescribeFileSystems.html
    def list_efs_file_systems(self):
        
        efs_list = []
        errors_list = []
        invalid_regions = []

        for region in self.region:
            try:
                session, error = self.create_aws_session(region)
                if error:
                    errors_list.append(f'Error while creating session in {region}. {error}')
                    continue

                efs_client = session.client('efs')
                response = efs_client.describe_file_systems()
                if cowdictutils.is_valid_array(response, 'FileSystems'):
                    for file_system in response['FileSystems']:
                        file_system['Region'] = region
                        efs_list.append(file_system)
                else:
                    invalid_regions.append(region)

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
        
        if invalid_regions:
            errors_list.append(f"No Elastic File System was found for the provided AWS credentials in region(s): {', '.join(invalid_regions)}")

        return efs_list, errors_list
    
    def get_time_stamp(self, data):
        data_utc = data.astimezone(pytz.utc)
        data_dt = data_utc.astimezone(tz.tzlocal())
        data_time_stamp = pd.Timestamp(data_dt)
        return self.convert_timestamp(data_time_stamp)
    

    def convert_timestamp(self, data, unit=None):
        if unit:
            # Convert using the specified unit (e.g., 'ms' for milliseconds)
            return pd.to_datetime(data, unit=unit).dt.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        else:
            # Convert using default settings (assuming data is already in a valid format)
            return pd.to_datetime(data).strftime('%Y-%m-%dT%H:%M:%S.%fZ')    


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
    
    '''
       resource_info = {
         'resource_type'  : 'AwsIamUser',
         'Resource'       : 'user_name',
         'Region'         : 'user_region',
         'ResourceParent' : 'main resource under which this sub-resource is found.

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
                return None, f'invalid resource type :: {resource_type}'
        else:
            return None, "errror while fetching resource url - resource type is missing"
        
    
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
                        return None, f'required field {field} not found or empty in input dict'           
        return url, None

    def extract_placeholders(self, input_str, pattern):
        matches = re.findall(pattern, input_str)
        return matches

    def get_current_datetime(self):       
        current_time = datetime.utcnow()
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

    # Standardizes the column names of the DataFrame by capitalizing the first letter of each word and removing spaces.
    def standardize_column_names(self, df):
        df.columns = df.columns.map(lambda x: ''.join([w[0].upper(
        ) + w[1:] if len(w) >= 1 else w.upper() for w in x.split('.')])).str.replace(' ', '')
        return df

        
