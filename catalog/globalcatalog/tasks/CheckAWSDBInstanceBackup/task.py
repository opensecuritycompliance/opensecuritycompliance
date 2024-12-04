
from typing import overload
from compliancecowcards.structs import cards
# As per the selected app, we're importing the app package
from appconnections.awsappconnector import awsappconnector
import pandas as pd
import uuid
import json
import os
from compliancecowcards.utils import cowdictutils


class Task(cards.AbstractTask):

    def execute(self) -> dict:
        error = self.validate_inputs()
        if error:
            return self.upload_log_file([{'Error': error}])

        aws_connector = awsappconnector.AWSAppConnector(
            user_defined_credentials=awsappconnector.UserDefinedCredentials.from_dict(
                self.task_inputs.user_object.app.user_defined_credentials
            )
        )

        log_file_path = self.task_inputs.user_inputs.get('LogFile')
        if log_file_path:
            return {
                'LogFile': log_file_path
            }

        if not cowdictutils.is_valid_key(self.task_inputs.user_inputs, 'RDSDBInstancesList'):
            return self.upload_log_file([{'Error': 'Missing input: RDSDBInstancesList'}])
        
        file_path = self.task_inputs.user_inputs.get('RDSDBInstancesList')
        try:
            file_extension = os.path.splitext(file_path)[1]
            if file_extension != '.parquet':
                err_msg = f"Provided {os.path.basename(file_path)} is not supported. Please upload a RDSDBInstancesList file with the '.parquet' extension. The provided file is of type {file_extension}"
                return self.upload_log_file([{"Error": err_msg}])
        except IndexError:
            return self.upload_log_file([{"Error": "Failed to generate VerifyDBRetentionPeriod report. Please contact support for further details."}])


        db_instances_df, error = self.download_parquet_file_from_minio_as_df(
            self.task_inputs.user_inputs.get('RDSDBInstancesList'))
        if error:
            return self.upload_log_file([{'Error': error}])

        db_instances_columns = {
            'DBInstanceArn', 'DBInstanceIdentifier', 'Region', 'DBInstanceStatus'}
        if not db_instances_df.empty:
            if db_instances_columns.issubset(db_instances_df.columns):
                # Filter only DBInstance statuses that are available
                filtered_df = db_instances_df[db_instances_df['DBInstanceStatus'] == 'available']
                if not filtered_df.empty:
                    # If the MinimumRequiredRetentionPeriod is not provided by user input, it is taken as 30 days by default
                    minimum_retention_period = int(self.task_inputs.user_inputs.get(
                        'MinimumRequiredRetentionPeriod'))
                    if not minimum_retention_period:
                        minimum_retention_period = 30
                    standardized_df = filtered_df.apply(
                        lambda x: self.check_db_instances_backup(x, minimum_retention_period, aws_connector), axis=1, result_type='expand')
                    return self.upload_output_file(aws_connector, standardized_df)
                else:
                    return self.upload_log_file([{'Error': 'There are no available statuses for RDS DB instances.'}])

            else:
                return self.upload_log_file([{'Error': 'The expected columns [DBInstanceArn, DBInstanceIdentifier, Region, DBInstanceStatus] are not available in the RDSDBInstancesList.'}])
        else:
            return self.upload_log_file([{'Error': 'No resources were found for RDS DB instances to perform the backup-enabled check.'}])


    def check_db_instances_backup(self, db_instances_info, minimum_retention_period, aws_connector):
        is_backup_enabled, meets_minimum_retention = False, False
        backup_retention_period = 'N/A'
        validation_status_code, validation_status_notes, compliance_status, compliance_status_reason = (
            'BK_DS', 'Backup is disabled', 'NON_COMPLIANT', 'The record is non-compliant because the DB backup feature is disabled. Taking RDS backups is advisable to protect data against loss, enable point-in-time recovery, and ensure compliance with industry regulations.')
        if 'BackupRetentionPeriod' in db_instances_info:
            backup_retention_period = str(
                db_instances_info['BackupRetentionPeriod'])
            is_backup_enabled = True
            if db_instances_info['BackupRetentionPeriod'] >= minimum_retention_period:
                meets_minimum_retention = True

        if is_backup_enabled and meets_minimum_retention:
            validation_status_code = 'BK_EN_MN_RT_P'
            validation_status_notes = 'The DB backup feature is enabled and meets the expected retention period'
            compliance_status = 'COMPLIANT'
            compliance_status_reason = 'The RDS backups meet the minimum retention period requirements, ensuring compliance, data integrity, and support for long-term analysis.'
        elif is_backup_enabled and not meets_minimum_retention:
            validation_status_code = 'BK_EN_MN_RT_NP'
            validation_status_notes = 'Backup is enabled but does not meet the expected retention period'
            compliance_status = 'NON_COMPLIANT'
            compliance_status_reason = 'The record is non-compliant because RDS backup does not meet the expected retention period. RDS backups must meet minimum retention periods to preserve data integrity, comply with regulations, and enable long-term analysis.'
        resource_info = {
            'resource_type': awsappconnector.RDS_DB_INSTANCE,
            'Resource': db_instances_info.get('DBInstanceIdentifier'),
            'Region': db_instances_info.get('Region')
        }
        resource_url, _ = aws_connector.get_resource_url(resource_info)
        return {
            'System': 'aws',
            'Source': 'compliancecow',
            'ResourceID': db_instances_info['DBInstanceArn'],
            'ResourceName': db_instances_info['DBInstanceIdentifier'],
            'ResourceType': awsappconnector.RDS_DB_INSTANCE,
            'ResourceLocation': db_instances_info['Region'],
            'ResourceTags': db_instances_info.get('TagList'),
            'ResourceURL': resource_url,
            'MinimumRequiredRetentionPeriod': minimum_retention_period,
            'ActualRetentionPeriod': backup_retention_period,
            'IsBackupEnabled': is_backup_enabled,
            'MeetsMinimumRetentionRequirement':  meets_minimum_retention,
            'ValidationStatusCode': validation_status_code,
            'ValidationStatusNotes': validation_status_notes,
            'ComplianceStatus': compliance_status,
            'ComplianceStatusReason': compliance_status_reason,
            'EvaluatedTime': aws_connector.get_current_datetime(),
            'UserAction': '',
            'ActionStatus': '',
            'ActionResponseURL': ''
        }

    def upload_output_file(self, aws_connector, df):
        desired_column_order = ['System','Source','ResourceID','ResourceName','ResourceType','ResourceLocation','ResourceTags','ResourceURL','MinimumRequiredRetentionPeriod','ActualRetentionPeriod','IsBackupEnabled','MeetsMinimumRetentionRequirement','ValidationStatusCode','ValidationStatusNotes','ComplianceStatus','ComplianceStatusReason','EvaluatedTime','UserAction','ActionStatus','ActionResponseURL']
        df.columns= desired_column_order
        absolute_file_path, error = self.upload_df_as_parquet_file_to_minio(
            df, f'DBInstanceBackupEnabled-{str(uuid.uuid4())}')
        if error:
            return {'error': error}
        return {
            'DBInstanceBackupEnabled': absolute_file_path
        }

    def upload_log_file(self, errors_list):
        absolute_file_path, error = self.upload_file_to_minio(file_content=json.dumps(errors_list).encode(
            'utf-8'), file_name=f'LogFile-{str(uuid.uuid4())}.json', content_type='application/json')
        if error:
            return {'error': error}
        return {
            'LogFile': absolute_file_path
        }

    def validate_inputs(self):
        task_inputs = self.task_inputs
        if not task_inputs:
            return 'Missing: Task inputs'

        user_object = self.task_inputs.user_object
        if (
            not user_object
            or not user_object.app
            or not user_object.app.user_defined_credentials
        ):
            return 'Missing: User defined credentials'

        if not self.task_inputs.user_inputs:
            return 'Missing: User inputs'

        return None
