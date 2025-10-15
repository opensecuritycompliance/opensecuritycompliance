
from typing import Tuple, List
from compliancecowcards.structs import cards
#As per the selected app, we're importing the app package 
from compliancecowcards.utils import cowdictutils
from applicationtypes.gcpconnector import gcpconnector
import pandas as pd

logger = cards.Logger() # Initializes a Logger instance to log data, use logger.log_data(dict) to log a data

class Task(cards.AbstractTask):

    def execute(self) -> dict:

        self.errors_list = []

        error = self.check_inputs(['MinimumRequiredRetentionPeriod'])
        if error:
            return self.upload_log_file_panic(error)
        
        db_instance_file_url = ''
        if cowdictutils.is_valid_key(self.task_inputs.user_inputs, 'GCPDataBaseInstanceList'):
            db_instance_file_url = self.task_inputs.user_inputs['GCPDataBaseInstanceList']

        prev_log_file_url = ''
        if cowdictutils.is_valid_key(self.task_inputs.user_inputs, 'LogFile'):
            prev_log_file_url =  self.task_inputs.user_inputs['LogFile']

        if prev_log_file_url and not db_instance_file_url:
            return {'LogFile': prev_log_file_url}
        
        if prev_log_file_url:
            self.errors_list, error = self.download_json_file_from_minio_as_dict(self.task_inputs.user_inputs['LogFile'])
            if error:
                return error
        
        db_instance_df, error = self.download_parquet_file_from_minio_as_df(self.task_inputs.user_inputs['GCPDataBaseInstanceList'])
        if error:
            return self.upload_log_file_panic(f'Error occurred while downloading GCPDataBaseInstanceList file :: {error}')
        
        # Verify db_instance_df
        if db_instance_df.empty:
            return self.upload_log_file_panic("GCPDataBaseInstanceList file is empty, please check")
        
        required_columns = { "InstanceBackupConfiguration", "ETag", "InstanceName", "InstanceType", "InstanceURL", "ProjectName" }
        missing_columns = required_columns.difference(db_instance_df.columns)
        if missing_columns:
            return self.upload_log_file_panic(f"The following columns are missing in GCPDataBaseInstanceList file :: '{', '.join(missing_columns)}'")
        
        self.app = gcpconnector.GCPConnector(
            app_url=self.task_inputs.user_object.app.application_url,
            app_port=self.task_inputs.user_object.app.application_port,
            user_defined_credentials=gcpconnector.UserDefinedCredentials.from_dict(
                self.task_inputs.user_object.app.user_defined_credentials)
        )
        
        standardised_report_df = db_instance_df.apply(
            self.get_db_retention_period_report,
            axis=1,
            result_type='expand'
        )

        output_file_url, error = self.upload_df_as_parquet_file_to_minio(standardised_report_df, 'GCPDBRetentionPeriodReport')
        if error:
            return self.upload_log_file_panic(f'Error occurred while uploading GCPDBRetentionPeriodReport :: {error}')
        
        log_file_url = ''
        if self.errors_list:
            log_file_url, error = self.upload_log_file(self.errors_list)
            if error:
                return error
        
        return {
            'GCPDBRetentionPeriodReport': output_file_url,
            'LogFile': log_file_url
        }
    
    def check_inputs(self, required_user_inputs: List[str]) -> str:
        if self.task_inputs is None:
            return 'Task inputs are missing'
        user_object = self.task_inputs.user_object
        if (
            user_object is None
            or user_object.app is None
            or user_object.app.application_url is None
            or user_object.app.user_defined_credentials is None
        ):
            return 'User defined credentials are missing"'
        
        if self.task_inputs.user_inputs is None:
            return 'User inputs are missing'
        
        missing_inputs = []
        for input in required_user_inputs:
            if not cowdictutils.is_valid_key(self.task_inputs.user_inputs, input):
                missing_inputs.append(input)

        return "The following inputs: " + ", ".join(missing_inputs) + " is/are empty" if missing_inputs else ""
    
    def upload_log_file(self, error_data) -> Tuple[str, dict]:
        if not isinstance(error_data, list):
            error_data = [error_data]
        
        [logger.log_data(dict(error_item)) for error_item in error_data]

        file_url, error = self.upload_df_as_json_file_to_minio(
            df=pd.json_normalize(error_data),
            file_name="LogFile"
        )
        if error:
            return None, {'error': f"Error while uploading LogFile :: {error}"}
        return file_url, None
    
    def upload_log_file_panic(self, error_data) -> dict:
        if isinstance(error_data, str):
            error_data = {'Error': error_data}
        self.errors_list.append(error_data)
        file_url, error = self.upload_log_file(self.errors_list)
        if error:
            return error
        return { 'LogFile': file_url }
    
    def get_db_retention_period_report(self, instance: pd.Series):
        instance_backup_config: dict = instance['InstanceBackupConfiguration']

        is_backup_enabled = bool(instance_backup_config.get('BackupEnabled'))

        minimum_retention = int(self.task_inputs.user_inputs['MinimumRequiredRetentionPeriod'])
        actual_retention = int(instance_backup_config.get('BackupRetentionCount', 0))
        
        record = {
            'System': 'gcp',
            'Source': 'compliancecow',
            'ResourceID': instance['ETag'],
            'ResourceName': instance['InstanceName'],
            'ResourceType': 'CloudSQLInstance',
            'ResourceLocation': 'N/A',
            'ResourceTags': 'N/A',
            'ResourceURL': instance['InstanceURL'],
            'ProjectName': instance['ProjectName'],
            'MinimumRequiredRetentionPeriod': minimum_retention,
            'ActualRetentionPeriod': actual_retention,
            'IsBackupEnabled': str(is_backup_enabled).lower(),
            'MeetsMinimumRetentionRequirement':  'N/A',
            'ValidationStatusCode': 'BK_DS',
            'ValidationStatusNotes': 'Backup is disabled',
            'ComplianceStatus': 'NON_COMPLIANT',
            'ComplianceStatusReason': 'The record is non-compliant because the DB backup feature is disabled. Taking backups is advisable to protect data against loss, enable point-in-time recovery, and ensure compliance with industry regulations.',
            'EvaluatedTime': self.app.get_current_datetime(),
            'UserAction': '',
            'ActionStatus': '',
            'ActionResponseURL': ''
        }

        if is_backup_enabled:
            if actual_retention >= minimum_retention:
                record.update({
                    'MeetsMinimumRetentionRequirement':  "true",
                    'ValidationStatusCode': 'BK_EN_MN_RT_P',
                    'ValidationStatusNotes': 'Backup feature is enabled and it also meets the expected retention period',
                    'ComplianceStatus': 'COMPLIANT',
                    'ComplianceStatusReason': 'The Database backups meet the minimum retention period requirements, ensuring compliance, data integrity, and support for long-term analysis.',
                })
            else:
                record.update({
                    'MeetsMinimumRetentionRequirement':  "false",
                    'ValidationStatusCode': 'BK_EN_MN_RT_NP',
                    'ValidationStatusNotes': 'Backup is enabled but it does not meet the expected retention period',
                    'ComplianceStatus': 'NON_COMPLIANT',
                    'ComplianceStatusReason': 'The record is non-compliant because backup does not meet the expected retention period. DataBase backups must meet minimum retention periods to preserve data integrity, comply with regulations, and enable long-term analysis.',
                })

        return record
