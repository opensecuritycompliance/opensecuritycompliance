
from typing import Tuple, List
from compliancecowcards.structs import cards
#As per the selected app, we're importing the app package 
from applicationtypes.gcpconnector import gcpconnector
import pandas as pd

logger = cards.Logger() # Initializes a Logger instance to log data, use logger.log_data(dict) to log a data

class Task(cards.AbstractTask):

    def execute(self) -> dict:

        errors_list = []

        error = self.check_inputs()
        if error:
            return self.upload_log_file_panic(error)

        self.app = gcpconnector.GCPConnector(
            app_url=self.task_inputs.user_object.app.application_url,
            app_port=self.task_inputs.user_object.app.application_port,
            user_defined_credentials=gcpconnector.UserDefinedCredentials.from_dict(
                self.task_inputs.user_object.app.user_defined_credentials)
        )

        projects_response, error = self.app.list_projects()
        if error:
            return self.upload_log_file_panic(f'Error occurred while fetching projects :: {error}')
        
        project_names = [project.get('name', '') for project in projects_response]
        error = self.validate_include_projects(project_names)
        if error:
            errors_list.append({'Error': error})

        standard_output: List[dict] = []

        for project in projects_response:
            project_name = project.get('name', '')
            project_id = project.get('projectId', '')

            if self.check_is_project_in_scope(project_name):
                project_instances, error = self.get_instances_list_for_project(project_name, project_id)
                if error:
                    return self.upload_log_file_panic(error)
                
                standard_output.extend(project_instances)

        output_file_url = ''
        if standard_output:
            output_file_url, error = self.upload_df_as_parquet_file_to_minio(
                df=pd.DataFrame(standard_output),
                file_name='GCPDataBaseInstanceList'
            )
            if error:
                return self.upload_log_file_panic(f'Error while uploading GCPDataBaseInstanceList file :: {error}')
        else:
            errors_list.append({'Error': 'No in scope projects were found'})
        
        log_file_url = ''
        if errors_list:
            log_file_url, error =  self.upload_log_file(errors_list)
            if error:
                return error

        return {
            'GCPDataBaseInstanceList': output_file_url,
            'LogFile': log_file_url
        }
    
    def check_inputs(self) -> str:
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
        
        return ''
    
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
        file_url, error = self.upload_log_file(error_data)
        if error:
            return error
        return { 'LogFile': file_url }
    
    def check_is_project_in_scope(self, project_name: str) -> bool:
        projects_to_include: str = self.task_inputs.user_inputs.get('IncludeProjects', '')
        projects_to_exclude: str = self.task_inputs.user_inputs.get('ExcludeProjects', '')

        projects_to_include_list = [item.strip() for item in projects_to_include.split(',')] if projects_to_include and isinstance(projects_to_include, str) else []
        projects_to_exclude_list = [item.strip() for item in projects_to_exclude.split(',')] if projects_to_exclude and isinstance(projects_to_exclude, str) else []

        return not (projects_to_exclude_list and project_name in projects_to_exclude_list) and (not projects_to_include_list or project_name in projects_to_include_list)
    
    def validate_include_projects(self, projects_list: list[str]):
        projects_to_include: str = self.task_inputs.user_inputs.get('IncludeProjects', '')
        projects_to_include_list = [item.strip() for item in projects_to_include.split(',')] if projects_to_include and isinstance(projects_to_include, str) else []

        invalid_projects = set(projects_to_include_list) - set(projects_list)
        if invalid_projects:
            return f"The following projects provided in IncludeProjects are invalid: {', '.join(invalid_projects)}"
        
        return ''
    
    def get_instances_list_for_project(self, project_name: str, project_id: str) -> Tuple[List[dict], str]:
        instances_response, error = self.app.list_db_instances(project_id)
        if error:
            return [], f"Error while fetching DB instances :: {error}"
        
        db_instances: List[dict] = instances_response.get('items', [])
        if not db_instances:
            return [], f"No instances found for project '{project_name}'"
        
        project_instances: List[dict] = []
        
        for instance in db_instances:
            instance_name = instance.get('name')
            instance_ip_addresses: List[dict] = instance.get('ipAddresses', [])
            instance_ip_addresses = [ip.get('ipAddress', '') for ip in instance_ip_addresses if ip.get('ipAddress', '')]

            backup_config: dict = instance.get('settings', {}).get('backupConfiguration', {})
            if backup_config:
                backup_config = {
                    "BackupStartTime": backup_config.get('startTime'),
                    "BackupLocation": backup_config.get('location'),
                    "BackupRetentionCount": int(backup_config.get('backupRetentionSettings', {}).get('retainedBackups', 0)),
                    "BackupEnabled": backup_config.get('enabled'),
                    "BackupBinaryLogEnabled": backup_config.get('binaryLogEnabled'),
                    "BackupTransactionLogRetentionDays": backup_config.get('transactionLogRetentionDays'),
                    "BackupTransactionalLogStorageState": backup_config.get('transactionalLogStorageState'),
                }

            project_instances.append(
                {
                    "ProjectName": project_name,
                    "ETag": instance.get('etag'),
                    "InstanceName": instance_name,
                    "InstanceConnectionName": instance.get('connectionName'),
                    "InstanceState": instance.get('state'),
                    "InstanceRegion": instance.get('region'),
                    "InstanceType": instance.get('instanceType'),
                    "InstanceURL": f"https://console.cloud.google.com/sql/instances/{instance_name}/overview?project={project_id}",
                    "InstanceDatabaseVersion": instance.get('databaseVersion'),
                    "InstanceCreatedTime": instance.get('createTime'),
                    "InstanceIPAddresses": instance_ip_addresses,
                    "InstanceServiceAccountEmail": instance.get('serviceAccountEmailAddress'),
                    "InstanceBackupConfiguration": backup_config
                }
            )

        return project_instances, ''
