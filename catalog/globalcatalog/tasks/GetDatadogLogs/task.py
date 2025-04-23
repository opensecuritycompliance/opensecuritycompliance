
from typing import Tuple, List
from compliancecowcards.structs import cards
#As per the selected app, we're importing the app package 
from appconnections.datadogconnector import datadogconnector
import uuid
import pandas as pd
from datetime import timezone, timedelta

class Task(cards.AbstractTask):

    def execute(self) -> dict:

        error = self.check_inputs()
        if error:
            return self.upload_log_file_panic({ 'error': error })
        
        app = datadogconnector.DatadogConnector(
            app_url=self.task_inputs.user_object.app.application_url,
            app_port=self.task_inputs.user_object.app.application_port,
            user_defined_credentials=datadogconnector.UserDefinedCredentials.from_dict(
                self.task_inputs.user_object.app.user_defined_credentials)
        )

        from_date = self.task_inputs.from_date
        to_date = self.task_inputs.to_date
        if from_date == to_date:
            to_date = to_date + timedelta(hours=23, minutes=59)
        
        logs, error = app.list_logs(
            from_date=from_date.astimezone(timezone.utc).isoformat(),
            to_date=to_date.astimezone(timezone.utc).isoformat(),
        )
        if error:
            return self.upload_log_file_panic(error)
        
        if not logs:
            return self.upload_log_file_panic({ 'error': 'No logs found for the given time period.' })
        
        logs_list = []
        for log in logs:
            log_attrs: dict = log.get('attributes', {})
            log_data = {
                "System": "datadog",
                "Source": "compliancecow",
                "ResourceID": log.get('id', ''),
                "ResourceName": "N.A",
                "ResourceType": "log",
                "ResourceLocation": "N/A",
                "ResourceTags": "N/A",
                "ResourceURL": f"{app.app_url.rstrip().rstrip('/')}/logs?event={log.get('id', '')}",
                "LogMessage": log_attrs.get('message', ''),
                "LogStatus": log_attrs.get('status', ''),
                "LogHost": log_attrs.get('host', ''),
                "LogService": log_attrs.get('service', ''),
                "LogCreatedDate": log_attrs.get('timestamp', ''),
                "UserAction": "",
                "ActionStatus": "",
                "ActionResponseURL": ""
            }

            logs_list.append(log_data)

        output_file_url, error = self.upload_output_file(logs_list, "DatadogLogs")
        if error:
            return self.upload_log_file_panic(error)
        
        response = {
            "DatadogLogs": output_file_url
        }

        return response
    
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
        
        return ""
    
    def upload_log_file_panic(self, error_data) -> dict:
        if not isinstance(error_data, list):
            error_data = [error_data]
        file_url, error = self.upload_file_to_minio(
            file_content=error_data,
            file_name=f"LogFile-{str(uuid.uuid4())}.json",
            content_type="application/json"
        )
        if error:
            return { 'error': f"Error while uploading LogFile :: {error}" }
        
        return {
            'LogFile': file_url
        }
    
    def upload_output_file(self, output_data, file_name) -> Tuple[str, dict]:
        if not output_data:
            return None, None
        
        file_url, error = self.upload_df_as_parquet_file_to_minio(
            df=pd.json_normalize(output_data),
            file_name=file_name
        )
        if error:
            return None, { 'error': f"Error while uploading {file_name} file :: {error}" }
        return file_url, None
