
from typing import Tuple
from compliancecowcards.structs import cards
#As per the selected app, we're importing the app package 
from applicationtypes.azureappconnector import azureappconnector
import pandas as pd

class Task(cards.AbstractTask):

    def execute(self) -> dict:

        error = self.check_inputs()
        if error:
            return self.upload_log_file_panic({'Error': error})
        
        user_defined_credentials = (self.task_inputs.user_object.app).to_dict()
        azure_connector = azureappconnector.AzureAppConnector.from_dict(user_defined_credentials)

        input_retention_data = self.task_inputs.user_inputs["RetentionInDays"]

        log_analytics_workspace_data, error = self.download_json_file_from_minio_as_dict(
            file_url=self.task_inputs.user_inputs["AzureLogAnalyticsWorkSpaceData"]
        )
        if error:
            return self.upload_log_file_panic({"Error": f"Error while downloading AzureLogAnalyticsWorkSpaceData file :: {error}"})
        
        output = []
        for data in log_analytics_workspace_data:
            compliance_status = "NON_COMPLIANT"
            compliance_status_reason = "Data retention period does not meet the compliance standards"
            validation_status_notes= f"Workspace default retention period is less than {input_retention_data} days"
            validation_status_code = "INSUFFICIENT_RETENTION_PERIOD"
            resource_id = data.get("ResourceID")

            resource_name, resource_type = self.extract_fields_from_id(resource_id)
            evaluated_time = azure_connector.get_current_datetime()

            retention_data = data.get("PropertiesRetentionInDays")
            if not input_retention_data:
                input_retention_data = 0

            if retention_data :
                if int(retention_data) == int(input_retention_data):
                    compliance_status = "COMPLIANT"
                    compliance_status_reason = "Data retention period meets the compliance standards"
                    validation_status_notes = f"Workspace default retention period meets the expected retention period of {input_retention_data} days"
                    validation_status_code = "SUFFICIENT_RETENTION_PERIOD"

                elif int(retention_data) > int(input_retention_data):
                    compliance_status = "COMPLIANT"
                    compliance_status_reason = "Data retention period meets the compliance standards"
                    validation_status_notes = f"Workspace default retention period is more than the expected retention period of {input_retention_data} days"
                    validation_status_code = "EXCESS_RETENTION_PERIOD"

                resource_url, error = azure_connector.get_resource_url(resource_id)
                if error:
                    resource_url = ""

                output_report = {
                    "System": "azure",
                    "Source": "compliancecow",

                    "ResourceID": resource_id,
                    "ResourceName": resource_name,
                    "ResourceURL": resource_url,
                    "ResourceType": resource_type,
                    "ResourceLocation": "",
                    "ResourceTags": data.get("Tags", ""),

                    "ValidationStatusCode": validation_status_code,
                    "ValidationStatusNotes": validation_status_notes,
                    "ComplianceStatus": compliance_status,
                    "ComplianceStatusReason": compliance_status_reason,
                    
                    "EvaluatedTime": evaluated_time,
                    'UserAction': '',
                    'ActionStatus': '',
                    'ActionResponseURL': ''
                }

                output.append(output_report)

        output_df = pd.DataFrame(output)
        file_url, error = self.upload_output_file(output_df, "AzureLogAnalyticsWkSpaceRetentionPeriodReport")
        if error :
            return self.upload_log_file_panic(error)

        response = {
            "LogAnalyticsWkSpaceRetentionPeriodReport" : file_url,
        }

        return response
    
    def extract_fields_from_id(self, id: str) -> Tuple[str, str]:
        resourceGroups, resourceGroupsType = "", ""

        parts = id.split("/")
        resourceGroupsType = parts[-2][:1].upper() + parts[-2][1:]

        resourceGroups = parts[4] if len(parts) > 3 else id

        return resourceGroups, resourceGroupsType
    
    def upload_log_file(self, error_data) -> Tuple[str, dict]:
        if not isinstance(error_data, list):
            error_data = [error_data]
        file_url, error = self.upload_df_as_json_file_to_minio(
            df=pd.DataFrame(error_data),
            file_name="LogFile"
        )
        if error:
            return None, {'Error': f"Error while uploading LogFile :: {error}"}
        return file_url, None
    
    def upload_log_file_panic(self, error_data) -> dict:
        file_url, error = self.upload_log_file(error_data)
        if error:
            return error
        return { 'LogFile': file_url }
    
    def upload_output_file(self, output_data: pd.DataFrame, file_name) -> Tuple[str, dict]:
        if output_data.empty:
            return None, None
        
        file_url, error = self.upload_df_as_json_file_to_minio(
            df=output_data,
            file_name=file_name
        )
        if error:
            return None, { 'Error': f"Error while uploading {file_name} file :: {error}" }
        return file_url, None
    
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
        
        emptyAttrs = []
        if self.task_inputs.user_inputs is None:
            emptyAttrs.append("User inputs")
        if not self.task_inputs.user_inputs.get("AzureLogAnalyticsWorkSpaceData"):
            emptyAttrs.append("AzureLogAnalyticsWorkSpaceData")
        if not self.task_inputs.user_inputs.get("RetentionInDays"):
            emptyAttrs.append("RetentionInDays")
        
        return "The following inputs: " + ", ".join(
            emptyAttrs) + " is/are empty, please check the user inputs." if emptyAttrs else ""
