
from typing import Tuple
from compliancecowcards.structs import cards
#As per the selected app, we're importing the app package 
from appconnections.azureappconnector import azureappconnector
import pandas as pd

class Task(cards.AbstractTask):

    def execute(self) -> dict:
        error = self.check_inputs()
        if error:
            return self.upload_log_file_panic({'Error': error})
        
        user_defined_credentials = (self.task_inputs.user_object.app).to_dict()
        azure_connector = azureappconnector.AzureAppConnector.from_dict(user_defined_credentials)

        service_princple_type_data, error = azure_connector.list_azure_service_principals( )
        if error:
            return self.upload_log_file_panic({"Error": f"Error while getting azure service principals :: {error}"})
        
        service_princple_type_details = []
        for service_princple_type_data in service_princple_type_data :
            new_flattened_output = azure_connector.replace_empty_dicts_with_none(service_princple_type_data)

            flattened_output = azure_connector.flatten_json(new_flattened_output)
            service_princple_type_details.append(flattened_output)
        
        service_princple_type_data_df = pd.DataFrame(service_princple_type_details)
        file_url, error = self.upload_output_file(service_princple_type_data_df, "AzureServicePrincipalsData")
        if error :
            return self.upload_log_file_panic(error)

        response = {
            "AzureServicePrincipalsData" : file_url
        }

        return response
    
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
        
        return ""
    