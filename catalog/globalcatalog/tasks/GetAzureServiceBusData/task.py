from typing import Tuple
from compliancecowcards.structs import cards
# As per the selected app, we're importing the app package
from applicationtypes.azureappconnector import azureappconnector
import pandas as pd


class Task(cards.AbstractTask):

    def execute(self) -> dict:
        error = self.check_inputs()
        if error:
            return self.upload_log_file_panic({'Error': error})

        app = azureappconnector.AzureAppConnector(
            app_url=self.task_inputs.user_object.app.application_url,
            app_port=self.task_inputs.user_object.app.application_port,
            user_defined_credentials=azureappconnector.UserDefinedCredentials.from_dict(
                self.task_inputs.user_object.app.user_defined_credentials)
        )

        service_bus_namespaces_list, error = app.get_azure_service_bus_namespaces_data()
        if error:
            return self.upload_log_file_panic({"Error": f"Error while fetching azure service bus data :: {error}"})
        
        service_bus_namespaces_list = app.replace_empty_dicts_with_none(service_bus_namespaces_list)
        service_bus_namespaces_df = pd.DataFrame(service_bus_namespaces_list)

        if "properties" in service_bus_namespaces_df.columns:
            service_bus_namespaces_df = pd.concat(
                [
                    service_bus_namespaces_df.drop(["properties"], axis=1),
                    pd.json_normalize(service_bus_namespaces_df["properties"])
                ],
                axis=1
            )

        service_bus_namespaces_df.columns = service_bus_namespaces_df.columns.map(
            lambda x: "".join(
                [w[0].upper() + w[1:] if len(w) >= 1 else w.upper() for w in x.split(".")]
            )
        )

        file_url, error = self.upload_output_file(
            output_data=service_bus_namespaces_df,
            file_name="AzureServiceBusNameSpaces"
        )
        if error:
            return self.upload_log_file_panic(error)

        diagnostic_df, error = app.get_service_bus_namespaces_diagnostic_settings_data(
            pd.DataFrame(service_bus_namespaces_df[["Id", "Name"]])
        )
        if error:
            return self.upload_log_file_panic({'Error': f"Error while getting service bus namespaces diagnostic settings data :: {error}"})
        
        diagnostic_df = diagnostic_df.map(
            lambda x: None if isinstance(x, list) and len(x) == 0 else x
        )

        diagnostic_df.columns = diagnostic_df.columns.map(
            lambda x: "".join(
                [w[0].upper() + w[1:] if len(w) >= 1 else w.upper() for w in x.split(".")]
            )
        )
        diagnostic_df_url, error = self.upload_df_as_csv_file_to_minio(
            df=diagnostic_df,
            file_name="ServiceBusNameSpacesDiagnosticSettings"
        )
        if error:
            return self.upload_log_file_panic(error)
        
        response = {
            "AzureServiceBusNameSpaces": file_url,
            "ServiceBusNameSpacesDiagnosticSettings": diagnostic_df_url,
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
