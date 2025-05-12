from typing import Tuple
from applicationtypes.azureappconnector import azureappconnector
from compliancecowcards.structs import cards
import pandas as pd
from datetime import datetime
import ast

class Task(cards.AbstractTask):
    def execute(self) -> dict:
        error = self.check_inputs()
        if error:
            return self.upload_log_file_panic({'Error': error})

        # download diagnostic settings file
        diagnostic_setting_df, error = self.download_csv_file_from_minio_as_df(
            file_url=self.task_inputs.user_inputs["ServiceBusDiagnosticSettingsDataFilePath"]
        )
        if error:
            return self.upload_log_file_panic({'Error': f"Error while downloading ServiceBusDiagnosticSettingsData file :: {error}"})
        
        self.azure_connector = azureappconnector.AzureAppConnector(
            app_url=self.task_inputs.user_object.app.application_url,
            app_port=self.task_inputs.user_object.app.application_port,
            user_defined_credentials=azureappconnector.UserDefinedCredentials.from_dict(
                self.task_inputs.user_object.app.user_defined_credentials
            )
        )

        columns = {
            "Id": "ResourceID",
            "Name": "ResourceName",
            "Values": "Values",
        }
        required_columns = set(columns.keys())

        if not required_columns.issubset(diagnostic_setting_df.columns):
            return self.upload_log_file_panic({'Error': f'The following columns are missing in ServiceBusDiagnosticSettingsData file: {", ".join(required_columns.difference(diagnostic_setting_df.columns))}'})
        
        diagnostic_setting_df = diagnostic_setting_df.rename(columns=columns)
        diagnostic_setting_df["System"] = "azure"
        diagnostic_setting_df["Source"] = "compliancecow"
        diagnostic_setting_df["ResourceType"] = "ServiceBusNameSpace"

        diagnostic_setting_df[
            [
                "ResourceURL",
                "DiagnosticLogEnabledInServiceBusNameSpace",
                "ComplianceStatus",
                "ValidationStatusCode",
                "ComplianceStatusReason",
                "ValidationStatusNotes",
                "EvaluatedTime",
            ]
        ] = diagnostic_setting_df.apply(self.update_status, axis=1)

        standard_df = diagnostic_setting_df[
            [
                "System",
                "Source",
                "ResourceID",
                "ResourceType",
                "ResourceName",
                "ResourceURL",
                "DiagnosticLogEnabledInServiceBusNameSpace",
                "ComplianceStatus",
                "ComplianceStatusReason",
                "ValidationStatusCode",
                "ValidationStatusNotes",
                "EvaluatedTime",
            ]
        ]

        standard_df['UserAction'] = ''
        standard_df['ActionStatus'] = ''
        standard_df['ActionResponseURL'] = ''

        file_url, error = self.upload_output_file(
            output_data=standard_df,
            file_name="DiagnosticLogsInServiceBusNameSpace"
        )
        if error:
            return self.upload_log_file_panic(error)

        response = {
            "DiagnosticLogsInServiceBusNameSpace": file_url,
        }

        return response

    def update_status(self, row):
        enabled = False

        if row["Values"] and pd.notna(row["Values"]):
            for item in ast.literal_eval(row["Values"]):
                properties = item.get("properties")
                if properties:
                    logs = properties.get("logs")
                    if logs:
                        for log in logs:
                            log_enabled = log.get("enabled")
                            if log_enabled:
                                enabled = log_enabled
                                break

        resource_url, error = self.azure_connector.get_resource_url(row["ResourceID"])
        if error:
            resource_url = ""

        if enabled:
            compliance_details = {
                "ComplianceStatus": "COMPLIANT",
                "ValidationStatusCode": "DIAG_LOGS_ENABLED",
                "ComplianceStatusReason": "Diagnostic log category(ies) are enabled",
                "ValidationStatusNotes": "No actions required",
            }
        else:
            compliance_details = {
                "ComplianceStatus": "NON_COMPLIANT",
                "ValidationStatusCode": "DIAG_LOGS_DISABLED",
                "ComplianceStatusReason": "None of the diagnostic categor(ies) are enabled",
                "ValidationStatusNotes": "Enable one or more diagnostic logs for the resource",
            }

        return pd.Series({
            "ResourceURL": resource_url,
            "DiagnosticLogEnabledInServiceBusNameSpace": enabled,
            **compliance_details,
            "EvaluatedTime": self.azure_connector.get_current_datetime(),
        })
    
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
        
        file_url, error = self.upload_df_as_csv_file_to_minio(
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
        if not self.task_inputs.user_inputs.get("ServiceBusDiagnosticSettingsDataFilePath"):
            emptyAttrs.append("ServiceBusDiagnosticSettingsDataFilePath")
        
        return "The following inputs: " + ", ".join(
            emptyAttrs) + " is/are empty, please check the user inputs." if emptyAttrs else ""
