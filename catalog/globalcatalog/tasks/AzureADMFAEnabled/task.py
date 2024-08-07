from typing import Tuple, List
from appconnections.azureappconnector import azureappconnector
from compliancecowcards.structs import cards
import pandas as pd
from datetime import datetime


class Task(cards.AbstractTask):
    def execute(self) -> dict:
        error = self.check_inputs()
        if error:
            return self.upload_log_file_panic({'Error': error})

        user_auth_data_df, error = self.download_json_file_from_minio_as_df(
            file_url=self.task_inputs.user_inputs.get("AzureADUsersAuthDataPath")
        )
        if error :
            return self.upload_log_file_panic({"Error": f"Error while downloading AzureADUsersAuthData file :: {error}"})

        self.azure_connector = azureappconnector.AzureAppConnector(
            app_url=self.task_inputs.user_object.app.application_url,
            app_port=self.task_inputs.user_object.app.application_port,
            user_defined_credentials=azureappconnector.UserDefinedCredentials.from_dict(
                self.task_inputs.user_object.app.user_defined_credentials
            )
        )

        user_auth_data_df["System"] = "azure"
        user_auth_data_df["Source"] = "compliancecow"
        user_auth_data_df["ResourceType"] = "AD Users"

        # check if list of columns are present in incoming data frame
        columns = {
            "Id": "ResourceID",
            "UserPrincipalName": "ResourceName",
            "IsMfaRegistered": "MFAEnforced",
        }

        columns_set = set(columns.keys())
        if not columns_set.issubset(user_auth_data_df.columns):
            return self.upload_log_file_panic({
                'Error': f"The following required columns are missing in AzureADUsersAuthData file: '{', '.join(columns_set.difference(user_auth_data_df.columns))}'"
            })
        
        user_auth_data_df = user_auth_data_df.rename(columns=columns)

        user_auth_data_df["MFAEnforced"] = user_auth_data_df["MFAEnforced"].fillna(False)

        errors_list: List[dict] = []
        user_auth_data_df[
            [
                "ResourceURL",
                "ComplianceStatus",
                "ComplianceStatusCode",
                "ComplianceStatusReason",
                "ValidationStatusNotes",
                "EvaluatedTime"
            ]
        ] = user_auth_data_df.apply(
            lambda row: self.compute_compliance_status(row, errors_list),
            axis=1
        )

        user_auth_data_df['UserAction'] = ''
        user_auth_data_df['ActionStatus'] = ''
        user_auth_data_df['ActionResponseURL'] = ''

        standard_df = user_auth_data_df[
            [
                "System",
                "Source",
                "ResourceID",
                "ResourceType",
                "ResourceName",
                "ResourceURL",
                "MFAEnforced",
                "ComplianceStatus",
                "ComplianceStatusCode",
                "ComplianceStatusReason",
                "ValidationStatusNotes",
                "EvaluatedTime",
                'UserAction',
                'ActionStatus',
                'ActionResponseURL'
            ]
        ]

        log_file_url = ""
        if errors_list:
            log_file_url, error = self.upload_log_file(error_data=errors_list)
            if error:
                return {'Error': f'Error while uploading LogFile :: {error}'}

        file_url, error = self.upload_output_file(
            output_data=standard_df,
            file_name='AzureADMFAEnabled'
        )
        if error:
            return self.upload_log_file_panic(error)
        
        response = {
            "AzureADMFAEnabled": file_url,
            "LogFile": log_file_url
        }

        return response

    def compute_compliance_status(self, row: pd.Series, errors_list: List[dict]) -> pd.Series:
        if "MFAEnforced" in row and row["MFAEnforced"] == True:
            compliance_status = "COMPLIANT"
            compliance_status_code = "MFA_ENFORCED"
            compliance_status_reason = "MFA is enforced for the user"
            validation_status_notes = "No actions required"
        else:
            compliance_status = "NON_COMPLIANT"
            compliance_status_code = "MFA_NOT_ENFORCED"
            compliance_status_reason = "MFA is not enforced for Active Directory (AD) users"
            validation_status_notes = "MFA Should be enforced"

        evaluated_time = self.azure_connector.get_current_datetime() # Current time

        resource_url, error = self.azure_connector.get_azure_user_url(row["ResourceName"])
        if error:
            errors_list.append({
                'ResourceName': row["ResourceName"],
                'Error': f'Error while getting ResourceURL :: {error}'
            })

        return pd.Series(
            [
                resource_url,
                compliance_status,
                compliance_status_code,
                compliance_status_reason,
                validation_status_notes,
                evaluated_time,
            ]
        )
    
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
        if not self.task_inputs.user_inputs.get("AzureADUsersAuthDataPath"):
            emptyAttrs.append("AzureADUsersAuthDataPath")
        
        return "The following inputs: " + ", ".join(
            emptyAttrs) + " is/are empty, please check the user inputs." if emptyAttrs else ""
