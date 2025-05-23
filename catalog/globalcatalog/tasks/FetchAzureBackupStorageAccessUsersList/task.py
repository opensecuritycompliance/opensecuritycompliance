
from typing import Tuple, List
from compliancecowcards.structs import cards
#As per the selected app, we're importing the app package 
from applicationtypes.azureappconnector import azureappconnector
import pandas as pd
import re

class PermissionStatus:
    PERMISSION_DENIED = 0
    PERMISSION_ALLOWED_SPECIFIC = 1
    PERMISSION_ALLOWED_ALL = 2


class Task(cards.AbstractTask):

    def execute(self) -> dict:

        error = self.check_inputs()
        if error:
            return self.upload_log_file_panic({'Error': error})

        self.app = azureappconnector.AzureAppConnector(
            app_url=self.task_inputs.user_object.app.application_url,
            app_port=self.task_inputs.user_object.app.application_port,
            user_defined_credentials=azureappconnector.UserDefinedCredentials.from_dict(
                self.task_inputs.user_object.app.user_defined_credentials)
        )
        
        storage_accounts_df, error = self.download_json_file_from_minio_as_df(self.task_inputs.user_inputs.get("AzureStorageAccountsData"))
        if error:
            return self.upload_log_file_panic({'Error': f'Error while downloading AzureStorageAccountsData :: {error}'})
        
        # Filter Storage Accounts that match the regex pattern
        backup_storage_regex_pattern = self.task_inputs.user_inputs.get("BackupStorageRegexPattern")
        if backup_storage_regex_pattern:
            storage_accounts_df = storage_accounts_df[storage_accounts_df["Name"].str.contains(backup_storage_regex_pattern, regex=True)]

        role_assignments_df, error = self.download_json_file_from_minio_as_df(self.task_inputs.user_inputs.get("AzureRoleAssignmentsData", ""))
        if error:
            return self.upload_log_file_panic({'Error': f'Error while downloading AzureRoleAssignmentsData :: {error}'})
        
        user_role_assignments_df = role_assignments_df[role_assignments_df.get("ResourceType") == "User"]
        
        users_df, error = self.download_json_file_from_minio_as_df(self.task_inputs.user_inputs.get("AzureUsersList"))
        if error:
            return self.upload_log_file_panic({'Error': f'Error while downloading AzureUsersList :: {error}'})
        
        output_df = pd.DataFrame()
        for _, user_row in users_df.iterrows():
            standardized_user_report = self.get_standardized_report_for_user(user_row, user_role_assignments_df, storage_accounts_df)
            output_df = pd.concat([output_df, standardized_user_report], ignore_index=True)

        file_url, error = self.upload_df_as_parquet_file_to_minio(output_df, "AzureBackupStorageAccessUsersList")
        if error:
            return error

        response = {
            "AzureBackupStorageAccessUsersList": file_url
        }

        return response
    
    def get_standardized_report_for_user(self, user_row: pd.Series, user_role_assignments_df: pd.DataFrame, storage_accounts_df: pd.DataFrame) -> pd.DataFrame:
        role_assignments_for_user_df: pd.DataFrame = user_role_assignments_df[user_role_assignments_df.get("ResourceID") == user_row.get("ResourceID")]

        resource_url, _ = self.app.get_azure_user_url(user_id=user_row.get("ResourceID"))

        user_records_list: List[dict] = []
        init_user_record = {
            "System": "azure",
            "Source": "compliancecow",
            "ResourceID": user_row.get("ResourceID"),
            "ResourceName": user_row.get("UserPrincipalName"),
            "ResourceType": "User",
            "ResourceURL": resource_url,
            "StorageAccount": "",
            "StorageAccountURL": "",
            "Permissions": "",
            "DataPermissions": "",
            "Scope": "",
            "ValidationStatusCode": "WR_N_AC",
            "ValidationStatusNotes": "No review required. User does not have write access to any Backup Storage Account.",
            "ComplianceStatus": "",
            "ComplianceStatusReason": "",
            "EvaluatedTime": self.app.get_current_datetime(),
            "UserAction": "",
            "ActionStatus": "",
            "ActionResponseURL": ""
        }

        if not role_assignments_for_user_df.empty:
            allowed_storage_accounts_df = pd.DataFrame()
            for _, role_assignments_row in role_assignments_for_user_df.iterrows():
                permissions = role_assignments_row.get("Permissions")
                allowed_permissions, allowed_data_permissions = self.get_storage_write_permissions(permissions)
                if allowed_permissions or allowed_data_permissions:
                    scope = role_assignments_row.get("Scope", "")
                    new_allowed_storage_accounts_df = storage_accounts_df[storage_accounts_df.get("Id", "").str.contains(scope)].copy()
                    
                    if not new_allowed_storage_accounts_df.empty:
                        new_allowed_storage_accounts_df["Permissions"] = [allowed_permissions] * len(new_allowed_storage_accounts_df)
                        new_allowed_storage_accounts_df["DataPermissions"] = [allowed_data_permissions] * len(new_allowed_storage_accounts_df)
                        new_allowed_storage_accounts_df["Scope"] = [scope] * len(new_allowed_storage_accounts_df)
                        allowed_storage_accounts_df = pd.concat([allowed_storage_accounts_df, new_allowed_storage_accounts_df])

            if not allowed_storage_accounts_df.empty:
                unique_allowed_storage_account_names = allowed_storage_accounts_df.get("Name").drop_duplicates()
                for storage_account_name in unique_allowed_storage_account_names:
                    storage_account_df: pd.DataFrame = allowed_storage_accounts_df[allowed_storage_accounts_df.get("Name") == storage_account_name]

                    storage_account_allowed_permissions = []
                    storage_account_allowed_data_permissions = []

                    if not storage_account_df.empty:
                        for _, storage_account_row in storage_account_df.iterrows():
                            storage_account_allowed_permissions.extend(storage_account_row.get("Permissions", []))
                            storage_account_allowed_data_permissions.extend(storage_account_row.get("DataPermissions", []))
                            
                        user_record = init_user_record.copy()
                        user_record.update({
                            "StorageAccount": storage_account_name,
                            "StorageAccountURL": storage_account_df.iloc[0].get("ResourceURL", ""),
                            "Permissions": ", ".join(list(set(storage_account_allowed_permissions))),
                            "DataPermissions": ", ".join(list(set(storage_account_allowed_data_permissions))),
                            "Scope": storage_account_row.get("Scope"),
                            "ValidationStatusCode": "WR_AC_ND_RW",
                            "ValidationStatusNotes": f"Review Required. User has write access to '{storage_account_name}' Storage Account."
                        })
                        user_records_list.append(user_record)

        if not user_records_list:
            user_records_list.append(init_user_record)
            
        return pd.DataFrame(user_records_list)
    
    def get_storage_write_permissions(self, permissions: list) -> Tuple[List[str], List[str]]:
        allowed_permissions = []
        allowed_data_permissions = []
        for permission_detail in permissions:
            actions = permission_detail.get('actions', [])
            not_actions = permission_detail.get('notActions', [])
            data_actions = permission_detail.get('dataActions', [])
            not_data_actions = permission_detail.get('notDataActions', [])

            new_allowed_permissions = self.get_allowed_permissions_from_actions(actions, not_actions)
            if new_allowed_permissions:
                allowed_permissions.extend(new_allowed_permissions)

            new_allowed_data_permissions = self.get_allowed_permissions_from_actions(data_actions, not_data_actions)
            if new_allowed_data_permissions:
                allowed_data_permissions.extend(new_allowed_data_permissions)

        return allowed_permissions, allowed_data_permissions

    def get_allowed_permissions_from_actions(self, actions: list, not_actions: list) -> list:
        allowed_permissions = []
        if actions:
            for action in actions:
                action_permission_status: PermissionStatus = self.get_permission_status(action)
                if action_permission_status == PermissionStatus.PERMISSION_ALLOWED_SPECIFIC:
                    allowed_permissions.append(action)
                elif action_permission_status == PermissionStatus.PERMISSION_ALLOWED_ALL:
                    permission_to_check = "*/" if action == "*" else action.rstrip("*")
                    blacklist_permissions = {
                        permission_to_check + "write",
                        permission_to_check + "delete",
                        permission_to_check + "action"
                    }

                    if not blacklist_permissions.issubset(not_actions):
                        allowed_permissions.append(action)

        return allowed_permissions
    
    def get_permission_status(self, permission: str) -> PermissionStatus:
        if not permission:
            return PermissionStatus.PERMISSION_DENIED
        if re.match(r"Microsoft\.(.+)\/storageAccounts.*\/(write|delete|action)", permission) or re.match(r"^\*\/(write|delete|action)$", permission):
            return PermissionStatus.PERMISSION_ALLOWED_SPECIFIC
        if permission == "*" or re.match(r"Microsoft\.(.+)\/storageAccounts.*\/(\*)", permission):
            return PermissionStatus.PERMISSION_ALLOWED_ALL
        return PermissionStatus.PERMISSION_DENIED
    
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
        
        file_url, error = self.upload_df_as_parquet_file_to_minio(
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
        if not self.task_inputs.user_inputs.get("AzureStorageAccountsData"):
            emptyAttrs.append("AzureStorageAccountsData")
        if not self.task_inputs.user_inputs.get("AzureRoleAssignmentsData"):
            emptyAttrs.append("AzureRoleAssignmentsData")
        if not self.task_inputs.user_inputs.get("AzureUsersList"):
            emptyAttrs.append("AzureUsersList")
        if not self.task_inputs.user_inputs.get("BackupStorageRegexPattern"):
            emptyAttrs.append("BackupStorageRegexPattern")
        
        return "The following inputs: " + ", ".join(
            emptyAttrs) + " is/are empty" if emptyAttrs else ""
