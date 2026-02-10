
from datetime import datetime, timedelta, timezone
from io import StringIO
import logging
from typing import overload
import uuid
from compliancecowcards.structs import cards
from compliancecowcards.utils import cowdictutils
#As per the selected app, we're importing the app package 
from applicationtypes.azureappconnector import azureappconnector
import pandas as pd

logger = cards.Logger() # Initializes a Logger instance to log data, use logger.log_data(dict) to log a data

class Task(cards.AbstractTask):

    def execute(self) -> dict:

        permission_config_file = self.task_inputs.user_inputs.get("PermissionConfigFile")
        rows = [] 
        try:
            if permission_config_file:
                cookiedb_file_bytes, error = self.download_file_from_minio(file_url=permission_config_file)
                if not error:
                    rows = self.read_csv_file(cookiedb_file_bytes)
                else:
                    raise Exception(error)
        except Exception as e:
            error = f"Error downloading CSV DB file: {str(e)}"
            log_url, log_error = self.upload_log_file([{ 'Error': error }])
            if log_error:
                return {"error": log_error}
            return {"LogFile": log_url}
       
        app = azureappconnector.AzureAppConnector(
            app_url=self.task_inputs.user_object.app.application_url,
            app_port=self.task_inputs.user_object.app.application_port,
            user_defined_credentials=azureappconnector.UserDefinedCredentials.from_dict(
                self.task_inputs.user_object.app.user_defined_credentials)
        )

        df = pd.DataFrame(rows, columns=['Category', 'ActivityName', 'PermissionScope'])

        inactive_window = self.task_inputs.user_inputs.get("InactivePermissionsWindow")
        
        if not inactive_window:
            log_file_url, error = self.upload_log_file({ 'Error': 'The inactive permission window is empty. Please specific "inactive permission window" below 30 days, as Azure audit logs are only retained for that period.'})
            if error:
                return { 'Error': error }
            return { "LogFile": log_file_url } 

        if inactive_window > 30:
            log_file_url, error = self.upload_log_file({ 'Error': 'The inactive permission window exceeds 30 days. Please specific "inactive permission window" below 30 days, as Azure audit logs are only retained for that period.'})
            if error:
                return { 'Error': error }
            return { "LogFile": log_file_url } 
        
        current_date = datetime.now(timezone.utc)
        from_date = current_date - timedelta(days=inactive_window)
        to_date = current_date  

        if from_date.tzinfo is None:
            from_date = from_date.replace(tzinfo=timezone.utc)

        if to_date.tzinfo is None:
            to_date = to_date.replace(tzinfo=timezone.utc)

        csv_permissions = df[['ActivityName', 'PermissionScope']].set_index('ActivityName')['PermissionScope'].to_dict()
         
        user_manager_df, error = self.download_csv_file_from_minio_as_df(
            self.task_inputs.user_inputs.get('UserManagerDetails'))
        if error:
            return [], [{"Error" : "Error while downloading 'UserManagerDetails'"}]
        users, error = app.list_azure_users()
        if error:
            log_file_url, error = self.upload_log_file({ 'Error': f"Error while getting azure users :: {error}" })
            if error:
                return { 'Error': error }
            return { "LogFile": log_file_url } 

        unused_permissions = []
        response_data = []

        if isinstance(users, list):
            for user in users:
                user_id = self.verify_and_get_dict_value(user, "id")
                user_name = self.verify_and_get_dict_value(user, "mail")
                resource_url, error = app.get_azure_user_url(user_id)
                if error:
                    log_file_url, error = self.upload_log_file({'Error': f"Error while getting Azure user URL for user {user_id}: {error}"})
                    if error:
                        return {'Error': error}
                    return {"LogFile": log_file_url}
                
                manager_name, err  = self.get_manager_for_user(user_manager_df, user_name)
                if err or not manager_name or pd.isna(manager_name):
                    manager_name = "N/A"
                
                user_roles_with_permission, error = app.get_user_role_with_permission(user_id)
                if error:
                    log_file_url, error = self.upload_log_file({'Error': f"Error while fetching user roles and permissions for user {user_id}: {error}"})
                    if error:
                        return {'Error': error}
                    return {"LogFile": log_file_url}
                
                user_permissions = []

                if user_roles_with_permission:
                    for role in user_roles_with_permission:
                        if not 'Permissions' in role:
                            continue
                        user_permissions.extend(role['Permissions'].split(', '))

                    if not user_permissions:
                        continue

                evaluated_time = app.get_current_datetime()

                user_response = {
                    "System": 'azure',
                    "Source": 'compliancecow',
                    "ResourceID": user_id,
                    "ResourceName": user_name,
                    "ResourceType": "User",
                    "ResourceLocation": 'N/A',
                    "ResourceTags": 'N/A',
                    "ResourceURL": resource_url,
                    "UnusedPermissions": [],
                    "InactivePermissionsWindow"  : inactive_window,
                    "Manager"                    : manager_name,
                    "ValidationStatusCode": "N/A",  
                    "ValidationStatusNotes": "N/A",  
                    "ComplianceStatus": "N/A", 
                    "ComplianceStatusReason": "N/A", 
                    "EvaluatedTime": evaluated_time,
                    "UserAction": "",
                    "ActionStatus": "",
                    "ActionResponseURL": "",
                    "UserFormID"                    : "",
                    "UserFormStatus"                : "",
                    "ManagerFormID"                 : "",
                    "ManagerFormStatus"             : "",
                    "CountOfUnusedPermissionsToBeDeleted" : 0,
                    "ActionUnusedPermissionsToDelete" : "",
                    "RecordID": ""
                }
            
                user_logs, error = app.get_audit_logs_for_user(user_id, from_date, to_date)
                if error:
                    log_file_url, error = self.upload_log_file({'Error': f"Error while fetching audit logs for user {user_id}: {error}"})
                    if error:
                        return {'Error': error}
                    return {"LogFile": log_file_url}

                if user_logs and isinstance(user_logs, list):
                    log_activity_names = [log['activityDisplayName'] for log in user_logs if 'activityDisplayName' in log]

                    for permission in csv_permissions.values():
                        if permission not in user_permissions:
                            user_response["UnusedPermissions"].append(permission)
                        else:
                            matching_activities = [activity for activity, perm_scope in csv_permissions.items() if perm_scope == permission]
                            activity_found = False
                            for activity in matching_activities:
                                if activity in log_activity_names:
                                    activity_found = True
                                    break
                            if not activity_found:
                                user_response["UnusedPermissions"].append(permission)    


                if len(user_response["UnusedPermissions"]) == 0:
                    user_response["ValidationStatusCode"] = "UNUSED_PERM_NOT_PRESENT"
                    user_response["ValidationStatusNotes"] = "Unused permission(s) not present"
                    user_response["ComplianceStatus"] = "COMPLIANT"
                    user_response["ComplianceStatusReason"] = (
                        f"The record is compliant because unused permissions are not present for a user - {user_name}. "
                        "Hence managing and auditing permissions becomes easier and more efficient, as it eliminates "
                        "redundant access rights and focuses on relevant roles and responsibilities."
                    )

                else:
                    user_response["ValidationStatusCode"] = "UNUSED_PERM_PRESENT"
                    user_response["ValidationStatusNotes"] = "Unused permission(s) present"
                    user_response["ComplianceStatus"] = "NON_COMPLIANT"
                    user_response["ComplianceStatusReason"] = (
                        f"The record is non-compliant because {len(user_response['UnusedPermissions'])} unused permissions are present "
                        f"for a user - {user_name}. Unused permissions can create potential vulnerabilities in your system, "
                        "as they might be exploited by malicious actors if they gain access."
                    )
                    unused_permissions.extend(user_response["UnusedPermissions"])

                response_data.append(user_response)

        response = {}
        users_file_url, error = self.upload_output_file(response_data, "AzureUnusedPermissionReport")
        if error:
            return { 'Error': error }
        
        response["AzureUnusedPermissionReport"] = users_file_url
        
        return response      

    def upload_log_file(self, error_data):
        if not isinstance(error_data, list):
            error_data = [error_data]
        file_url, error = self.upload_file_to_minio(
            file_content=error_data,
            file_name=f"LogFile-{str(uuid.uuid4())}.json",
            content_type="application/json"
        )
        if error:
            return None, {'Error': f"Error while uploading LogFile :: {error}"}
        return file_url, None
    
    def verify_and_get_dict_value(self, mdict: dict, key: str):
        return mdict[key] if cowdictutils.is_valid_key(mdict, key) else ""
    
    def read_csv_file(self, file_bytes):
        input_payload = file_bytes.decode('utf-8')
        if input_payload:
            df = pd.read_csv(StringIO(input_payload))
            return df.values.tolist()
        else:
            error_msg = "The uploaded CookieDBFile is empty. Please make sure to upload a non-empty CookieDBFile and provide the CookieDBFile."
            logging.error(error_msg)
            return []

    def upload_output_file(self, output_data, file_name):
        if not output_data:
            return None, None

        df = pd.DataFrame(output_data)

        file_url, error = self.upload_df_as_parquet_file_to_minio(
            df=df,
            file_name=file_name
        )
        if error:
            return None, { 'Error': f"Error while uploading {file_name} file :: {error}" }
        return file_url, None
    
    def get_manager_for_user(self, df, target_user):
        try:    
            if 'User' not in df.columns or 'Manager' not in df.columns:
                return None, "CSV file must contain 'Users' and 'Manager' columns."
            for _, row in df.iterrows():
                users_list = row['User'].split(',')
                if target_user in users_list:
                    return row['Manager'], None
            return None, f"No manager found for user '{target_user}'."   
        except Exception as e:
            return None, str(e)    