from compliancecowcards.structs import cards
from applicationtypes.azureappconnector import azureappconnector
from compliancecowcards.utils import cowdictutils
import pandas as pd
import uuid
from datetime import datetime


class Task(cards.AbstractTask):

    def execute(self) -> dict:

        error = self.check_inputs()
        if error:
            log_file_url, error = self.upload_log_file({ 'Error': error })
            if error:
                return { 'Error': error }
            return { "LogFile": log_file_url }

        azure_connector = azureappconnector.AzureAppConnector(
            app_url=self.task_inputs.user_object.app.application_url,
            app_port=self.task_inputs.user_object.app.application_port,
            user_defined_credentials=azureappconnector.UserDefinedCredentials.from_dict(
                self.task_inputs.user_object.app.user_defined_credentials)
        )

        users, error = azure_connector.list_azure_users()
        if error:
            log_file_url, error = self.upload_log_file({ 'Error': f"Error while getting azure users :: {error}" })
            if error:
                return { 'Error': error }
            return { "LogFile": log_file_url }
        
        users_list = []
        admin_users_list = []
        errors_list = []
        if isinstance(users, list):
            for user in users:
                user_id = self.verify_and_get_dict_value(user, "id")
                user_name = self.verify_and_get_dict_value(user, "displayName")

                user_memberships, error = azure_connector.list_azure_user_memberships(user_id)
                if error:
                    errors_list.append({
                        "Error": f"UserID: {user_id}, UserName: {user_name} - Error occurred while getting user memberships :: {error}"
                    })
                    continue

                user_group_details = [group for group in user_memberships if self.verify_and_get_dict_value(group, "@odata.type") == "#microsoft.graph.group"]
                user_groups = [{
                    "GroupID": self.verify_and_get_dict_value(group, "id"),
                    "GroupName": self.verify_and_get_dict_value(group, "displayName")
                } for group in user_group_details]

                user_roles = [self.verify_and_get_dict_value(role, "displayName") for role in user_memberships if self.verify_and_get_dict_value(role, "@odata.type") == "#microsoft.graph.directoryRole"]
                is_user_admin = len(user_roles) > 0

                user_details = {
                    "System": "intune",
                    "Source": "compliancecow",
                    "ResourceID": user_id,
                    "ResourceName": self.verify_and_get_dict_value(user, "displayName"),
                    "ResourceType": "User",
                    "ResourceLocation": "N/A",
                    "ResourceTags": "N/A",
                    "ResourceURL": f"https://portal.azure.com/#view/Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/overview/userId/{user_id}",
                    "UserEmail": self.verify_and_get_dict_value(user, "userPrincipalName"),
                    "UserGroups": user_groups,
                    "UserIsAdmin":is_user_admin,
                    "UserAdminRoles": user_roles,
                }

                users_list.append(user_details)

                if is_user_admin:
                    admin_users_list.append(user_details)
        else:
            log_file_url, error = self.upload_log_file({ 'Error': "Users data is not readable" })
            if error:
                return { 'Error': error }
            return { "LogFile": log_file_url }
        
        response = {}

        if errors_list:
            log_file_url, error = self.upload_log_file(errors_list)
            if error:
                return { 'Error': error }
            response["LogFile"] = log_file_url

        users_file_url, error = self.upload_output_file(users_list, "IntuneUsers")
        if error:
            return { 'Error': error }

        admin_users_file_url, error = self.upload_output_file(admin_users_list, "IntuneAdminUsers")
        if error:
            return { 'Error': error }
        
        response.update({
            "IntuneUsers": users_file_url,
            "IntuneAdminUsers": admin_users_file_url,
        })

        return response
    
    def check_inputs(self):
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
    
    def verify_and_get_dict_value(self, mdict: dict, key: str):
        return mdict[key] if cowdictutils.is_valid_key(mdict, key) else ""
    
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
    
    def upload_output_file(self, output_data, file_name):
        if not output_data:
            return None, None
        
        file_url, error = self.upload_df_as_parquet_file_to_minio(
            df=pd.json_normalize(output_data),
            file_name=file_name
        )
        if error:
            return None, { 'Error': f"Error while uploading {file_name} file :: {error}" }
        return file_url, None
    
    def get_current_datetime(self):
        current_time = datetime.utcnow()
        formatted_time = current_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        return formatted_time
