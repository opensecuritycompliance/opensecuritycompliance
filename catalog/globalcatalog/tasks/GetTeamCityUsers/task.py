
from typing import Tuple
from compliancecowcards.structs import cards
#As per the selected app, we're importing the app package 
from applicationtypes.teamcityconnector import teamcityconnector
import pandas as pd
import uuid


class Task(cards.AbstractTask):

    def execute(self) -> dict:

        error = self.check_inputs()
        if error:
            return self.upload_log_file_panic({ 'Error': error })

        app = teamcityconnector.TeamCityConnector(
            app_url=self.task_inputs.user_object.app.application_url,
            app_port=self.task_inputs.user_object.app.application_port,
            user_defined_credentials=teamcityconnector.UserDefinedCredentials.from_dict(
                self.task_inputs.user_object.app.user_defined_credentials)
        )

        users_response, error = app.list_users()
        if error:
            if 'error' in error:
                error['Error'] = error.pop('error')
            return self.upload_log_file_panic(error)
        
        users = users_response.get('user', [])
        users_data = []
        errors_list = []
        for user in users:
            user_details, error = app.get_user(user.get('id'))
            if error:
                errors_list.append({
                    "Error": f"UserName: {user.get('username', '')} - Error occurred while fetching user with id: {user.get('id', '')}"
                })

            # Get user groups
            group_data = user_details.get("groups", {})
            user_groups = group_data.get('group', [])
            groups_list = []
            for group in user_groups:
                groups_list.append({
                    "GroupKey": group.get("key", ""),
                    "GroupName": group.get("name", "")
                })

            # Get user roles
            role_data = user_details.get("roles", {})
            user_roles = role_data.get('role', [])
            roles_list = []
            for role in user_roles:
                role_id = role.get('roleId', '')
                if role_id:
                    roles_list.append(role_id)

            user_data = {
                "System": "teamcity",
                "Source": "compliancecow",
                "ResourceID": user_details.get("id", ""),
                "ResourceName": user_details.get("username", ""),
                "ResourceType": "User",
                "ResourceLocation": "N/A",
                "ResourceTags": "N/A",
                "ResourceURL": f"{app.app_url.rstrip().rstrip('/')}/admin/editUser.html?userId={user_details.get('id', '')}",
                "UserName": user_details.get('name', ''),
                "UserEmail": user_details.get('email', ''),
                "UserGroups": groups_list,
                "UserIsAdmin": True if roles_list else False,
                "UserRoles": roles_list,
                "UserAction": "",
                "ActionStatus": "",
                "ActionResponseURL": ""
            }

            users_data.append(user_data)
        
        response = {}
        if errors_list:
            log_file_url, error = self.upload_log_file(errors_list)
            if error: return error

            response["LogFile"] = log_file_url

        output_file_url, error = self.upload_output_file(users_data, "TeamCityUsers")
        if error: return error

        response['TeamCityUsers'] = output_file_url

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
    
    def upload_log_file(self, error_data) -> Tuple[str, dict]:
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
    
    def upload_log_file_panic(self, error_data) -> dict:
        file_url, error = self.upload_log_file(error_data)
        if error:
            return error
        return { 'LogFile': file_url }
    
    def upload_output_file(self, output_data, file_name) -> Tuple[str, dict]:
        if not output_data:
            return None, None
        
        file_url, error = self.upload_df_as_parquet_file_to_minio(
            df=pd.DataFrame(output_data),
            file_name=file_name
        )
        if error:
            return None, { 'Error': f"Error while uploading {file_name} file :: {error}" }
        return file_url, None
