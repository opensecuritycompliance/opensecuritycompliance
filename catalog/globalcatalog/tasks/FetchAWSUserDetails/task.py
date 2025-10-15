from typing import overload
from compliancecowcards.structs import cards
#As per the selected app, we're importing the app package 
from applicationtypes.awsappconnector import awsappconnector
from compliancecowcards.utils import cowdictutils
import json
import uuid
import pandas as pd


class Task(cards.AbstractTask):

    def execute(self) -> dict:

        error_list = self.validate()
        if error_list:
            return self.upload_log_file(error_list)
        
        aws_connector = awsappconnector.AWSAppConnector(
            user_defined_credentials=awsappconnector.UserDefinedCredentials.from_dict(
                self.task_inputs.user_object.app.user_defined_credentials),
        )

        # fetch user list
        users, error_list = aws_connector.list_users()
        if error_list:
            return self.upload_log_file(error_list)
        
        # fetch user - groups, roles, policies and permissions
        users_with_permissions, error_list = self.get_user_details(users, aws_connector)
        if error_list and not users_with_permissions:
            return self.upload_log_file(error_list)
        
        response = {}
        if users_with_permissions:
            file_path, error = self.upload_df_as_parquet_file_to_minio(
             df=pd.json_normalize(users_with_permissions),
             file_name=f"AWSUserDetails-{str(uuid.uuid4())}")
            if error:
                return self.upload_log_file([{"Error" : f"An error occurred while uploading 'AWSUserDetails'. {error}"}])
            response['AWSUserDetails'] = file_path
        if error_list:
            log_file_path, error = self.upload_file_to_minio(file_content=json.dumps(error_list).encode('utf-8'), 
                                                         file_name=f'LogFile-{str(uuid.uuid4())}.json', content_type='application/json')
            if error:
                return self.upload_log_file([{"Error" : f"An error occurred while uploading 'LogFile'. {error}"}])
            response['LogFile'] = log_file_path
        return response
    

    def get_user_details(self, users, app):

        # fetch all policies in aws.
        # This is a master list that contains all aws policies. 
        # Helpful to fetch user group policies, role policies with policy entities
        polices, error_list = app.list_policies("All")
        if error_list:
            return [], error_list
        
        permission_df = pd.DataFrame
        if cowdictutils.is_valid_key(self.task_inputs.user_inputs, "PermissionConfigFile"):
            permission_df, error = self.download_csv_file_from_minio_as_df(
                self.task_inputs.user_inputs.get('PermissionConfigFile'))
            if error:
                return [], [{"Error" : f"Error while downloading 'PermissionConfigFile'. {error}"}]
        
        users_with_permissions = []
        final_error_list = []

        for user in users:
            user_name = user.get('UserName', '')
            if user_name:
                # Fetch user url
                resource_url = ''
                if user_name == "root_account":
                    resource_url = 'N/A'
                else:
                    resource_info_dict = {
                            awsappconnector.RESOURCE_TYPE: awsappconnector.IAM_USER, 
                            awsappconnector.RESOURCE_FIELD: user_name, 
                            awsappconnector.REGION_FIELD: "global",}
                    resource_url, _ = app.get_resource_url(resource_info_dict)

                user_permissions = []
                user_groups = []
                user_roles = []

                # collect all user policies ( directly attached, groups, roles)
                user_polices = []
                # track policies of different ways
                directly_attached_polices = []
                group_policies = []
                role_policies = []

                # Fetch user polices 
                directly_attached_polices, error_list  = app.list_user_policy_names(user_name, polices)
                if error_list:
                    final_error_list.extend(error_list)
                if directly_attached_polices:
                    user_polices.extend(directly_attached_polices)

                # Fetch user groups 
                user_groups, error_list = app.list_groups_for_user(user_name)
                if error_list:
                    final_error_list.extend(error_list)
                
                # Fetch user roles 
                user_roles, error_list = app.list_user_roles(user_name)
                if error_list:
                    final_error_list.extend(error_list)
                
                # Fetch policies that applicable for groups and adding to user policies
                if user_groups:
                    group_policies, error_list = app.list_group_policies(user_groups, polices)
                    if error_list:
                        final_error_list.extend(error_list)
                    if group_policies:
                        user_polices.extend(group_policies)
                
                # Fetch policies that applicable for roles and adding to user policies
                if user_roles:
                    role_policies, error_list = app.list_role_policies(user_roles, polices)
                    if error_list:
                        final_error_list.extend(error_list)
                    if role_policies:
                        user_polices.extend(role_policies)

                # Fetch actions for user policies
                if user_polices:
                    user_permissions, error_list = app.list_action_for_polcies(user_polices, polices)
                    if error_list:
                        final_error_list.extend(error_list)
                
                if user_permissions and not permission_df.empty:
                    user_modified_permissions, _ = app.modify_user_permissions(permission_df, user_permissions)
                    if user_modified_permissions:
                        user_permissions = user_modified_permissions
                
                user_with_permissions = {
                        "System"                        : "aws",
                        "Source"                        : "compliancecow",
                        "ResourceID"                    : user.get('Arn', ''),
                        "ResourceName"                  : user.get('UserName', ''),
                        "ResourceType"                  : "User",
                        "ResourceURL"                   : resource_url,
                        "UserID"                        : user.get('UserId', ''),
                        "CreateDate"                    : app.convert_timestamp(user.get('CreateDate', '')),
                        "PoliciesAttachedDirectly"      : directly_attached_polices if directly_attached_polices else [],
                        "PoliciesAttachedViaGroups"     : group_policies if group_policies else [],
                        "PoliciesAttachedViaRoles"      : role_policies if role_policies else [],
                        "Groups"                        : user_groups if user_groups else [],
                        "Roles"                         : user_roles if user_roles else [],
                        "Permissions"                   : user_permissions if user_permissions else [],
                    }

                users_with_permissions.append(user_with_permissions)
        
        if final_error_list:
            final_error_list = list(set(final_error_list)) 

        return users_with_permissions, final_error_list

    
    def upload_log_file(self, errors_list):
        log_file_path, error = self.upload_file_to_minio(file_content=json.dumps(errors_list).encode('utf-8'), 
                                                         file_name=f'LogFile-{str(uuid.uuid4())}.json', content_type='application/json')
        if error:
            return {'Error': error}
        return {'LogFile': log_file_path}
    

    def validate(self):
        task_inputs = self.task_inputs
        if not task_inputs:
            return [{'Error' : 'Task input is missing'}]
        user_object = task_inputs.user_object
        if not user_object or not user_object.app or not user_object.app.user_defined_credentials:
            return [{'Error' : 'User defined credential is missing'}]