from typing import overload
from compliancecowcards.structs import cards
from appconnections.oktaconnector import oktaconnector
from compliancecowcards.utils import cowdictutils
import json
import uuid
import logging
import pandas as pd




class Task(cards.AbstractTask):

    def execute(self) -> dict:

        error = self.validate()
        if error:
            return self.upload_log_file([{'Error': error}])
        
        okta_connector = oktaconnector.OktaConnector(
            app_url=self.task_inputs.user_object.app.application_url,
            app_port=self.task_inputs.user_object.app.application_port,
            user_defined_credentials=oktaconnector.UserDefinedCredentials.from_dict(
                self.task_inputs.user_object.app.user_defined_credentials)
        )

        users, error = okta_connector.get_users()
        if error:
            return self.upload_log_file([{'Error': error}])
        # handle empty users
        if len(users) == 0:
            return self.upload_log_file([{'Error': "The admin list is empty for the given Okta credentials."}])
        
        standardized_data, error_list = self.update_user_details(users, okta_connector)
        # handle empty users
        if len(standardized_data) == 0:
            return self.upload_log_file([{'Error': "Admin user list is empty for the given Okta credentials."}])

        response = {}

        if standardized_data:
             file_path, error = self.upload_df_as_parquet_file_to_minio(
             df=pd.json_normalize(standardized_data),
             file_name='OktaPrivilegedUserDetails'
             )
             response['OktaPrivilegedUserDetails'] = file_path
        
        if error_list:
            err_dict = self.upload_log_file(error_list)
            if cowdictutils.is_valid_key(err_dict, 'Error'):
                return {'Error': err_dict['Error']}
            if cowdictutils.is_valid_key(err_dict, 'LogFile'):
                response['LogFile'] = err_dict['LogFile']

        return response
    

    def update_user_details(self, user_list: list, app_connector: oktaconnector.OktaConnector):

        error_list = []
        data_list = []

        try:
                # fetch mfa policy details
                policies, error = app_connector.get_policiesv1(type='MFA_ENROLL')  
                if error:
                    error_list.append(f"An error occurred while getting policies for MFA ENROLL: {error}")  
                    return data_list, error_list
                if len(policies) == 0:
                    policies = ["The 'MFA_ENROLL' policy must be enabled to enhance security measures by mandating the use of phishing-resistant authenticators"]
                    return data_list, error_list
                
                # mfa factor assigned policies
                factor_assigned_groups = []
                for policy in policies:
                    if 'conditions' in policy and 'people' in policy['conditions'] and 'groups' in policy['conditions']['people'] and 'include' in policy['conditions']['people']['groups']:
                        ids = policy['conditions']['people']['groups']['include']
                        for id in ids:
                            factor_assigned_groups.append(id)
                    
                for user in user_list:

                    mfa_enabled = False

                    user_name = f"{user.profile.firstName} {user.profile.lastName}"

                    # fetch user role details
                    user_roles, error = app_connector.get_user_roles(user.id)
                    if error:
                            error_list.append(f"Failed to fetch role details for the user - {user_name}: {error}")
                    if len(user_roles) == 0:
                        # Users without roles are not considered admins, so they are ignored.
                        continue        
                    # fetch role permisson
                    user_role_with_permission = []
                    roles = []
                    for role_data in user_roles:
                        role = role_data.label
                        roles.append(role)
                        permissions_details, error = app_connector.get_role_permission(role)
                        if error:
                            error_list.append(f"Failed to fetch permission details for the role - {role}. User included in role: {user_name}")
                        permission_list = []
                        if permissions_details:
                            if 'permissions' in permissions_details:
                                for permission in permissions_details['permissions']:
                                    if 'label' in permission:
                                        permission_list.append(permission['label'])
                                
                        user_role_with_permission.append(
                            {
                                "Role" : role,
                                "Permissions" : ",".join(permission_list) if permission_list else ''
                            }
                        ) 
                    
                    # fetch user group details
                    group_details = []
                    group_ids = []
                    groups, error = app_connector.get_user_groups(user.id)
                    if error:
                        error_list.append(f"Failed to fetch group details for the user - {user_name}: {error}")
                        # get group details of user, but ignore BUILT_IN groups
                    if len(groups) == 0:
                        group_details = ["No groups attached"]  
                    else:    
                        for group in groups:
                                group_details.append(group.profile.name)
                                group_ids.append(group.id)

                    # check user groups comes under mfa factor assigned policies
                    factors_list = [] 
                    user_mfa_grps = []
                    for id in group_ids:
                        if id in factor_assigned_groups:
                            user_mfa_grps.append(id)
                    # getting the factors for user enabled 
                    if user_mfa_grps:
                        mfa_enabled = True
                        for policy in policies:
                            if 'conditions' in policy and 'people' in policy['conditions'] and 'groups' in policy['conditions']['people'] and 'include' in policy['conditions']['people']['groups']:
                                 ids = policy['conditions']['people']['groups']['include']
                                 for id in ids:
                                     if id in group_ids:
                                         if 'settings' in policy and 'factors' in policy['settings']:
                                            factors = policy['settings']['factors']
                                            for factor in factors:
                                                if not factor in factors_list:
                                                    factors_list.append(factor)
                                 

                    user_record = {
                        "System": "okta",
                        "Source": "compliancecow",
                        "ResourceID": user.id,
                        "ResourceName": user_name,
                        "ResourceType": "User",
                        "ResourceLocation": "N/A",
                        "ResourceTags": "N/A",
                        "ResourceURL": f"{app_connector.app_url.rstrip().rstrip('/').replace('.okta', '-admin.okta')}/admin/user/profile/view/{user.id}#tab-account",
                        "UserEmail": user.profile.email,
                        "UserGroups": group_details,
                        "UserRoles": roles,
                        "RolePermission": user_role_with_permission,
                        "MFAEnabled": mfa_enabled,
                        "UserAuthenticationFactors" : factors_list,
                        "ComplianceStatus":"",
                        "ComplianceReason":""
                    }
                    data_list.append(user_record)
                return data_list, error_list
            
        except AttributeError as e:
            logging.exception("AttributeError occured: %s", str(e))
            print("AttributeError occured: %s", str(e))
            error_list.append(f"AttributeError exception occured. Failed to generate a okta privileged user details")
            return data_list, error_list
 
        except IndexError as e:
            logging.exception("IndexError occured: %s", str(e))
            error_list.append(f"IndexError exception occured. Failed to generate a okta privileged user details")
            return data_list, error_list
            
        

    # basic task level validation
    def validate(self):
        task_inputs = self.task_inputs
        if not task_inputs:
            return 'Task input is missing'
        user_object = self.task_inputs.user_object
        if (
            not user_object
            or not user_object.app
            or not user_object.app.user_defined_credentials
        ):
            return 'User defined credential is missing'
        return None
    
    # upload log file 
    def upload_log_file(self, errors_list):
        log_file_path, error = self.upload_file_to_minio(file_content=json.dumps(errors_list).encode('utf-8'), 
                                                         file_name=f'LogFile-{str(uuid.uuid4())}.json', content_type='application/json')
        if error:
            return {'Error': error}
        return {
            'LogFile': log_file_path,
            "ComplianceStatus_": "NOT_DETERMINED", 
            "CompliancePCT_": 0,
            }



