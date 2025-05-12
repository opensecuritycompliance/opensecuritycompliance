
from typing import overload
from compliancecowcards.structs import cards
#As per the selected app, we're importing the app package 
from applicationtypes.azureappconnector import azureappconnector
import json
import uuid
import pandas as pd
import logging
from compliancecowcards.utils import cowdictutils


class Task(cards.AbstractTask):

    def execute(self) -> dict:

        error = self.validate()
        if error:
            return self.upload_log_file([{'Error': error}])
        
        app_connector = azureappconnector.AzureAppConnector(
            app_url=self.task_inputs.user_object.app.application_url,
            app_port=self.task_inputs.user_object.app.application_port,
            user_defined_credentials=azureappconnector.UserDefinedCredentials.from_dict(
                self.task_inputs.user_object.app.user_defined_credentials)
        )

        # fetch user registration details
        user_registration_details, error = app_connector.get_user_registration_details()
        if error:
            return self.upload_log_file([{'Error': error}])
        user_registration_details_dict = (pd.json_normalize(user_registration_details)).to_dict(orient="records")

        standard_report, error_details = self.get_standard_report(user_registration_details_dict, app_connector)

        response = {}
        if standard_report:
             file_path, error = self.upload_df_as_parquet_file_to_minio(
             df=pd.json_normalize(standard_report),
             file_name=f"IntunePrivilegedUserDetails-{str(uuid.uuid4())}"
             )
             if error:
                 return self.upload_log_file(error)
             response['IntunePrivilegedUserDetails'] = file_path

        if error_details:
            log_response = self.upload_log_file(error_details)
            if cowdictutils.is_valid_key(log_response, 'Error'):
                response['Error'] = log_response['Error']
            elif cowdictutils.is_valid_key(log_response, 'LogFile'):
                response['LogFile'] = log_response['LogFile']
                
        return response
    
    
    def get_standard_report(self, user_registration_details_dict, app_connector: azureappconnector.AzureAppConnector):

        standard_report = []
        error_list = []
        try:
            for user in user_registration_details_dict:
            
                if user['isAdmin'] == False:
                   continue
                user_id = user['id']
                # fetch resource url
                resource_url, _ = app_connector.get_azure_user_url(user_id)
                # roles 
                roles, err = app_connector.get_user_role_assignments(user_id)
                if err:
                    error_list.append(err)
                # groups
                groups, err = app_connector.get_user_groups(user_id)
                if err:
                    error_list.append(err)

                user_record = {
                            "System": "intune",
                            "Source": "compliancecow",
                            "ResourceID": user['id'],
                            "ResourceName": user['userDisplayName'],
                            "ResourceType": "User",
                            "ResourceLocation": "N/A",
                            "ResourceTags": "N/A",
                            "ResourceURL": resource_url if resource_url else '',
                            "UserEmail": user['userPrincipalName'],
                            "UserGroups":  groups if not groups is None else [],
                            "UserRoles": roles if not roles is None else [],
                            "MFAEnabled": user['isMfaRegistered'],
                            "UserAuthenticationFactors" : user['methodsRegistered']
                        }
                standard_report.append(user_record)
                
            return standard_report, error_list
            
        except KeyError as e:
                logging.exception("A keyError exception occurred while standardizing data for user - %s: %s", user['userDisplayName'], str(e))
                error_list.append(f"Failed to standardize data for user - {user['userDisplayName']}. {azureappconnector.SUPPORT_MSG}")
                return standard_report, error_list
        
    def upload_log_file(self, errors_list):
        log_file_path, error = self.upload_file_to_minio(file_content=json.dumps(errors_list).encode('utf-8'), 
                                                         file_name=f'LogFile-{str(uuid.uuid4())}.json', content_type='application/json')
        if error:
            return {'Error': error}
        return {'LogFile': log_file_path}
    
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
