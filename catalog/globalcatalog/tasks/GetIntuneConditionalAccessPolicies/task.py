from compliancecowcards.structs import cards
from applicationtypes.azureappconnector import azureappconnector
from compliancecowcards.utils import cowdictutils
import pandas as pd
import uuid

class Task(cards.AbstractTask):

    def execute(self) -> dict:
        error = self.check_inputs()
        if error:
            log_file_url, error = self.upload_log_file({ 'error': error })
            if error:
                return { 'error': error }
            return { "LogFile": log_file_url }
        
        azure_connector = azureappconnector.AzureAppConnector(
            app_url=self.task_inputs.user_object.app.application_url,
            app_port=self.task_inputs.user_object.app.application_port,
            user_defined_credentials=azureappconnector.UserDefinedCredentials.from_dict(
                self.task_inputs.user_object.app.user_defined_credentials)
        )

        policies, error = azure_connector.list_azure_conditional_access_policies()
        if error:
            log_file_url, error = self.upload_log_file({ 'error': f"Error while getting Intune logs :: {error}" })
            if error:
                return { 'error': error }
            return { "LogFile": log_file_url }
        
        policies_list = []
        if isinstance(policies, list):
            for policy in policies:
                policy_state = self.verify_and_get_dict_value(policy, "state")
                policy_id = self.verify_and_get_dict_value(policy, "id")

                policy_data = {
                    "System": "intune",
                    "Source": "compliancecow",
                    "ResourceID": policy_id,
                    "ResourceName": self.verify_and_get_dict_value(policy, "displayName"),
                    "ResourceURL": f"https://portal.azure.com/#view/Microsoft_AAD_ConditionalAccess/PolicyBlade/policyId/{policy_id}",
                    "ResourceType": "N/A",
                    "ResourceLocation": "N/A",
                    "ResourceTags": "N/A",
                    "PolicyStatus": "ACTIVE" if policy_state == "enabled" else "INACTIVE",
                    "PolicyIncludedGroups": [],
                    "PolicyExcludedGroups": [],
                    "PolicyIncludedUsers": [],
                    "PolicyExcludedUsers": [],
                    "MaxSessionLifetimeMinutes": None,
                    "SigninFrequencyEnabled": False,
                    "FrequencyIntervalIsEveryTime": False,
                    "PolicyCreationDate": self.verify_and_get_dict_value(policy, "createdDateTime"),
                }

                policy_conditions = self.verify_and_get_dict_value(policy, "conditions")
                if not policy_conditions:
                    policies_list.append(policy_data)
                    continue

                policy_users_conditions = self.verify_and_get_dict_value(policy_conditions, "users")
                if not policy_users_conditions:
                    policies_list.append(policy_data)
                    continue

                policy_data.update({
                    "PolicyIncludedGroups": policy_users_conditions["includeGroups"] if cowdictutils.is_valid_key(policy_users_conditions, "includeGroups") else [],
                    "PolicyExcludedGroups": policy_users_conditions["excludeGroups"] if cowdictutils.is_valid_key(policy_users_conditions, "excludeGroups") else [],
                    "PolicyIncludedUsers": policy_users_conditions["includeUsers"] if cowdictutils.is_valid_key(policy_users_conditions, "includeUsers") else [],
                    "PolicyExcludedUsers": policy_users_conditions["excludeUsers"] if cowdictutils.is_valid_key(policy_users_conditions, "excludeUsers") else [],
                })

                policy_session_controls = self.verify_and_get_dict_value(policy, "sessionControls")
                if not policy_session_controls:
                    policies_list.append(policy_data)
                    continue

                policy_signin_frequency = self.verify_and_get_dict_value(policy_session_controls, "signInFrequency")
                if not policy_signin_frequency:
                    policies_list.append(policy_data)
                    continue

                frequency_is_enabled = policy_signin_frequency["isEnabled"] if cowdictutils.is_valid_key(policy_signin_frequency, "isEnabled") else False
                freqency_interval_type = self.verify_and_get_dict_value(policy_signin_frequency, "frequencyInterval")
                
                policy_data.update({
                    "SigninFrequencyEnabled": frequency_is_enabled,
                    "FrequencyIntervalIsEveryTime": freqency_interval_type == 'everyTime',
                })

                policy_signin_frequency_type = self.verify_and_get_dict_value(policy_signin_frequency, "type")
                policy_signin_frequency_value = policy_signin_frequency["isEnabled"] if cowdictutils.is_valid_key(policy_signin_frequency, "value") else -1
                if not policy_signin_frequency_type or policy_signin_frequency_value < 0:
                    policies_list.append(policy_data)
                    continue

                minutes_convertion_mult_val = 60 if policy_signin_frequency_type == "hours" else 60*24 if policy_signin_frequency_type == "days" else 0
                if not minutes_convertion_mult_val:
                    policies_list.append(policy_data)
                    continue

                max_session_lifetime_minutes = int(policy_signin_frequency_value) * minutes_convertion_mult_val
                policy_data.update({
                    "MaxSessionLifetimeMinutes": max_session_lifetime_minutes,
                })
                policies_list.append(policy_data)

        policies_file_url, error = self.upload_output_file(policies_list, "IntuneConditionalAccessPolicies")
        if error:
            return { 'error': error }

        response = {
            "IntuneConditionalAccessPolicies": policies_file_url
        }

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
            return None, {'error': f"Error while uploading LogFile :: {error}"}
        return file_url, None
    
    def upload_output_file(self, output_data, file_name):
        file_url, error = self.upload_df_as_parquet_file_to_minio(
            df=pd.json_normalize(output_data),
            file_name=file_name
        )
        if error:
            return None, { 'error': f"Error while uploading {file_name} file :: {error}" }
        return file_url, None
    