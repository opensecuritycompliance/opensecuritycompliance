from compliancecowcards.structs import cards
from applicationtypes.oktaconnector import oktaconnector
import pandas as pd
import uuid

class Task(cards.AbstractTask):

    def execute(self) -> dict:
        error = self.check_inputs()
        if error:
            log_file_url, error = self.upload_log_file({ 'Error': error })
            if error:
                return { 'Error': error }
            return { "LogFile": log_file_url }

        okta_connector = oktaconnector.OktaConnector(
            app_url=self.task_inputs.user_object.app.application_url,
            app_port=self.task_inputs.user_object.app.application_port,
            user_defined_credentials=oktaconnector.UserDefinedCredentials.from_dict(
                self.task_inputs.user_object.app.user_defined_credentials)
        )

        policies, error = okta_connector.get_policies()
        if error:
            file_url, error = self.upload_log_file({ 'Error': f"Error while getting policies :: {error}" })
            if error:
                return error
            return { "LogFile": file_url }
        
        policies_details_list = []
        errors_list = []
        for policy in policies:
            rules, error = okta_connector.get_policy_rules(policyId=policy.id)
            if error:
                errors_list.append({
                    "Error": f"PolicyID: {policy.id}, PolicyName: {policy.name} - Error occurred while getting policy rules :: {error}"
                })
                continue

            max_session_lifetime_minutes = 0
            if rules:
                max_session_lifetime_minutes = max(
                    rule.actions.signon.session.max_session_lifetime_minutes for rule in rules if rule.status == 'ACTIVE'
                )

            policies_details_list.append({
                "System": "okta",
                "Source": "compliancecow",
                "ResourceID": policy.id,
                "ResourceName": policy.name,
                "ResourceURL": f"{okta_connector.app_url.rstrip().rstrip('/').replace('.okta', '-admin.okta')}/admin/access/policies",
                "ResourceType": "N/A",
                "ResourceLocation": "N/A",
                "ResourceTags": "N/A",
                "PolicyDescription": policy.description,
                "PolicyStatus": policy.status,
                "PolicyIncludedGroups": policy.conditions.people.groups.include,
                "PolicyExcludedGroups": policy.conditions.people.groups.exclude,
                "PolicyIncludedUsers": [],
                "PolicyExcludedUsers": [],
                "MaxSessionLifetimeMinutes": max_session_lifetime_minutes,
                "SigninFrequencyEnabled": True,
                "FrequencyIntervalIsEveryTime": False,
                "PolicyCreationDate": policy.created,
            })

        response = {}

        if errors_list:
            log_file_url, error = self.upload_log_file(errors_list)
            if error:
                return { 'Error': error }
            response["LogFile"] = log_file_url
        
        policies_details_file_url, error = self.upload_output_file(policies_details_list, "OktaSignOnPolicies")
        if error:
            return { 'Error': error }
        
        response["OktaSignOnPolicies"] = policies_details_file_url

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
        file_url, error = self.upload_df_as_parquet_file_to_minio(
            df=pd.json_normalize(output_data),
            file_name=file_name
        )
        if error:
            return None, { 'Error': f"Error while uploading {file_name} file :: {error}" }
        return file_url, None


