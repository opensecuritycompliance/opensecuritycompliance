from compliancecowcards.structs import cards
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
        
        policies_df, error = self.download_parquet_file_from_minio_as_df(self.task_inputs.user_inputs.get("PoliciesData"))
        if error:
            log_file_url, error = self.upload_log_file({ 'Error': f"Error while downloading PoliciesData file :: {error}" })
            if error:
                return { 'Error': error }
            return { "LogFile": log_file_url }
        
        # check if PoliciesData contains required columns
        if not policies_df.empty:
            policy_columns = [
                'System',
                'Source',
                'ResourceID',
                'ResourceName',
                'ResourceURL',
                'ResourceType',
                'ResourceLocation',
                'ResourceTags',
                'PolicyStatus',
                'PolicyIncludedGroups',
                'PolicyExcludedGroups',
                'PolicyIncludedUsers',
                'PolicyExcludedUsers',
                'MaxSessionLifetimeMinutes',
                'SigninFrequencyEnabled',
                'FrequencyIntervalIsEveryTime',
                'PolicyCreationDate',
            ]
            for column in policy_columns:
                if column not in policies_df.columns:
                    log_file_url, error = self.upload_log_file({ 'Error': f"Invalid PoliciesData file, please check." })
                    if error:
                        return { 'Error': error }
                    return { "LogFile": log_file_url }
        else:
            log_file_url, error = self.upload_log_file({ 'Error': f"PoliciesData file has no content." })
            if error:
                return { 'Error': error }
            return { "LogFile": log_file_url }
        
        admin_users_df, error = self.download_parquet_file_from_minio_as_df(self.task_inputs.user_inputs.get("AdminUsersData"))
        if error:
            log_file_url, error = self.upload_log_file({ 'Error': f"Error while downloading AdminUsersData file :: {error}" })
            if error:
                return { 'Error': error }
            return { "LogFile": log_file_url }
        
        # check if AdminUsersData contains required columns
        if not admin_users_df.empty:
            user_columns = [
                'System',
                'Source',
                'ResourceID',
                'ResourceName',
                'ResourceType',
                'ResourceLocation',
                'ResourceTags',
                'ResourceURL',
                'UserEmail',
                'UserGroups',
                'UserIsAdmin',
                'UserAdminRoles'
            ]
            
            for column in user_columns:
                if column not in admin_users_df.columns:
                    log_file_url, error = self.upload_log_file({ 'Error': f"Invalid AdminUsersData file, please check." })
                    if error:
                        return { 'Error': error }
                    return { "LogFile": log_file_url }
        else:
            log_file_url, error = self.upload_log_file({ 'Error': f"AdminUsersData file has no content." })
            if error:
                return { 'Error': error }
            return { "LogFile": log_file_url }

        allowed_session_lifetime_minutes = int(self.task_inputs.user_inputs.get("AllowedSessionLifetimeMinutes"))
        
        # get ACTIVE policies
        active_policies_df = policies_df[
            (policies_df.get("PolicyStatus") == "ACTIVE") &
            (policies_df.get("SigninFrequencyEnabled") == True)
        ]

        # get policies with FrequencyIntervalIsEveryTime option
        compliant_policies_1_df = active_policies_df[
            policies_df.get("FrequencyIntervalIsEveryTime") == True
        ]
        compliant_policies_1_list = compliant_policies_1_df.to_dict(orient="records")

        # get policies with MaxSessionLifetimeMinutes less than or equal to AllowedSessionLifetimeMinutes
        compliant_policies_2_df = active_policies_df[
                (policies_df.get("MaxSessionLifetimeMinutes") is not None) &
                (policies_df.get("MaxSessionLifetimeMinutes") <= allowed_session_lifetime_minutes) &
                (policies_df.get("MaxSessionLifetimeMinutes") > 0)
        ]
        compliant_policies_2_list = compliant_policies_2_df.to_dict(orient="records")

        # combine compliant policies
        compliant_policies_list = compliant_policies_1_list + compliant_policies_2_list
        # handle empty compliant policies
        if len(compliant_policies_list) == 0:
            log_file_url, error = self.upload_log_file([{ 'Error': 'No policy was found with the MaxSessionLifetime requirement.'}])
            if error:
                return { 'Error': error }
            return { "LogFile": log_file_url }


        admin_users_list = admin_users_df.to_dict(orient="records")

        output_records_list = []
        for user in admin_users_list:
            output_record = {
                "System": user.get("System", ""),
                "Source": user.get("Source", ""),
                "ResourceID": user.get("ResourceID", ""),
                "ResourceName": user.get("ResourceName", ""),
                "ResourceURL": user.get("ResourceURL", ""),
                "ResourceType": "User",
                "ResourceLocation": "N/A",
                "ResourceTags": "N/A",
                "UserEmail": user.get("UserEmail", ""),
                "PolicyID": None,
                "PolicyName": None,
                "AllowedSessionLifetimeMinutes": allowed_session_lifetime_minutes,
                "MaxSessionLifetimeMinutes": None,
                "SigninFrequencyEnabled": None,
                "FrequencyIntervalIsEveryTime": None,
                "ValidationStatusCode": f"POLICY_NA",
                "ValidationStatusNotes": f"The user does not have any compliant policy attached.",
                "ComplianceStatus": "NON_COMPLIANT",
                "ComplianceStatusReason": f"The user does not have any compliant policy attached. It is recommended to attach a policy with a session timeout set to less than {allowed_session_lifetime_minutes} minutes for improved security and operational efficiency.",
                "EvaluatedTime": self.get_current_datetime(),
                "UserAction": "",
                "ActionStatus": "",
                "ActionResponseURL": ""
            }

            user_group_ids = [group.get("GroupID", "") for group in user.get("UserGroups", [])]

            for policy in compliant_policies_list:
                policy_includes_user = len(
                    [
                        user_detail.get("UserId", "")
                        for user_detail in policy.get("PolicyIncludedUsers", {})
                        if user.get("ResourceID", "") == user_detail.get("UserId", "")
                    ]
                ) > 0

                if not policy_includes_user:
                    common_group_ids = [user_group_id for user_group_id in user_group_ids if user_group_id in policy.get("PolicyIncludedGroups", "")]
                    policy_includes_user = len(common_group_ids) > 0 and \
                        user.get("ResourceID", "") not in [
                            user_detail.get("UserId", "")
                            for user_detail in policy.get("PolicyExcludedUsers", {})
                        ]

                if policy_includes_user:    
                    output_record.update({
                            "PolicyID": policy.get("ResourceID", ""),
                            "PolicyName": policy.get("ResourceName", ""),
                            "MaxSessionLifetimeMinutes": str(policy.get("MaxSessionLifetimeMinutes", "")),
                            "SigninFrequencyEnabled": True,
                            "FrequencyIntervalIsEveryTime": False,
                            "ValidationStatusCode": f"TIMEOUT_LT_{allowed_session_lifetime_minutes}_MIN",
                            "ValidationStatusNotes": f"The timeout for administrative sessions is set to less than or equal to {allowed_session_lifetime_minutes} minutes.",
                            "ComplianceStatus": "COMPLIANT",
                            "ComplianceStatusReason": f"The timeout for administrative sessions is set to less than or equal to {allowed_session_lifetime_minutes} minutes. Your proactive management of session timeouts ensures enhanced security and efficiency.",
                        })
                    if policy.get("FrequencyIntervalIsEveryTime", ""):
                        output_record.update({
                            "MaxSessionLifetimeMinutes": "N/A",
                            "FrequencyIntervalIsEveryTime": True,
                            "ValidationStatusCode": f"FREQ_INT_EVRY_TIME",
                            "ValidationStatusNotes": f"The Session Frequency Interval is set to Every Time.",
                            "ComplianceStatusReason": f"The Session Frequency Interval is set to Every Time. This option is evaluated on every sign-in attempt to an application in scope for this policy.",
                        })
                        
                    break

            output_records_list.append(output_record)

        output_file_url, error = self.upload_output_file(output_records_list, "AdministrativeSessionTimeoutReport")
        if error:
            return { 'Error': error }
        
        # Upload extended schemas
        policies_file_url, error = self.upload_output_file(policies_df, "PoliciesList")
        if error:
            return { 'Error': error }
        
        compliant_policies_file_url, error = self.upload_output_file(pd.json_normalize(compliant_policies_list), "CompliantPoliciesList")
        if error:
            return { 'Error': error }
        
        admin_users_file_url, error = self.upload_output_file(admin_users_df, "AdminUsers")
        if error:
            return { 'Error': error }

        response = {
            "AdministrativeSessionTimeoutReport": output_file_url,
            "Policies": policies_file_url,
            "CompliantPolicies": compliant_policies_file_url,
            "AdminUsers": admin_users_file_url
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
        
        emptyAttrs = []
        if self.task_inputs.user_inputs is None:
            emptyAttrs.append("User inputs")
        if not self.task_inputs.user_inputs.get("PoliciesData"):
            emptyAttrs.append("ConditionalAccessPoliciesData")
        if not self.task_inputs.user_inputs.get("AdminUsersData"):
            emptyAttrs.append("AdminUsersData")
        if not self.task_inputs.user_inputs.get("AllowedSessionLifetimeMinutes"):
            emptyAttrs.append("AllowedSessionLifetimeMinutes")
        
        return "The following inputs: " + ", ".join(
            emptyAttrs) + " is/are empty" if emptyAttrs else ""
    
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
        df = output_data if isinstance(output_data, pd.DataFrame) else pd.json_normalize(output_data)
        if df.empty:
            return None, None
        
        file_url, error = self.upload_df_as_parquet_file_to_minio(
            df=df,
            file_name=file_name
        )
        if error:
            return None, { 'Error': f"Error while uploading {file_name} file :: {error}" }
        return file_url, None
    
    def get_current_datetime(self):
        current_time = datetime.utcnow()
        formatted_time = current_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        return formatted_time
    
    def download_parquet_file_from_minio_as_df(self, file_url=None):
        file_ext = file_url.split(".")[-1].lower()
        if file_ext != "parquet":
            return None, f"Provided file type is not supported. Please upload a file with the 'parquet' extension. The provided file is of type '{file_ext}'"
        
        return super().download_parquet_file_from_minio_as_df(file_url)
