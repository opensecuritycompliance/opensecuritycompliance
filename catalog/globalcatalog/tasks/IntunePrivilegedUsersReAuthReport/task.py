from typing import overload
from compliancecowcards.structs import cards
#As per the selected app, we're importing the app package 
from applicationtypes.azureappconnector import azureappconnector
from compliancecowcards.utils import cowdictutils
import os
import json
import uuid
import pandas as pd
import logging


class Task(cards.AbstractTask):

    def execute(self) -> dict:

        error = self.validate()
        if error:
            return self.upload_log_file([{'Error': error}])
        
        condiional_policies_df, error = self.download_parquet_file_from_minio_as_df(
            self.task_inputs.user_inputs.get('IntuneConditionalAccessPolicies'))
        if error:
            return self.upload_log_file([{'Error': error}])
        # handle empty conditional policies
        if condiional_policies_df.empty:
            return self.upload_log_file([{'Error': "No policies found in 'IntuneConditionalAccessPolicies'"}])
        

        user_reg_df, error = self.download_parquet_file_from_minio_as_df(
            self.task_inputs.user_inputs.get('IntuneUserRegistrationDetails'))
        if error:
            return self.upload_log_file([{'Error': error}])
        # handle empty user reg details
        if user_reg_df.empty:
            return self.upload_log_file([{'Error': "No privileged users found in 'IntuneConditionalAccessPolicies'"}])
        
        # handle invalid file
        user_registration_columns = {
              'ResourceID', 'ResourceName', 'ResourceType', 'UserEmail', 'UserGroups', 'UserRoles', 'ResourceURL', 'MFAEnabled'}
        # handle if conditional check fields are missing
        if not user_registration_columns.issubset(user_reg_df.columns):
            columns_not_present = set(user_registration_columns) - set(user_reg_df.columns)
            if columns_not_present:
                   msg = "Missing column: " + ', '.join(columns_not_present)
            return self.upload_log_file([{'Error': f"Invalid 'IntuneUserRegistrationDetails' file. {msg}"}])
        
        conditional_access_columns = {
              'PolicyIncludedUsers', 'PolicyIncludedLocation', 'PolicyExcludedLocation', 'ResourceName', 'ResourceID', 'PolicyStatus', 'PolicyCreationDate', 'SignInRiskLevels', 'SigninFrequencyEnabled'}
        # handle if conditional check fields are missing
        if not conditional_access_columns.issubset(condiional_policies_df.columns):
            columns_not_present = set(conditional_access_columns) - set(condiional_policies_df.columns)
            if columns_not_present:
                   msg = "Missing column: " + ', '.join(columns_not_present)
            return self.upload_log_file([{'Error': f"Invalid 'IntuneConditionalAccessPolicies' file. {msg}"}])
        
        

        standard_report, error_list = self.get_standard_report(condiional_policies_df, user_reg_df)

        if error_list:
            return self.upload_log_file(error_list)
        
        if standard_report:
            file_path, error = self.upload_df_as_parquet_file_to_minio(
             df=pd.json_normalize(standard_report),
             file_name=f"IntunePrivilegedReAuthReport-{str(uuid.uuid4())}"
             )
            if error:
                 return self.upload_log_file(error)
        
        return { "IntunePrivilegedReAuthReport" : file_path }


    def get_standard_report(self, policies_df, users_df):

        users_list = users_df.to_dict(orient="records")
        allowed_sign_in_risk_levels = self.task_inputs.user_inputs.get('AllowedSignInRiskLevels')

        standard_reports = []
        error_list = []

        try:
                for user in users_list:
                    
                    # igoring non admins
                    if not user['MFAEnabled']:
                        continue
                    
                    user_id = user['ResourceID']
                    compliance_status =  ''
                    compliance_status_reason = ''
                    validation_status_code = ''
                    validation_status_notes = ''
                    is_reauthentication_enabled = False
                    
                    # fetch policy info and named location of a user
                    policy_info , location_details, error = self.get_user_policy_info(user_id, policies_df)
                    if error:
                        error_list.append([{"Error": error}])
                        return standard_reports, error_list
                    
                    # to track compliance_status_reason
                    policies_under_not_allowed_sign_in_levels = []
                    policies_under_no_sign_in_levels = []
                    policies_under_allowed_sign_levels = []
                    sign_frequency_enabled_policies = []
                    sign_frequency_not_enabled_policies = []
                    active_policies = []
                    not_active_policies = []


                    for pol in policy_info:

                        # handle signInRiskLevels
                        sign_in_risk_levels = pol['SignInRiskLevels']
                        if len(sign_in_risk_levels) != 0:
                            missing_sign_in_risk_levels = set(allowed_sign_in_risk_levels) - set(sign_in_risk_levels)
                            if missing_sign_in_risk_levels:
                                policies_under_not_allowed_sign_in_levels.append(f"{pol['Name']}: {list(missing_sign_in_risk_levels)}")

                            else:
                                policies_under_allowed_sign_levels.append(pol['Name'])
        
                        else:
                            policies_under_no_sign_in_levels.append(pol['Name'])
        
                        # handle policy status
                        if pol['Status'] == 'ACTIVE':
                            active_policies.append(pol['Name'])
                        else:
                            not_active_policies.append(pol['Name'])
                        # handle sign in frequency 
                        if pol['SigninFrequencyEnabled']:
                            sign_frequency_enabled_policies.append(pol['Name'])
                        else:
                            sign_frequency_not_enabled_policies.append(pol['Name'])

                    is_valid_sign_in_risk_level_exist = len(policies_under_not_allowed_sign_in_levels) == 0 and len(policies_under_no_sign_in_levels ) == 0 and len(policies_under_allowed_sign_levels) !=0
                    is_sign_frequency_enabled = len(sign_frequency_enabled_policies) != 0 and len(sign_frequency_not_enabled_policies) == 0
                    is_active_policy_present = len(active_policies) != 0 and len(not_active_policies) == 0

                    if is_valid_sign_in_risk_level_exist and is_sign_frequency_enabled and is_active_policy_present:
                        compliance_status = 'COMPLIANT'
                        compliance_status_reason = f'The record is compliant as the policies/policy {active_policies} enabled for the user is/are active, has/have an allowed sign-in risk level, and has/have sign-in frequency enabled'
                        validation_status_code = "RE_ATH_ENB"
                        validation_status_notes = "Reauthentication is enabled for the user"
                        is_reauthentication_enabled = True
                    else:
                            # handling other cases - non compliant
                            compliance_status = "NON_COMPLIANT"
                            compliance_status_reason = 'The record is non-compliant due to the following reason/reasons. '
                            validation_status_code = "RE_ATH_NT_ENB"
                            validation_status_notes = "Reauthentication is not enabled for the user"
                            count = 1

                            if not policy_info:
                                compliance_status_reason = 'The record is non-compliant since no conditional access policies/policy are enabled for the user. Enabling conditional access policies/policy enhances security by enforcing granular access controls based on user roles, location, and device compliance. These policies help mitigate risks and ensure compliance with organizational security requirements.' 
                            if policies_under_not_allowed_sign_in_levels:
                                msg = ', '.join(map(str, policies_under_not_allowed_sign_in_levels))
                                compliance_status_reason += f"{count}. Policy/policies does not meet required sign in risk levels. {msg}. Expected sign in risk level: {allowed_sign_in_risk_levels} "
                                count += 1
                            if policies_under_no_sign_in_levels:
                                msg = ', '.join(map(str, policies_under_no_sign_in_levels))
                                compliance_status_reason += f"{count}. No sign in risk level enabled for the policy/policies: {msg}. "
                                count += 1
                            if sign_frequency_not_enabled_policies:
                                msg = ', '.join(map(str, sign_frequency_not_enabled_policies))
                                compliance_status_reason += f"{count}. No sign in frequency enabled for the policy/policies: {msg}. "
                                count += 1
                            if not_active_policies:
                                msg = ', '.join(map(str, not_active_policies))
                                compliance_status_reason += f"{count}. Policy/policies are not in active state: {msg}. "
                                count += 1
            
                    user_record = {
                                "System": "intune",
                                "Source": "compliancecow",
                                "ResourceID": user['ResourceID'],
                                "ResourceName": user['ResourceName'],
                                "ResourceType": user['ResourceType'],
                                "ResourceLocation": "N/A",
                                "ResourceTags": "N/A",
                                "ResourceURL": user['ResourceURL'],
                                "UserEmail": user['UserEmail'],
                                "AllowedSignInRiskLevels": allowed_sign_in_risk_levels,
                                "IsReAuthenticationEnabled" : is_reauthentication_enabled,
                                "UserGroups": user['UserGroups'],
                                "UserRoles": user['UserRoles'],
                                "MFAEnabled": user['MFAEnabled'],
                                "PolicyDetails" : policy_info if policy_info else [],
                                "LocationDetails" : location_details if location_details else [],
                                "ValidationStatusCode" : validation_status_code,
                                "ValidationStatusNotes" : validation_status_notes,
                                "ComplianceStatus": compliance_status,
                                "ComplianceStatusReason": compliance_status_reason,
                                "UserAction": '',
                                "ActionStatus": '',
                                "ActionResponseURL": ''
                            }
                    standard_reports.append(user_record)
                return standard_reports, error_list  

        except AttributeError as e:
            error_list.append([{"Error": "Failed to fetch the conditional access policy details. Attribute exception occured."}])
            logging.exception("Failed to fetch the conditional access policy details: %s", str(e))
            return standard_reports, error_list
        except KeyError as e:
            error_list.append([{"Error": "Failed to fetch the conditional access policy details. Keyerror exception occured."}])
            
            return standard_reports, error_list


    def get_user_policy_info(self, user_id, df):
        policy_details = []
        location_details = []
        error_list = []
        try:
            # looping policies to get the condition access and location details for user
            for _, row in df.iterrows():
                # PolicyIncludedUsers - users included in policy
                included_users = row['PolicyIncludedUsers']
                if included_users is not None and len(included_users) != 0: 
                    for user in included_users:
                        if 'UserId' in user:
                            if user['UserId'] == user_id:
                                # policy object
                                policy_detail = {
                                    'Name': row['ResourceName'],
                                    'Id': row['ResourceID'],
                                    'Status' : row['PolicyStatus'],
                                    'CreationDate': row['PolicyCreationDate'],
                                    'SignInRiskLevels' : row['SignInRiskLevels'],
                                    'SigninFrequencyEnabled' : row['SigninFrequencyEnabled']
                                }
                                policy_details.append(policy_detail)
                                # included location object
                                included_location = row['PolicyIncludedLocation']
                                if included_location is not None and len(included_location) != 0:
                                    for location in included_location:
                                        if 'Name' in location and 'id' in location and 'isTrusted' in location and 'Address' in location:
                                            location_detail = {
                                            'Name': location['Name'],
                                            'Id': location['id'],
                                            'IsTrusted' : location['isTrusted'],
                                            'Address' : location['Address'],
                                            'PolcyName': row['ResourceName'],
                                            'PolicyStatus' : row['PolicyStatus'],
                                            'LocationStatus' : 'Included'}
                                            location_details.append(location_detail)
                                        else:
                                            error_list.append({"Error": "Invalid 'IntuneConditionalAccessPolicies'. Please provide valid 'IntuneConditionalAccessPolicies' to proceed."})
                                            return policy_details, location_details, error_list
                                # excluded location object
                                excluded_location = row['PolicyExcludedLocation']
                                if excluded_location is not None and len(excluded_location) != 0:
                                    for location in excluded_location:
                                        if 'Name' in location and 'id' in location and 'isTrusted' in location and 'Address' in location:
                                            location_detail = {
                                            'Name': location['Name'],
                                            'Id': location['id'],
                                            'IsTrusted' : location['isTrusted'],
                                            'Address' : location['Address'],
                                            'PolcyName': row['ResourceName'],
                                            'PolicyStatus' : row['PolicyStatus'],
                                            'LocationStatus' : 'Included'}
                                            location_details.append(location_detail)
                                        else:
                                            error_list.append({"Error" : "Invalid 'IntuneConditionalAccessPolicies'. Please provide valid 'IntuneConditionalAccessPolicies' to proceed."})
                                            return policy_details, location_details, error_list
                        else:
                            error_list.append({"Error" : "Invalid 'IntuneConditionalAccessPolicies'. Please provide valid 'IntuneConditionalAccessPolicies' to proceed."})
                            return policy_details, location_details, error_list            

            return policy_details, location_details, error_list
        except AttributeError as e:
            error_list.append({"Error" : "Failed to fetch the conditional access policy details. Attribute exception occured."})
            return policy_details, location_details, error_list
        except KeyError as e:
            error_list.append({"Error" : "Failed to fetch the conditional access policy details. Keyerror exception occured."})
            return policy_details, location_details, error_list

    

    def upload_log_file(self, errors_list):
        log_file_path, error = self.upload_file_to_minio(file_content=json.dumps(errors_list).encode('utf-8'), 
                                                         file_name=f'LogFile-{str(uuid.uuid4())}.json', content_type='application/json')
        if error:
            return {'Error': error}
        return {
            'LogFile': log_file_path,
            "ComplianceStatus_": "NOT_DETERMINED", 
            "CompliancePCT_": 0
            }
    

    # basic task level validation
    def validate(self):
        task_inputs = self.task_inputs
        if not task_inputs:
            return "Task input is missing"
        if not isinstance((self.task_inputs.user_inputs["AllowedSignInRiskLevels"]), list):
            return "Provided 'AllowedSignInRiskLevels' type is not supported. Supported type is list."
        if not cowdictutils.is_valid_array(self.task_inputs.user_inputs, 'AllowedSignInRiskLevels'):
            return "Invalid input - 'AllowedSignInRiskLevels'"
        if not cowdictutils.is_valid_key(self.task_inputs.user_inputs, 'IntuneConditionalAccessPolicies'):
            return "'IntuneConditionalAccessPolicies' is missing. Please upload a valid 'IntuneConditionalAccessPolicies'"
        if not isinstance((self.task_inputs.user_inputs["IntuneConditionalAccessPolicies"]), str):
            return "Provided 'IntuneConditionalAccessPolicies' type is not supported. Supported type is string."
        intune_conditional_access_policy_path = self.task_inputs.user_inputs.get("IntuneConditionalAccessPolicies")
        err_msg = self.is_valid_parquet_file(intune_conditional_access_policy_path)
        if err_msg:
            return err_msg
        if not cowdictutils.is_valid_key(self.task_inputs.user_inputs, 'IntuneUserRegistrationDetails'):
            return "'IntuneUserRegistrationDetails' is missing. Please upload a valid 'IntuneUserRegistrationDetails'"
        if not isinstance((self.task_inputs.user_inputs["IntuneUserRegistrationDetails"]), str):
            return "Provided 'IntuneUserRegistrationDetails' type is not supported. Supported type is string."
        intune_user_reg_path = self.task_inputs.user_inputs.get("IntuneUserRegistrationDetails")
        err_msg = self.is_valid_parquet_file(intune_user_reg_path)
        if err_msg:
            return err_msg
        user_object = self.task_inputs.user_object
        if (
            not user_object
            or not user_object.app
            or not user_object.app.user_defined_credentials
        ):
            return "User defined credential is missing"
        return None
    
    def is_valid_parquet_file(self, file_path):
        file_extension = os.path.splitext(file_path)[1]
        if file_extension != '.parquet':
            return f"Provided {os.path.basename(file_path)} is not supported. Please upload a file with the '.parquet' extension. The provided file is of type {file_extension}"
        return ''
