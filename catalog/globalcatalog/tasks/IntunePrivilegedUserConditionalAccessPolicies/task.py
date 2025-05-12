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
            return self.upload_log_file([{'Error': "No privileged users found in 'IntuneUserRegistrationDetails'"}])
        
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
             file_name=f"IntunePrivilegedConsoleAccessReport-{str(uuid.uuid4())}"
             )
            if error:
                 return self.upload_log_file(error)
        
        return { "IntunePrivilegedConsoleAccessReport" : file_path }


    def get_standard_report(self, policies_df, users_df):

        users_list = users_df.to_dict(orient="records")

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
                    is_third_party_vpn_access_blocked = False
                    
                    # fetch policy info and named location of a user
                    policy_info , location_details, error = self.get_user_policy_info(user_id, policies_df)
                    if error:
                        error_list.append({"Error": error})
                        return standard_reports, error_list
                

                    # track compliance status reason
                    conditional_policy_exist = True if policy_info else False
                    named_loc_exist = True if location_details else False
                    trusted_and_active = []
                    trusted_not_active = []
                    active_not_trusted = []
                    not_active_not_trusted = []
                
                    if conditional_policy_exist and named_loc_exist:
                        for loc in location_details:
                            if loc:
                                if loc['IsTrusted'] and loc['PolicyStatus'] == 'ACTIVE':
                                    trusted_and_active.append(loc['Name'])
                                if not loc['IsTrusted'] and loc['PolicyStatus'] == 'ACTIVE':
                                    active_not_trusted.append(loc['Name'])
                                if  loc['IsTrusted'] and loc['PolicyStatus'] != 'ACTIVE':
                                    trusted_not_active.append(loc['Name'])
                                if  not loc['IsTrusted'] and loc['PolicyStatus'] != 'ACTIVE':
                                    not_active_not_trusted.append(loc['Name'])
                                
                    validation_status_code = 'THD_PAR_VPN_ACS_NT_BLD'
                    validation_status_notes = 'Third Party VPN access not blocked'
                    compliance_status = "NON_COMPLIANT"
                    compliance_status_reason = 'The record is non-compliant as '

                    if not conditional_policy_exist:
                        compliance_status_reason = "The record is non-compliant since no conditional access policy/policies is/are enabled for the user. Enabling conditional access policy/policies enhance security by enforcing granular access controls based on user roles, location, and device compliance. They help mitigate risks and ensure compliance with organizational security requirements."
                    if conditional_policy_exist and not named_loc_exist:
                        compliance_status_reason = "The record is non-compliant because the user is not enabled under conditional access policy/policies that include(s) named location(s), thereby posing a security risk due to unrestricted access."
                    compliance_condition = trusted_and_active and not trusted_not_active and not active_not_trusted and not not_active_not_trusted
                    if compliance_condition:
                        msg = ', '.join(map(str, trusted_and_active))
                        compliance_status_reason = f'The record is compliant as trustable named location(s) is/are enabled in active policy/policies:  {msg}'
                        validation_status_code = 'THD_PAR_VPN_ACS_BLD'
                        validation_status_notes = 'Third Party VPN access blocked'
                        compliance_status = "COMPLIANT"
                        is_third_party_vpn_access_blocked = True
                    if trusted_not_active:
                        msg = ', '.join(map(str, trusted_not_active))
                        compliance_status_reason += f'named location(s) enabled in policy/policies is/are trustable, but the policy/policies is/are not active: {msg}. '
                    if active_not_trusted:
                        msg = ', '.join(map(str, active_not_trusted))
                        compliance_status_reason += f'non trusted location(s) is/are enabled in active policy/policies: {msg}. '
                    if not_active_not_trusted:
                        msg = ', '.join(map(str, not_active_not_trusted))
                        compliance_status_reason += f'non trusted location(s) is/are enabled in non-active policy/policies: {msg}. '
                    
            
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
                                "UserGroups": user['UserGroups'],
                                "UserRoles": user['UserRoles'],
                                "MFAEnabled": user['MFAEnabled'],
                                "PolicyDetails" : policy_info if policy_info else [],
                                "LocationDetails" : location_details if location_details else [],
                                "IsThirdPartyVPNAccessBlocked": is_third_party_vpn_access_blocked,
                                "ValidationStatusCode" : validation_status_code,
                                "ValidationStatusNotes" : validation_status_notes,
                                "ComplianceStatus": compliance_status,
                                "ComplianceStatusReason": compliance_status_reason
                            }
                    standard_reports.append(user_record)
                return standard_reports, error_list  

        except AttributeError as e:
            error_list.append({"Error": "Failed to fetch the conditional access policy details. Attribute exception occured."})
            logging.exception("Failed to fetch the conditional access policy details: %s", str(e))
            return standard_reports, error_list
        except KeyError as e:
            error_list.append({"Error": "Failed to fetch the conditional access policy details. Keyerror exception occured."})
            logging.exception("Failed to fetch the conditional access policy details: %s", str(e))
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
                                            error_list.append({"Error" : "Invalid 'IntuneConditionalAccessPolicies'. Please provide valid 'IntuneConditionalAccessPolicies' to proceed."})
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
            error_list.append({"Error" :"Failed to fetch the conditional access policy details. Keyerror exception occured."})
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
