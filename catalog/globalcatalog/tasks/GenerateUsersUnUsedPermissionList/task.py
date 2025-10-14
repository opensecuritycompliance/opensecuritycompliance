
from typing import overload
from compliancecowcards.structs import cards
#As per the selected app, we're importing the app package 
from applicationtypes.awsappconnector import awsappconnector
import json
import uuid
import pandas as pd


class Task(cards.AbstractTask):

    def execute(self) -> dict:
        
        response = {}
        if self.task_inputs.user_inputs.get('LogFile') and not self.task_inputs.user_inputs.get('UserDetails'):
            return {"LogFile" : self.task_inputs.user_inputs.get('LogFile')}
        
        if not self.task_inputs.user_inputs.get('UserDetails') and not self.task_inputs.user_inputs.get('LogFile'):
            return {'UsersUnUsedPermissionReport' : ""}

        error_list = self.validate()
        if error_list:
            return self.upload_log_file(error_list)

        # download and validate UserDetails
        user_df, error = self.download_parquet_file_from_minio_as_df(
            self.task_inputs.user_inputs.get('UserDetails'))
        if error:
            return self.upload_log_file([{"Error": f"Error while downloading 'UserDetails'. {error}"}])
        if user_df.empty:
            return self.upload_log_file([{"Error": "Provided 'UserDetails' is empty. Please provide a valid 'UserDetails' or contact support for further details"}])
        
        
        # handle invalid file
        required_columns = { 'System', 'Source', 'ResourceID', 'ResourceTags', 'ResourceName', 'ResourceLocation', 'Manager', 'ResourceURL'}
        # handle if conditional check fields are missing
        if not required_columns.issubset(user_df.columns):
            columns_not_present = set(required_columns) - set(user_df.columns)
            msg = ''
            if columns_not_present:
                   msg = "Missing column: " + ', '.join(columns_not_present)
            return self.upload_log_file([{'Error': f"Invalid 'UserDetails' file. {msg}"}])
        
        user_list = user_df.to_dict('records')
        std_report = []
        for user in user_list:
            user_name = user.get('ResourceName')
            unused_permissions: list[str] = []
            
            ValidationStatusCode    =  "UNUSED_PERM_NOT_PRESENT"
            ValidationStatusNotes   =  "Unused permission(s) not present"
            ComplianceStatus        =  "COMPLIANT"
            ComplianceStatusReason  = f"The record is compliant because unused permissions are not present for a user - {user_name}. Hence managing and auditing permissions becomes easier and more efficient, as it eliminates redundant access rights and focuses on relevant roles and responsibilities."

            if len(user.get('UnusedPermissions')) !=  0:
                ValidationStatusCode    =  "UNUSED_PERM_PRESENT"
                ValidationStatusNotes   =  "Unused permission(s) present"
                ComplianceStatus        =  "NON_COMPLIANT"
                ComplianceStatusReason  = f"The record is non-compliant because {str(len(user.get('UnusedPermissions')))} unused permissions are present for a user - {user_name}. Unused permissions can create potential vulnerabilities in your system, as they might be exploited by malicious actors if they gain access"
                unused_permissions.extend(user.get('UnusedPermissions'))

            data = {
                "System"                        : user.get('System', 'N/A'),
                "Source"                        : user.get('Source', 'N/A'),
                "ResourceID"                    : user.get('ResourceID', 'N/A'),
                "ResourceTags"                  : user.get('ResourceTags', 'N/A'),
                "ResourceType"                  : "User",
                "ResourceName"                  : user_name,
                "ResourceLocation"              : user.get('ResourceLocation', 'N/A'),
                "ResourceURL"                   : user.get('ResourceURL', 'N/A'),
                "InactivePermissionsWindow"     : user.get('InactivePermissionsWindow', 'N/A'),
                "Manager"                       : user.get('Manager', 'N/A'),
                "UnusedPermissions"             : unused_permissions,
                "ValidationStatusCode"          : ValidationStatusCode,
                "ValidationStatusNotes"         : ValidationStatusNotes,
                "ComplianceStatus"              : ComplianceStatus,
                "ComplianceStatusReason"        : ComplianceStatusReason,
                "UserAction"                    : "",
                "ActionStatus"                  : "",
                "ActionResponseURL"             : "",
                "UserFormID"                    : "",
                "UserFormStatus"                : "",
                "ManagerFormID"                 : "",
                "ManagerFormStatus"             : "",
                "CountOfUnusedPermissionsToBeDeleted" : 0,
                "ActionUnusedPermissionsToDelete" : "",
                "RecordID": ""
            }
            std_report.append(data)

            
        if std_report:
            file_path, error = self.upload_df_as_parquet_file_to_minio(
             df=pd.json_normalize(std_report),
             file_name=f"UsersUnUsedPermissionReport-{str(uuid.uuid4())}")
            if error:
                return self.upload_log_file([f"An error occurred while uplaoding 'UsersUnUsedPermissionReport'. {error}"])
            response['UsersUnUsedPermissionReport'] = file_path
        
        return response


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