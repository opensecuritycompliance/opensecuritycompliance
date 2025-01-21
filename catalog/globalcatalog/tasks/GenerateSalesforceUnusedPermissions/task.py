
from typing import Tuple
import json
from compliancecowcards.structs import cards
#As per the selected app, we're importing the app package 
from appconnections.salesforceappconnector import salesforceappconnector
import pandas as pd
import toml
import uuid
from datetime import datetime, timezone
import re
from compliancecowcards.utils import cowdictutils


logger = cards.Logger() # Initializes a Logger instance to log data, use logger.log_data(dict) to log a data

class Task(cards.AbstractTask):

    def execute(self) -> dict:

        # The following code allows you to access the input values from the YAML configuration file you provided.
        # 'user_inputs' is a dictionary containing these values.
        #
        # self.task_inputs.user_inputs.get("BucketName")

        # You can instantiate the application (selected during rule initialization) using the following approach.
        #
        app = salesforceappconnector.SalesforceAppConnector(
            app_url=self.task_inputs.user_object.app.application_url,
            app_port=self.task_inputs.user_object.app.application_port,
            user_defined_credentials=salesforceappconnector.UserDefinedCredentials.from_dict(
                self.task_inputs.user_object.app.user_defined_credentials)
        )
        
		# You can use validate_attributes function to validate the attributes of SalesforceAppConnector Credentials
		# Validate attributes for CustomType
		# custom_type = app.user_defined_credentials.custom_type
		# if isinstance(custom_type, salesforceappconnector.CustomType):
		# 	validation_result = custom_type.validate_attributes()

        # You can upload files to Minio by following this approach.
        # file_content: bytes
        # file_name: string
        # content_type: file formats.
        #
        # file_url, error = self.upload_file_to_minio(file_content=file_content, file_name=file_name, content_type=content_type)

        # You can download files from Minio by following this approach.
        # file_url: str
        #
        # file_bytes, error = self.download_file_from_minio(file_url=file_url)

        error = self.check_inputs()
        if error:
            return self.upload_log_file({"Error": error})

        input_file_url = self.task_inputs.user_inputs.get("UserDataFile")
        permissions_map_file_url = self.task_inputs.user_inputs.get("PermissionsMapFile")
        eventlog_file_url = self.task_inputs.user_inputs.get("EventLogFile")

        input_file_bytes, error = self.download_file_from_minio(input_file_url)
        if error:
            return self.upload_log_file(error)
        
        try:
            users_data = json.loads(input_file_bytes)
        except json.JSONDecodeError as e:
            return self.upload_log_file({"Error": f"Failed to decode JSON: {e}"})
            
        permissons_file_bytes, error = self.download_file_from_minio(permissions_map_file_url)
        try:
            permissions_map = toml.loads(permissons_file_bytes.decode('utf-8'))
        except toml.TomlDecodeError as e:
            return self.upload_log_file({"Error": f"Failed to decode Toml: {e}"})
       

        eventlog_file_bytes, error = self.download_file_from_minio(eventlog_file_url)
        try:
            eventlog = json.loads(eventlog_file_bytes)
            if len(eventlog)>0:
                eventlog=eventlog[0]
        except json.JSONDecodeError as e:
            return self.upload_log_file({"Error": f"Failed to decode JSON: {e}"})
        
        
        combined_event_logs=pd.DataFrame()
        
        for event in eventlog.get("records",[]):
            if event["Id"]:
                response,err = app.get_eventlog_by_id(event["Id"])
                if err:
                    return self.upload_log_file_panic(err)
                if not response.empty:
                    if combined_event_logs.empty and  "USER_ID_DERIVED" in response.columns :
                        combined_event_logs = response
                    elif  "USER_ID_DERIVED" in response.columns:
                        combined_event_logs = pd.concat([combined_event_logs,response], ignore_index=True)

        standard_structure = []
        error_list = []
        inactive_permissions_window=0
        if eventlog and eventlog.get("URL",False):
            pattern = r"LAST_N_DAYS:(\d+)"
            match = re.search(pattern,eventlog.get("URL"))
            if match:
                inactive_permissions_window = int(match.group(1))
                

        for user in users_data:
            unused_permissions = permissions_map["PermissionMappings"]
            users_permissions = []
            error=""
            for permissions in user.get("PermissionSetAssignment",[]):
                permissions_list,err = app.get_permissions_by_permissionset_id(permissions.get("PermissionSetId"))
                if error:
                    error_list.append({"Error":error})
                    break            
                filtered_permissions = [key for key, value in permissions_list.items() if key.startswith("Permissions") and value is True]
                users_permissions.extend(filtered_permissions)
            if error:
                continue            
            users_eventLog=pd.DataFrame()

            if not combined_event_logs.empty:
                users_eventLog = combined_event_logs[combined_event_logs['USER_ID_DERIVED'] == user["Id"]]
            
            if not users_eventLog.empty:
                event_type_list = users_eventLog['EVENT_TYPE'].tolist()
                for events in event_type_list:
                    key_with_event = [key for key, value in unused_permissions.items() if value == events]
                    for keyevent in key_with_event:
                        if keyevent in users_permissions:
                            users_permissions.remove(keyevent)
            
            if 'PermissionSetAssignment' in user:
                del user["PermissionSetAssignment"]
                
            profile_url=""
            app_url=self.task_inputs.user_object.app.application_url
            if not app_url.endswith('/'):
                profile_url +="/"       
            profile_url+=f"lightning/r/User/{user.get('Id')}/view"
            
            manager="N/A"
            if user.get("ManagerId",False):
                manager_data,err = app.get_user_by_id(user.get("ManagerId"))
                manager = manager_data.get("Email","N/A")
            
            country = "N/A"
            if user.get("Country", False):
                country = user.get("Country")
                
            name = f"{user.get('FirstName') or ''} {user.get('LastName') or ''}".strip()
            user_response = {
                    "System": 'salesforce',
                    "Source": 'compliancecow',
                    "ResourceID": user.get("Id"),
                    "ResourceName": user.get("Email"),
                    "ResourceType": "User",
                    "ResourceLocation": country,
                    "ResourceTags": [],
                    "ResourceURL": f"{app_url}{profile_url}",
                    "Name": name,
                    "UnusedPermissions": users_permissions,
                    "InactivePermissionsWindow"  : inactive_permissions_window,
                    "Manager": manager,
                    "ValidationStatusCode": "N/A",  
                    "ValidationStatusNotes": "N/A",  
                    "ComplianceStatus": "N/A", 
                    "ComplianceStatusReason": "N/A", 
                    "EvaluatedTime": datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S %Z'),
                    "UserAction": "",
                    "ActionStatus": "",
                    "ActionResponseURL": "",
                    "UserFormID"        : "",
                    "UserFormStatus"    : "",
                    "ManagerFormID"     : "",
                    "ManagerFormStatus" : "",
                    "CountOfUnusedPermissionsToBeDeleted" : 0,
                    "ActionUnusedPermissionsToDelete" : "",
                    "RecordID": ""
                }
            if len(user_response["UnusedPermissions"]) == 0:
                user_response["ValidationStatusCode"] = "UNUSED_PERM_NOT_PRESENT"
                user_response["ValidationStatusNotes"] = "Unused permission(s) not present"
                user_response["ComplianceStatus"] = "COMPLIANT"
                user_response["ComplianceStatusReason"] = (
                    f"The record is compliant because unused permissions are not present for a user - {user_response['ResourceName']}. "
                    "Hence managing and auditing permissions becomes easier and more efficient, as it eliminates "
                    "redundant access rights and focuses on relevant roles and responsibilities."
                )
            else:
                user_response["ValidationStatusCode"] = "UNUSED_PERM_PRESENT"
                user_response["ValidationStatusNotes"] = "Unused permission(s) present"
                user_response["ComplianceStatus"] = "NON_COMPLIANT"
                user_response["ComplianceStatusReason"] = (
                    f"The record is non-compliant because {len(user_response['UnusedPermissions'])} unused permissions are present "
                    f"for a user - {user_response['ResourceName']}. Unused permissions can create potential vulnerabilities in your system, "
                    "as they might be exploited by malicious actors if they gain access."
                )
                 
            standard_structure.append(user_response)
                 
        file_url, error = self.upload_output_file("SalesforceUnusedPermissions",standard_structure) 
        if error:
            return self.upload_log_file(error)
            
        response = {
            "OutputFile": file_url,
        }

        if len(error_list) > 0:
            log_file_url, error = self.upload_output_file("LogFile",error_list) 
            if error:
                return self.upload_log_file(error)
            response["LogFile"] = log_file_url

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
        
        if self.task_inputs.user_inputs is None:
            return 'User inputs are missing'
        
        required_inputs = ['UserDataFile','PermissionsMapFile','EventLogFile']
        missing_inputs = []
        for input in required_inputs:
            if not cowdictutils.is_valid_key(self.task_inputs.user_inputs, input) or self.task_inputs.user_inputs[input]=="<<MINIO_FILE_PATH>>" :
                missing_inputs.append(input)

        return "The following inputs: " + ", ".join(missing_inputs) + " is/are Empty/Invalid" if missing_inputs else ""
    
    def upload_output_file(self, file_name, data):
        output_data_json = json.dumps(data)
        file_name = f'{file_name}-{str(uuid.uuid4())}.json'
        absolute_file_path, error = self.upload_file_to_minio(
            file_name=file_name,
            file_content=output_data_json,
            content_type='application/json',
        )
        if error:
            return '', error

        return absolute_file_path, None
    
    def upload_log_file(self, error_data) -> Tuple[str, dict]:
        if not isinstance(error_data, list):
            error_data = [error_data]
        
        [logger.log_data(dict(error_item)) for error_item in error_data]

        file_url, error = self.upload_df_as_json_file_to_minio(
            df=pd.json_normalize(error_data),
            file_name="LogFile"
        )
        if error:
            return None, {'Error': f"Error while uploading LogFile :: {error}"}
        return file_url, None
    
    def upload_log_file_panic(self, error_data) -> dict:
        if isinstance(error_data, str):
            error_data = {'Error': error_data}
        file_url, error = self.upload_log_file(error_data)
        if error:
            return error
        return { 'LogFile': file_url }
