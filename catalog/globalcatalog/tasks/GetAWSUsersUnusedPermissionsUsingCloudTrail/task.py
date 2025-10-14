
from typing import overload
from compliancecowcards.structs import cards
#As per the selected app, we're importing the app package 
from applicationtypes.awsappconnector import awsappconnector
import json
import uuid
import pandas as pd
from datetime import datetime
from datetime import datetime, timedelta
from compliancecowcards.utils import cowdictutils
import pytz
import urllib.parse
import os


class Task(cards.AbstractTask):

    def execute(self) -> dict: 

        response = {}

        if self.task_inputs.user_inputs.get('AWSEventsLogFile'):
            response['AWSEventsLogFile'] = self.task_inputs.user_inputs.get('AWSEventsLogFile')
        if self.task_inputs.user_inputs.get('AWSUserDetailsLogFile'):
            response['AWSUserDetailsLogFile'] = self.task_inputs.user_inputs.get('AWSUserDetailsLogFile')
        if not self.task_inputs.user_inputs.get('EventDetails') or  not self.task_inputs.user_inputs.get('UserDetails'):
            return response

        val_err_list = self.validate()
        if val_err_list:
            return self.upload_log_file(val_err_list)
        
        # Download 'EventFile'
        event_config_df, error = self.download_csv_file_from_minio_as_df(
            self.task_inputs.user_inputs.get('EventFile'))
        if error:
            return self.upload_log_file(self.add_key_in_list([f"Error while downloading 'EventFile'. {error}"]))

        # Download 'UserManagerDetails'
        manager_info_df, error = self.download_csv_file_from_minio_as_df(
            self.task_inputs.user_inputs.get('UserManagerDetails'))
        if error:
            return self.upload_log_file([{"Error" : f"Error while downloading 'UserManagerDetails'. {error}"}])
        
        # Download 'UserDetails'
        user_details_df, error = self.download_parquet_file_from_minio_as_df(
            self.task_inputs.user_inputs.get('UserDetails'))
        if error:
            return self.upload_log_file([f"Error while downloading 'UserDetails'. {error}"])

        # Download 'EventDetails'
        event_details_df, error = self.download_parquet_file_from_minio_as_df(
            self.task_inputs.user_inputs.get('EventDetails'))
        if error:
            return self.upload_log_file([f"Error while downloading 'EventDetails'. {error}"])
        
        empty_files = []
        if event_config_df.empty:
            empty_files.append("EventFile")
        if manager_info_df.empty:
            empty_files.append("UserManagerDetails")
        if user_details_df.empty:
            empty_files.append("UserDetails")
        if event_details_df.empty:
            empty_files.append("EventDetails")
        if empty_files:
            return self.upload_log_file([{"Error" : f"Empty File(s): {', '.join(empty_files)}"}])
    
        # filter events for inactive_window
        inactive_window = self.task_inputs.user_inputs.get("InactivePermissionsWindow")
        event_details_df['EventTime'] = pd.to_datetime(event_details_df['EventTime']).dt.tz_convert('UTC')
        cutoff_date = datetime.now(pytz.UTC) - timedelta(days=inactive_window)
        filtered_events_df = event_details_df[event_details_df['EventTime'] >= cutoff_date]

        # filter the service and permissions
        event_config_df["IsRequired"] = event_config_df["IsRequired"].str.strip().str.lower()
        filtered_event_file_df = event_config_df.loc[(event_config_df['IsRequired'] == 'yes')]
        service_with_permissions = {}
        filtered_event_list = filtered_event_file_df.to_dict(orient='records')
        try:
            for event in filtered_event_list:
                resource_type = event['ResourceType']
                service = resource_type.split("::")[1]
                event_names = event['EventNames']
                if event_names != "*":
                    event_names = event_names.split(",")
                else:
                    event_names = ["*"]
                if service in service_with_permissions and not "*" in service_with_permissions[service]:
                    perm_list = []
                    perm_list.extend(event_names)
                    perm_list.extend(service_with_permissions[service])
                    service_with_permissions[service] = perm_list
                else:
                    service_with_permissions[service] = event_names
        except (IndexError,KeyError,ValueError,AttributeError) as e:
            return self.upload_log_file([{"Error": f"Error occured while handling 'EventFile'. Please proceed with valid file. {str(e)}"}])

        user_list = user_details_df.to_dict('records')
        final_list = []
        for user in user_list:

            user_name = user['ResourceName']
            user_permissions = user['Permissions']

            input_permissions, error_list = self.get_input_permissions(user_permissions, service_with_permissions)
            if error_list:
                return self.upload_log_file(error_list)
            permissions_used_for_events = self.get_user_events(filtered_events_df, user_name)
            user_permission_set = set(input_permissions)
            permissions_used_for_events_set = set(permissions_used_for_events)
            difference = user_permission_set - permissions_used_for_events_set
            un_used_permission_list = []
            if difference:
               un_used_permission_list = list(difference)

            manager_name, err  = self.get_manager_for_user(manager_info_df, user_name)
            if err:
                manager_name = "N/A"


            data = {
                    "System"                     : "aws",
                    "Source"                     : "compliancecow",
                    "ResourceID"                 : user.get('ResourceID', 'N/A'),
                    "ResourceTags"               : "N/A",
                    "ResourceType"               : "user",
                    "ResourceName"               : user_name,
                    "ResourceLocation"           : "global",
                    "ResourceURL"                : user.get('ResourceURL', 'N/A'),
                    "InactivePermissionsWindow"  : inactive_window,
                    "Manager"                    : manager_name,
                    "UnusedPermissions"          : un_used_permission_list,}
            final_list.append(data)

        if final_list:
            file_path, error = self.upload_df_as_parquet_file_to_minio(
             df=pd.json_normalize(final_list),
             file_name=f"AWSUsersUnsedPermissionList-{str(uuid.uuid4())}")
            if error:
                return self.upload_log_file([f"An error occurred while uplaoding 'AWSUsersUnsedPermissionList'. {error}"])
            response['AWSUsersUnsedPermissionList'] =  file_path
            
        return response

    
    def upload_log_file(self, errors_list):

        log_file_path, error = self.upload_file_to_minio(file_content=json.dumps(errors_list).encode('utf-8'), 
                                                         file_name=f'LogFile-{str(uuid.uuid4())}.json', content_type='application/json')
        if error:
            return {'Error': error}
        return {'AWSUsersUnsedPermissionListLogFile': log_file_path}
    

    def get_manager_for_user(self, df, target_user):
        try:    
            if 'Users' not in df.columns or 'Manager' not in df.columns:
                return None, "CSV file must contain 'Users' and 'Manager' columns."
            for _, row in df.iterrows():
                users_list = row['Users'].split(',')
                if target_user in users_list:
                    return row['Manager'], None
            return None, f"No manager found for user '{target_user}'."   
        except Exception as e:
            return None, str(e)    

    def get_input_permissions(self, user_permissions, service_with_permissions):

        try:
            input_permissions = []
            for permission in user_permissions:
                per_info = permission.split(":")
                service = per_info[0]
                service_permission = ''
                if len(per_info) == 2:
                    service_permission =  per_info[1]
                else:
                    continue
                if service.upper() in service_with_permissions:
                    service_permissions = service_with_permissions[service.upper()]
                    if "*" in service_permissions:
                        if service_permission != "*":
                           input_permissions.append(permission)
                        continue
                    if service_permission == "*":
                        if not "*" in service_permissions:
                           for per in service_permissions:
                               input_permissions.append(service+":"+per)
                        continue
                    elif service_permission in service_permissions:
                        input_permissions.append(permission)
            if input_permissions:
                input_permissions = list(set(input_permissions))
            return input_permissions, []
        except (IndexError,KeyError,ValueError,AttributeError) as e:
            return [], [{"Error": f"Error occured while handling user permission. {str(e)}"}]
        

    def get_user_events(self, event_df, user_name):
        filtered_df = event_df[event_df['UserName'] == user_name]
        eventnames = filtered_df['ResourceName']
        return list(eventnames)
    
    
    def validate(self):
        task_inputs = self.task_inputs
        if not task_inputs:
            return [{'Error': 'Task input is missing'}]
        user_object = task_inputs.user_object
        if not (user_object and user_object.app and user_object.app.user_defined_credentials):
            return [{'Error': 'User defined credential is missing'}]
        
        user_inputs = task_inputs.user_inputs 
        error_list = []
        empty_inputs = []   
        invalid_file_paths = []
        unsupported_types = []

        if not cowdictutils.is_valid_key(user_inputs, 'InactivePermissionsWindow'):
            empty_inputs.append("'InactivePermissionsWindow'")
        else:
            if not isinstance(user_inputs.get("InactivePermissionsWindow"), int):
                error_list.append({"Error" : "'InactivePermissionsWindow' type is not supported. Supported type is int"})
        
        # Validate UserManagerDetails
        user_manag_info_path = user_inputs.get('UserManagerDetails')
        if not user_manag_info_path:
            empty_inputs.append('UserManagerDetails')
        elif not isinstance(user_manag_info_path, str):
            unsupported_types.append('UserManagerDetails')
        else:
            if not self.is_valid_url(user_manag_info_path):
                invalid_file_paths.append('UserManagerDetails')
            else:
                extension = self.get_extension(user_manag_info_path)
                if extension  != ".csv":
                    error_list.append({"Error" : f"'UserManagerDetails' extension - '{extension}' is not supported. Supported extension is '.csv'"})
        
        # Validate EventFile
        event_file_path = user_inputs.get('EventFile')
        if not event_file_path:
            empty_inputs.append('EventFile')
        elif not isinstance(event_file_path, str):
            unsupported_types.append('EventFile')
        else:
            if not self.is_valid_url(event_file_path):
                invalid_file_paths.append('EventFile')
            else:
                extension = self.get_extension(event_file_path)
                if extension  != ".csv":
                    error_list.append({"Error" : f"'EventFile' extension - '{extension}' is not supported. Supported extension is '.csv'"})
        
        # Validate EventDetails
        if not cowdictutils.is_valid_key(user_inputs, 'EventDetails'):
            empty_inputs.append("'EventDetails'")
        else:
            event_url = self.task_inputs.user_inputs.get("EventDetails")
            if not isinstance(event_url, str):
                unsupported_types.append("EventDetails")
            else:
                is_valid = self.is_valid_url(event_url)
                if not is_valid:
                    invalid_file_paths.append("'EventDetails'")
        
        # Validate UserDetails
        if not cowdictutils.is_valid_key(user_inputs, 'UserDetails'):
            empty_inputs.append("'UserDetails'")
        else:
            user_url = self.task_inputs.user_inputs.get("UserDetails")
            if not isinstance(user_url, str):
                unsupported_types.append("UserDetails")
            else:
                is_valid = self.is_valid_url(user_url)
                if not is_valid:
                    invalid_file_paths.append("'UserDetails'")
        
        if empty_inputs:
            error_list.append({"Error":f"Empty inputs: {', '.join(empty_inputs)}"})
        if unsupported_types:
            error_list.append({"Error":f"Unsupported types: {', '.join(unsupported_types)}. Supported type is string"})
        if invalid_file_paths:
            error_list.append(f"Invalid file path(s): {', '.join(invalid_file_paths)}. Valid file path: http://host:port/folder_name/file_name_with_extension")
        return error_list

    def is_valid_url(self, url):
        try:
            result = urllib.parse.urlparse(url)
            if not all([result.scheme, result.netloc]):
                return False
        except ValueError:
            return False
        return True
    
    def get_extension(self, file_path):
        try:
            file_extension = os.path.splitext(file_path)[1]
            return file_extension
        except IndexError:
            return ''
