from typing import overload
from compliancecowcards.structs import cards
#As per the selected app, we're importing the app package 
from applicationtypes.oktaconnector import oktaconnector
import uuid
import pandas as pd
import pytz
import json

class Task(cards.AbstractTask):

    def execute(self) -> dict:

        error = self.check_inputs()
        if error:
            log_file_url, error = self.upload_log_file([{ 'Error': error }])
            if error:
                    return { 'Error': error }
            return { "LogFile": log_file_url }
        
        user_records, error = self.download_parquet_file_from_minio_as_df(self.task_inputs.user_inputs.get("OktaUsers"))
        if error:
            log_file_url, error = self.upload_log_file([{ 'Error': f"Error while downloading OktaAdminUsers file :: {error}" }])
            if error:
                return { 'Error': error }
            return { "LogFile": log_file_url }
        
        okta_connector = oktaconnector.OktaConnector(
            app_url=self.task_inputs.user_object.app.application_url,
            app_port=self.task_inputs.user_object.app.application_port,
            user_defined_credentials=oktaconnector.UserDefinedCredentials.from_dict(
                self.task_inputs.user_object.app.user_defined_credentials)
        )

        try:
            user_records["UserCreatedDateTemp"] = pd.to_datetime(user_records["UserCreatedDate"], format="mixed", utc=True)
        except ValueError as e:
            return self.upload_log_file({'Error': f'Error occurred while formatting date in OktaUsers file :: {e}'})

        from_date = pd.Timestamp(self.task_inputs.from_date)
        to_date = pd.Timestamp(self.task_inputs.to_date)

        if not from_date.tz:
            from_date = from_date.tz_localize(pytz.UTC)
        if not to_date.tz:
            to_date = to_date.tz_localize(pytz.UTC)

        user_records = user_records[
            (user_records["UserCreatedDateTemp"] >= from_date) & 
            (user_records["UserCreatedDateTemp"] <= to_date)
        ]

        user_records = user_records.drop(columns=["UserCreatedDateTemp"])

        users_list = user_records.to_dict(orient='records')
        users_dict = {}
        for user in users_list:
            user_groups = user.pop('UserGroups', [])

            users_dict[user.get('ResourceID')] = {
                **user,
                "UserGroups": user_groups,
                "Roles": {},
                "UserApplications": [],
                "ValidationStatusCode": "", 
                "ValidationStatusNotes": "",
                "EvaluatedTime": okta_connector.get_current_datetime(),
                "UserAction": "",
                "ActionStatus": "",
                "ActionResponseURL": "",
            }
        
        include_groups = [group.strip() for group in self.task_inputs.user_inputs.get("IncludeGroups", "").split(",")] if self.task_inputs.user_inputs.get("IncludeGroups") else []
        exclude_groups = [group.strip() for group in self.task_inputs.user_inputs.get("ExcludeGroups", "").split(",")] if self.task_inputs.user_inputs.get("ExcludeGroups") else []

        include_apps = [group.strip() for group in self.task_inputs.user_inputs.get("IncludeApps", "").split(",")] if self.task_inputs.user_inputs.get("IncludeApps") else []
        exclude_apps = [group.strip() for group in self.task_inputs.user_inputs.get("ExcludeApps", "").split(",")] if self.task_inputs.user_inputs.get("ExcludeApps") else []
        
        errors_list = []

        groups, error = okta_connector.get_groups()

        valid_group_names = {group.profile.name for group in groups}

        invalid_groups = [group for group in include_groups if group not in valid_group_names]
        if invalid_groups:
             errors_list.append({ 'Error': f"Invalid group(s): {', '.join(invalid_groups)}" })

        applications, error = okta_connector.get_applications()
        if error:
            file_url, error = self.upload_log_file([{ 'Error': f"Error while getting applications :: {error}" }])
            if error:
                return error
            return { "LogFile": file_url }
        
        valid_apps = {app.label for app in applications}
        invalid_apps = [app for app in include_apps if app not in valid_apps]
        if invalid_apps:
            errors_list.append({ 'Error': f"Invalid application(s): {', '.join(invalid_apps)}" })

        error_messages = []
        if invalid_groups and len(invalid_groups) == len(include_groups):
            error_messages.append({'Error': "All include groups are invalid."})

        if invalid_apps and len(invalid_apps) == len(include_apps):
            error_messages.append({'Error': "All include applications are invalid."})

        if error_messages:
            log_file_url, error = self.upload_log_file(error_messages)
            if error:
                return {'Error': error}
            return {"LogFile": log_file_url}
        
        for app in applications:
            user_data, error = okta_connector.get_application_users(app.id, retries=3)
            if error:
                errors_list.append({
                    "Error": f"Error occurred while getting user for AppId - {app.id} :: {error}"
                })
                continue

            group_data , error = okta_connector.get_application_groups(app.id, retries=3)
            if error:
                errors_list.append({
                    "Error": f"Error occurred while getting groups for AppId - {app.id} :: {error}"
                })
                continue

            for user in user_data:                
                if user.id in users_dict:
                    user_groups = users_dict[user.id].get('UserGroups', [])

                    filtered_groups = []
                    for group in user_groups:
                        if (not exclude_groups or group['GroupName'] not in exclude_groups) and (not include_groups or group['GroupName'] in include_groups):
                            filtered_groups.append(group)
                    
                    users_dict[user.id]['UserGroups'] = filtered_groups

                    should_include_apps = not include_apps or app.label in include_apps
                    should_exclude_apps = not exclude_apps or app.label not in exclude_apps  

                    if should_include_apps and should_exclude_apps:
                        for key, value in user.profile.items():
                            if 'role' in key.lower():
                                if app.label not in users_dict[user.id]["Roles"]:
                                    users_dict[user.id]["Roles"][app.label] = [] 
                                if isinstance(value, str) and value:
                                    users_dict[user.id]["Roles"][app.label].append(value)
                                elif isinstance(value, list):
                                    users_dict[user.id]["Roles"][app.label].extend(value)

                        if user.scope == "USER":    
                            users_dict[user.id]['UserApplications'].append(app.label)

                        else:
                            user_group_map = {group['GroupID']: group['GroupName'] for group in filtered_groups}

                            for group in group_data:
                                group_name = user_group_map.get(group.id) 
                                if group_name and (not include_groups or group_name in include_groups) and (not exclude_groups or group_name not in exclude_groups) :             
                                        users_dict[user.id]['UserApplications'].append(app.label)
                                        break

        for _, details in users_dict.items():
            if isinstance(details, dict):
                if list(details.get('UserApplications')) and list(details.get('UserGroups')):
                    details['ValidationStatusCode'] = "USR_IN_SCP_APP_AND_GRP"
                    details['ValidationStatusNotes'] = "User is part of in-scope application and in-scope group."
                
                elif list(details.get('UserApplications')) and not list(details.get('UserGroups')):
                    details['ValidationStatusCode'] = "USR_IN_SCP_APP_ONLY"
                    details['ValidationStatusNotes'] = "User is part of in-scope applications but not part of any in-scope groups."
                
                elif not list(details.get('UserApplications')) and list(details.get('UserGroups')):
                    details['ValidationStatusCode'] = "USR_IN_SCP_GRP_ONLY"
                    details['ValidationStatusNotes'] = "User is not part of any in-scope applications but is part of in-scope groups."
                else:
                    details['ValidationStatusCode'] = "USR_NOT_IN_SCP"
                    details['ValidationStatusNotes'] = "User is not part of any in-scope applications and is not part of any in-scope groups."
        
        response = {}

        if errors_list:
            log_file_url, error = self.upload_log_file(errors_list)
            if error:
                return { 'Error': error }
            response["LogFile"] = log_file_url

        action_roles_format = "Application: {application_name}\n     • {application_roles}"
        output_records = [{
            **user,
            "UserGroups": [group.get('GroupName') for group in user.get('UserGroups', [])] or None,
            "UserApplications": user.get('UserApplications') if user.get('UserApplications') else None, 
            "ActionRoles": "\n".join([
                action_roles_format.format(
                    application_name=key,
                    application_roles='\n     • '.join(value)
                ) for key, value in user.get('Roles', {}).items()
            ]),
            "Roles": json.dumps(user.get('Roles', {}))
        } for user in users_dict.values()]
        
        users_file_url, error = self.upload_output_file(output_records, "OktaInscopeUserDetails")
        if error:
            return { 'Error': error }
        
        response["OktaInscopeUserDetails"] = users_file_url

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
        if not self.task_inputs.user_inputs.get("OktaUsers"):
            emptyAttrs.append("OktaUsers")

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
        if not output_data:
            return None, None

        df = pd.DataFrame(output_data)

        file_url, error = self.upload_df_as_parquet_file_to_minio(
            df=df,
            file_name=file_name
        )
        if error:
            return None, { 'Error': f"Error while uploading {file_name} file :: {error}" }
        return file_url, None