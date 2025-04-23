
from typing import overload
from compliancecowcards.structs import cards
# As per the selected app, we're importing the app package
from appconnections.oktaconnector import oktaconnector
import uuid
import pandas as pd


class Task(cards.AbstractTask):

    def execute(self) -> dict:
        error = self.check_inputs()
        if error:
            log_file_url, error = self.upload_log_file([{'error': error}])
            if error:
                return {'error': error}
            return {"LogFile": log_file_url}

        self.okta_connector = oktaconnector.OktaConnector(
            app_url=self.task_inputs.user_object.app.application_url,
            app_port=self.task_inputs.user_object.app.application_port,
            user_defined_credentials=oktaconnector.UserDefinedCredentials.from_dict(
                self.task_inputs.user_object.app.user_defined_credentials)
        )

        users, error = self.okta_connector.get_users()
        if error:
            file_url, error = self.upload_log_file(
                [{'error': f"Error while getting users :: {error}"}])
            if error:
                return error
            return {"LogFile": file_url}

        users_list, admin_users_list, errors_list = self.retrieve_okta_user_data(
            users)

        deactivated_users, error = self.okta_connector.get_deactivated_users()
        if error:
            file_url, error = self.upload_log_file(
                [{'error': f"Error while getting the deactivated users :: {error}"}])
            if error:
                return error
            return {"LogFile": file_url}

        deactivated_users_list, deactivated_admin_users_list, deactivated_errors_list = self.retrieve_okta_user_data(
            deactivated_users)

        users_list.extend(deactivated_users_list)
        admin_users_list.extend(deactivated_admin_users_list)
        errors_list.extend(deactivated_errors_list)

        response = {}

        if errors_list:
            log_file_url, error = self.upload_log_file(errors_list)
            if error:
                return {'error': error}
            response["LogFile"] = log_file_url

        users_file_url, error = self.upload_output_file(
            users_list, "OktaUsers")
        if error:
            return {'error': error}

        admin_users_file_url, error = self.upload_output_file(
            admin_users_list, "OktaAdminUsers")
        if error:
            return {'error': error}

        response.update({
            "OktaUsers": users_file_url,
            "OktaAdminUsers": admin_users_file_url
        })

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

    def _build_user_record(self, user):
        user_id = user.id if hasattr(user, 'id') else user['id']
        user_name = f"{user.profile.firstName} {user.profile.lastName}" if hasattr(
            user, 'profile') else f"{user['profile']['firstName']} {user['profile']['lastName']}"

        user_roles_data, error = self.okta_connector.get_user_roles(user_id)
        if error:
            return None, {
                "UserID": user_id,
                "UserName": user_name,
                "Error": f"Error occurred while getting user roles :: {error}"
            }

        user_roles = [role.label for role in user_roles_data]

        groups, error = self.okta_connector.get_user_groups(user_id)
        if error:
            return None, {
                "UserID": user_id,
                "UserName": user_name,
                "Error": f"Error occurred while getting user groups :: {error}"
            }

        group_details = [{
            "GroupID": group.id,
            "GroupName": group.profile.name
        } for group in groups if group.type.value != 'BUILT_IN']

        user_record = {
            "System": "okta",
            "Source": "compliancecow",
            "ResourceID": user_id,
            "ResourceName": user_name,
            "ResourceType": "User",
            "ResourceLocation": "N/A",
            "ResourceTags": "N/A",
            "ResourceURL": f"{self.okta_connector.app_url.rstrip().rstrip('/').replace('.okta', '-admin.okta')}/admin/user/profile/view/{user_id}#tab-account",
            "UserEmail": user.profile.email if hasattr(user, 'profile') else user['profile']['email'],
            "UserStatus": user.status if hasattr(user, 'status') else user['status'],
            "UserStatusChanged": user.status_changed if hasattr(user, 'status_changed') else user['statusChanged'],
            "UserGroups": group_details,
            "UserIsAdmin": bool(user_roles),
            "UserAdminRoles": user_roles,
            "UserCreatedDate": user.created if hasattr(user, 'created') else user['created'],
            "UserLastLogin": user.last_login if hasattr(user, 'last_login') else user['lastLogin'],
            "UserPasswordChanged": user.password_changed if hasattr(user, 'password_changed') else user['passwordChanged']
        }

        return user_record, None

    def retrieve_okta_user_data(self, users):
        users_list, admin_users_list, errors_list = [], [], []
        for user in users:
            user_record, error = self._build_user_record(user)
            if error:
                errors_list.append(error)
                continue
            users_list.append(user_record)
            if user_record["UserIsAdmin"]:
                admin_users_list.append(user_record)

        return users_list, admin_users_list, errors_list

    def retrieve_okta_deactivated_user_data(self, users):
        users_list, admin_users_list, errors_list = [], [], []
        for user in users:
            user_record, error = self._build_user_record(user)
            if error:
                errors_list.append(error)
                continue
            users_list.append(user_record)
            if user_record["UserIsAdmin"]:
                admin_users_list.append(user_record)

        return users_list, admin_users_list, errors_list

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
        if not output_data:
            return None, None

        file_url, error = self.upload_df_as_parquet_file_to_minio(
            df=pd.json_normalize(output_data),
            file_name=file_name
        )
        if error:
            return None, {'error': f"Error while uploading {file_name} file :: {error}"}
        return file_url, None
