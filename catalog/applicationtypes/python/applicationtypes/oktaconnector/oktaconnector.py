from okta.client import Client as OktaClient
from aiohttp.client_exceptions import ClientConnectionError
import asyncio
import requests
import json
import time
from datetime import datetime


class APIKey:
    api_key: str

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key

    @staticmethod
    def from_dict(obj) -> 'APIKey':
        api_key = ""
        if isinstance(obj, dict):
            api_key = obj.get("APIKey", "")

        return APIKey(api_key)

    def to_dict(self) -> dict:
        result: dict = {}
        result["APIKey"] = self.api_key
        return result

    def validate_attributes(self) -> str:
        emptyAttrs = []
        if not self.api_key:
            emptyAttrs.append("APIKey")

        return "Invalid Credentials: " + ", ".join(
            emptyAttrs) + " is empty" if emptyAttrs else ""


class UserDefinedCredentials:
    api_key: APIKey

    def __init__(self, api_key: APIKey) -> None:
        self.api_key = api_key

    @staticmethod
    def from_dict(obj) -> 'UserDefinedCredentials':
        api_key = None
        if isinstance(obj, dict):
            api_key = APIKey.from_dict(obj.get("APIKey", None))
        return UserDefinedCredentials(api_key)

    def to_dict(self) -> dict:
        result: dict = {}
        result["APIKey"] = self.api_key.to_dict()
        return result


class OktaConnector:
    app_url: str
    app_port: int
    user_defined_credentials: UserDefinedCredentials

    def __init__(
            self,
            app_url: str = None,
            app_port: int = None,
            user_defined_credentials: UserDefinedCredentials = None) -> None:
        self.app_url = app_url
        self.app_port = app_port
        self.user_defined_credentials = user_defined_credentials
        self.client = None

    @staticmethod
    def from_dict(obj) -> 'OktaConnector':
        app_url, app_port, user_defined_credentials = "", "", None
        if isinstance(obj, dict):
            app_url = obj.get("AppURL", "")
            if not app_url:
                app_url = obj.get("appURL", "")
            app_port = obj.get("AppPort", 0)
            if not app_port:
                app_port = obj.get("appPort", 0)
            user_defined_credentials_dict = obj.get("UserDefinedCredentials",
                                                    None)
            if user_defined_credentials_dict is None:
                user_defined_credentials_dict = obj.get(
                    "userDefinedCredentials", None)
            if bool(user_defined_credentials_dict):
                user_defined_credentials = UserDefinedCredentials.from_dict(
                    user_defined_credentials_dict)

        return OktaConnector(app_url, app_port, user_defined_credentials)

    def to_dict(self) -> dict:
        result: dict = {}
        result["AppURL"] = self.app_url
        result["AppPort"] = self.app_port
        result[
            "UserDefinedCredentials"] = self.user_defined_credentials.to_dict(
            )
        return result
    
    def get_current_datetime(self):
        current_time = datetime.utcnow()
        formatted_time = current_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        return formatted_time
    
    # https://github.com/okta/okta-sdk-python
    def create_new_client(self):
        if "-admin" in self.app_url:
            return "Your Okta domain should not contain -admin. You can copy your domain from the Okta Developer Console. Follow these instructions to find it: https://developer.okta.com/docs/guides/find-your-domain/overview"
        error = self.user_defined_credentials.api_key.validate_attributes()
        if error: 
            return error
        
        if not self.client:
            self.client = OktaClient({
                'orgUrl': self.app_url,
                'token': self.user_defined_credentials.api_key.api_key
            })
        
        return None

    def validate(self) -> bool and dict:
        error = self.create_new_client()
        if error: 
            return False, error
        
        _, _, error = asyncio.run(self.client.list_users({ 'limit': 1 }))
        if error:
            return False, self._get_okta_error_msg(error)

        return True, None
    
    def get_users(self):
        error = self.create_new_client()
        if error: 
            return None, error
        
        users, _, error = asyncio.run(self.client.list_users())
        if error: 
            return None, self._get_okta_error_msg(error)
        
        return users, None

    def get_applications(self):
        error = self.create_new_client()
        if error: 
            return None, error
        applications, _, error = asyncio.run(self.client.list_applications())
        if error: 
            return None, self._get_okta_error_msg(error)
        
        return applications, None

    def is_valid_user(self, userId) -> bool:
        error = self.create_new_client()
        if error: 
            return False
        
        user, _, error = asyncio.run(self.client.get_user(userId))
        if error or not user:
            return False
        
        return True
    
    def get_user_roles(self, userId):
        error = self.create_new_client()
        if error: 
            return None, error
        
        roles, _, error = asyncio.run(self.client.list_assigned_roles_for_user(userId))
        if error: 
            return None, self._get_okta_error_msg(error)
        
        return roles, None
    
    def get_application_users(self, appId, retries=3):
        back_off = 1
        while retries > 0:
            try:
                error = self.create_new_client()
                if error: 
                    return None, error
                users, _, error = asyncio.run(self.client.list_application_users(appId))
                if error: 
                    return None, self._get_okta_error_msg(error)
                return users, None
            
            except requests.exceptions.RequestException as e:
                retries -= 1  
                if retries == 0:
                    return None, f"Failed after {3} attempts: {e}"  # Initial number of retries was 3
                time.sleep(back_off)
                back_off *= 2 

    def get_application_groups(self, appId, retries):
        back_off = 1
        while retries > 0:
            try:
                error = self.create_new_client()
                if error:
                    return None, error
                
                groups, _, error = asyncio.run(self.client.list_application_group_assignments(appId))
                if error: 
                    return None, self._get_okta_error_msg(error)
                return groups, None
            
            except requests.exceptions.RequestException as e:
                retries -= 1 
                if retries == 0:
                    return None, f"Failed after {3} attempts: {e}"
                time.sleep(back_off)
                back_off *= 2  

    def get_user_details(self, userId):
        error = self.create_new_client()
        if error: 
            return None, error
        users, _, error = asyncio.run(self.client.get_user(userId))
        if error: 
            return None, self._get_okta_error_msg(error)
        return users, None

    def is_admin_user(self, userId, should_validate_user: bool = True) -> bool:
        error = self.create_new_client()
        if error: 
            return False
        
        if (should_validate_user and self.is_valid_user(userId)) or not should_validate_user:
            # get admin roles attached to the user
            roles, error = self.get_user_roles(userId)

            # if there are no roles, user is not admin
            if error or not roles: 
                return False
            
            return True
        
        return False
    
    def get_admin_users(self):
        error = self.create_new_client()
        if error: 
            return None, error
        
        users, error = self.get_users()
        if error:
            return None, error
        
        admin_users = [user for user in users if self.is_admin_user(user.id, should_validate_user=False)]
        return admin_users, error
    
    def get_user_factors(self, user_id):
        response, error = self.fetch_api_response(endpoint_url=f"/api/v1/users/{user_id}/factors")
        if error:
            return None, { 'error': error }
        return response, None
    
    def get_role_permission(self, role_id):
        response, error = self.fetch_api_response(endpoint_url=f"/api/v1/iam/roles/{role_id}/permissions")
        if error:
            return None, { 'error': error }
        return response, None
    
    def get_groups(self):
        error = self.create_new_client()
        if error: 
            return None, error
        
        groups, _, error = asyncio.run(self.client.list_groups())
        if error:
            return None, self._get_okta_error_msg(error)

        return groups, None

    
    def get_user_groups(self, userId):
        error = self.create_new_client()
        if error: 
            return None, error
        
        users, _, error = asyncio.run(self.client.list_user_groups(userId))
        if error: 
            return None, self._get_okta_error_msg(error)
        
        return users, None
    
    def get_admin_roles(self):
        error = self.create_new_client()
        if error: 
            return None, error
        
        users, _, error = asyncio.run(self.client)
        if error: 
            return None, self._get_okta_error_msg(error)
        
        return users, None
    
    def get_policies(self, type = 'OKTA_SIGN_ON'):
        error = self.create_new_client()
        if error: 
            return None, error
        
        policies, _, error = asyncio.run(self.client.list_policies({'type': type}))
        if error:
            return None, self._get_okta_error_msg(error)
        
        return policies, None
    
    # need to merge with "get_policies". temporarily added to fetch policy factors which is missing in "get_policies"
    def get_policiesv1(self, type = 'MFA_ENROLL'):
        policies, error = self.fetch_api_response(endpoint_url=f"/api/v1/policies?type={type}")
        if error:
            return None, { 'error': error }
        return policies, None
    
    def get_policy_rules(self, policyId):
        error = self.create_new_client()
        if error: 
            return None, error
        
        rules, _, error = asyncio.run(self.client.list_policy_rules(policyId))
        if error:
            return None, self._get_okta_error_msg(error)
        
        return rules, None
    
    def get_logs(
        self,
        from_date: str = "",
        to_date: str = "",
        sort_order: str = "DESCENDING"
    ):
        error = self.create_new_client()
        if error: 
            return None, error

        query_params = {
            'since': from_date,
            'until': to_date,
            'sortOrder': sort_order
        }

        logs, res, error = asyncio.run(self.client.get_logs(query_params=query_params))
        if error:
            return None, self._get_okta_error_msg(error)

        while res.has_next():
            new_logs, error = asyncio.run(res.next())
            if error:
                return None, self._get_okta_error_msg(error)
            if not new_logs:
                break
            logs.extend(new_logs)
        
        return logs, None
    
    def get_admin_logs(self):
        error = self.create_new_client()
        if error: 
            return None, error
        
        logs, error = self.get_logs()
        if error:
            return None, error
        
        admin_users, error = self.get_admin_users()
        if error:
            return None, error
        
        admin_user_ids = [user.id for user in admin_users]
        
        admin_logs = [log for log in logs if log.actor.type == 'User' and log.actor.id in admin_user_ids]

        return admin_logs, None

    def get_devices(self):
        devices, error = self.fetch_api_response(endpoint_url="/api/v1/devices")
        if error:
            return None, { 'error': error }
        
        return devices, None
    
    def get_device_users(self, deviceId):
        users, error = self.fetch_api_response(endpoint_url=f"/api/v1/devices/{deviceId}/users")
        if error:
            return None, { 'error': error }
        
        return users, None

    def fetch_api_response(
        self,
        endpoint_url: str,
        headers: dict = {},
        payload: dict = {},
        method: str = "get"
    ):
        if "-admin" in self.app_url:
            return None, "Your Okta domain should not contain -admin. You can copy your domain from the Okta Developer Console. Follow these instructions to find it: https://developer.okta.com/docs/guides/find-your-domain/overview"
        url = self.app_url.rstrip().rstrip("/")
        url = url + endpoint_url
        data = json.dumps(payload)
        headers.update({
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': f'SSWS {self.user_defined_credentials.api_key.api_key}'
        })
        response = requests.request(
            url=url,
            method=method,
            data=data,
            headers=headers
        )

        if response.ok:
            data, error = None, None
            try:
                data = response.json()
            except requests.JSONDecodeError:
                data = response
                error = "response is in an invalid format"
                
            return data, error
        
        return None, f"Error! {response.text}"
    
    def _get_okta_error_msg(self, error):
        if error:
            try:
                if isinstance(error, ClientConnectionError):
                    return "Invalid AppURL"
                elif error.error_summary == "Invalid token provided":
                    return "Invalid URL/APIKey. Please check."
                else:
                    return error.message            
            except AttributeError:
                return str(error)
        else:
            return None

    def get_deactivated_users(self):
        deactivated_users, error = self.fetch_api_response(
            endpoint_url=f'/api/v1/users?filter=status eq "DEPROVISIONED"')
        if error:
            return None, self._get_okta_error_msg(error)

        return deactivated_users, None
    
    def unassign_user_role(self, user_id, role_id):
        response, error = self.fetch_api_response(
            endpoint_url=f'/api/v1/users/{user_id}/roles/{role_id}', method="DELETE")
        if response.status_code == 204:
            return ''
        if error:
            return error
        return f'Failed to unassign role {role_id} to user {user_id}'