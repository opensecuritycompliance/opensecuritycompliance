from typing import Tuple
import requests
import json
import http

class AccessToken:
    access_token: str

    def __init__(self, access_token: str) -> None:
        self.access_token = access_token

    @staticmethod
    def from_dict(obj) -> 'AccessToken':
        access_token = ""
        if isinstance(obj, dict):
            access_token = obj.get("AccessToken", "")

        return AccessToken(access_token)

    def to_dict(self) -> dict:
        result: dict = {}
        result["AccessToken"] = self.access_token
        return result

    def validate_attributes(self) -> str:
        emptyAttrs = []
        if not self.access_token:
            emptyAttrs.append("AccessToken")

        return "Invalid Credentials: " + ", ".join(
            emptyAttrs) + " is empty" if emptyAttrs else ""


class UserDefinedCredentials:
    access_token: AccessToken

    def __init__(self, access_token: AccessToken) -> None:
        self.access_token = access_token

    @staticmethod
    def from_dict(obj) -> 'UserDefinedCredentials':
        access_token = None
        if isinstance(obj, dict):
            access_token = AccessToken.from_dict(obj.get("AccessToken", None))
        return UserDefinedCredentials(access_token)

    def to_dict(self) -> dict:
        result: dict = {}
        result["AccessToken"] = self.access_token.to_dict()
        return result


class TeamCityConnector:
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

    @staticmethod
    def from_dict(obj) -> 'TeamCityConnector':
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

        return TeamCityConnector(app_url, app_port, user_defined_credentials)

    def to_dict(self) -> dict:
        result: dict = {}
        result["AppURL"] = self.app_url
        result["AppPort"] = self.app_port
        result[
            "UserDefinedCredentials"] = self.user_defined_credentials.to_dict(
            )

        return result

    def validate(self) -> Tuple[bool, str]:
        _, error = self.list_users()
        if error:
            return False, error.get('error', '')
        return True, None
    
    def list_users(self) -> Tuple[dict, dict]:
        users, error = self.fetch_api_response("/app/rest/users")
        if error:
            return None, { 'error': error }
        
        return users, None
    
    def get_user(self, user_id) -> Tuple[dict, dict]:
        user, error = self.fetch_api_response(f"/app/rest/users/id:{user_id}")
        if error:
            return None, { 'error': error }
        
        return user, None
    
    def get_user_groups(self, user_id) -> Tuple[dict, dict]:
        user_groups, error = self.fetch_api_response(f"/app/rest/users/id:{user_id}/groups")
        if error:
            return None, { 'error': error }
        
        return user_groups, None
    
    def get_user_roles(self, user_id) -> Tuple[dict, dict]:
        user_roles, error = self.fetch_api_response(f"/app/rest/users/id:{user_id}/roles")
        if error:
            return None, { 'error': error }
        
        return user_roles, None
    
    def list_groups(self) -> Tuple[dict, dict]:
        groups, error = self.fetch_api_response("/app/rest/userGroups")
        if error:
            return None, { 'error': error }
        
        return groups, None
    
    def get_group(self, group_key: str) -> Tuple[dict, dict]:
        users, error = self.fetch_api_response(f"/app/rest/userGroups/key:{group_key}")
        if error:
            return None, { 'error': error }
        
        return users, None
    
    def fetch_api_response(
        self,
        endpoint_url: str,
        headers: dict = None,
        payload: dict = None,
        method: str = "get"
    ) -> Tuple[dict, str]:
        
        headers = {} if headers is None else headers
        payload = {} if payload is None else payload
        
        url = self.app_url.rstrip().rstrip("/")
        url = url + endpoint_url
        data = json.dumps(payload)
        headers.update({
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.user_defined_credentials.access_token.access_token}'
        })

        try:
            response = requests.request(
                url=url,
                method=method,
                data=data,
                headers=headers
            )
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            return None, f'Invalid URL, please check.'
        except requests.exceptions.RequestException:
            return None, f'An unknown exception has occurred.'  

        if response.ok:
            data, error = None, None
            try:
                data = response.json()
            except requests.JSONDecodeError:
                data = response
                error = "Response is in an invalid format."
                
            return data, error
        
        if response.status_code == http.HTTPStatus.UNAUTHORIZED:
            return None, "Invalid Access Token, please check."
        
        return None, f"An unknown error has occurred, response status code: {response.status_code}"
