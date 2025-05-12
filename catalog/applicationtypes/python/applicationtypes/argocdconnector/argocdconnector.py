import http
import json
from typing import List, Any, Dict
from datetime import datetime, timezone
import requests

class BasicAuthentication:
    user_name: str
    password: str

    def __init__(self, user_name: str, password: str) -> None:
        self.user_name = user_name
        self.password = password

    @staticmethod
    def from_dict(obj) -> 'BasicAuthentication':
        user_name, password = "", ""
        if isinstance(obj, dict):
            user_name = obj.get("UserName", "")
            password = obj.get("Password", "")

        return BasicAuthentication(user_name, password)

    def to_dict(self) -> dict:
        result: dict = {}
        result["UserName"] = self.user_name
        result["Password"] = self.password
        return result

    def validate_attributes(self) -> str:
        emptyAttrs = []
        if not self.user_name:
            emptyAttrs.append("UserName")

        if not self.password:
            emptyAttrs.append("Password")

        return "Invalid Credentials: " + ", ".join(
            emptyAttrs) + " is empty" if emptyAttrs else ""


class UserDefinedCredentials:
    basic_authentication: BasicAuthentication

    def __init__(self, basic_authentication: BasicAuthentication) -> None:
        self.basic_authentication = basic_authentication

    @staticmethod
    def from_dict(obj) -> 'UserDefinedCredentials':
        basic_authentication = None
        if isinstance(obj, dict):
            basic_authentication = BasicAuthentication.from_dict(
                obj.get("BasicAuthentication", None))
        return UserDefinedCredentials(basic_authentication)

    def to_dict(self) -> dict:
        result: dict = {}
        result["BasicAuthentication"] = self.basic_authentication.to_dict()
        return result


class ArgoCDConnector:
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
    def from_dict(obj) -> 'ArgoCDConnector':
        app_url, app_port, user_defined_credentials = "", "", None

        if isinstance(obj, dict):
            app_url = obj.get("AppURL", "")
            if not app_url:
                app_url = obj.get("appURL", "")
            if not app_url:
                app_url = obj.get("appurl", "")
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

        return ArgoCDConnector(app_url, app_port, user_defined_credentials)

    def to_dict(self) -> dict:
        result: dict = {}
        result["AppURL"] = self.app_url
        result["AppPort"] = self.app_port
        result[
            "UserDefinedCredentials"] = self.user_defined_credentials.to_dict(
            )

        return result

    def validate(self) -> bool and dict:
        basic_auth = self.user_defined_credentials.basic_authentication
        token, error = self.get_api_token(basic_auth.user_name, basic_auth.password)
        if error:
            return False, error
        is_enabled, error = self.verify_account()
        if error:
            return False, error
        return True, None
    
    def get_api_token(self, username, password):
        argo_cd_url, error = self.get_app_url()
        if error:
            return None, error
        url = f"{argo_cd_url}/api/v1/session"
        payload = json.dumps({
            "username": username,
            "password": password
            })
        
        headers = {
            'Content-Type': 'application/json',
        }
        
        try:
            response = requests.request("POST", url, headers=headers, data=payload, verify=False) # verify is used for local development to bye-pass ssl verification
            response.raise_for_status()
            token = response.json().get("token")

            if token:
                return token, None
            else:
                raise ValueError("Token not found in the response.")

        except requests.exceptions.Timeout:
            return None, "TimeoutError: The request timed out. Please try again."
        except requests.exceptions.ConnectionError:
            return None, "ConnectionError: Failed to connect to the server. Invalid URL."
        except requests.exceptions.HTTPError as http_err:
            status_code = response.status_code
            if status_code == http.HTTPStatus.UNAUTHORIZED:
                return None, "Error 401: Unauthorized. Invalid username and/or password."
            elif status_code == http.HTTPStatus.FORBIDDEN:
                return None, "Error 403: Forbidden. Invalid username and/or password.."
            else:
                return None, f"HTTPError: An HTTP error occurred: {http_err}"
        except requests.exceptions.RequestException as req_err:
            return None, f"RequestException: An error occurred during the request: {req_err}"
        except ValueError as ve:
            return None, f"ValueError: {ve}"

    # https://cd.apps.argoproj.io/swagger-ui#operation/AccountService_GetAccount
    def verify_account(self):
        argo_cd_url, error = self.get_app_url()
        if error:
            return None, error
        basic_auth = self.user_defined_credentials.get("BasicAuthentication")
        username = basic_auth.get("UserName","")
        password = basic_auth.get("Password","")

        url = f"{argo_cd_url}/api/v1/account/{username}"
        token, error = self.get_api_token(username, password)
        if error:
            return False, error
        payload = {}
        headers = {
            "Authorization": f"Bearer {token}"
        }

        try:
            response = requests.request("GET", url, headers=headers, data=payload, verify=False)
            response.raise_for_status()

            account_data = response.json()
            enabled = account_data.get("enabled", False)
            if enabled:
                return True, None
            else:
                return False, None
        
        except requests.exceptions.Timeout:
            return None, "TimeoutError: The request timed out. Please try again."
        except requests.exceptions.ConnectionError:
            return None, "ConnectionError: Failed to connect to the server. Invalid URL."
        except requests.exceptions.HTTPError as http_err:
            status_code = response.status_code
            if status_code == http.HTTPStatus.UNAUTHORIZED:
                return None, "Error 401: Unauthorized. Invalid username and/or password."
            elif status_code == http.HTTPStatus.FORBIDDEN:
                return None, "Error 403: Forbidden. Invalid username and/or password."
            elif status_code == http.HTTPStatus.NOT_FOUND:
                return None, f"Error 404: User '{basic_auth.user_name}' not found."
            else:
                return None, f"HTTPError: An HTTP error occurred: {http_err}"
        except requests.exceptions.RequestException as req_err:
            return None, f"RequestException: An error occurred during the request: {req_err}"
        

    # https://cd.apps.argoproj.io/swagger-ui#operation/ApplicationService_List
    def get_applications(self):
        argo_cd_url, error = self.get_app_url()
        if error:
            return False, error
        basic_auth = self.user_defined_credentials.get("BasicAuthentication")
        username = basic_auth.get("UserName","")
        password = basic_auth.get("Password","")

        url = f"{argo_cd_url}/api/v1/applications"
        token, error = self.get_api_token(username, password)
        if error:
            return False, error
        headers = {
            "Authorization": f"Bearer {token}"
        }
        try:

            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            
            applications_data = response.json()
            return applications_data, None
        except requests.exceptions.Timeout:
            return None, "TimeoutError: The request timed out. Please try again."
        except requests.exceptions.ConnectionError:
            return None, "ConnectionError: Failed to connect to the server. Invalid URL."
        except requests.exceptions.HTTPError as http_err:
            status_code = response.status_code
            if status_code == http.HTTPStatus.UNAUTHORIZED:
                return None, "Error 401: Unauthorized. Invalid username and/or password."
            elif status_code == http.HTTPStatus.FORBIDDEN:
                return None, "Error 403: Forbidden. Invalid username and/or password."
            elif status_code == http.HTTPStatus.NOT_FOUND:
                return None, "Error 404: Not Found. The endpoint may be incorrect."
            else:
                return None, f"HTTPError: An HTTP error occurred: {http_err}"
        except requests.exceptions.RequestException as req_err:
            return None, f"RequestException: An error occurred during the request: {req_err}"
        
    def get_app_url(self):
        url = self.app_url
        if not url:
            return None, "AppURL is empty"

        return url.rstrip().rstrip("/"), None
    
    def get_current_datetime(self):       
        current_time = datetime.now(timezone.utc)
        formatted_time = current_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        return formatted_time