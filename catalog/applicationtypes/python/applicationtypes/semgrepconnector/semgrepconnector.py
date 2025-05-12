import http
from typing import List, Any, Dict
from datetime import datetime, timezone
import requests
from requests.exceptions import HTTPError, Timeout

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


class SemgrepConnector:
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
    def from_dict(obj) -> 'SemgrepConnector':
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

        return SemgrepConnector(app_url, app_port, user_defined_credentials)

    def to_dict(self) -> dict:
        result: dict = {}
        result["AppURL"] = self.app_url
        result["AppPort"] = self.app_port
        result[
            "UserDefinedCredentials"] = self.user_defined_credentials.to_dict(
            )

        return result
    
    def validate(self):
        validate, err = self.get_deployments()
        if err:
            return False, err
        return True, None

    def get_headers(self):
        return {
            "Authorization": f"Bearer {self.user_defined_credentials.access_token.access_token}",
            "Content-Type": "application/json"
        }

    def get_deployments(self):
        url = f"https://semgrep.dev/api/v1/deployments"
        try:
            response = requests.get( url, headers=self.get_headers())
            if response.status_code == http.HTTPStatus.UNAUTHORIZED :
                return None, "Invalid AccessToken."
            response.raise_for_status()
            return response.json(), None
        except HTTPError as http_err:
            return None, f"HTTP error occurred: {http_err}"
        except Timeout as timeout_err:
            return None, f"Request timed out: {timeout_err}"
        except ConnectionError as conn_err:
            return None, f"Connection error occurred: {conn_err}"
        except requests.RequestException as req_err:
            return None, f"Request error occurred: {req_err}"
        
    def get_projects(self, deployment_slug, project_name=""):
        if project_name:
            url = f"https://semgrep.dev/api/v1/deployments/{deployment_slug}/projects/{project_name}"
        else:
            url = f"https://semgrep.dev/api/v1/deployments/{deployment_slug}/projects"

        try:
            response = requests.get(url, headers=self.get_headers())
            response.raise_for_status()
            return response.json(), None
        except requests.HTTPError as http_err:
            return None, f"HTTP error occurred: {http_err}"
        except requests.Timeout as timeout_err:
            return None, f"Request timed out: {timeout_err}"
        except requests.ConnectionError as conn_err:
            return None, f"Connection error occurred: {conn_err}"
        except requests.RequestException as req_err:
            return None, f"Request error occurred: {req_err}"

    def list_findings(self, deployment_slug, issue_type="sast", repos=[], severities=[]):
        url = f"https://semgrep.dev/api/v1/deployments/{deployment_slug}/findings"
        try:
            params = {
            "issue_type": issue_type,
            "repos": ",".join(repos),
            }
            if severities:
                params["severities"] = ",".join(severities)

            response = requests.get(url, headers=self.get_headers(), params=params)
            response.raise_for_status()
            return response.json(), None
        except HTTPError as http_err:
            return None, f"HTTP error occurred: {http_err}"
        except Timeout as timeout_err:
            return None, f"Request timed out: {timeout_err}"
        except ConnectionError as conn_err:
            return None, f"Connection error occurred: {conn_err}"
        except requests.RequestException as req_err:
            return None, f"Request error occurred: {req_err}"

    def list_secrets(self, deployment_id, cursor=None, repos=[], severities=[]):
        url = f"https://semgrep.dev/api/v1/deployments/{deployment_id}/secrets"
        try:
            params = {
                "repo": ",".join(repos),
            }
            if cursor:
                params["cursor"] = cursor
            if severities:
                params["severity"] = ",".join(severities)

            response = requests.get( url, headers=self.get_headers(), params=params)
            response.raise_for_status()
            return response.json(), None
        except HTTPError as http_err:
            return None, f"HTTP error occurred: {http_err}"
        except Timeout as timeout_err:
            return None, f"Request timed out: {timeout_err}"
        except ConnectionError as conn_err:
            return None, f"Connection error occurred: {conn_err}"
        except requests.RequestException as req_err:
            return None, f"Request error occurred: {req_err}"
        
    def get_current_datetime(self):       
        current_time = datetime.now(timezone.utc)
        formatted_time = current_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        return formatted_time