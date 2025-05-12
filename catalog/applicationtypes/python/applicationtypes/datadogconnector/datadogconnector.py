from typing import Tuple, List
import requests
import json
import http

class DataDogCred:
    api_key: str
    application_key: str

    def __init__(self, api_key: str, application_key: str) -> None:
        self.api_key = api_key
        self.application_key = application_key

    @staticmethod
    def from_dict(obj) -> 'DataDogCred':
        api_key, application_key = "", ""
        if isinstance(obj, dict):
            api_key = obj.get("APIKey", "")
            application_key = obj.get("ApplicationKey", "")

        return DataDogCred(api_key, application_key)

    def to_dict(self) -> dict:
        result: dict = {}
        result["APIKey"] = self.api_key
        result["ApplicationKey"] = self.application_key
        return result

    def validate_attributes(self) -> str:
        emptyAttrs = []
        if not self.api_key:
            emptyAttrs.append("APIKey")

        if not self.application_key:
            emptyAttrs.append("ApplicationKey")

        return "Invalid Credentials: " + ", ".join(
            emptyAttrs) + " is empty" if emptyAttrs else ""


class UserDefinedCredentials:
    data_dog_cred: DataDogCred

    def __init__(self, data_dog_cred: DataDogCred) -> None:
        self.data_dog_cred = data_dog_cred

    @staticmethod
    def from_dict(obj) -> 'UserDefinedCredentials':
        data_dog_cred = None
        if isinstance(obj, dict):
            data_dog_cred = DataDogCred.from_dict(obj.get("DataDogCred", None))
        return UserDefinedCredentials(data_dog_cred)

    def to_dict(self) -> dict:
        result: dict = {}
        result["DataDogCred"] = self.data_dog_cred.to_dict()
        return result


class DatadogConnector:
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
    def from_dict(obj) -> 'DatadogConnector':
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

        return DatadogConnector(app_url, app_port, user_defined_credentials)

    def to_dict(self) -> dict:
        result: dict = {}
        result["AppURL"] = self.app_url
        result["AppPort"] = self.app_port
        result["UserDefinedCredentials"] = self.user_defined_credentials.to_dict()
        return result

    def validate(self) -> Tuple[bool, str]:
        _, error = self.fetch_api_response(endpoint_url="/api/v2/logs/events")
        if error:
            return False, error
        return True, None
    
    def list_logs(self, from_date: str = "", to_date: str = "") -> Tuple[List[dict], dict]:
        params = {}
        if from_date:
            params['filter[from]'] = from_date
        if to_date:
            params['filter[to]'] = to_date

        params['page[limit]'] = 1000
        
        logs = []
        cursor = ''
        
        while True:
            if cursor:
                params['page[cursor]'] = cursor

            response, error = self.fetch_api_response(
                endpoint_url="/api/v2/logs/events",
                params=params
            )
            if error:
                return None, { 'error': error }

            new_logs = response.get('data', [])
            if not isinstance(new_logs, list):
                return None, { 'error': 'Got an invalid response. The \'data\' field must be a list.' }
            
            logs += new_logs 

            cursor = response.get('meta', {}).get('page', {}).get('after', '')
            if not cursor:
                break
        
        return logs, None
    
    def list_detection_rules(self) -> Tuple[List[dict], dict]:
        params = {
            'page[size]': 1000,
        }
        
        rules = []
        cur_page_num = 0
        while True:
            params['page[number]'] = cur_page_num
            response, error = self.fetch_api_response(
                endpoint_url="/api/v2/security_monitoring/rules",
                params=params
            )
            if error:
                return None, { 'error': error }
            
            new_rules = response.get('data')

            if not new_rules:
                break

            if not isinstance(new_rules, list):
                return None, { 'error': 'Got an invalid response. The \'data\' field must be a list.' }
            
            rules += new_rules
            
            cur_page_num += 1

        return rules, None
        
    
    def fetch_api_response(
        self,
        endpoint_url: str = "",
        params: dict = None,
        headers: dict = None,
        payload: dict = None,
        method: str = "get"
    ) -> Tuple[dict, str]:
        
        headers = {} if headers is None else headers
        
        url = self.app_url.rstrip().rstrip("/") + endpoint_url
        data = json.dumps(payload) if payload else ""
        headers.update({
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'DD-API-KEY': self.user_defined_credentials.data_dog_cred.api_key,
            'DD-APPLICATION-KEY': self.user_defined_credentials.data_dog_cred.application_key
        })

        try:
            response = requests.request(
                url=url,
                method=method,
                data=data,
                headers=headers,
                params=params
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
        
        if response.status_code == http.HTTPStatus.UNAUTHORIZED or response.status_code == http.HTTPStatus.FORBIDDEN:
            return None, "API Key or Application Key is invalid, please check."
        
        return None, f"An unknown error has occurred, response status code: {response.status_code}"

