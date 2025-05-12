from typing import List, Any, Dict
import requests
import re
import json
import base64
import subprocess
import tempfile
from urllib.parse import urlencode
from io import StringIO
import pandas as pd
import http
import jq

class CustomType:
    validation_curl: str
    credential_json: str

    def __init__(self, validation_curl: str, credential_json: str) -> None:
        self.validation_curl = validation_curl
        self.credential_json = credential_json

    @staticmethod
    def from_dict(obj) -> 'CustomType':
        validation_curl, credential_json = "", ""
        if isinstance(obj, dict):
            validation_curl = obj.get("ValidationCURL", "")
            credential_json = obj.get("CredentialJson", "")

        return CustomType(validation_curl, credential_json)

    def to_dict(self) -> dict:
        result: dict = {}
        result["ValidationCURL"] = self.validation_curl
        result["CredentialJson"] = self.credential_json
        return result

    def validate_attributes(self) -> str:
        emptyAttrs = []
        if not self.validation_curl:
            emptyAttrs.append("ValidationCURL")

        return "Invalid Credentials: " + ", ".join(
            emptyAttrs) + " is empty" if emptyAttrs else ""


class UserDefinedCredentials:
    custom_type: CustomType

    def __init__(self, custom_type: CustomType) -> None:
        self.custom_type = custom_type

    @staticmethod
    def from_dict(obj) -> 'UserDefinedCredentials':
        custom_type = None
        if isinstance(obj, dict):
            custom_type = CustomType.from_dict(obj.get("CustomType", None))
        return UserDefinedCredentials(custom_type)

    def to_dict(self) -> dict:
        result: dict = {}
        result["CustomType"] = self.custom_type.to_dict()
        return result


class SalesforceAppConnector:
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
    def from_dict(obj) -> 'SalesforceAppConnector':
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

        return SalesforceAppConnector(app_url, app_port,
                                      user_defined_credentials)

    def to_dict(self) -> dict:
        result: dict = {}
        result["AppURL"] = self.app_url
        result["AppPort"] = self.app_port
        result["UserDefinedCredentials"] = self.user_defined_credentials.to_dict()

        return result

    def validate(self) -> bool and dict:
        validation_curl = self.user_defined_credentials.custom_type.validation_curl
        
        if validation_curl.strip()=='':
             return False , {'Error': 'ValidationCURL cannot be empty.'} 
        credentials_json = {}
        
        if self.user_defined_credentials.custom_type.credential_json :
            credentials_json_bytes = base64.b64decode(self.user_defined_credentials.custom_type.credential_json).decode('utf-8')
            try:
                credentials_json = json.loads(credentials_json_bytes)
            except json.JSONDecodeError as e:
                return False , {'Error': 'Error while reading "CredentialJson" data, Invalid JSON data.'} 
        
        parsed_curl, error = self.replace_placeholder(validation_curl , 'CustomType', credentials_json)
        if error :
            return False , {'Error': 'Error while processing place holders.'} 
        
        return self.validate_curl(parsed_curl)
    
    def replace_placeholder(self, target_str, placeholder_prefix, value_dict):
        pattern = f"<<{placeholder_prefix}([^>]+)>>"
        matches = re.findall(pattern, target_str)

        if not matches:
            return target_str, None

        for placeholder_key in matches:
            query = placeholder_key.strip()
            if not query.startswith(".") :
                query = f".{placeholder_key.strip()}"
            parsed_value = jq.first( query, value_dict)
            if parsed_value  :
                target_str = target_str.replace(f"<<{placeholder_prefix}{placeholder_key}>>" , parsed_value.strip())

            else:
                file_type = placeholder_prefix[:-1]
                if file_type == "inputfile":
                    file_type = "InputFile"
                else:
                    file_type = "AppInfo"
                    
                return "", {"error": f"Cannot resolve query '{placeholder_prefix}{placeholder_key}'. {file_type} has no field {placeholder_key}."}
        
        return target_str, None
    
    def validate_curl(self , parsed_curl ) :
        
        status_code ,_, error = self.execute_curl(parsed_curl)
        if error  :
            return False , {'Error': 'CURL command failed. Please check the URL and parameters.'} 
        
        sucessful_statues = ['200','201','202' , '204']
        is_resp_valid = True if status_code in sucessful_statues else False
        if is_resp_valid:
            return True,None
        else:
            return False , {'Error': f"CURL command failed with HTTP status code {status_code}. Check the CURL or Credentials."} 
            
    
    
    def execute_curl(self, curl_cmd):
        curl_cmd = curl_cmd.replace('\\','')
        curl_cmd = curl_cmd.replace('\n','')
        
        try:
            result = subprocess.run(
                curl_cmd + ' -s -o /dev/null -w "%{http_code}"',  
                shell=True, 
                check=True,  
                stdout=subprocess.PIPE,  
                stderr=subprocess.PIPE,  
                text=True  
            )

            status_code = result.stdout.strip()

            with tempfile.NamedTemporaryFile() as temp_file:
                body_cmd = curl_cmd + f' -s -o {temp_file.name}'
                subprocess.run(body_cmd, shell=True, check=True)

                temp_file.seek(0)  # Ensure we're at the beginning of the file
                response_body = temp_file.read()

            return status_code, response_body, None

        except subprocess.CalledProcessError as e:
            return None, None, f"An error occurred: {e.stderr}"
        
        
    def get_salesforce_access_token(self):
        access_token = ""
        url = (
            f"https://login.salesforce.com/services/oauth2/token"
        )
        credentialsJSon = self.user_defined_credentials.custom_type.credential_json
        
        decoded_bytes = base64.b64decode(credentialsJSon)
        decoded_string = decoded_bytes.decode('utf-8')
        credentials = json.loads(decoded_string)
        form = {
            "grant_type":credentials["grant_type"],
            "client_id": credentials["client_id"],
            "client_secret": credentials["client_secret"],
            "username": credentials["username"],
            "password": credentials["password"],
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = requests.post(url, data= urlencode(form), headers=headers)

        if response.status_code ==  http.HTTPStatus.OK:
            credential = json.loads(response.text)
            access_token = credential["token_type"]+" " + credential["access_token"]
            return access_token, None
        else:
            return None, response.text

    
    def get_credential_json_data(self) :
        credentials_json = {}
        credentials_json_bytes = base64.b64decode(self.user_defined_credentials.custom_type.credential_json).decode('utf-8')
        try:
            credentials_json = json.loads(credentials_json_bytes)
        except json.JSONDecodeError as e:
            return None , f"Error while reading \"CredentialJson\" data, Invalid JSON data: {e}"
        return credentials_json,None

    
    def get_permissions_by_permissionset_id(self, permission_set_id):
        if not permission_set_id:
            return None,"PermissionSetId cannot be Empty"
        
        authorization, err=self.get_salesforce_access_token()
        if err:
            return None, err

        headers = {
                "Content-Type": "application/json",
                "Authorization": authorization,
            }
        
        request_url=self.app_url
        if not self.app_url.endswith('/'):
            request_url +="/"

        request_url+="services/data/v41.0/sobjects/PermissionSet/"+permission_set_id

        response = requests.get(request_url, headers=headers)

        resBody = response.json()
        if response.status_code == http.HTTPStatus.OK or response.status_code == http.HTTPStatus.CREATED:
            return resBody, None
        else:
            errNew = response.text
            if not  errNew:
                errNew = response
            return None, f"An error occurred while retrieving permissions for the permission set - '{permission_set_id}'. {str(errNew)}"
        
    def get_eventlog_by_id(self, event_log_id):
        if not event_log_id:
            return None, "event_log_id cannot be Empty"
        
        authorization, err=self.get_salesforce_access_token()
        if err:
            return None, err

        headers = {
                "Content-Type": "application/json",
                "Authorization": authorization,
            }
        
        request_url=self.app_url
        if not self.app_url.endswith('/'):
            request_url +="/"

        request_url+="services/data/v41.0/sobjects/EventLogFile/"+event_log_id+"/LogFile"

        response = requests.get(request_url, headers=headers)
        # return response
        if response.status_code == http.HTTPStatus.OK:
            csv_data = StringIO(response.text)
            dataFrame = pd.read_csv(csv_data)
            return dataFrame,None
        else:
            errNew = response.text
            if not  errNew:
                errNew = response
            return None, errNew
        

    def get_user_by_id(self, user_id):
        if not user_id:
            return None,"PermissionSetId cannot be Empty"
        
        authorization, err=self.get_salesforce_access_token()
        if err:
            return None, err

        headers = {
                "Content-Type": "application/json",
                "Authorization": authorization,
            }
        
        request_url=self.app_url
        if not self.app_url.endswith('/'):
            request_url +="/"

        request_url+="services/data/v41.0/sobjects/User/"+user_id

        response = requests.get(request_url, headers=headers)

        resBody = response.json()
        if response.status_code == http.HTTPStatus.OK:
            return resBody, None
        else:
            errNew = response.text
            if not  errNew:
                errNew = response
            return None, errNew