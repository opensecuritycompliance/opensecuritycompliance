import time
from typing import List, Any, Dict
import pandas as pd
import requests
import http
from datetime import datetime
from urllib.parse import urlencode
from compliancecowcards.utils import cowdictutils

class SnykCredential:
    api_key: str

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key

    @staticmethod
    def from_dict(obj) -> 'SnykCredential':
        api_key = ""
        if isinstance(obj, dict):
            api_key = obj.get("ApiKey", "")

        return SnykCredential(api_key)

    def to_dict(self) -> dict:
        result: dict = {}
        result["ApiKey"] = self.api_key
        return result

    def validate_attributes(self) -> str:
        emptyAttrs = []
        if not self.api_key:
            emptyAttrs.append("ApiKey")

        return "Invalid Credentials: " + ", ".join(
            emptyAttrs) + " is empty" if emptyAttrs else ""


class UserDefinedCredentials:
    snyk_credential: SnykCredential

    def __init__(self, snyk_credential: SnykCredential) -> None:
        self.snyk_credential = snyk_credential

    @staticmethod
    def from_dict(obj) -> 'UserDefinedCredentials':
        snyk_credential = None
        if isinstance(obj, dict):
            snyk_credential = SnykCredential.from_dict(
                obj.get("SnykCredential", None))
        return UserDefinedCredentials(snyk_credential)

    def to_dict(self) -> dict:
        result: dict = {}
        result["SnykCredential"] = self.snyk_credential.to_dict()
        return result


class SnykAppConnector:
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
    def from_dict(obj) -> 'SnykAppConnector':
        app_url, app_port, user_defined_credentials, linked_applications = "", "", None, None
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

        return SnykAppConnector(app_url, app_port, user_defined_credentials)

    def to_dict(self) -> dict:
        result: dict = {}
        result["AppURL"] = self.app_url
        result["AppPort"] = self.app_port
        result[
            "UserDefinedCredentials"] = self.user_defined_credentials.to_dict(
            )

        return result

    def validate(self) -> bool and dict:

        org_id, user_name, error = self.get_self_details()
        if error:
            return False, error

        login_url = self.app_url.rstrip("/")
        
        validation_url = f"{login_url}/rest/orgs/{org_id}/settings/sast?version=2024-06-10"
        response, error = self.make_api_call(url=validation_url)
        if error:
            error_message = error if isinstance(error, str) else error.get("error", "Invalid URL")
            if "Unauthorized" in error_message or "Access Forbidden" in error_message or "Account trial expired" in error_message:
                return False, "Invalid API Key."
            return False, error_message
        
        if response:
            return True, None

        return False, "Invalid API Key."  
    
    def make_api_call(self,url, method='GET', params=None, data=None, json=None):
        api_key = self.user_defined_credentials.snyk_credential.api_key
        headers = {
                'Authorization': 'token ' + api_key,
                'Content-Type': 'application/json'
                }
        try:
            response = requests.request(method=method, url=url, headers=headers, params=params, data=data, json=json)

            if response.status_code == http.HTTPStatus.FORBIDDEN:
                return None, {"error": "Invalid API Key."}
            if response.status_code == http.HTTPStatus.UNAUTHORIZED:
                return None, {"error": "Unauthorized."}
            if response.status_code == http.HTTPStatus.OK or response.status_code == http.HTTPStatus.CREATED:
                return response, None
            
            response.raise_for_status()
            return None , { "error" : response.json()} 

        except requests.exceptions.HTTPError as http_err:
            return None, {"error": f"HTTP error occurred: {http_err}"}
        except requests.exceptions.ConnectionError:
            return None, {"error": "Connection error occurred. Please check the network."}
        except requests.exceptions.Timeout:
            return None, {"error": "Request timed out. Please try again later."}
        except requests.exceptions.RequestException as err:
            return None, {"error": f"An unexpected error occurred: {err}"}

    def flatten_json(self, json_obj, parent_key='', level=0):
        flattened_dict = {}
        for key, value in json_obj.items():
            key = key[0].upper() + key[1:]
            if key == "Id":
                key = "ResourceID"
            parent_key = parent_key.capitalize()
            new_key = f"{parent_key}{key}" if parent_key else key
            if isinstance(value, dict) and level != 1:
                flattened_dict.update(self.flatten_json(
                    value, new_key, level=level+1))
            else:
                flattened_dict[new_key] = value
        return flattened_dict
    
    
    def get_snyk_issues_report(self , org_id,  project) : 
        
        login_url = self.app_url
        login_url = login_url.rstrip("/")
        
        url = login_url + "/v1/org/{org_id}/project/{project_id}/aggregated-issues"
        url = url.replace("{org_id}" , org_id)
        
        reports = []
        
        url = url.replace("{project_id}" , project)
        
        payload = {
            "includeDescription": True,
            "includeIntroducedThrough": True
            }
        
        
        response ,error = self.make_api_call(url = url ,method="POST", json=payload)
        if error :
            return None,error
        
        response_body = response.json()
        
        issues_list= response_body.get("issues")
        
        if issues_list :
            reports.extend(issues_list)
        
            
        return reports ,None
    
    def  get_image_details(self , org_id,  project) : 
        login_url = self.app_url
        login_url = login_url.rstrip("/")
        
        url = login_url + "/v1/org/{org_id}/project/{project_id}"
        url = url.replace("{org_id}" , org_id)
        url = url.replace("{project_id}" , project)
        
        
        response ,error = self.make_api_call(url = url)
        if error :
            if "Not Found for url" in error["error"] :
                return "", {"error" : "Invalid Project ID " + project }
            return "",error
        
        response_body = response.json()
        
        return response_body ,None
    

    def get_epss_score_for_cve(self, cve_id):
        epss_api = f"https://api.first.org/data/v1/epss?cve={cve_id}"

        try:
            response = requests.get(epss_api)
            response.raise_for_status()
            epss_res_data = response.json()

            if epss_res_data.get("data"):
                epss_score_float = float(epss_res_data["data"][0]["epss"])
                epss_percentile_float = float(epss_res_data["data"][0]["percentile"])
                epss_score = f"{epss_score_float * 100:.2f}"
                epss_percentile = f"{epss_percentile_float * 100:.2f}"
                epss_date = epss_res_data["data"][0]["date"]
                return epss_score, epss_percentile, epss_date, None
            else:
                return "", "", "", "No data available for the given CVE."
        except requests.RequestException as err:
            return "", "", "", str(err)
        
    def get_org_id_using_name(self , org_name) :
        
        login_url = self.app_url
        login_url = login_url.rstrip("/")
        
        url = login_url + "/v1/orgs"
        
        response ,error = self.make_api_call(url = url)
        if error :
            return "",error
        
        response_body = response.json()
        orgs_df = pd.DataFrame(response_body.get("orgs" , None))
        if not orgs_df.empty   :
            org_id_list = orgs_df.loc[orgs_df["name"] == org_name, "id"].values
            if len(org_id_list) > 0 :
                return org_id_list[0] ,None
            else:
                return None ,{"error" : "Invalid organization name."}
                
        return None ,{"error" : "Invalid organization name."}

    # Get authenticated user details
    def get_self_details(self):
        base_url = self.app_url
        url = base_url + "/rest/self"
        params = {
            "version": "2024-08-22"
        }
        api_key = self.user_defined_credentials.snyk_credential.api_key
        headers = {
            'Authorization': f'token {api_key}',
            'Content-Type': 'application/json'
        }
        try:
            response = requests.request(method="GET", url=url, headers=headers, params=params)
            response.raise_for_status()
            response_data = response.json()
            if not cowdictutils.is_valid_key(response_data, "data"):
                return None, None, {"error": "The 'data' key is missing in the authentication response."}
            
            authenticate_data = response_data["data"]
            if not cowdictutils.is_valid_key(authenticate_data, "attributes"):
                return None, None, {"error": "The 'attributes' key is missing in the 'data' field."}
            
            authenticate_attributes = authenticate_data["attributes"]
            if not cowdictutils.is_valid_key(authenticate_attributes, "default_org_context"):
                return None, None, {"error": "The 'default_org_context' key is missing in the 'attributes' data."}
            if not cowdictutils.is_valid_key(authenticate_attributes, "username"):
                return None, None, {"error": "The 'username' key is missing in the 'attributes' data."}

            org_id = authenticate_attributes["default_org_context"]
            user_name = authenticate_attributes["username"]

            return org_id, user_name, None

        except requests.exceptions.HTTPError as http_err:
            return None, None, {"error": f"HTTP error occurred: {http_err}"}
        except requests.exceptions.RequestException as err:
            return None, None, {"error": f"Request error occurred: {err}"}
        
    # Get targets by org ID
    def get_targets_by_org(self, org_id):
        base_url = self.app_url
        url = base_url + f"/rest/orgs/{org_id}/targets"
        params = {
            "version": "2024-08-22"
        }
        response_url = f"{url}?{urlencode(params)}"
        
        api_key = self.user_defined_credentials.snyk_credential.api_key
        headers = {
            'Authorization': f'token {api_key}',
            'Content-Type': 'application/json'
        }
        
        target_data = []
        retries = 3
        backoff = 1
        while retries > 0:
            try:
                response = requests.get(url=response_url, headers=headers)
                response.raise_for_status()
                data = response.json()
                target_data.extend(data.get("data", []))

                response_url = data.get("links", {}).get("next", None)
                if response_url != None:
                    response_url = base_url + response_url
                else:
                    break
            except requests.exceptions.HTTPError as http_err:
                return None, {"error": f"HTTP error occurred: {http_err}"}
            except requests.exceptions.RequestException as err:
                retries -= 1
                if retries == 0:
                    return None, {"error": f"Request error occurred: {err}"}
                time.sleep(backoff)
                backoff *= 2
        return target_data, None

    # List all projects for an Org with the given Org ID and Target ID
    def get_projects_by_org_and_target(self, org_id, target_ids=None):
        base_url = self.app_url
        url = base_url + f"/rest/orgs/{org_id}/projects"
        params = {
            "version": "2024-08-22"
        }
        if target_ids:
            params["target_id"] = target_ids
        response_url = f"{url}?{urlencode(params, doseq=True)}"
        
        api_key = self.user_defined_credentials.snyk_credential.api_key
        headers = {
            'Authorization': f'token {api_key}',
            'Content-Type': 'application/json'
        }
        
        project_data = []
        retries = 3
        backoff = 1
        while retries > 0:
            try:
                response = requests.get(url=response_url, headers=headers)
                response.raise_for_status()
                data = response.json()
                project_data.extend(data.get("data", []))

                response_url = data.get("links", {}).get("next", None)
                if response_url:
                    response_url = base_url + response_url
                else:
                    break
            except requests.exceptions.HTTPError as http_err:
                return None, {"error": f"HTTP error occurred: {http_err}"}
            except requests.exceptions.RequestException as err:
                retries -= 1
                if retries == 0:
                    return None, {"error": f"Request error occurred: {err}"}
                time.sleep(backoff)
                backoff *= 2
        return project_data, None

    # Get issues by org ID and project ID
    def get_issues_by_org_and_project(self, org_id, project_id=None):
        base_url = self.app_url
        url = base_url + f"/rest/orgs/{org_id}/issues"
        params = {
            "version": "2024-08-22",
            "scan_item.id": project_id,
            "scan_item.type": "project"
        }
        response_url = f"{url}?{urlencode(params)}"
        
        api_key = self.user_defined_credentials.snyk_credential.api_key
        headers = {
            'Authorization': f'token {api_key}',
            'Content-Type': 'application/json'
        }
        
        issue_data = []
        retries = 3
        backoff = 1
        while retries > 0:
            try:
                response = requests.get(url=response_url, headers=headers)
                response.raise_for_status()
                data = response.json()
                issue_data.extend(data.get("data", []))

                response_url = data.get("links", {}).get("next", None)
                if response_url:
                    response_url = base_url + response_url
                else:
                    break
            except requests.exceptions.HTTPError as http_err:
                return None, {"error": f"HTTP error occurred: {http_err}"}
            except requests.exceptions.RequestException as err:
                retries -= 1
                if retries == 0:
                    return None, {"error": f"Request error occurred: {err}"}
                time.sleep(backoff)
                backoff *= 2
        return issue_data, None
    
    def get_current_datetime(self):
        
        current_time = datetime.utcnow()
        formatted_time = current_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        return formatted_time