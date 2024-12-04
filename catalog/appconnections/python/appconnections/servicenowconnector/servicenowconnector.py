from typing import List
import requests
import time
import pandas as pd
import http
import logging
import urllib.parse
from requests.auth import HTTPBasicAuth
from compliancecowcards.utils import cowdictutils


class SNOW:
    user_name: str
    password: str

    def __init__(self, user_name: str, password: str) -> None:
        self.user_name = user_name
        self.password = password

    @staticmethod
    def from_dict(obj) -> 'SNOW':
        user_name, password = "", ""
        if isinstance(obj, dict):
            user_name = obj.get("UserName", "")
            password = obj.get("Password", "")

        return SNOW(user_name, password)

    def to_dict(self) -> dict:
        result: dict = {}
        result["UserName"] = self.user_name
        result["Password"] = self.password
        return result


class UserDefinedCredentials:
    snow: SNOW

    def __init__(self, snow: SNOW) -> None:
        self.snow = snow

    @staticmethod
    def from_dict(obj) -> 'UserDefinedCredentials':
        snow = None
        if isinstance(obj, dict):
            snow = SNOW.from_dict(obj.get("SNOW", None))
        return UserDefinedCredentials(snow)

    def to_dict(self) -> dict:
        result: dict = {}
        result["SNOW"] = self.snow.to_dict()
        return result


class ServiceNowConnector:
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
    def from_dict(obj) -> 'ServiceNowConnector':
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

        return ServiceNowConnector(app_url, app_port, user_defined_credentials)

    def to_dict(self) -> dict:
        result: dict = {}
        result["AppURL"] = self.app_url
        result["AppPort"] = self.app_port
        result[
            "UserDefinedCredentials"] = self.user_defined_credentials.to_dict(
        )
        return result

    def validate(self) -> bool and dict:
        try:
            base_url = self.app_url
            user_name = self.user_defined_credentials.snow.user_name
            password = self.user_defined_credentials.snow.password
            url = f"{base_url}/api/now/ui/meta/cmdb_ci_ec2_instance"
            res = requests.get(url, auth=(user_name, password))
            if res.status_code == 200:
                return True,None
            elif res.status_code == 401:
                return False,{"error": "Invalid UserName or Password"}
            else:
                error = res.json().get("error")
                return False,error
        except requests.exceptions.ConnectionError:
            return False, {"error": "Invalid AppURL"}

# INFO : You can implement methods (to access the application) which can be then invoked from your task code
    def get_link_value(self, links, links_map, field):
        user_name = self.user_defined_credentials.snow.user_name
        password = self.user_defined_credentials.snow.password
        for link in links:
            retries = 3
            back_off = 1
            try:
                if not link or str(link) == "nan":
                    continue
                if links_map.get(link):
                    continue
                url = f"{link}?sysparm_fields={field},"
                response = requests.get(url, auth=(user_name, password))
                if response.status_code != 200:
                    return links_map, {"error": "invalid status code"}
                res = response.json()
                if res:
                    result = res.get("result")
                    if result:
                        links_map[link] = result.get(field)
            except requests.exceptions.RequestException as e:
                retries -= 1
                if retries == 0:
                    return links_map, {"error": e}
                time.sleep(back_off)
                back_off *= 2
        return links_map, None

    def fetch_data(self, base_url):
        max_record = 10000
        current_page = 1
        temp_df = pd.DataFrame()
        user_name = self.user_defined_credentials.snow.user_name
        password = self.user_defined_credentials.snow.password
        while True:
            retries = 3
            back_off = 1
            try:
                url = f"{base_url}&sysparm_limit={max_record}&sysparm_offset={(current_page-1)*max_record}"
                response = requests.get(url, auth=(user_name, password))
                if response.status_code != 200:
                    return temp_df, {"error": f"invalid status code.{response.status_code}"}
                current_page += 1
                df = pd.DataFrame(response.json().get("result"))
                if df.empty:
                    return temp_df, None
                temp_df = pd.concat([temp_df, df], axis=0)
            except requests.exceptions.RequestException as e:
                retries -= 1
                if retries == 0:
                    return temp_df, f"error:{e}"
                time.sleep(back_off)
                back_off *= 2


    # https://docs.servicenow.com/bundle/washingtondc-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html
    def list_change_requests(self, table_name):
        
        if not table_name or not isinstance(table_name, str):
            return None, "Invalid Table name. Please provide a valid table name to proceed"
        
        if not self.app_url or not self.is_valid_url(self.app_url):
            return None, "Invalid App URL. Please provide a valid App URL to proceed"

        user_name, password, err = self.get_auth_credentials()
        if err:
            return None, err

        sysparm_limit = 10000
        sysparm_offset = 0
        total_change_reqs = []

        while True:
            query_params = {
                'sysparm_limit': sysparm_limit,
                'sysparm_offset': sysparm_offset,
            }
            change_reqs, err_msg = self.make_api_call(
                url=f"{self.app_url}/api/now/table/{table_name}",
                method='GET',
                user_name=user_name,
                password=password,
                params=query_params
            )
            if err_msg:
                return None, err_msg
            if not change_reqs:
                break
            
            total_change_reqs.extend(change_reqs['result'])
            sysparm_offset += len(change_reqs['result'])
            if len(change_reqs['result']) < sysparm_limit:
                break
        return total_change_reqs, ''
    

    def list_change_requests_for_given_period(self, from_date, to_date, table_name):

        if not from_date or not to_date:
            return None, "From date and to date are mandatory to proceed."
        
        change_reqs, err_msg = self.list_change_requests(table_name)
        if err_msg:
            return None, err_msg
        change_reqs_df = pd.DataFrame(change_reqs)

        if change_reqs_df.empty:
            return None, ""

        if 'opened_at' not in change_reqs_df.columns:
            return None, "'opened_at' column is not present in the change requests."

        # Convert the 'opened_at' column to datetime
        change_reqs_df['opened_at'] = pd.to_datetime(change_reqs_df['opened_at'])

        if change_reqs_df['opened_at'].isnull().any():
            return None, "Some dates in 'opened_at' could not be converted to datetime."
        
        # Convert datetime format for comparision 
        from_date = from_date.strftime("%Y/%m/%d %H:%M")
        to_date = to_date.strftime("%Y/%m/%d %H:%M")
        
        # Filter the DataFrame based on the date range
        filtered_df = change_reqs_df[(change_reqs_df['opened_at'] >= from_date) 
                                     & (change_reqs_df['opened_at'] <= to_date)]
        
        return filtered_df.to_dict(orient='records'), ''
    
    def get_assignment_group(self, assignment_grp_id):

        if not assignment_grp_id:
            return None, 'Assignment group ID is mandatory to assignment user details.'
        if not isinstance(assignment_grp_id, str):
            return None, 'Invalid Assignment group ID. Supported type: String'

        user_name, password, err = self.get_auth_credentials()
        if err:
            return None, err
        
        assign_grp_details, err_msg = self.make_api_call(
            url       = f'{self.app_url}/api/now/table/sys_user_group/{assignment_grp_id}',
            method    = 'GET',
            user_name = user_name,
            password  = password,
            
        )
        if err_msg:
            return None, err_msg
        
        if cowdictutils.is_valid_key(assign_grp_details, 'result'):
            return assign_grp_details.get('result'), ''
    
        return None, f'Failed to fetch assignment group ({assignment_grp_id}) details . Please contact support for further details.'
    
    
    def get_user(self, user_id):

        if not user_id:
            return None, 'User ID is mandatory to fetch user details.'
        if not isinstance(user_id, str):
            return None, 'Invalid User ID. Supported type: String'
        
        user_name, password, err = self.get_auth_credentials()
        if err:
            return None, err

        user_details, err_msg = self.make_api_call(
            url     = f'{self.app_url}/api/now/table/sys_user/{user_id}',
            method  = 'GET',
            user_name= user_name,
            password= password,
        )
        if err_msg:
            return None, err_msg
        
        if cowdictutils.is_valid_key(user_details, 'result'):
            return user_details.get('result'), ''
    
        return None, f'Failed to fetch user({user_id}) details . Please contact support for further details.'
    
    
    def get_resource_url(self, sys_id):

        empty_fields = []
        if not self.app_url:
            empty_fields.append("App URL")
        if not sys_id:
            empty_fields.append("Sys ID")

        if empty_fields:
            return '', "These fields are mandatory for generating the resource URL: " + ", ".join(empty_fields)

        return f"{self.app_url.rstrip('/')}/change_request.do?sys_id={sys_id}", ""
        
     # Generic method to make api call
    def make_api_call(self, url, method, headers=None, json=None, data=None, files=None, user_name=None, password=None, params=None):
        if not url:
            return None, 'API URL is mandatory to make an API call'
            
        err_msg = f"Error occurred while making API call to '{url}'. "
        supported_methods = ['GET', 'POST', 'PATCH', 'PUT', 'DELETE']
        
        if method not in supported_methods:
            return None, f"Invalid HTTP method. Supported types: {', '.join(supported_methods)}"
        
        max_retries = 3
        try_count = 0

        response = None

        while try_count < max_retries:
            try:
                response = requests.request(
                    method, url, auth=HTTPBasicAuth(user_name, password),
                    headers=headers, json=json, data=data, files=files,
                    params=params
                )
                
                if "Your instance is hibernating" in response.text:
                    return None, "Your ServiceNow instance is hibernating. Please sign in to wake it up."
                
                if response.status_code == http.HTTPStatus.UNAUTHORIZED:
                    return None, f"{err_msg}Invalid 'UserName' or 'Password'"
                elif response.status_code == http.HTTPStatus.NOT_FOUND:
                    err_msg += "Resource not found. Please try again with valid data."
                    return None, f"{err_msg} {response.text}" if response.text else err_msg
                elif response.status_code == http.HTTPStatus.FORBIDDEN:
                    err_msg += "Access Denied. Please try with valid permission."
                    return None, f"{err_msg} {response.text}" if response.text else err_msg
                elif response.status_code == http.HTTPStatus.TOO_MANY_REQUESTS:
                    logging.info(f"Retrying API call to '{url}' since received response status code is {http.HTTPStatus.TOO_MANY_REQUESTS}. Retry count: {try_count}")
                elif response.ok:
                    return response.json(), None
                
                return None, f"{err_msg}Error message: {response.text}" if response.text else f"{err_msg}Status code: {response.status_code}. Please contact support for further details"
                
            except requests.exceptions.ConnectionError as e:
                err_msg = f"Connection error occurred while making API call to {url}. {str(e)}"
            except requests.exceptions.Timeout as e:
                err_msg = f"Timeout exception occurred while making API call to {url}. {str(e)}"
            except requests.JSONDecodeError as e:
                err_msg = f"Error while typecasting API response to JSON. {str(e)}"
                return None, err_msg
            except requests.exceptions.RequestException as e:
                err_msg = f"Request exception occurred while making API call to {url}. {str(e)}"

            logging.info(f"Retrying API call to '{url}'. {err_msg}. Retry count: {try_count}")
            try_count += 1
            time.sleep(2)

        if response:
            return None, f"{err_msg} even after maximum retries. Status code: {response.status_code}"
        
        return None, f"{err_msg} even after maximum retries."
    

    def is_valid_url(self, url):
        try:
            result = urllib.parse.urlparse(url)
            if not all([result.scheme, result.netloc]):
                return False
            return True
        except ValueError as e:
            return False
    
    # Generic method to auth creds for all api calls 
    def get_auth_credentials(self):
        user_defined_credentials = self.user_defined_credentials
        if (cowdictutils.is_valid_key(user_defined_credentials, 'UserName') and 
            cowdictutils.is_valid_key(user_defined_credentials, 'Password')):
            return user_defined_credentials.get('UserName'), user_defined_credentials.get('Password'), ''
        return "", "", "'UserName' or 'Password' is empty"