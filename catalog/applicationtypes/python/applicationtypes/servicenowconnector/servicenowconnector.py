from typing import List, Any, Dict
import requests
import time
import pandas as pd
import http
import logging
import urllib.parse
from requests.auth import HTTPBasicAuth
from compliancecowcards.utils import cowdictutils
from urllib.parse import urlparse


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


class OAuth:
    client_id: str
    client_secret: str

    def __init__(self, client_id: str, client_secret: str) -> None:
        self.client_id = client_id
        self.client_secret = client_secret

    @staticmethod
    def from_dict(obj) -> 'OAuth':
        client_id, client_secret = "", ""
        if isinstance(obj, dict):
            client_id = obj.get("ClientID", "")
            client_secret = obj.get("ClientSecret", "")

        return OAuth(client_id, client_secret)

    def to_dict(self) -> dict:
        result: dict = {}
        result["ClientID"] = self.client_id
        result["ClientSecret"] = self.client_secret
        return result

    def validate_attributes(self) -> str:
        emptyAttrs = []
        if not self.user_name:
            emptyAttrs.append("UserName")

        if not self.password:
            emptyAttrs.append("Password")

        if not self.client_id:
            emptyAttrs.append("ClientID")

        if not self.client_secret:
            emptyAttrs.append("ClientSecret")

        return "Invalid Credentials: " + ", ".join(
            emptyAttrs) + " is empty" if emptyAttrs else ""


class UserDefinedCredentials:
    snow: SNOW
    o_auth: OAuth

    def __init__(self, snow: SNOW, o_auth: OAuth) -> None:
        self.snow = snow
        self.o_auth = o_auth

    @staticmethod
    def from_dict(obj) -> 'UserDefinedCredentials':
        snow, o_auth = None, None
        if isinstance(obj, dict):
            snow = SNOW.from_dict(obj.get("SNOW", None))
            o_auth = OAuth.from_dict(obj.get("OAuth", None))
        return UserDefinedCredentials(snow, o_auth)

    def to_dict(self) -> dict:
        result: dict = {}
        result["SNOW"] = self.snow.to_dict()
        result["OAuth"] = self.o_auth.to_dict()
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

    def validate(self) -> tuple[bool, dict | None]:
        if not self.is_empty_servicenow_basic_auth():
            return self.validate_servicenow_basic_auth()
        elif not self.is_empty_servicenow_oauth():
            return self.validate_servicenow_oauth()
        else:
            return False, {"Error": "No valid ServiceNow credentials provided"}

    def is_empty_servicenow_basic_auth(self):
        creds = self.user_defined_credentials.snow
        return not all((creds.user_name, creds.password))

    def is_empty_servicenow_oauth(self):
        creds = self.user_defined_credentials.o_auth
        return not all((creds.client_id, creds.client_secret))

    def validate_servicenow_basic_auth(self):
        try:
            base_url = self.app_url
            creds = self.user_defined_credentials.snow

            url = f"{base_url}/api/now/table/sys_user?sysparm_limit=1"
            res = requests.get(url, auth=(creds.user_name, creds.password))

            if res.status_code == 200:
                return True, None
            elif res.status_code == 401:
                return False, {"error": "Invalid username or password"}
            else:
                return False, res.json().get("error", {"error": "Unknown error"})

        except requests.exceptions.ConnectionError:
            return False, {"error": "Invalid AppURL"}

    def get_servicenow_oauth_token(self):
        try:
            base_url = self.get_base_url()
            creds = self.user_defined_credentials.o_auth

            token_url = f"{base_url}/oauth_token.do"

            payload = {
                "grant_type": "client_credentials",
                "client_id": creds.client_id,
                "client_secret": creds.client_secret
            }

            res = requests.post(token_url, data=payload)

            if res.status_code == 200:
                data = res.json()
                return f"{data.get('token_type')} {data.get('access_token')}", None
            elif res.status_code == 401:
                return None, {"error": "Invalid client_id or client_secret"}
            else:
                return None, res.json().get("error")

        except requests.exceptions.ConnectionError:
            return None, {"error": "Invalid AppURL"}

    def get_base_url(self):
        return self.app_url.rstrip("/")

    def validate_servicenow_oauth(self):
        token, error = self.get_servicenow_oauth_token()
        if error:
            return False, error

        try:
            base_url = self.app_url
            url = f"{base_url}/api/now/table/sys_user?sysparm_limit=1"

            headers = {
                "Authorization": f"{token}",
                "Accept": "application/json"
            }

            res = requests.get(url, headers=headers)

            if res.status_code == 200:
                return True, None
            elif res.status_code == 401:
                return False, {"error": "Invalid or expired OAuth token"}
            else:
                return False, res.json().get("error", {"error": "Unknown error"})

        except requests.exceptions.ConnectionError:
            return False, {"error": "Invalid AppURL"}

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
        change_reqs_df['opened_at'] = pd.to_datetime(
            change_reqs_df['opened_at'])

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
            url=f'{self.app_url}/api/now/table/sys_user_group/{assignment_grp_id}',
            method='GET',
            user_name=user_name,
            password=password,

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
            url=f'{self.app_url}/api/now/table/sys_user/{user_id}',
            method='GET',
            user_name=user_name,
            password=password,
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
                    logging.info(
                        f"Retrying API call to '{url}' since received response status code is {http.HTTPStatus.TOO_MANY_REQUESTS}. Retry count: {try_count}")
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

            logging.info(
                f"Retrying API call to '{url}'. {err_msg}. Retry count: {try_count}")
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

    def upload_record(self, table_name, record_data):
        """
        Uploads a record to the specified ServiceNow table using the Table API.

        Args:
            table_name (str): The name of the ServiceNow table.
            record_data (dict): Dictionary containing the record fields and values.

        Returns:
            tuple: (record_response, error_message)
        """

        # Input Validation
        if not table_name or not isinstance(table_name, str):
            return None, "Table name is required and must be a string."
        if not record_data or not isinstance(record_data, dict):
            return None, "Record data must be a non-empty dictionary."

        # Get auth credentials
        user_name, password, err = self.get_auth_credentials()
        if err:
            return None, err

        # Construct API URL
        url = f"{self.app_url}/api/now/table/{table_name}"

        headers = {"Content-Type": "application/json",
                   "Accept": "application/json"}

        # Make POST request to create a new record
        response_data, err_msg = self.make_api_call(
            url=url,
            method="POST",
            user_name=user_name,
            password=password,
            json=record_data,
            headers=headers,
        )

        if err_msg:
            return None, err_msg

        # Return the result
        if cowdictutils.is_valid_key(response_data, "result"):
            return response_data.get("result"), ""

        return (
            None,
            f'Failed to upload record to table "{table_name}". Please contact support.',
        )

    def update_cmdb_table(self, url, payload):
        username, password, err = self.get_auth_credentials()
        if err:
            return None, err

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        response = requests.post(url, headers=headers, auth=HTTPBasicAuth(
            username, password), json=payload)

        if response.status_code not in [200, 201]:
            if response.status_code == 401:
                return None, {"error": "Invalid UserName or Password"}
            else:
                error = response.json().get(
                    "error", {"message": "Unknown error"})
                return None, error

        result = response.json()
        sys_id = result.get("result", {}).get("sys_id")
        tag_url = self.build_tag_url(url)
        tag_payload = {
            "table": "cmdb_ci",
            "sys_id": sys_id,
            "tags": ["pci"]
        }

        tag_response = requests.post(tag_url, headers=headers, auth=HTTPBasicAuth(
            username, password), json=tag_payload)
        if tag_response.status_code not in [200, 201]:
            return None, {"error": "Tag update failed", "details": tag_response.text}

        return result, None

    def build_tag_url(self, cmdb_url: str) -> str:
        """
        Given a ServiceNow table API URL, build the tag API URL.
        """
        parsed = urlparse(cmdb_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        return f"{base_url}/api/ntni/add_sys_tag_for_record"

    def upload_attachment(
        self,
        table_name: str,
        table_sys_id: str,
        file_name: str,
        file_bytes: bytes,
        content_type: str = "application/pdf"
    ) -> tuple[dict | None, dict | None]:

        try:
            base_url = self.get_base_url()
            access_token, error = self.get_servicenow_oauth_token()
            if error:
                return None, error

            url = (
                f"{base_url}/api/now/attachment/file"
                f"?table_name={table_name}"
                f"&table_sys_id={table_sys_id}"
                f"&file_name={file_name}"
            )

            headers = {
                "Accept": "application/json",
                "Authorization": f"{access_token}",
                "Content-Type": content_type,
            }

            res = requests.post(url, headers=headers, data=file_bytes)

            if res.status_code == 201:
                return res.json(), None

            if res.status_code == 401:
                return None, {"error": "Unauthorized - invalid or expired token"}

            error_body = res.json()
            return None, error_body.get("error", {"error": "Failed to upload attachment"})

        except requests.exceptions.ConnectionError:
            return None, {"error": "Invalid AppURL"}
        except Exception as ex:
            return None, {"error": str(ex)} 

    def update_assessment_instance_state(self, sys_id, data):

        if not sys_id:
            return None, "Sys ID is mandatory to update assessment instance."
        if not isinstance(sys_id, str):
            return None, "Invalid Sys ID. Supported type: String"

        user_name, password, err = self.get_auth_credentials()
        if err:
            return None, err

        response, err_msg = self.make_api_call(
            url=f"{self.app_url}/api/now/table/asmt_assessment_instance/{sys_id}",
            method="PATCH",
            headers={"Content-Type": "application/json"},
            user_name=user_name,
            password=password,
            data=data,
        )
        if err_msg:
            return None, err_msg

        if cowdictutils.is_valid_key(response, "result"):
            return response.get("result"), ""

        return (
            None,
            f"Failed to update assessment instance ({sys_id}) state . Please contact support for further details.",
        )

    def update_attestation_answer(self, sys_id, data):

        if not sys_id:
            return None, "Sys ID is mandatory to update assessment instance."
        if not isinstance(sys_id, str):
            return None, "Invalid Sys ID. Supported type: String"

        user_name, password, err = self.get_auth_credentials()
        if err:
            return None, err

        response, err_msg = self.make_api_call(
            url=f"{self.app_url}/api/now/table/asmt_assessment_instance_question/{sys_id}",
            method="PATCH",
            user_name=user_name,
            password=password,
            data=data,
        )
        if err_msg:
            return None, err_msg

        if cowdictutils.is_valid_key(response, "result"):
            return response.get("result"), ""

        return (
            None,
            f"Failed to update attestation answer - {sys_id} . Please contact support for further details.",
        )
    

    def get_ass_instance_question(self, sys_id):

        if not sys_id:
            return None, "Sys ID is mandatory to update assessment instance."
        if not isinstance(sys_id, str):
            return None, "Invalid Sys ID. Supported type: String"

        user_name, password, err = self.get_auth_credentials()
        if err:
            return None, err

        response, err_msg = self.make_api_call(
            url=f"{self.app_url}/api/now/table/asmt_assessment_instance_question/{sys_id}",
            method="GET",
            user_name=user_name,
            password=password,
        )
        if err_msg:
            return None, err_msg

        if cowdictutils.is_valid_key(response, "result"):
            return response.get("result"), ""

        return (
            None,
            f"Failed to get ass instance question - {sys_id} . Please contact support for further details.",
        )
    
    def create_ass_instance_question(self, payload):

        if not payload:
            return None, "payload is mandatory to update assessment instance."

        user_name, password, err = self.get_auth_credentials()
        if err:
            return None, err

        response, err_msg = self.make_api_call(
            url=f"{self.app_url}/api/now/table/asmt_assessment_instance_question",
            method="POST",
            user_name=user_name,
            headers={"Content-Type":"application/json"},
            password=password,
            data=payload
        )
        if err_msg:
            return None, err_msg

        if cowdictutils.is_valid_key(response, "result"):
            return response.get("result"), ""

        return (
            None,
            f"Failed to create assessment instance - {payload} . Please contact support for further details.",
        )

    def update_smart_attestation_answer(self, sys_id, data):

        if not sys_id:
            return None, "Sys ID is mandatory to update assessment instance."
        if not isinstance(sys_id, str):
            return None, "Invalid Sys ID. Supported type: String"

        user_name, password, err = self.get_auth_credentials()
        if err:
            return None, err

        response, err_msg = self.make_api_call(
            url=f"{self.app_url}/api/now/table/sn_smart_asmt_question_instance/{sys_id}",
            method="PATCH",
            user_name=user_name,
            password=password,
            data=data,
        )
        if err_msg:
            return None, err_msg

        if cowdictutils.is_valid_key(response, "result"):
            return response.get("result"), ""

        return (
            None,
            f"Failed to update attestation answer - {sys_id} . Please contact support for further details.",
        )

    def update_attestation_file_upload_answer(self, sys_id, file_name, data, headers):

        if not sys_id:
            return None, "Sys ID is mandatory to update assessment instance."
        if not isinstance(sys_id, str):
            return None, "Invalid Sys ID. Supported type: String"

        user_name, password, err = self.get_auth_credentials()
        if err:
            return None, err

        url = (
            f"{self.app_url}/api/now/attachment/file"
            f"?table_name=asmt_assessment_instance_question"
            f"&table_sys_id={sys_id}"
            f"&file_name={file_name}"
        )

        response, err_msg = self.make_api_call(
            url=url,
            method="POST",
            user_name=user_name,
            password=password,
            data=data,
            headers=headers,
        )
        if err_msg:
            return None, err_msg

        if cowdictutils.is_valid_key(response, "result"):
            return response.get("result"), ""

        return (
            None,
            f"Failed to update attestation answer - {sys_id} . Please contact support for further details.",
        )

    def update_smart_attestation_file_upload_answer(
        self, sys_id, file_name, data, headers
    ):

        if not sys_id:
            return None, "Sys ID is mandatory to update assessment instance."
        if not isinstance(sys_id, str):
            return None, "Invalid Sys ID. Supported type: String"

        user_name, password, err = self.get_auth_credentials()
        if err:
            return None, err

        url = (
            f"{self.app_url}/api/now/attachment/file"
            f"?table_name=sn_smart_asmt_question_instance"
            f"&table_sys_id={sys_id}"
            f"&file_name={file_name}"
        )

        response, err_msg = self.make_api_call(
            url=url,
            method="POST",
            user_name=user_name,
            password=password,
            data=data,
            headers=headers,
        )
        if err_msg:
            return None, err_msg

        if cowdictutils.is_valid_key(response, "result"):
            return response.get("result"), ""

        return (
            None,
            f"Failed to update attestation answer - {sys_id} . Please contact support for further details.",
        )

    def update_smart_assessment_instance_state(self, sys_id, data):

        if not sys_id:
            return None, "Sys ID is mandatory to update assessment instance."
        if not isinstance(sys_id, str):
            return None, "Invalid Sys ID. Supported type: String"

        user_name, password, err = self.get_auth_credentials()
        if err:
            return None, err

        response, err_msg = self.make_api_call(
            url=f"{self.app_url}/api/now/table/sn_smart_asmt_instance/{sys_id}",
            method="PATCH",
            headers={"Content-Type": "application/json"},
            user_name=user_name,
            password=password,
            data=data,
        )
        if err_msg:
            return None, err_msg

        if cowdictutils.is_valid_key(response, "result"):
            return response.get("result"), ""

        return (
            None,
            f"Failed to update assessment instance ({sys_id}) state . Please contact support for further details.",
        )

    def get_sn_smart_asmt_response_option_instance(self, ass_instance, qn_instance):

        if not ass_instance or not qn_instance:
            return (
                None,
                "Assessment instance and Question instance are mandatory to update assessment instance.",
            )

        user_name, password, err = self.get_auth_credentials()
        if err:
            return None, err
        

        url = (
            f"{self.app_url}/api/now/table/sn_smart_asmt_response_option_instance"
            f"?sysparm_query=question_instance.assessment_questionSTARTSWITH{qn_instance}"
            f"%5Eassessment_instance.numberSTARTSWITH{ass_instance}"
            f"&sysparm_limit=10"
        )

        response, err_msg = self.make_api_call(
            # url=f"{self.app_url}/api/now/table/sn_smart_asmt_response_option_instance?sysparm_query=question_instance.assessment_questionSTARTSWITH{qn_instance}%3F%5Eassessment_instance.numberSTARTSWITH{ass_instance}&sysparm_limit=10",
            url = url,
            method="GET",
            headers={"Content-Type": "application/json"},
            user_name=user_name,
            password=password,
        )
        if err_msg:
            return None, err_msg

        if cowdictutils.is_valid_key(response, "result"):
            return response.get("result"), ""

        return (
            None,
            f"Failed to update sn_smart_asmt_response_option_instance data. Assessment Instance - {ass_instance}, Question Instance - {qn_instance}. Please contact support for further details.",
        )

    def get_sn_smart_asmt_response_option_value(self, id):

        if not id:
            return (
                None,
                "Assessment response option id is mandatory to update assessment instance.",
            )

        user_name, password, err = self.get_auth_credentials()
        if err:
            return None, err

        response, err_msg = self.make_api_call(
            url=f"{self.app_url}/api/now/table/sn_smart_asmt_response_option/{id}",
            method="GET",
            headers={"Content-Type": "application/json"},
            user_name=user_name,
            password=password,
        )
        if err_msg:
            return None, err_msg

        if cowdictutils.is_valid_key(response, "result"):
            result = response.get("result")
            return result["text_label"], None

        return (
            None,
            f"Failed to get reponse if option - {id}. Please contact support for further details.",
        )

    def update_sn_smart_asmt_response_option_instance(self, sys_is, payload):

        if not sys_is or not payload:
            return (
                None,
                "Sys id and payload are mandatory to update assessment instance.",
            )

        user_name, password, err = self.get_auth_credentials()
        if err:
            return None, err

        response, err_msg = self.make_api_call(
            url=f"{self.app_url}/api/now/table/sn_smart_asmt_response_option_instance/{sys_is}",
            method="PATCH",
            headers={"Content-Type": "application/json"},
            user_name=user_name,
            password=password,
            data=payload,
        )
        if err_msg:
            return None, err_msg

        if cowdictutils.is_valid_key(response, "result"):
            return response.get("result"), ""

        return (
            None,
            f"Failed to update sn_smart_asmt_response_option_instance data. Assessment Instance - {ass_instance}, Question Instance - {qn_instance}. Please contact support for further details.",
        )