import jira
import http
import requests
import jira.exceptions
from urllib3.exceptions import MaxRetryError
from compliancecowcards.utils import cowdictutils
import logging

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


class JiraCloud:
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
    def from_dict(obj) -> 'JiraCloud':
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

        return JiraCloud(app_url, app_port, user_defined_credentials)

    def to_dict(self) -> dict:
        result: dict = {}
        result["AppURL"] = self.app_url
        result["AppPort"] = self.app_port
        result[
            "UserDefinedCredentials"] = self.user_defined_credentials.to_dict(
            )
        return result

    def validate(self) -> bool and dict:
        err = self.validate_attributes() 
        if err:
            False, None
        
        return self.is_valid_credentials()
    
    def is_valid_credentials(self):
        client, error = self.create_new_client()
        if error: 
           return False, error
        try:
            # fetch user details
            user_details = client.myself()
            if user_details:
                return True, None
            return False, f"Failed to fetch user details for the given credentials."

        except jira.exceptions.JIRAError as error:
            status_code = error.status_code if hasattr(error, 'status_code') else 'Unknown'  
            if status_code == http.HTTPStatus.UNAUTHORIZED:
                return False, "Invalid UserName and/or Password."          
            return False, f"Validation failed. Exception occured while validating app."
        
    def create_new_client(self):
        try:
            app_url = self.app_url
            username = self.user_defined_credentials.basic_authentication.user_name
            password = self.user_defined_credentials.basic_authentication.password
            client = jira.JIRA(app_url, basic_auth=(username, password),max_retries=0)
            return client, None
        
        except jira.exceptions.JIRAError as e:
            if e.status_code == http.HTTPStatus.UNAUTHORIZED or e.status_code == http.HTTPStatus.FORBIDDEN:
              return None, "Invalid UserName and/or Password."
            if e.status_code == http.HTTPStatus.NOT_FOUND:
                return None, "Invalid URL."
            return None, "Failed to create client."
        except requests.exceptions.RequestException as e:
            if isinstance(e.args[0], MaxRetryError):
                return False, "Invalid URL."
            return None, "Failed to create client."
    
    def validate_attributes(self) -> str:
        emptyAttrs = []
        if not self.user_defined_credentials.basic_authentication.user_name:
            emptyAttrs.append("UserName")

        if not self.user_defined_credentials.basic_authentication.password:
            emptyAttrs.append("Password")

        return "Invalid Credentials: " + ", ".join(
            emptyAttrs) + " is empty" if emptyAttrs else ""
    

    # https://developer.atlassian.com/cloud/jira/platform/rest/v2/api-group-issue-search/#api-rest-api-2-search-post
    def search_issues_using_jql(self, req_body_dict):
    
        error_list = []
        issue_list = []
        client, error = self.create_new_client()
        if error: 
           return issue_list, error_list.append({"Error":error})
        
        if not req_body_dict:
           error_list.append({"Error" : "The 'req_body_dict' is empty. Please provide a valid 'req_body_dict'"})
           return issue_list, error_list
        
        # required fields to form request body
        expand = []
        fields = ""
        jql = ""
        max_results = 0
        start_at = 0
        properties = []

        if isinstance(req_body_dict, dict):
            if cowdictutils.is_valid_array(req_body_dict, 'expand'):
                expand = req_body_dict['expand']
            if cowdictutils.is_valid_key(req_body_dict, 'fields'):
                fields = req_body_dict['fields']
            if cowdictutils.is_valid_key(req_body_dict, 'jql'):
                jql = req_body_dict['jql']
            if cowdictutils.is_valid_key(req_body_dict, 'max_results'):
                max_results = req_body_dict['max_results']
            if cowdictutils.is_valid_key(req_body_dict, 'properties'):
                properties = req_body_dict['properties']
        else:
            error_list.append({"Error" : f"Failed to search issue(s): Invalid request body format - {type(req_body_dict)}. Supported format: 'dict'"})
            return issue_list, error_list
        
        try:
            while True:
                issues = client.search_issues(
                    jql_str = jql,
                    startAt=start_at, 
                    maxResults=max_results, 
                    fields=fields,
                    expand = expand,
                    properties = properties
                    )
                if not issues:
                    break
                for issue in issues:
                    issue_list.append(issue)
                # Update pagination parameters for the next iteration
                start_at += max_results
            return issue_list, error_list
        except jira.exceptions.JIRAError as e:
            if e.status_code == http.HTTPStatus.BAD_REQUEST:
                error_list.append({"Error" : f"Internal error ::  {e.text}. Please contact support for further details"})
                return issue_list, error_list
            logging.debug(f"Exception occured while searching issues: {e}")
            error_list.append({"Error" :"Exception occured while searching issues. Please contact support format for further details"})
            return issue_list, error_list