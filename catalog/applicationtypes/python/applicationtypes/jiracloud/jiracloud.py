import jira
import http
import requests
import jira.exceptions
from urllib3.exceptions import MaxRetryError
from compliancecowcards.utils import cowdictutils
import logging
from requests.auth import HTTPBasicAuth
import json
import requests
from jira import JIRA, JIRAError
import jira
import jmespath
from typing import Tuple, Optional, Dict, Any
import base64


class BasicAuthentication:
    user_name: str
    password: str

    def __init__(self, user_name: str, password: str) -> None:
        self.user_name = user_name
        self.password = password

    @staticmethod
    def from_dict(obj) -> "BasicAuthentication":
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
    def from_dict(obj) -> "UserDefinedCredentials":
        basic_authentication = None
        if isinstance(obj, dict):
            basic_authentication = BasicAuthentication.from_dict(
                obj.get("BasicAuthentication", None)
            )
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
        user_defined_credentials: UserDefinedCredentials = None,
    ) -> None:
        self.app_url = app_url
        self.app_port = app_port
        self.user_defined_credentials = user_defined_credentials

    @staticmethod
    def from_dict(obj) -> "JiraCloud":
        app_url, app_port, user_defined_credentials = "", "", None
        if isinstance(obj, dict):
            app_url = obj.get("AppURL", "")
            if not app_url:
                app_url = obj.get("appURL", "")
            app_port = obj.get("AppPort", 0)
            if not app_port:
                app_port = obj.get("appPort", 0)
            user_defined_credentials_dict = obj.get("UserDefinedCredentials", None)
            if user_defined_credentials_dict is None:
                user_defined_credentials_dict = obj.get("userDefinedCredentials", None)
            if bool(user_defined_credentials_dict):
                user_defined_credentials = UserDefinedCredentials.from_dict(
                    user_defined_credentials_dict
                )

        return JiraCloud(app_url, app_port, user_defined_credentials)

    def to_dict(self) -> dict:
        result: dict = {}
        result["AppURL"] = self.app_url
        result["AppPort"] = self.app_port
        result["UserDefinedCredentials"] = self.user_defined_credentials.to_dict()
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
            status_code = (
                error.status_code if hasattr(error, "status_code") else "Unknown"
            )
            if status_code == http.HTTPStatus.UNAUTHORIZED:
                return False, "Invalid UserName and/or Password."
            return False, f"Validation failed. Exception occured while validating app."

    def create_new_client(self, rest_api_version: str = "2"):
        try:
            app_url = self.app_url
            username = self.user_defined_credentials.basic_authentication.user_name
            password = self.user_defined_credentials.basic_authentication.password
            client = jira.JIRA(
                options={"rest_api_version": rest_api_version},
                server=app_url,
                basic_auth=(username, password),
                max_retries=0,
            )
            return client, None

        except jira.exceptions.JIRAError as e:
            if (
                e.status_code == http.HTTPStatus.UNAUTHORIZED
                or e.status_code == http.HTTPStatus.FORBIDDEN
            ):
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

        return (
            "Invalid Credentials: " + ", ".join(emptyAttrs) + " is empty"
            if emptyAttrs
            else ""
        )

    def audit_logs(self):
        audit_record = []
        error_list = []
        headers = {"Accept": "application/json"}
        url = f"{self.app_url}/rest/api/3/auditing/record"

        try:
            response = requests.get(
                url,
                auth=HTTPBasicAuth(
                    self.user_defined_credentials.basic_authentication.user_name,
                    self.user_defined_credentials.basic_authentication.password,
                ),
                headers=headers,
            )

            response.raise_for_status()
            if response.status_code == 200:
                if cowdictutils.is_valid_key(response.json(), "records"):
                    audit_record = response.json().get("records")
                else:
                    error_list.append(
                        "Invalid response format: 'records' not found in the response."
                    )

        except requests.exceptions.HTTPError as http_err:
            error_list.append(
                f"HTTP error occurred: {http_err} - Status Code: {response.status_code}"
            )
        except requests.exceptions.RequestException as req_err:
            error_list.append(f"Request error occurred: {req_err}")
        except json.JSONDecodeError:
            error_list.append("Error decoding JSON response from Jira Cloud.")

        return audit_record, error_list

    # https://developer.atlassian.com/cloud/jira/platform/rest/v2/api-group-issue-search/#api-rest-api-2-search-post

    def search_issues_using_jql(self, req_body_dict):

        error_list = []
        issue_list = []

        if not req_body_dict:
            error_list.append(
                "The 'req_body_dict' is empty. Please provide a valid 'req_body_dict'"
            )
            return issue_list, error_list

        # required fields to form request body
        fields = ""
        jql = ""
        max_results = 10
        start_at = 0

        if isinstance(req_body_dict, dict):
            if cowdictutils.is_valid_array(req_body_dict, "expand"):
                expand = req_body_dict["expand"]
            if cowdictutils.is_valid_key(req_body_dict, "fields"):
                fields = req_body_dict["fields"]
                if isinstance(fields, list):
                    fields = ",".join(fields)
            if cowdictutils.is_valid_key(req_body_dict, "jql"):
                jql = req_body_dict["jql"]
            if cowdictutils.is_valid_key(req_body_dict, "max_results"):
                max_results = req_body_dict["max_results"]
            if cowdictutils.is_valid_key(req_body_dict, "properties"):
                properties = req_body_dict["properties"]
        else:
            error_list.append(
                f"Failed to search issue(s): Invalid request body format - {type(req_body_dict)}. Supported format: 'dict'"
            )
            return issue_list, error_list

        try:
            while True:

                params = {
                    "jql": jql,
                    "fields": fields,
                    "startAt": start_at,
                    "maxResults": max_results,
                }
                params = {
                    k: v for k, v in params.items() if v not in (None, "", [], {})
                }

                response = requests.get(
                    url=f"{self.app_url}/rest/api/3/search/jql",
                    params=params,
                    auth=HTTPBasicAuth(
                        self.user_defined_credentials.basic_authentication.user_name,
                        self.user_defined_credentials.basic_authentication.password,
                    ),
                )

                if response.status_code != 200:
                    error_list.append(
                        f"Failed to search issues. Status: {response.status_code}, Response: {response.text}"
                    )
                    break

                data = response.json()

                issues = data.get("issues", [])
                issue_list.extend(issues)
                if not issues or len(issues) < max_results:
                    break
                # Update pagination parameters for the next iteration
                start_at += max_results
            return issue_list, error_list

        except requests.exceptions.Timeout:
            error_list.append("Jira API request timed out. Please try again later.")
            return issue_list, error_list
        except requests.exceptions.ConnectionError:
            error_list.append(
                "Unable to connect to Jira API. Please check network or URL."
            )
            return issue_list, error_list
        except requests.exceptions.RequestException as e:
            error_list.append(
                f"Unexpected error while calling Jira API: {str(e)}. Please contact support."
            )
            return issue_list, error_list
        except Exception as e:
            logging.exception("Unexpected exception while searching issues")
            error_list.append(
                f"Internal error while searching issues: {str(e)}. Please contact support."
            )
            return issue_list, error_list

    # pass the permissions as a string seperated by commas eg: "MODIFY_REPORTER,ASSIGN_ISSUES,..."
    def get_user_permissions(self, project_key: str, permission: str):
        try:
            jira_connector, error = self.create_new_client()
            if error:
                return None, error
            permissions = jira_connector.my_permissions(
                permissions=permission, projectKey=project_key
            )
            return permissions, None
        except jira.exceptions.JIRAError as e:
            print(
                f"Unable to fetch Jira user permissions for user - {self.user_defined_credentials.basic_authentication.user_name} : {self.bytes_to_string(e.response.content)}"
            )
            return (
                None,
                f"Unable to fetch Jira user permissions for user - {self.user_defined_credentials.basic_authentication.user_name}. Please contact admin/support to fix this issue.",
            )

    def search_user(self, user_name: str):
        try:
            client, error = self.create_new_client()
            if error:
                return None, error
            users = client.search_users(query=user_name)

            return users, None
        except jira.exceptions.JIRAError as e:
            print(
                f"Unable to search user - {user_name} : {self.bytes_to_string(e.response.content)}"
            )
            return (
                None,
                f"Unable to search user - {user_name}. Please contact admin/support to fix this issue.",
            )

    def create_issue_v3(
        self, issueConfig: dict, _rest_api_version=3
    ) -> Tuple[dict, Optional[str]]:
        try:
            client, error = self.create_new_client(
                rest_api_version=str(_rest_api_version)
            )
            if error:
                return None, error
            assignee = jmespath.search("assignee.name", issueConfig)
            if assignee:
                users = client.search_users(query=assignee)
                if users:
                    issueConfig["assignee"] = {"id": users[0].accountId}
                else:
                    return (None, f"User '{assignee}' not found in Jira.")

            issue = client.create_issue(fields=issueConfig)
            return issue, None
        except Exception as e:
            print(
                f"Unable to create issue - {issueConfig} : {self.bytes_to_string(e.response.content)}"
            )
            return (
                None,
                f"Unable to create issue - {issueConfig}. Please contact admin/support to fix this issue.\n More info: {self.bytes_to_string(e.response.content)}",
            )

    def create_issue(self, parent_issue_key=None, issueConfig=None):
        try:
            client, error = self.create_new_client()
            if error:
                print(f"Unable to create the Jira issue : {error}")
                return (
                    None,
                    "Unable to create the Jira issue. Please contact admin/support to fix this issue.",
                )

            required_fields = ["key", "summary", "description", "issuetype"]
            for field in required_fields:
                if not cowdictutils.is_valid_key(issueConfig, field):
                    return (
                        None,
                        f"The '{field}' field is mandatory for creating an issue. Please rerun the assessment with a valid Jira config input (toml) file. If the issue persists, contact the admin/support.",
                    )

            issue_data = {
                "project": {"key": issueConfig["key"]},
                "summary": issueConfig["summary"],
                "description": issueConfig["description"],
                "issuetype": {"name": issueConfig["issuetype"]},
            }

            if parent_issue_key:
                issue_data["parent"] = {"key": parent_issue_key}

            # Handle assignee with accountId lookup
            if cowdictutils.is_valid_key(issueConfig, "assignee"):
                assignee_name = issueConfig.get("assignee")
                users = client.search_users(query=assignee_name)
                if users:
                    issue_data["assignee"] = {"accountId": users[0].accountId}
                else:
                    print(
                        f"Warning: No Jira user found for assignee '{assignee_name}'. Leaving unassigned."
                    )

            # Reporter (optional, if needed)
            if cowdictutils.is_valid_key(issueConfig, "reporter"):
                reporter_name = issueConfig.get("reporter")
                users = client.search_users(query=reporter_name)
                if users:
                    issue_data["reporter"] = {"accountId": users[0].accountId}
                else:
                    print(
                        f"Warning: No Jira user found for reporter '{reporter_name}'."
                    )

            if cowdictutils.is_valid_key(issueConfig, "priority"):
                issue_data["priority"] = {"name": issueConfig.get("priority")}

            new_issue = client.create_issue(fields=issue_data)
            return new_issue, None

        except jira.exceptions.JIRAError as e:
            error_content = e.response.content
            try:
                error_json = json.loads(error_content)
                if "errors" in error_json and "project" in error_json["errors"]:
                    project_key = issueConfig["key"]
                    return (
                        None,
                        f'The specified project key ("Project" = "{project_key}") doesn\'t exist. Please re-run the assessment with a valid Jira config input (toml) file. If the issue persists, contact admin/support.',
                    )
            except json.JSONDecodeError:
                pass
            print(
                f"Unable to create the Jira issue : {self.bytes_to_string(e.response.content)}"
            )
            return (
                None,
                "Unable to create the Jira issue. Please contact admin/support to fix this issue.",
            )

    def get_issue(self, issue_key: str):
        if not issue_key:
            return (
                None,
                "Unable to get Jira issue details; the 'issue_key' field is empty. Please contact admin/support to fix this issue.",
            )

        try:
            client, error = self.create_new_client()
            if error:
                print(f"Unable to get Jira issue details for the {issue_key} : {error}")
                return (
                    None,
                    f"Unable to get Jira issue details for the {issue_key}. Please contact admin/support to fix this issue.",
                )
            issue_details = client.issue(issue_key)
            return issue_details, None

        except jira.exceptions.JIRAError as e:
            print(
                f"Unable to get Jira issue details for the {issue_key} : {self.bytes_to_string(e.response.content)}"
            )
            return (
                None,
                f"Unable to get Jira issue details for the {issue_key}. Please contact admin/support to fix this issue.",
            )

    def get_issue_details(
        self, issue_key: str
    ) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """
        Fetch detailed Jira issue information using REST API.

        Args:
            issue_key (str): The Jira issue key (e.g., "ABC-88").

        Returns:
            Tuple containing:
                - issue_data (dict or None): The parsed issue JSON if successful.
                - error_message (str or None): An error message if the request fails.
        """
        if not issue_key:
            return None, "Issue key is empty. Cannot fetch details."

        try:
            base_url, auth = self.get_jira_base_url_and_auth()
            url = f"{base_url}/rest/api/2/issue/{issue_key}"
            headers = {"Accept": "application/json"}

            response = requests.get(url, auth=auth, headers=headers)

            if response.status_code != 200:
                return (
                    None,
                    f"Failed to get issue details: {response.status_code} - {response.text}",
                )

            issue_data: Dict[str, Any] = response.json()
            return issue_data, None

        except Exception as e:
            return None, f"Exception while fetching issue details: {str(e)}"

    def get_jira_base_url_and_auth(self) -> Tuple[str, Tuple[str, str]]:
        """
        Provides the Jira base URL and basic auth credentials.

        Returns:
            A tuple of:
                - base_url (str): Jira instance URL.
                - auth (tuple): Tuple of (email, api_token).
        """
        base_url: str = self.app_url
        email: str = self.user_defined_credentials.basic_authentication.user_name
        api_token: str = self.user_defined_credentials.basic_authentication.password

        return base_url, (email, api_token)

    def bytes_to_string(self, bytes_data):
        try:
            return bytes_data.decode("utf-8")
        except UnicodeDecodeError:
            return "Failed to decode bytes to string"

    def get_jira_issue_url(self, issue_key: str) -> str:
        """
        Returns the full Jira issue URL given the issue key and base URL.

        Args:
            issue_key (str): The Jira issue key, e.g., "PROJ-123"
            base_url (str): Your Jira base URL, e.g., "https://yourcompany.atlassian.net"

        Returns:
            str: Full URL to the Jira issue
        """
        return f"{self.app_url}/browse/{issue_key}"

    def upload_attachment(
        self, issue_key: str, files: list
    ) -> Tuple[Optional[Any], Optional[str]]:
        app_url = self.build_api_url(f"/rest/api/2/issue/{issue_key}/attachments")
        username = self.user_defined_credentials.basic_authentication.user_name
        password = self.user_defined_credentials.basic_authentication.password
        credentials = f"{username}:{password}"
        encoded_credentials = base64.b64encode(credentials.encode("utf-8")).decode(
            "utf-8"
        )

        headers = {
            "Authorization": f"Basic {encoded_credentials}",
            "X-Atlassian-Token": "no-check",
        }

        response, error = self.make_api_request(
            url=app_url, headers=headers, method="POST", files=files
        )

        if error:
            return None, error

        if response.status_code in (http.HTTPStatus.OK, http.HTTPStatus.CREATED):
            return response.content, None
        else:
            return (
                None,
                f"Unable to upload the attachment to issue {issue_key}. Status Code: {response.status_code}. Message: {response.text}",
            )

    def make_api_request(
        self, url, headers, method="GET", json=None, data=None, files=None
    ):
        try:
            if method.upper() == "GET":
                response = requests.get(url, headers=headers)
            elif method.upper() == "POST":
                response = requests.post(
                    url, headers=headers, json=json, data=data, files=files
                )
            elif method.upper() == "PATCH":
                response = requests.patch(url, headers=headers, json=json)

            if not response:
                return None, f"{response.text}"

            return response, None

        except requests.exceptions.ConnectionError as e:
            return None, f"Connection error: {e}"
        except requests.exceptions.Timeout as e:
            return None, f"Request timed out: {e}"
        except requests.exceptions.RequestException as e:
            return None, f"Other request exception: {e}"

    def build_api_url(self, endpoint):
        return f'{self.app_url.rstrip("/")}{endpoint}'
