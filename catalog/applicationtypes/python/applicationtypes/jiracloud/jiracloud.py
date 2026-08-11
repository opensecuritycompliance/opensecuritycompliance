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
from typing import ParamSpec, Tuple, Optional, Dict, Any, Callable, TypeVar
import base64
import time

R = TypeVar("R")
P = ParamSpec("P")


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


class OAuth:
    client_id: str
    client_secret: str

    def __init__(self, client_id: str, client_secret: str) -> None:
        self.client_id = client_id
        self.client_secret = client_secret

    @staticmethod
    def from_dict(obj) -> "OAuth":
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


class UserDefinedCredentials:
    basic_authentication: Optional[BasicAuthentication]
    o_auth: Optional[OAuth]

    def __init__(
        self,
        basic_authentication: Optional[BasicAuthentication] = None,
        o_auth: Optional[OAuth] = None,
    ) -> None:
        self.basic_authentication = basic_authentication
        self.o_auth = o_auth

    @staticmethod
    def from_dict(obj) -> "UserDefinedCredentials":
        basic_authentication = None
        o_auth = None
        if isinstance(obj, dict):
            basic_auth_dict = obj.get("BasicAuthentication", None)
            if basic_auth_dict:
                basic_authentication = BasicAuthentication.from_dict(basic_auth_dict)

            oauth_dict = obj.get("OAuth", None)
            if oauth_dict:
                o_auth = OAuth.from_dict(oauth_dict)

        return UserDefinedCredentials(basic_authentication, o_auth)

    def to_dict(self) -> dict:
        result: dict = {}
        if self.basic_authentication:
            result["BasicAuthentication"] = self.basic_authentication.to_dict()
        if self.o_auth:
            result["OAuth"] = self.o_auth.to_dict()
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

    def get_oauth_token(self) -> Tuple[Optional[str], Optional[str]]:
        """
        Fetches OAuth token using client credentials.
        Returns: (token, error)
        """
        if not self.user_defined_credentials.o_auth:
            return None, "OAuth credentials not configured"

        url: str = "https://auth.atlassian.com/oauth/token"
        payload: dict = {
            "grant_type": "client_credentials",
            "client_id": self.user_defined_credentials.o_auth.client_id,
            "client_secret": self.user_defined_credentials.o_auth.client_secret,
        }
        headers: dict = {"Content-Type": "application/json"}

        response, error = self.make_api_request_with_retry(
            method="POST", url=url, headers=headers, json=payload
        )
        if error:
            return None, f"Failed to get OAuth token: {error}"

        if response.status_code != 200:
            return (
                None,
                f"Failed to get OAuth token: {response.status_code} - {response.text}",
            )

        data: dict = response.json()
        token: Optional[str] = data.get("access_token")
        if not token:
            return None, "No access token in response"

        return token, None

    def get_accessible_resources(
        self, token: str
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Gets accessible resources (cloud ID) for the OAuth token.
        Returns: (cloud_id, error)
        """
        url: str = "https://api.atlassian.com/oauth/token/accessible-resources"
        headers: dict = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }

        response, error = self.make_api_request_with_retry(
            method="GET", url=url, headers=headers
        )
        if error:
            return None, f"Failed to get accessible resources: {error}"

        if response.status_code != 200:
            return (
                None,
                f"Failed to get accessible resources: {response.status_code} - {response.text}",
            )

        resources: list = response.json()
        if not resources:
            return None, "No accessible resources found"

        cloud_id: Optional[str] = resources[0].get("id")
        if not cloud_id:
            return None, "No cloud ID in accessible resources"

        return cloud_id, None

    def validate(self) -> bool and dict:
        err = self.validate_attributes()
        if err:
            return False, None

        return self.is_valid_credentials()

    def is_valid_credentials(self):
        """Validate credentials by attempting to fetch user details."""
        # Try OAuth if available
        if self.user_defined_credentials.o_auth:
            token, error = self.get_oauth_token()
            if error:
                return False, error

            # Verify token can access resources
            cloud_id, error = self.get_accessible_resources(token)
            if error:
                return False, error

            return True, None

        # Fall back to basic auth
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
                return None, "Invalid URL."
            return None, "Failed to create client."

    def validate_attributes(self) -> str:
        """Validate that required credentials are present for either OAuth or BasicAuth."""
        empty_attrs = []

        oauth = self.user_defined_credentials.o_auth
        basic_auth = self.user_defined_credentials.basic_authentication

        # OAuth validation
        oauth_client_id = getattr(oauth, "client_id", None)
        oauth_client_secret = getattr(oauth, "client_secret", None)

        has_oauth = oauth_client_id and oauth_client_secret

        # BasicAuth validation
        username = getattr(basic_auth, "user_name", None)
        password = getattr(basic_auth, "password", None)

        has_basic_auth = username and password

        # If neither authentication method is fully configured
        if not has_oauth and not has_basic_auth:

            # OAuth partially configured
            if oauth:
                if not oauth_client_id:
                    empty_attrs.append("ClientID")
                if not oauth_client_secret:
                    empty_attrs.append("ClientSecret")

            # BasicAuth partially configured
            if basic_auth:
                if not username:
                    empty_attrs.append("UserName")
                if not password:
                    empty_attrs.append("Password")

            # Nothing configured at all
            if not oauth and not basic_auth:
                empty_attrs.append(
                    "Either OAuth(ClientID, ClientSecret) or "
                    "BasicAuth(UserName, Password)"
                )

        return (
            f"Invalid Credentials: {', '.join(empty_attrs)} is empty"
            if empty_attrs
            else ""
        )

    # Centralized retryable API request with exponential backoff
    def make_api_request_with_retry(
        self,
        method: str,
        url: str,
        headers: dict = None,
        auth: tuple = None,
        params: dict = None,
        json: dict = None,
        data: dict = None,
        files: dict | list = None,
        max_retries: int = 5,
        backoff_intervals: list = [5, 10, 30, 60, 90],
    ) -> Tuple[Optional[requests.Response], Optional[str]]:
        """
        Handles HTTP 429, 5xx, timeout, and connection errors with exponential backoff retries.
        """
        session = requests.Session()

        for attempt in range(max_retries):
            try:
                response = session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    auth=auth,
                    params=params,
                    json=json,
                    data=data,
                    files=files,
                    timeout=60,
                )

                # Handle rate limiting
                if response.status_code == 429:
                    retry_after = response.headers.get("Retry-After")
                    wait_time = (
                        int(retry_after)
                        if retry_after
                        else backoff_intervals[min(attempt, len(backoff_intervals) - 1)]
                    )
                    logging.warning(
                        f"Rate-limited (429). Retrying after {wait_time}s..."
                    )
                    time.sleep(wait_time)
                    continue

                # Handle transient 5xx errors
                if 500 <= response.status_code < 600:
                    wait_time = backoff_intervals[
                        min(attempt, len(backoff_intervals) - 1)
                    ]
                    logging.warning(
                        f"Server error {response.status_code}. Retrying after {wait_time}s..."
                    )
                    time.sleep(wait_time)
                    continue

                # Success
                return response, None

            except (
                requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                MaxRetryError,
            ) as e:
                wait_time = backoff_intervals[min(attempt, len(backoff_intervals) - 1)]
                logging.warning(
                    f"Connection/Timeout error: {e}. Retrying in {wait_time}s..."
                )
                time.sleep(wait_time)
                continue

            except Exception as e:
                return None, f"Unhandled exception during API call: {str(e)}"

        return (
            None,
            f"Failed after {max_retries} retries. Possibly rate-limited or server error.",
        )

    def make_api_request_with_retry_using_sdk(
        self,
        sdk_func: Callable[P, R],
        retries=5,
        backoff_intervals=[5, 10, 30, 60, 90],
        *args: P.args,
        **kwargs: P.kwargs,
    ) -> Optional[R]:
        for attempt in range(retries):
            try:
                return sdk_func(*args, **kwargs)
            except JIRAError as e:
                # Handle rate limiting
                if e.status_code == 429:
                    retry_after = e.response.headers.get("Retry-After")
                    wait_time = (
                        int(retry_after)
                        if retry_after
                        else backoff_intervals[min(attempt, len(backoff_intervals) - 1)]
                    )
                    logging.warning(
                        f"Rate-limited (429). Retrying after {wait_time}s..."
                    )
                    time.sleep(wait_time)
                    continue

                # Handle transient 5xx errors
                if 500 <= e.status_code < 600:
                    wait_time = backoff_intervals[
                        min(attempt, len(backoff_intervals) - 1)
                    ]
                    logging.warning(
                        f"Server error {e.status_code}. Retrying after {wait_time}s..."
                    )
                    time.sleep(wait_time)
                    continue
                raise

    def audit_logs(self):
        """Fetch audit logs from Jira using configured authentication method."""
        audit_record = []
        error_list = []

        url = f"{self.app_url}/rest/api/3/auditing/record"
        headers, auth = self.get_auth_headers_or_tuple()

        if headers is None and auth is None:
            error_list.append("Authentication failed: No valid credentials configured")
            return audit_record, error_list

        # Ensure Accept header is set
        if headers is None:
            headers = {}

        headers["Accept"] = "application/json"

        response, error = self.make_api_request_with_retry(
            method="GET",
            url=url,
            headers=headers,
            auth=auth,
        )

        if error:
            error_list.append(error)
            return audit_record, error_list

        if response.status_code == 200:
            data = response.json()
            if cowdictutils.is_valid_key(data, "records"):
                audit_record = data.get("records", [])
            else:
                error_list.append("Invalid response format: 'records' not found.")
        else:
            error_list.append(
                f"Unexpected status code {response.status_code}: {response.text}"
            )

        return audit_record, error_list

    # https://developer.atlassian.com/cloud/jira/platform/rest/v2/api-group-issue-search/#api-rest-api-2-search-post
    def search_issues_using_jql(self, req_body_dict):
        """Search for issues using JQL with pagination support using make_api_request_with_retry."""
        error_list = []
        issue_list = []

        if not req_body_dict:
            error_list.append(
                "The 'req_body_dict' is empty. Please provide a valid 'req_body_dict'"
            )
            return issue_list, error_list

        fields = ""
        jql = ""
        max_results = 10
        next_page_token = None

        headers, auth = self.get_auth_headers_or_tuple()
        if headers is None and auth is None:
            error_list.append("Authentication failed: No valid credentials configured")
            return issue_list, error_list

        if headers is None:
            headers = {}
        headers["Accept"] = "application/json"

        if not isinstance(req_body_dict, dict):
            error_list.append(
                f"Failed to search issue(s): Invalid request body format - "
                f"{type(req_body_dict)}. Supported format: 'dict'"
            )
            return issue_list, error_list

        if cowdictutils.is_valid_key(req_body_dict, "fields"):
            fields = req_body_dict["fields"]
            if isinstance(fields, list):
                fields = ",".join(fields)

        if cowdictutils.is_valid_key(req_body_dict, "jql"):
            jql = req_body_dict["jql"]

        if cowdictutils.is_valid_key(req_body_dict, "max_results"):
            max_results = req_body_dict["max_results"]

        try:
            while True:

                params = {
                    "jql": jql,
                    "fields": fields,
                    "maxResults": max_results,
                }

                if next_page_token:
                    params["nextPageToken"] = next_page_token

                params = {
                    k: v
                    for k, v in params.items()
                    if v not in (None, "", [], {})
                }

                response, error = self.make_api_request_with_retry(
                    method="GET",
                    url=f"{self.app_url}/rest/api/3/search/jql",
                    headers=headers,
                    auth=auth,
                    params=params,
                )

                if error:
                    error_list.append(error)
                    return issue_list, error_list

                if response.status_code != 200:
                    error_list.append(
                        f"Failed to search issues. "
                        f"Status: {response.status_code}, "
                        f"Response: {response.text}"
                    )
                    return issue_list, error_list

                data = response.json()

                issues = data.get("issues", [])
                issue_list.extend(issues)

                is_last = data.get("isLast", True)

                # Stop when Jira indicates this is the last page
                if is_last:
                    break

                next_page_token = data.get("nextPageToken")

                # Safety check
                if not next_page_token:
                    error_list.append(
                        "Pagination error. 'nextPageToken' is missing while 'isLast' is False."
                    )
                    break

            return issue_list, error_list

        except Exception as e:
            logging.exception("Unexpected exception while searching issues")
            error_list.append(
                f"Internal error while searching issues: {str(e)}. "
                f"Please contact support."
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

    def get_priorities(self) -> tuple[list[jira.Priority] | Any, str | None]:
        try:
            jira_connector, error = self.create_new_client()
            if error:
                return None, error
            priorities = jira_connector.priorities()
            return priorities, None
        except jira.exceptions.JIRAError as e:
            print(
                f"Unable to fetch Jira priorities : {self.bytes_to_string(e.response.content)}"
            )
            return (
                None,
                f"Unable to fetch Jira priorities. Please contact admin/support to fix this issue.",
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
                users = self.make_api_request_with_retry_using_sdk(
                    client.search_users, query=assignee
                )
                if users:
                    issueConfig["assignee"] = {"id": users[0].accountId}
                else:
                    issueConfig["assignee"] = {}

            issue = {}
            for idx in range(2):
                try:
                    issue = self.make_api_request_with_retry_using_sdk(
                        client.create_issue, fields=issueConfig
                    )
                    break
                except JIRAError as e:
                    if e.status_code != http.HTTPStatus.BAD_REQUEST or idx:
                        raise
                    issueConfig["assignee"] = {}
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
                try:
                    users = self.make_api_request_with_retry_using_sdk(
                        client.search_users, query=assignee_name
                    )
                    if users:
                        assignable_users = self.make_api_request_with_retry_using_sdk(
                            client.search_assignable_users_for_issues,
                            project=issueConfig["key"],
                            query=assignee_name,
                        )
                        if assignable_users:
                            issue_data["assignee"] = {"accountId": users[0].accountId}
                    else:
                        logging.warning(
                            f"No Jira user found for assignee '{assignee_name}'. Leaving unassigned."
                        )
                except JIRAError as e:
                    logging.warning(
                        f"Unable to search/assign user '{assignee_name}': {e}. Leaving unassigned."
                    )

            # Reporter (optional, if needed)
            if cowdictutils.is_valid_key(issueConfig, "reporter"):
                reporter_name = issueConfig.get("reporter")
                try:
                    users = self.make_api_request_with_retry_using_sdk(
                        client.search_users, query=reporter_name
                    )
                    if users:
                        issue_data["reporter"] = {"accountId": users[0].accountId}
                    else:
                        logging.warning(
                            f"No Jira user found for reporter '{reporter_name}'."
                        )
                except JIRAError as e:
                    logging.warning(
                        f"Unable to search for reporter '{reporter_name}': {e}."
                    )

            if cowdictutils.is_valid_key(issueConfig, "priority"):
                issue_data["priority"] = {"name": issueConfig.get("priority")}

            new_issue = self.make_api_request_with_retry_using_sdk(
                client.create_issue, fields=issue_data
            )
            return new_issue, None

        except JIRAError as e:
            error_content = e.response.content
            try:
                error_json = json.loads(error_content)
                if "errors" in error_json and "project" in error_json["errors"]:
                    project_key = issueConfig["key"]
                    return (
                        None,
                        f'The specified project key ("Project" = "{project_key}") doesn\'t exist. Please re-run the assessment with a valid Jira config input (toml) file. If the issue persists, contact admin/support.',
                    )
            except (json.JSONDecodeError, TypeError):
                pass

            logging.exception(f"Unable to create the Jira issue: {issueConfig}")
            return (
                None,
                f"Unable to create the Jira issue. Status: {e.status_code if hasattr(e, 'status_code') else 'Unknown'}. Please contact admin/support to fix this issue.\nMore info: {self.bytes_to_string(error_content)}",
            )
        except Exception as e:
            logging.exception(f"Unexpected error while creating issue: {issueConfig}")
            return (
                None,
                f"Unexpected error while creating issue. Please contact admin/support to fix this issue.\nMore info: {str(e)}",
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
        """Fetch issue details using make_api_request_with_retry with auth support."""
        if not issue_key:
            return None, "Issue key is empty. Cannot fetch details."

        try:
            base_url, auth = self.get_jira_base_url_and_auth()
            url = f"{base_url}/rest/api/3/issue/{issue_key}"
            headers = {"Accept": "application/json"}

            response, error = self.make_api_request_with_retry(
                method="GET", url=url, headers=headers, auth=auth
            )

            if error:
                return None, f"Error fetching issue details: {error}"

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

    def get_auth_headers_or_tuple(self) -> Tuple[Optional[dict], Optional[tuple]]:
        """
        Returns authentication as headers dict (for OAuth) or auth tuple (for BasicAuth).

        Returns:
            (headers, auth_tuple):
                - If OAuth: (headers_dict_with_bearer_token, None)
                - If BasicAuth: (None, (username, password))
                - If error: (None, None) with logging
        """
        # Try OAuth first
        if self.user_defined_credentials.o_auth:
            token, error = self.get_oauth_token()
            if error:
                logging.error(f"Failed to get OAuth token: {error}")
                return None, None

            headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
            return headers, None

        # Fall back to BasicAuth
        if self.user_defined_credentials.basic_authentication:
            username = self.user_defined_credentials.basic_authentication.user_name
            password = self.user_defined_credentials.basic_authentication.password
            return None, HTTPBasicAuth(username, password)

        logging.error("No authentication credentials configured")
        return None, None

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
        """Upload attachment to issue using make_api_request_with_retry with auth support."""
        app_url = self.build_api_url(f"/rest/api/3/issue/{issue_key}/attachments")
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

        response, error = self.make_api_request_with_retry(
            method="POST", url=app_url, headers=headers, files=files
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

    def link_issues(
        self, inward_issue_key: str, outward_issue_key: str, link_type: str
    ) -> Tuple[Optional[Any], Optional[str]]:
        app_url = self.build_api_url("/rest/api/3/issueLink")
        username = self.user_defined_credentials.basic_authentication.user_name
        password = self.user_defined_credentials.basic_authentication.password
        credentials = f"{username}:{password}"
        encoded_credentials = base64.b64encode(credentials.encode("utf-8")).decode(
            "utf-8"
        )

        headers = {
            "Authorization": f"Basic {encoded_credentials}",
            "Content-Type": "application/json",
        }

        payload = {
            "type": {"name": link_type},
            "inwardIssue": {"key": inward_issue_key},
            "outwardIssue": {"key": outward_issue_key},
        }

        response, error = self.make_api_request_with_retry(
            url=app_url, headers=headers, method="POST", json=payload
        )

        if error:
            return None, error

        if response.status_code in (http.HTTPStatus.OK, http.HTTPStatus.CREATED):
            return response.content, None
        else:
            return (
                None,
                f"Unable to link issues {inward_issue_key} and {outward_issue_key}. Status Code: {response.status_code}. Message: {response.text}",
            )

    def find_user_oauth(self, username: str, token: str, cloud_id: str):
        """Search for a Jira user by name using OAuth. Returns (user_dict, error)."""
        try:
            url = f"https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/user/search"
            headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

            response, error = self.make_api_request_with_retry(
                method="GET", url=url, headers=headers, params={"query": username}
            )
            if error:
                return None, f"Failed to search user: {error}"
            if response.status_code != 200:
                return None, f"Failed to search user: {response.status_code}"

            users = response.json()
            return (
                (users[0], None)
                if isinstance(users, list) and users
                else (None, f"User '{username}' not found")
            )

        except Exception as e:
            return None, f"Error searching user: {str(e)}"

    def create_issue_oauth(self, issue_data: dict, token: str, cloud_id: str):
        """Create a Jira issue using OAuth. Returns (issue_id, issue_key, error)."""
        try:
            url = f"https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/2/issue"
            headers = {
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            }

            response, error = self.make_api_request_with_retry(
                method="POST", url=url, headers=headers, json=issue_data
            )
            if error:
                return None, None, f"Failed to create issue: {error}"

            if response.status_code not in [200, 201]:
                error_msg = response.text
                try:
                    error_detail = response.json()
                    error_msg = (
                        error_detail.get("errorMessages", [error_msg])[0]
                        if error_detail.get("errorMessages")
                        else error_msg
                    )
                except Exception:
                    pass
                return None, None, f"Failed to create issue: {error_msg}"

            result = response.json()
            return result.get("id"), result.get("key"), None

        except Exception as e:
            return None, None, f"Error creating issue: {str(e)}"

    def get_issue_info_oauth(self, issue_id: str, token: str, cloud_id: str):
        """Fetch full issue details using OAuth. Returns (issue_dict, error)."""
        try:
            url = f"https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/issue/{issue_id}"
            headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

            response, error = self.make_api_request_with_retry(
                method="GET", url=url, headers=headers
            )
            if error:
                return None, f"Failed to get issue: {error}"
            if response.status_code != 200:
                return None, f"Failed to get issue: {response.status_code}"

            return response.json(), None

        except Exception as e:
            return None, f"Error fetching issue info: {str(e)}"

    def upload_attachment_oauth(
        self,
        issue_id: str,
        file_content: bytes,
        file_name: str,
        token: str,
        cloud_id: str,
    ):
        """Upload a file attachment to a Jira issue using OAuth. Returns error string or None."""
        try:
            import io

            url = f"https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/issue/{issue_id}/attachments"
            headers = {
                "Authorization": f"Bearer {token}",
                "X-Atlassian-Token": "no-check",
            }

            response, error = self.make_api_request_with_retry(
                method="POST",
                url=url,
                headers=headers,
                files={"file": (file_name, io.BytesIO(file_content))},
            )
            if error:
                return f"Failed to upload attachment: {error}"
            if response.status_code not in [200, 201]:
                return f"Failed to upload attachment: {response.status_code}"
            return None

        except Exception as e:
            return f"Error uploading attachment: {str(e)}"

    def build_api_url(self, endpoint):
        return f'{self.app_url.rstrip("/")}{endpoint}'
