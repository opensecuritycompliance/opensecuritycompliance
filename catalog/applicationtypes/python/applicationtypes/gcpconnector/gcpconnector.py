from datetime import datetime, timezone
import base64
import logging
import os
import json
import re
from typing import Tuple, Optional
from google.auth.exceptions import GoogleAuthError
from google.api_core.exceptions import GoogleAPIError
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2 import service_account
from google.cloud import bigquery
from compliancecowcards.utils import cowdictutils
import requests
import urllib.parse

REPOSITORIES = "https://console.cloud.google.com/artifacts/docker/{project_name}/{region}/{asset_name}?project={project_name}"
PROJECTS = "https://console.cloud.google.com/welcome?project={asset_name}"
DISKS = "https://console.cloud.google.com/compute/disksDetail/zones/{region}/disks/{asset_name}"
FIREWALL_POLICIES = "https://console.cloud.google.com/net-security/firewall-manager/firewall-policies/details/{asset_name}?project={project_name}"
VM_INSTANCES = "https://console.cloud.google.com/compute/instancesDetail/zones/{region}/instances/{asset_name}?project={project_name}"
VM_INSTANCE_GROUPS = "https://console.cloud.google.com/compute/instanceGroups/details/{region}/{asset_name}?project={project_name}"
VM_INSTANCE_TEMPLATES = "https://console.cloud.google.com/compute/instanceTemplates/details/regions/{region}/{asset_name}?project={project_name}"
NETWORKS = "https://console.cloud.google.com/networking/networks/details/{asset_name}?project={project_name}"
ROUTES = "https://console.cloud.google.com/networking/routes/details/{asset_name}?project={project_name}"
SUBNETWORKS = "https://console.cloud.google.com/networking/subnetworks/details/{region}/{asset_name}?project={project_name}"
CLUSTER = "https://console.cloud.google.com/kubernetes/clusters/details/{region}/{asset_name}/details?project={project_name}"
NODES = "https://console.cloud.google.com/kubernetes/node/{region}/{cluster_name}/{asset_name}/summary?project={project_name}"
PODS = "https://console.cloud.google.com/kubernetes/pod/{region}/{cluster_name}/{namespace_name}/{asset_name}/details?project={project_name}"
STORAGE_CLASSES = "https://console.cloud.google.com/kubernetes/storageclass/{region}/{cluster_name}/{asset_name}/details?project={project_name}"
NODEPOOLS = "https://console.cloud.google.com/kubernetes/nodepool/{region}/{cluster_name}/{asset_name}?project={project_name}"
IAM_SERVICE_ACCOUNTS = "https://console.cloud.google.com/iam-admin/serviceaccounts/details/{asset_name}?project={project_name}"
IAM_SERVICE_ACCOUNT_KEYS = "https://console.cloud.google.com/iam-admin/serviceaccounts/details/{asset_name}/keys?project={project_name}"
LOG_BUCKETS = "https://console.cloud.google.com/logs/storage?project={project_name}"
LOG_SINKS = "https://console.cloud.google.com/logs/router?project={project_name}"
TOPICS = "https://console.cloud.google.com/cloudpubsub/topic/detail/{asset_name}?project={project_name}"
API_SERVICES = "https://console.cloud.google.com/apis/api/{asset_name}/metrics?project={project_name}"
IMAGE = "https://console.cloud.google.com/artifacts/docker/{project_name}/{region}/{repo_name}/{image_name}?project={project_name}"
BILLING = "https://console.cloud.google.com/billing/{asset_name}?project={project_name}"


class GoogleWorkSpace:
    user_email: str
    service_account_key_file: str

    def __init__(self, user_email: str, service_account_key_file: str) -> None:
        self.user_email = user_email
        self.service_account_key_file = service_account_key_file

    @staticmethod
    def from_dict(obj) -> "GoogleWorkSpace":
        user_email, service_account_key_file = "", ""
        if isinstance(obj, dict):
            user_email = obj.get("UserEmail", "")
            service_account_key_file = obj.get("ServiceAccountKeyFile", "")

        return GoogleWorkSpace(user_email, service_account_key_file)

    def to_dict(self) -> dict:
        result: dict = {}
        result["UserEmail"] = self.user_email
        result["ServiceAccountKeyFile"] = self.service_account_key_file
        return result

    def validate_attributes(self) -> str:
        emptyAttrs = []
        if not self.user_email:
            emptyAttrs.append("UserEmail")

        if not self.service_account_key_file:
            emptyAttrs.append("ServiceAccountKeyFile")

        return (
            "Invalid Credentials: " + ", ".join(emptyAttrs) + " is empty"
            if emptyAttrs
            else ""
        )


class UserDefinedCredentials:
    google_work_space: GoogleWorkSpace

    def __init__(self, google_work_space: GoogleWorkSpace) -> None:
        self.google_work_space = google_work_space

    @staticmethod
    def from_dict(obj) -> "UserDefinedCredentials":
        google_work_space = None
        if isinstance(obj, dict):
            google_work_space = GoogleWorkSpace.from_dict(
                obj.get("GoogleWorkSpace", None)
            )
        return UserDefinedCredentials(google_work_space)

    def to_dict(self) -> dict:
        result: dict = {}
        result["GoogleWorkSpace"] = self.google_work_space.to_dict()
        return result


class GCPConnector:
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
    def from_dict(obj) -> "GCPConnector":
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
            user_defined_credentials_dict = obj.get("UserDefinedCredentials", None)
            if user_defined_credentials_dict is None:
                user_defined_credentials_dict = obj.get("userDefinedCredentials", None)
            if bool(user_defined_credentials_dict):
                user_defined_credentials = UserDefinedCredentials.from_dict(
                    user_defined_credentials_dict
                )

        return GCPConnector(app_url, app_port, user_defined_credentials)

    def to_dict(self) -> dict:
        result: dict = {}
        result["AppURL"] = self.app_url
        result["AppPort"] = self.app_port
        result["UserDefinedCredentials"] = self.user_defined_credentials.to_dict()

        return result

    def validate(self) -> tuple[bool, str]:
        try:
            err_msg = (
                self.user_defined_credentials.google_work_space.validate_attributes()
            )
            if err_msg:
                return False, err_msg
            email_regex = re.compile(
                r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
            )
            if not email_regex.match(
                self.user_defined_credentials.google_work_space.user_email
            ):
                return False, "Invalid 'UserEmail'"
            projects, error = self.list_projects()
            if error:
                return False, error
            return True, ""
        except GoogleAuthError as e:
            logging.exception(
                "An exception occurred while fetching domain details: %s", str(e)
            )
            if len(e.args) >= 1:
                if cowdictutils.is_valid_key(e.args[1], "error_description"):
                    if e.args[1]["error_description"] == "Invalid email or User ID":
                        return False, "Invalid 'UserEmail'"
            return False, "Invalid 'UserEmail' or 'ServiceAccountKeyFile'"

    def validate_user_email(
        self, scope: Optional[str] = "https://www.googleapis.com/auth/cloud-platform"
    ) -> tuple[bool, str]:
        """
        Validates if the impersonated user email exists and has the required Google Sheets permissions.
        """
        try:

            credentials, error = self.create_config(scope)
            if error:
                return False, error

            credentials = credentials.with_subject(
                self.user_defined_credentials.google_work_space.user_email
            )
            credentials.refresh(Request())
            return True, ""

        except GoogleAuthError as e:
            logging.exception(
                "An exception occurred while validating user email: %s", str(e)
            )
            if len(e.args) >= 1:
                try:
                    if (
                        isinstance(e.args[1], dict)
                        and e.args[1].get("error_description")
                        == "Invalid email or User ID"
                    ):
                        return (
                            False,
                            "User email does not exist or lacks domain-wide delegation.",
                        )
                except Exception:
                    pass
            return False, f"Failed to validate user email: {str(e)}"

    def create_config(self, scope: str) -> tuple[service_account.Credentials, str]:
        try:
            service_account_json_key_decoded = base64.b64decode(
                self.user_defined_credentials.google_work_space.service_account_key_file
            )
            service_account_info = json.loads(service_account_json_key_decoded)
            credentials = service_account.Credentials.from_service_account_info(
                service_account_info, scopes=[scope]
            )
            return credentials, None
        except (GoogleAuthError, IOError, ValueError, TypeError) as e:
            logging.exception("An exception occurred while creating config: %s", str(e))
            return None, "Invalid 'UserEmail' or 'ServiceAccountKeyFile'"

    def get_current_datetime(self):
        current_time = datetime.now(timezone.utc)
        formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S") + " UTC"
        return formatted_time

    # https://cloud.google.com/resource-manager/reference/rest/v1/projects/list
    def list_projects(self) -> tuple[list, str]:
        try:
            scope = "https://www.googleapis.com/auth/cloud-platform.read-only"
            token_source, err = self.create_config(scope)
            if err:
                return None, err
            token_source.refresh(Request())
            # token_source._subject = (
            #     self.user_defined_credentials.google_work_space.user_email
            # )
            service = build("cloudresourcemanager", "v1", credentials=token_source)
            request = service.projects().list()
            response = request.execute()
            projects = response.get("projects", [])
            if not projects:
                return (
                    None,
                    "No projects found for the provided service account credentials.",
                )
            return projects, None
        except HttpError as e:
            return None, f"Http error occurred while fetching project lists: {e}"
        except AttributeError as e:
            return None, f"Attribute error occurred while fetching project lists: {e}"

    # https://cloud.google.com/security-command-center/docs/reference/rest/v2/projects.sources.findings/list?rep_location=global
    def fetch_findings(self, project_id: str) -> tuple[list, str]:

        scope = "https://www.googleapis.com/auth/cloud-platform"
        credentials, error = self.create_config(scope)
        if error:
            return None, error

        credentials.refresh(Request())
        access_token = credentials.token
        parent_path = f"projects/{project_id}/sources/-"  # For Project level
        headers = {"Authorization": f"Bearer {access_token}"}

        url = f"https://securitycenter.googleapis.com/v2/{parent_path}/findings"
        findings = []
        params = {}
        try:
            while True:
                response = requests.get(url, headers=headers, params=params)
                response.raise_for_status()

                try:
                    data = response.json()
                except ValueError as e:
                    raise ValueError(f"Error parsing JSON response: {e}")

                findings.extend(data.get("listFindingsResults", []))

                if "nextPageToken" in data:
                    params["pageToken"] = data["nextPageToken"]
                else:
                    break

            return findings, None

        except requests.exceptions.HTTPError as http_err:
            return None, f"HTTP error occurred: {http_err}"
        except requests.exceptions.ConnectionError as conn_err:
            return None, f"Connection error occurred: {conn_err}"
        except requests.exceptions.Timeout as timeout_err:
            return None, f"Timeout error occurred: {timeout_err}"
        except requests.exceptions.RequestException as req_err:
            return None, f"Request error occurred: {req_err}"
        except ValueError as parse_err:
            return None, f"JSON parsing error: {parse_err}"

    # https://cloud.google.com/compute/docs/reference/rest/v1/instances/list
    def fetch_vm_instances(self, project_id: str, zone: str) -> tuple[list, str]:
        scope = "https://www.googleapis.com/auth/cloud-platform"
        credentials, error = self.create_config(scope)
        if error:
            return None, error

        credentials.refresh(Request())
        access_token = credentials.token

        headers = {"Authorization": f"Bearer {access_token}"}

        url = f"https://compute.googleapis.com/compute/v1/projects/{project_id}/zones/{zone}/instances"
        vm_instances = []
        params = {}
        try:
            while True:
                response = requests.get(url, headers=headers, params=params)
                response.raise_for_status()

                try:
                    data = response.json()
                except ValueError as e:
                    raise ValueError(f"Error parsing JSON response: {e}")

                vm_instances.extend(data.get("items", []))

                if "nextPageToken" in data:
                    params["pageToken"] = data["nextPageToken"]
                else:
                    break

            return vm_instances, None

        except requests.exceptions.HTTPError as http_err:
            return None, f"HTTP error occurred: {http_err}"
        except requests.exceptions.ConnectionError as conn_err:
            return None, f"Connection error occurred: {conn_err}"
        except requests.exceptions.Timeout as timeout_err:
            return None, f"Timeout error occurred: {timeout_err}"
        except requests.exceptions.RequestException as req_err:
            return None, f"Request error occurred: {req_err}"
        except ValueError as parse_err:
            return None, f"JSON parsing error: {parse_err}"

    # https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters/list
    def fetch_gcp_clusters(self, project_id: str, location: str) -> tuple[list, str]:
        scope = "https://www.googleapis.com/auth/cloud-platform"
        credentials, error = self.create_config(scope)
        if error:
            return None, error

        credentials.refresh(Request())
        access_token = credentials.token

        headers = {"Authorization": f"Bearer {access_token}"}

        url = f"https://container.googleapis.com/v1/projects/{project_id}/locations/{location}/clusters"
        clusters = []
        params = {}
        try:
            while True:
                response = requests.get(url, headers=headers, params=params)
                response.raise_for_status()

                try:
                    data = response.json()
                except ValueError as e:
                    raise ValueError(f"Error parsing JSON response: {e}")

                clusters.extend(data.get("clusters", []))

                if "nextPageToken" in data:
                    params["pageToken"] = data["nextPageToken"]
                else:
                    break

            return clusters, None

        except requests.exceptions.HTTPError as http_err:
            return None, f"HTTP error occurred: {http_err}"
        except requests.exceptions.ConnectionError as conn_err:
            return None, f"Connection error occurred: {conn_err}"
        except requests.exceptions.Timeout as timeout_err:
            return None, f"Timeout error occurred: {timeout_err}"
        except requests.exceptions.RequestException as req_err:
            return None, f"Request error occurred: {req_err}"
        except ValueError as parse_err:
            return None, f"JSON parsing error: {parse_err}"

    # https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts/list
    def fetch_gcp_iam_service_accounts(self, project_id: str) -> tuple[list, str]:
        scope = "https://www.googleapis.com/auth/cloud-platform"
        credentials, error = self.create_config(scope)
        if error:
            return None, error

        credentials.refresh(Request())
        access_token = credentials.token

        headers = {"Authorization": f"Bearer {access_token}"}

        url = f"https://iam.googleapis.com/v1/projects/{project_id}/serviceAccounts"
        service_accounts = []
        params = {}
        try:
            while True:
                response = requests.get(url, headers=headers, params=params)
                response.raise_for_status()

                try:
                    data = response.json()
                except ValueError as e:
                    raise ValueError(f"Error parsing JSON response: {e}")

                service_accounts.extend(data.get("accounts", []))

                if "nextPageToken" in data:
                    params["pageToken"] = data["nextPageToken"]
                else:
                    break

            return service_accounts, None

        except requests.exceptions.HTTPError as http_err:
            return None, f"HTTP error occurred: {http_err}"
        except requests.exceptions.ConnectionError as conn_err:
            return None, f"Connection error occurred: {conn_err}"
        except requests.exceptions.Timeout as timeout_err:
            return None, f"Timeout error occurred: {timeout_err}"
        except requests.exceptions.RequestException as req_err:
            return None, f"Request error occurred: {req_err}"
        except ValueError as parse_err:
            return None, f"JSON parsing error: {parse_err}"

    # https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts/list
    def fetch_gcp_iam_service_account_keys(
        self, project_id: str, key_email: str
    ) -> tuple[list, str]:
        try:
            scope = "https://www.googleapis.com/auth/cloud-platform"
            credentials, error = self.create_config(scope)
            if error:
                return None, error

            credentials.refresh(Request())
            credentials._subject = (
                self.user_defined_credentials.google_work_space.user_email
            )

            service = build("iam", "v1", credentials=credentials)
            name = f"projects/{project_id}/serviceAccounts/{key_email}"

            request = service.projects().serviceAccounts().keys().list(name=name)
            response = request.execute()

            service_account_keys = response.get("keys", [])
            if not service_account_keys:
                return (
                    None,
                    f"No service account keys found for the service account {key_email} in the project id {project_id}.",
                )
            return service_account_keys, None

        except GoogleAuthError as auth_err:
            return None, f"Authentication error: {auth_err}"
        except HttpError as http_err:
            return (
                None,
                f"HTTP error occurred: {http_err.content.decode('utf-8') if hasattr(http_err, 'content') else http_err}",
            )
        except requests.exceptions.RequestException as req_err:
            return None, f"Request error occurred: {req_err}"

    def list_db_instances(self, project_id: str) -> Tuple[any, str]:
        try:
            scope = "https://www.googleapis.com/auth/cloud-platform"
            token_source, err = self.create_config(scope)
            if err:
                return None, err
            token_source._subject = (
                self.user_defined_credentials.google_work_space.user_email
            )
            service = build("sqladmin", "v1", credentials=token_source)

            request = service.instances().list(project=project_id)
            response = request.execute()
            if response:
                return response, ""
            else:
                return None, "Got empty response"
        except GoogleAuthError as e:
            logging.exception(
                "An exception occurred while creating application: %s", str(e)
            )
            return None, "Invalid 'UserEmail' or 'ServiceAccountKeyFile'"
        except HttpError as error:
            return None, f"An error occurred: {error.reason}"
        except AttributeError as e:
            return None, f"Attribute error occurred while fetching project lists: {e}"

    def list_firewall_rules(self, project_id: str) -> Tuple[list, str]:
        try:
            scope = "https://www.googleapis.com/auth/cloud-platform"
            token_source, err = self.create_config(scope)
            if err:
                return [], err
            token_source.refresh(Request())
            token_source._subject = (
                self.user_defined_credentials.google_work_space.user_email
            )
            service = build("compute", "v1", credentials=token_source)

            firewall_rules = []
            request = service.firewalls().list(project=project_id)
            while request is not None:
                response = request.execute()

                new_firewall_rules = response.get("items", [])
                firewall_rules.extend(new_firewall_rules)

                request = service.firewalls().list_next(
                    previous_request=request, previous_response=response
                )

            if not firewall_rules:
                return (
                    [],
                    f"No firewall rules found in the provided project: {project_id}.",
                )

            return firewall_rules, ""
        except GoogleAuthError as e:
            logging.exception(
                "An exception occurred while creating application: %s", str(e)
            )
            return [], "Invalid 'UserEmail' or 'ServiceAccountKeyFile'"
        except HttpError as error:
            return [], f"An error occurred: {error.reason}"
        except AttributeError as e:
            return [], f"Attribute error occurred while fetching project lists: {e}"

    # https://cloud.google.com/asset-inventory/docs/reference/rest/v1/assets/list
    def fetch_assets(self, project_id: str, content_type: str) -> tuple[list, str]:
        scope = "https://www.googleapis.com/auth/cloud-platform"
        credentials, error = self.create_config(scope)
        if error:
            return None, error

        credentials.refresh(Request())
        access_token = credentials.token

        url = f"https://cloudasset.googleapis.com/v1/projects/{project_id}/assets?contentType={content_type}&pageSize=100"
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {access_token}",
        }
        params = {}
        payload = {}
        assets = []
        try:
            while True:
                response = requests.get(
                    url, headers=headers, params=params, data=payload
                )
                response.raise_for_status()

                try:
                    data = response.json()
                except ValueError as e:
                    raise ValueError(f"Error parsing JSON response: {e}")

                if "assets" in data:
                    assets.extend(data["assets"])

                if "nextPageToken" in data:
                    params["pageToken"] = data["nextPageToken"]
                else:
                    break

            return assets, None
        except requests.exceptions.HTTPError as http_err:
            return None, f"HTTP error occurred: {http_err}"
        except requests.exceptions.ConnectionError as conn_err:
            return None, f"Connection error occurred: {conn_err}"
        except requests.exceptions.Timeout as timeout_err:
            return None, f"Timeout error occurred: {timeout_err}"
        except requests.exceptions.RequestException as req_err:
            return None, f"Request error occurred: {req_err}"
        except ValueError as parse_err:
            return None, f"JSON parsing error: {parse_err}"

    def list_firewall_rules(self, project_id: str) -> tuple[list, str]:
        try:
            scope = "https://www.googleapis.com/auth/cloud-platform"
            token_source, err = self.create_config(scope)
            if err:
                return [], err
            token_source.refresh(Request())
            token_source._subject = (
                self.user_defined_credentials.google_work_space.user_email
            )
            service = build("compute", "v1", credentials=token_source)

            firewall_rules = []
            request = service.firewalls().list(project=project_id)
            while request is not None:
                response = request.execute()

                new_firewall_rules = response.get("items", [])
                firewall_rules.extend(new_firewall_rules)

                request = service.firewalls().list_next(
                    previous_request=request, previous_response=response
                )

            if not firewall_rules:
                return (
                    [],
                    f"No firewall rules found in the provided project: {project_id}.",
                )

            return firewall_rules, ""
        except GoogleAuthError as e:
            logging.exception(
                "An exception occurred while creating application: %s", str(e)
            )
            return [], "Invalid 'UserEmail' or 'ServiceAccountKeyFile'"
        except HttpError as error:
            return [], f"An error occurred: {error.reason}"
        except AttributeError as e:
            return [], f"Attribute error occurred while fetching project lists: {e}"

    def build_resource_url(
        self,
        asset_name: str,
        resource_type: str,
        resource_name: str = None,
        resource_location: str = None,
        key_type: str = None,
    ) -> str:
        resource_url_dict = {
            "artifactregistry.googleapis.com/DockerImage": IMAGE,
            "artifactregistry.googleapis.com/Repository": REPOSITORIES,
            "cloudresourcemanager.googleapis.com/Project": PROJECTS,
            "compute.googleapis.com/Project": PROJECTS,
            "compute.googleapis.com/Disk": DISKS,
            "compute.googleapis.com/Firewall": FIREWALL_POLICIES,
            "compute.googleapis.com/Instance": VM_INSTANCES,
            "compute.googleapis.com/InstanceGroup": VM_INSTANCE_GROUPS,
            "compute.googleapis.com/InstanceTemplate": VM_INSTANCE_TEMPLATES,
            "compute.googleapis.com/Network": NETWORKS,
            "compute.googleapis.com/Route": ROUTES,
            "compute.googleapis.com/Subnetwork": SUBNETWORKS,
            "container.googleapis.com/Cluster": CLUSTER,
            "k8s.io/Node": NODES,
            "k8s.io/Pod": PODS,
            "storage.k8s.io/StorageClass": STORAGE_CLASSES,
            "container.googleapis.com/NodePool": NODEPOOLS,
            "iam.googleapis.com/ServiceAccount": IAM_SERVICE_ACCOUNTS,
            "iam.googleapis.com/ServiceAccountKey": IAM_SERVICE_ACCOUNT_KEYS,
            "logging.googleapis.com/LogBucket": LOG_BUCKETS,
            "logging.googleapis.com/LogSink": LOG_SINKS,
            "pubsub.googleapis.com/Topic": TOPICS,
            "serviceusage.googleapis.com/Service": API_SERVICES,
            "containerregistry.googleapis.com/Image": IMAGE,
            "cloudbilling.googleapis.com/ProjectBillingInfo": BILLING,
        }
        components = self.parse_asset_name(asset_name)
        template = resource_url_dict.get(resource_type)
        if not template:
            return "N/A"

        try:
            if resource_type in {
                "artifactregistry.googleapis.com/DockerImage",
                "containerregistry.googleapis.com/Image",
            }:
                components.update(
                    {
                        "image_name": components.get("asset_name", "").replace(
                            "@", "/"
                        ),
                        "repo_name": asset_name.split("/")[-3],
                    }
                )
                if resource_type == "containerregistry.googleapis.com/Image":
                    components.update(
                        {
                            "region": resource_location,
                            "project_name": asset_name.split("/")[-2],
                        }
                    )
            elif resource_type == "cloudbilling.googleapis.com/ProjectBillingInfo":
                components["asset_name"] = resource_name
            elif resource_type == "iam.googleapis.com/ServiceAccountKey":
                if key_type == "SYSTEM_MANAGED":
                    return "N/A"
                elif key_type == "USER_MANAGED":
                    components["asset_name"] = asset_name.split("/")[-3]
            return template.format(**components)
        except KeyError:
            return "Invalid"

    def parse_asset_name(self, asset_name: str) -> dict:
        parts = asset_name.split("/")

        project_name = "N/A"
        if "projects" in parts:
            project_index = parts.index("projects") + 1
            if project_index < len(parts):
                project_name = parts[project_index]
        region = "N/A"
        for key in ["locations", "regions", "zones"]:
            if key in parts:
                region_index = parts.index(key) + 1
                if region_index < len(parts):
                    region = parts[region_index]
                    break
        cluster_name = "N/A"
        if "clusters" in parts:
            cluster_index = parts.index("clusters") + 1
            if cluster_index < len(parts):
                cluster_name = parts[cluster_index]
        namespace_name = "N/A"
        if "namespaces" in parts:
            namespace_index = parts.index("namespaces") + 1
            if namespace_index < len(parts):
                namespace_name = parts[namespace_index]

        return {
            "project_name": project_name,
            "region": region,
            "cluster_name": cluster_name,
            "namespace_name": namespace_name,
            "asset_name": parts[-1] if len(parts) > 0 else "N/A",
        }

    def execute_bigquery_query(
        self, query: str, formatted_value: list = None
    ) -> tuple[list | dict, str]:
        try:
            scope = "https://www.googleapis.com/auth/bigquery"
            credentials, err = self.create_config(scope)
            if err:
                return None, err
            client = bigquery.Client(
                credentials=credentials, project=credentials.project_id
            )
            query_job = None
            if formatted_value:
                job_config = self.prepare_job_config(formatted_value)
                query_job = client.query(query, job_config=job_config)
            else:
                query_job = client.query(query)

            query_job.result()
            if query.strip().lower().startswith("select"):
                results = [dict(row) for row in query_job]
                return results, None
            else:
                return {
                    "query": query_job.query,
                    "status": "success",
                    "affected_rows": query_job.num_dml_affected_rows,
                }, None
        except GoogleAPIError as e:
            return None, f"An exception occurs while executing bigquery query: {str(e)}"
        except Exception as e:
            return None, f"Unexpected error: {str(e)}"

    def get_bigquery_table_schema(self, table_name: str) -> tuple[list | dict, str]:
        try:
            scope = "https://www.googleapis.com/auth/bigquery"
            credentials, err = self.create_config(scope)
            if err:
                return None, err
            client = bigquery.Client(
                credentials=credentials, project=credentials.project_id
            )
            table_data = client.get_table(table_name)
            table_schema = []
            for schema in table_data.schema:
                column_info = {
                    "name": schema.name,
                    "type": schema.field_type,
                    "mode": schema.mode,
                }
                table_schema.append(column_info)
            return table_schema, None
        except GoogleAPIError as e:
            return None, f"An exception occurs while executing bigquery query: {str(e)}"
        except Exception as e:
            return None, f"Unexpected error: {str(e)}"

    def prepare_job_config(self, query_params_list: list) -> bigquery.QueryJobConfig:
        query_parameters_formatted = [
            bigquery.ScalarQueryParameter(
                obj.get("field"),
                "BOOL" if obj.get("type") == "BOOLEAN" else obj.get("type"),
                obj.get("value"),
            )
            for obj in query_params_list
            if all(k in obj for k in ["field", "type", "value"])
        ]
        job_config = bigquery.QueryJobConfig(
            query_parameters=query_parameters_formatted
        )
        return job_config

    # Google Sheets API Methods
    def _get_sheets_headers(self) -> Tuple[dict, str]:
        """
        Get HTTP headers with Bearer token for Google Sheets API.

        Returns:
            Tuple[headers_dict, None] on success
            Tuple[None, error_message] on failure
        """
        try:
            scope = "https://www.googleapis.com/auth/spreadsheets"
            credentials, error = self.create_config(scope)
            if error:
                return None, error

            credentials = credentials.with_subject(
                self.user_defined_credentials.google_work_space.user_email
            )
            credentials.refresh(Request())
            access_token = credentials.token

            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            }

            return headers, None

        except Exception as e:
            logging.error(f"Error getting sheets headers: {str(e)}")
            return None, f"Failed to get authorization headers: {str(e)}"

    def create_spreadsheet(
        self, title: str, tab_titles: list
    ) -> Tuple[str, str, None] | Tuple[None, None, str]:
        """
        Create a new Google Spreadsheet with specified tabs.

        Args:
            title: Title of the spreadsheet
            tab_titles: List of tab/sheet names to create

        Returns:
            Tuple[spreadsheet_id, spreadsheet_url, None] on success
            Tuple[None, None, error_message] on failure
        """
        try:
            headers, error = self._get_sheets_headers()
            if error:
                return None, None, error

            # Prepare sheets array
            sheets = []
            for i, tab_title in enumerate(tab_titles):
                sheets.append(
                    {"properties": {"sheetId": i, "title": tab_title, "index": i}}
                )

            request_body = {"properties": {"title": title}, "sheets": sheets}

            url = "https://sheets.googleapis.com/v4/spreadsheets"
            response = requests.post(url, headers=headers, json=request_body)
            response.raise_for_status()

            data = response.json()
            spreadsheet_id = data.get("spreadsheetId")
            spreadsheet_url = data.get("spreadsheetUrl")

            logging.info(f"✓ Spreadsheet created: '{title}' - {spreadsheet_url}")

            return spreadsheet_id, spreadsheet_url, None

        except requests.exceptions.RequestException as e:
            error_msg = f"HTTP error creating spreadsheet: {str(e)}"
            logging.error(error_msg)
            return None, None, error_msg
        except Exception as e:
            error_msg = f"Error creating spreadsheet: {str(e)}"
            logging.error(error_msg)
            return None, None, error_msg

    def _get_sheet_id(
        self, spreadsheet_id: str, sheet_name: str
    ) -> Tuple[int, None] | Tuple[None, str]:
        """
        Get the sheet ID from the sheet name.

        Args:
            spreadsheet_id: ID of the spreadsheet
            sheet_name: Name of the sheet

        Returns:
            Tuple[sheet_id, None] on success
            Tuple[None, error_message] on failure
        """
        try:
            headers, error = self._get_sheets_headers()
            if error:
                return None, error

            url = f"https://sheets.googleapis.com/v4/spreadsheets/{spreadsheet_id}"
            response = requests.get(url, headers=headers)
            response.raise_for_status()

            spreadsheet_data = response.json()
            for sheet in spreadsheet_data.get("sheets", []):
                if sheet["properties"]["title"] == sheet_name:
                    return sheet["properties"]["sheetId"], None

            return None, f"Sheet '{sheet_name}' not found"

        except Exception as e:
            error_msg = f"Error getting sheet ID: {str(e)}"
            logging.error(error_msg)
            return None, error_msg

    def paste_csv_data(
        self, spreadsheet_id: str, sheet_name: str, csv_content: str
    ) -> Tuple[bool, None] | Tuple[None, str]:
        """
        Paste CSV data into a sheet using batchUpdate with pasteData.

        Args:
            spreadsheet_id: ID of the spreadsheet
            sheet_name: Name of the sheet/tab
            csv_content: Raw CSV string content

        Returns:
            Tuple[True, None] on success
            Tuple[None, error_message] on failure
        """
        try:
            headers, error = self._get_sheets_headers()
            if error:
                return None, error

            sheet_id, error = self._get_sheet_id(spreadsheet_id, sheet_name)
            if error:
                return None, error

            request_body = {
                "requests": [
                    {
                        "pasteData": {
                            "coordinate": {
                                "sheetId": sheet_id,
                                "rowIndex": 0,
                                "columnIndex": 0,
                            },
                            "data": csv_content,
                            "type": "NORMAL",
                            "delimiter": ",",
                        }
                    }
                ]
            }

            url = f"https://sheets.googleapis.com/v4/spreadsheets/{spreadsheet_id}:batchUpdate"
            response = requests.post(url, headers=headers, json=request_body)
            response.raise_for_status()

            logging.info(f"✓ CSV data pasted into '{sheet_name}'")
            return True, None

        except requests.exceptions.RequestException as e:
            error_msg = f"HTTP error pasting CSV data: {str(e)}"
            logging.error(error_msg)
            return None, error_msg
        except Exception as e:
            error_msg = f"Error pasting CSV data: {str(e)}"
            logging.error(error_msg)
            return None, error_msg

    def append_json_data(
        self, spreadsheet_id: str, sheet_name: str, data_2d: list
    ) -> Tuple[bool, None] | Tuple[None, str]:
        """
        Append JSON data to a sheet using values.append endpoint.

        Args:
            spreadsheet_id: ID of the spreadsheet
            sheet_name: Name of the sheet/tab
            data_2d: 2D array (list of lists) to append

        Returns:
            Tuple[True, None] on success
            Tuple[None, error_message] on failure
        """
        try:
            headers, error = self._get_sheets_headers()
            if error:
                return None, error

            if isinstance(data_2d, dict) and "values" in data_2d:
                request_body = data_2d
            else:
                request_body = {"values": data_2d}

            encoded_sheet_name = urllib.parse.quote(sheet_name)
            range_notation = f"'{encoded_sheet_name}'!A1"

            url = (
                f"https://sheets.googleapis.com/v4/spreadsheets/{spreadsheet_id}/values/"
                f"{range_notation}:append"
            )

            params = {
                "valueInputOption": "USER_ENTERED",
                "insertDataOption": "INSERT_ROWS",  # Appends to the bottom instead of overwriting
            }

            response = requests.post(
                url,
                headers=headers,
                json=request_body,
                params=params,
            )

            if response.status_code != 200:
                error_msg = f"HTTP {response.status_code}: {response.text}"
                logging.error(error_msg)
                return None, error_msg

            response.raise_for_status()

            logging.info(f"✓ JSON data appended to '{sheet_name}'")
            return True, None

        except requests.exceptions.RequestException as e:
            error_msg = f"HTTP error appending JSON data: {str(e)}"
            logging.error(error_msg)
            return None, error_msg
        except Exception as e:
            error_msg = f"Error appending JSON data: {str(e)}"
            logging.error(error_msg)
            return None, error_msg

    def json_to_2d_array(self, json_data: list) -> list:
        """
        Convert JSON data (list of dicts) to 2D array with headers.

        Args:
            json_data: List of dictionaries

        Returns:
            2D array with headers as first row
        """
        if not json_data:
            return []

        # Get all unique keys
        all_keys = set()
        for record in json_data:
            if isinstance(record, dict):
                all_keys.update(record.keys())

        headers = sorted(list(all_keys))
        rows = [headers]

        for record in json_data:
            if isinstance(record, dict):
                row = [str(record.get(key, "")) for key in headers]
            else:
                row = [str(record)]
            rows.append(row)

        return rows

    def populate_spreadsheet(
        self, spreadsheet_id: str, sheet_name: str, data_content: str, data_type: str
    ) -> Tuple[str, None] | Tuple[None, str]:
        """
        Populate a spreadsheet with data (CSV or JSON).

        Args:
            spreadsheet_id: ID of the spreadsheet
            sheet_name: Name of the sheet to populate
            data_content: Raw file content (CSV or JSON string)
            data_type: Either 'csv' or 'json'

        Returns:
            Tuple[spreadsheet_url, None] on success
            Tuple[None, error_message] on failure
        """
        try:
            if data_type.lower() == "csv":
                success, error = self.paste_csv_data(
                    spreadsheet_id, sheet_name, data_content
                )
                if error:
                    return None, error

            elif data_type.lower() == "json":
                json_data = json.loads(data_content)
                if not isinstance(json_data, list):
                    json_data = [json_data]

                data_2d = self.json_to_2d_array(json_data)
                success, error = self.append_json_data(
                    spreadsheet_id, sheet_name, data_2d
                )
                if error:
                    return None, error

            else:
                return None, f"Unsupported data_type: {data_type}. Use 'csv' or 'json'."

            # Get spreadsheet URL
            headers, error = self._get_sheets_headers()
            if error:
                return None, error

            url = f"https://sheets.googleapis.com/v4/spreadsheets/{spreadsheet_id}"
            response = requests.get(url, headers=headers)
            response.raise_for_status()

            spreadsheet_url = response.json().get("spreadsheetUrl")
            return spreadsheet_url, None

        except json.JSONDecodeError as e:
            error_msg = f"Invalid JSON content: {str(e)}"
            logging.error(error_msg)
            return None, error_msg
        except Exception as e:
            error_msg = f"Error populating spreadsheet: {str(e)}"
            logging.error(error_msg)
            return None, error_msg

    def format_spreadsheet_dynamically(
        self,
        spreadsheet_id: str,
        tab_name: str,
        formatted_data: list,
        formatter_functions: str = "",
    ) -> tuple[bool, str]:
        """
        Dynamically applies WRAP to long columns and AUTO-RESIZE to short columns.
        """
        try:
            headers, error = self._get_sheets_headers()
            if error:
                return False, f"Failed to get headers: {error}"

            sheet_id, error = self._get_sheet_id(spreadsheet_id, tab_name)
            if error:
                return False, f"Failed to get sheet ID: {error}"

            CHARACTER_LIMIT = 50
            long_columns = []
            short_columns = []

            funcs = (
                [
                    f.strip().replace(" ", "_").lower()
                    for f in formatter_functions.split(",")
                ]
                if formatter_functions
                else []
            )
            if not funcs:
                funcs = ["fixed_header", "auto_resize", "wrap_columns"]

            if not formatted_data:
                return True, ""

            num_columns = len(formatted_data[0])

            for col_index in range(num_columns):
                max_length = max(
                    (
                        len(str(row[col_index]))
                        for row in formatted_data
                        if col_index < len(row)
                    ),
                    default=0,
                )

                if max_length > CHARACTER_LIMIT:
                    long_columns.append(col_index)
                else:
                    short_columns.append(col_index)

            requests_payload = []

            if "fixed_header" in funcs:
                requests_payload.extend(
                    [
                        {
                            "updateSheetProperties": {
                                "properties": {
                                    "sheetId": sheet_id,
                                    "gridProperties": {"frozenRowCount": 1},
                                },
                                "fields": "gridProperties.frozenRowCount",
                            }
                        },
                        {
                            "repeatCell": {
                                "range": {
                                    "sheetId": sheet_id,
                                    "startRowIndex": 0,
                                    "endRowIndex": 1,
                                },
                                "cell": {
                                    "userEnteredFormat": {
                                        "backgroundColor": {
                                            "red": 0.9,
                                            "green": 0.9,
                                            "blue": 0.9,
                                        },
                                        "textFormat": {"bold": True},
                                    }
                                },
                                "fields": "userEnteredFormat(backgroundColor,textFormat)",
                            }
                        },
                    ]
                )

            if "auto_resize" in funcs:
                for col_index in short_columns:
                    requests_payload.append(
                        {
                            "autoResizeDimensions": {
                                "dimensions": {
                                    "sheetId": sheet_id,
                                    "dimension": "COLUMNS",
                                    "startIndex": col_index,
                                    "endIndex": col_index + 1,
                                }
                            }
                        }
                    )

            if "wrap_columns" in funcs:
                for col_index in long_columns:
                    requests_payload.append(
                        {
                            "repeatCell": {
                                "range": {
                                    "sheetId": sheet_id,
                                    "startRowIndex": 0,
                                    "startColumnIndex": col_index,
                                    "endColumnIndex": col_index + 1,
                                },
                                "cell": {"userEnteredFormat": {"wrapStrategy": "WRAP"}},
                                "fields": "userEnteredFormat.wrapStrategy",
                            }
                        }
                    )
                    requests_payload.append(
                        {
                            "updateDimensionProperties": {
                                "range": {
                                    "sheetId": sheet_id,
                                    "dimension": "COLUMNS",
                                    "startIndex": col_index,
                                    "endIndex": col_index + 1,
                                },
                                "properties": {"pixelSize": 300},
                                "fields": "pixelSize",
                            }
                        }
                    )

            if requests_payload:
                url = f"https://sheets.googleapis.com/v4/spreadsheets/{spreadsheet_id}:batchUpdate"
                response = requests.post(
                    url, headers=headers, json={"requests": requests_payload}
                )
                response.raise_for_status()

            return True, ""

        except Exception as e:
            return False, f"Dynamic formatting error: {str(e)}"

    def _get_drive_headers(self) -> Tuple[dict, str]:
        """
        Get HTTP headers with Bearer token for Google Drive API.
        """
        try:
            scope = "https://www.googleapis.com/auth/drive"
            credentials, error = self.create_config(scope)
            if error:
                return None, error

            credentials = credentials.with_subject(
                self.user_defined_credentials.google_work_space.user_email
            )
            credentials.refresh(Request())
            access_token = credentials.token

            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            }
            return headers, None
        except Exception as e:
            logging.error(f"Error getting drive headers: {str(e)}")
            return None, f"Failed to get authorization headers: {str(e)}"

    def share_spreadsheet(
        self, file_id: str, emails: list, role: str = "reader"
    ) -> tuple[bool, str]:
        """
        Share the spreadsheet with a list of emails.
        """
        try:
            headers, error = self._get_drive_headers()
            if error:
                return False, error

            url = f"https://www.googleapis.com/drive/v3/files/{file_id}/permissions"

            for email in emails:
                email = email.strip()
                if not email:
                    continue
                payload = {"type": "user", "role": role, "emailAddress": email}

                response = requests.post(
                    url,
                    headers=headers,
                    json=payload,
                    params={
                        "sendNotificationEmail": "true",
                        "supportsAllDrives": "true",
                    },
                )
                response.raise_for_status()

            return True, ""
        except requests.exceptions.RequestException as e:
            error_msg = f"HTTP error sharing spreadsheet: {str(e)}"
            logging.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Error sharing spreadsheet: {str(e)}"
            logging.error(error_msg)
            return False, error_msg

    def get_folder_id_by_path(
        self, folder_path: str, create_if_missing: bool = False, drive_id: str = "root"
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Resolves a folder path (e.g. 'Reports/Quarterly/Sample') to a Google Drive folder ID
        by traversing the path level-by-level under the impersonated user's Drive.

        Args:
            folder_path: Slash-separated folder path (e.g. 'ParentFolder/SubFolder')
            create_if_missing: If True, creates missing folders along the path.
                               If False (default), stops and returns an error when a folder is not found.
            drive_id: The Drive to search in. Use 'root' (default) for the user's My Drive,
                      or pass a Shared Drive ID (e.g. '0AFxxxxxx') to search inside a Shared Drive.

        Returns:
            Tuple[folder_id, None] on success
            Tuple[None, error_message] if a folder is not found (and create_if_missing=False) or on error
        """
        try:
            scope = "https://www.googleapis.com/auth/drive"
            credentials, err = self.create_config(scope)
            if err:
                return None, err

            # Impersonate the configured user so we search/create inside their Drive,
            # not the service account's own Drive.
            credentials = credentials.with_subject(
                self.user_defined_credentials.google_work_space.user_email
            )
            credentials.refresh(Request())

            service = build("drive", "v3", credentials=credentials)

            folder_names = [name for name in folder_path.strip("/").split("/") if name]
            if not folder_names:
                return (
                    None,
                    "Invalid folder path: path is empty or contains only slashes.",
                )

            # For Shared Drives, the traversal starts at the Shared Drive root (drive_id).
            # For My Drive, drive_id is 'root'.
            is_shared_drive = drive_id != "root"
            parent_id = drive_id

            for name in folder_names:
                query = (
                    f"name = '{name}' "
                    f"and mimeType = 'application/vnd.google-apps.folder' "
                    f"and trashed = false "
                    f"and '{parent_id}' in parents"
                )

                list_kwargs = dict(
                    q=query,
                    fields="files(id, name)",
                    includeItemsFromAllDrives=True,
                    supportsAllDrives=True,
                )
                # 'corpora' must be set to 'drive' with a driveId when querying a Shared Drive
                if is_shared_drive:
                    list_kwargs["corpora"] = "drive"
                    list_kwargs["driveId"] = drive_id

                results = service.files().list(**list_kwargs).execute()
                folders = results.get("files", [])

                if folders:
                    parent_id = folders[0]["id"]
                elif create_if_missing:
                    file_metadata = {
                        "name": name,
                        "mimeType": "application/vnd.google-apps.folder",
                        "parents": [parent_id],
                    }
                    new_folder = (
                        service.files()
                        .create(body=file_metadata, fields="id", supportsAllDrives=True)
                        .execute()
                    )
                    parent_id = new_folder.get("id")
                    logging.info(f"Created missing folder '{name}' in Drive path.")
                else:
                    return None, (
                        f"Folder '{name}' not found in the specified path '{folder_path}'. "
                        f"Ensure the folder exists in the "
                        f"{'Shared Drive' if is_shared_drive else 'My Drive'} of the configured user."
                    )

            return parent_id, None

        except Exception as e:
            error_msg = f"Error resolving folder path '{folder_path}': {str(e)}"
            logging.error(error_msg)
            return None, error_msg

    def move_file_to_folder(
        self, file_id: str, folder_id: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Moves a Google Drive file (e.g. a Spreadsheet) into the specified folder
        by updating its parents.

        Args:
            file_id: The ID of the file (spreadsheet) to move
            folder_id: The ID of the destination folder

        Returns:
            Tuple[True, None] on success
            Tuple[False, error_message] on failure
        """
        try:
            scope = "https://www.googleapis.com/auth/drive"
            credentials, err = self.create_config(scope)
            if err:
                return False, err

            credentials = credentials.with_subject(
                self.user_defined_credentials.google_work_space.user_email
            )
            credentials.refresh(Request())

            service = build("drive", "v3", credentials=credentials)

            # Fetch current parents so we can remove them when adding the new one
            file_metadata = (
                service.files()
                .get(fileId=file_id, fields="parents", supportsAllDrives=True)
                .execute()
            )
            current_parents = ",".join(file_metadata.get("parents", []))

            # Move: add new parent folder, remove existing parent(s)
            service.files().update(
                fileId=file_id,
                addParents=folder_id,
                removeParents=current_parents,
                fields="id, parents",
                supportsAllDrives=True,
            ).execute()

            logging.info(f"Moved file '{file_id}' to folder '{folder_id}'.")
            return True, None

        except Exception as e:
            error_msg = (
                f"Error moving file '{file_id}' to folder '{folder_id}': {str(e)}"
            )
            logging.error(error_msg)
            return False, error_msg
