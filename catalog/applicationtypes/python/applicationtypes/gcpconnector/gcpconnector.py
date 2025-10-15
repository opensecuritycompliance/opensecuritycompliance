from datetime import datetime, timezone
import base64
import logging
import os
import json
import re
from typing import Tuple
from google.auth.exceptions import GoogleAuthError
from google.api_core.exceptions import GoogleAPIError
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2 import service_account
from google.cloud import bigquery
from compliancecowcards.utils import cowdictutils
import requests

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
            token_source._subject = (
                self.user_defined_credentials.google_work_space.user_email
            )
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
