from appconnections.awsappconnector import awsappconnector
import io
from typing import List
import paramiko
import base64
from io import StringIO
from urllib.parse import urlparse
import json
from compliancecowcards.utils import cowdictutils

import paramiko.ssh_exception

class Jumphost:
    user_id: str
    ssh_private_key: str

    def __init__(self, user_id: str, ssh_private_key: str) -> None:
        self.user_id = user_id
        self.ssh_private_key = ssh_private_key

    @staticmethod
    def from_dict(obj) -> 'Jumphost':
        user_id, ssh_private_key = "", ""
        if isinstance(obj, dict):
            user_id = obj.get("UserID", "")
            ssh_private_key = obj.get("SshPrivateKey", "")

        return Jumphost(user_id, ssh_private_key)

    def to_dict(self) -> dict:
        result: dict = {}
        result["UserID"] = self.user_id
        result["SshPrivateKey"] = self.ssh_private_key
        return result

    def validate_attributes(self) -> str:
        emptyAttrs = []
        if not self.user_id:
            emptyAttrs.append("UserID")

        if not self.ssh_private_key:
            emptyAttrs.append("SshPrivateKey")

        return "Invalid Credentials: " + ", ".join(
            emptyAttrs) + " is empty" if emptyAttrs else ""


class LinkedApplications:
    aws_app_connector_app: List[awsappconnector.AWSAppConnector]

    def __init__(
            self, aws_app_connector_app: List[awsappconnector.AWSAppConnector]
    ) -> None:
        self.aws_app_connector_app = aws_app_connector_app

    @staticmethod
    def from_dict(obj) -> 'LinkedApplications':
        aws_app_connector_app = []
        if isinstance(obj, dict):
            aws_app_connector_app = [
                awsappconnector.AWSAppConnector.from_dict(item)
                for item in obj.get("AWSAppConnector", [])
            ]

        return LinkedApplications(aws_app_connector_app)

    def to_dict(self) -> dict:
        result: dict = {}
        result["AWSAppConnector"] = [
            item.to_dict() for item in self.aws_app_connector_app
        ]
        return result


class UserDefinedCredentials:
    jumphost: Jumphost

    def __init__(self, jumphost: Jumphost) -> None:
        self.jumphost = jumphost

    @staticmethod
    def from_dict(obj) -> 'UserDefinedCredentials':
        jumphost = None
        if isinstance(obj, dict):
            jumphost = Jumphost.from_dict(obj.get("Jumphost", None))
        return UserDefinedCredentials(jumphost)

    def to_dict(self) -> dict:
        result: dict = {}
        result["Jumphost"] = self.jumphost.to_dict()
        return result


class Kubernetes:

    # Persistent volumes
    LIST_PVS = 'kubectl --context={context_name} get pv -o json'
    # Fetch cluster and context details
    GET_CLUSTER_CONTEXT = "kubectl config view -o jsonpath='{\"Cluster\\tContexts\\n\"}{range .contexts[*]}{.context.cluster}{\"\\t\"}{.name}{\"\\n\"}{end}'"

    app_url: str
    app_port: int
    user_defined_credentials: UserDefinedCredentials
    linked_applications: LinkedApplications

    def __init__(self,
                 app_url: str = None,
                 app_port: int = None,
                 user_defined_credentials: UserDefinedCredentials = None,
                 linked_applications: LinkedApplications = None) -> None:
        self.app_url = app_url
        self.app_port = app_port
        self.user_defined_credentials = user_defined_credentials
        self.linked_applications = linked_applications

    @staticmethod
    def from_dict(obj) -> 'Kubernetes':
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

            linked_applications_dict = obj.get("LinkedApplications", None)
            if linked_applications_dict is None:
                linked_applications_dict = obj.get("linkedApplications", None)
            if bool(linked_applications_dict):
                linked_applications = LinkedApplications.from_dict(
                    linked_applications_dict)

        return Kubernetes(app_url, app_port, user_defined_credentials,
                          linked_applications)

    def to_dict(self) -> dict:
        result: dict = {}
        result["AppURL"] = self.app_url
        result["AppPort"] = self.app_port
        result[
            "UserDefinedCredentials"] = self.user_defined_credentials.to_dict(
            )
        result["LinkedApplications"] = self.linked_applications.to_dict()
        return result

    def validate(self) -> bool and dict:
        # PLACE-HOLDER

        result, err = self.validate_jumphost_cred()
        if err:
            return False, err
        return True, None
    
    def get_jumphost_cred(self):
        cred = []
        if self.user_defined_credentials is None:
            return ValueError("User Inputs is Empty")
        if self.user_defined_credentials.jumphost is None:
            return ValueError("Couldn't Find JumpHost Credentials in UserInputs")
        user_id = self.user_defined_credentials.jumphost.user_id
        if not user_id:
            cred.append("User id is empty")
        ssh_private_key = self.user_defined_credentials.jumphost.ssh_private_key
        if not ssh_private_key:
            cred.append("ssh_private key is empty")
        app_url = self.app_url
        port,host = None,None
        if app_url:
            parsed_url = urlparse(self.app_url)
            host = parsed_url.hostname
            port = parsed_url.port
        else:
            cred.append("App Url is empty")
            
        if not host or not port:
            cred.append("Invalid AppURL")
        
        if len(cred)>0:
            return "", "", "",  ValueError(", ".join(cred))
        return user_id, ssh_private_key, host, None

    def validate_jumphost_cred(self):

        query = "ls"  # Use a simple query for validation
        result, error = self.connect_instance(query)

        return result, error
        

    def connect_instance(self,query):
    
        query_result = None
        
        user_id, ssh_private_key, host, error = self.get_jumphost_cred()
        if error:
            return None, error

        try:
            
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            decoded_key_bytes = base64.b64decode(ssh_private_key).decode('utf-8')
            ssh_key = paramiko.RSAKey(file_obj=StringIO(decoded_key_bytes))
            ssh_client.connect(hostname=host, username=user_id, pkey=ssh_key)

            stdin, stdout, stderr = ssh_client.exec_command(query)
            query_result = stdout.read().decode('utf-8')
            stderr_content = stderr.read().decode('utf-8')
            error = f"Error type: {type(stderr_content).__name__}, Error message: {stderr_content}" if stderr_content else ""
        except paramiko.AuthenticationException:
            error = "Invalid username or SSH key."
        except paramiko.SSHException as ssh_error:
            error = f"SSH error: {ssh_error}"
        except paramiko.ssh_exception.NoValidConnectionsError:
            error = "Invalid AppURL."
        except Exception as e:
            if 'Incorrect padding' or 'Invalid base64-encoded string' in str(e):
                error = "Invalid SSH Key."
            else :
                error = f"Cannot connect: {e}."
        finally:
            if ssh_client and ssh_client.get_transport():
                ssh_client.close()

        return query_result, error

    def list_pvs(self, cluster_map):
        
        pv_list = []
        error_list = []

        if not cluster_map:
            return pv_list, error_list

        for cluster_name, context_name in cluster_map.items():
            response_str, error = self.connect_instance(self.LIST_PVS.format(context_name=context_name))
            if error:
                error_list.append(f"An error occurred while fetching the Kubernetes persistent volume list for cluster '{cluster_name}': {error}")
                continue
            try:
                response_json = json.loads(response_str)
            except json.JSONDecodeError as e:
                error_list.append(f"An exception occurred while converting the kubectl command response to JSON for cluster '{cluster_name}': {e}")
                continue
            items = response_json.get('items', [])
            if not items:
                error_list.append(f"No persistent volumes found for cluster '{cluster_name}'")
                continue
            for item in items:
                item['ClusterName'] = cluster_name
            pv_list.extend(items)

        return pv_list, error_list
    
    def get_include_cluster(self, include):

        error_list = []
        cluster_map = {}
        include_map = {}

        try:
            if not include:
                return None, ["Include cluster details is mandatory to retrieve cluster information."]

            # Forming command to include clusters
            include_command = self._build_grep_command(include, include_map, True)

            # Final command
            final_command = self.GET_CLUSTER_CONTEXT + include_command
            response_str, error = self.connect_instance(final_command)
            if error:
                return None, [f"An error occurred while fetching the Kubernetes cluster list. {error}"]

            if response_str:
                err = self._parse_response(response_str, include_map, cluster_map)
                if err:
                    error_list.append("Failed while processing query response. Please contact support for further details.")
                    return cluster_map, error_list
            invalid_include = [key for key, value in include_map.items() if not value]

            if not response_str and not error:
                return None, ["Failed to fetch the user-provided cluster details."]

            if invalid_include:
                error_list.append("Failed to fetch the following included cluster(s): " + ", ".join(invalid_include))

            return cluster_map, error_list

        except (KeyError, ValueError) as e:
            return None, ["Failed to fetch cluster context details. Please contact support for further details"]
        

    def get_include_and_exclude_cluster(self, include, exclude):
        error_list = []
        cluster_map = {}
        include_map = {}
        exclude_map = {}

        try:
            if not include:
                return None, ["Include cluster details is mandatory to retrieve cluster information."]

            # Forming command to include clusters
            include_command = self._build_grep_command(include, include_map, True)
            self._build_grep_command(exclude, exclude_map, False)

            # Final command
            final_command = self.GET_CLUSTER_CONTEXT + include_command
            response_str, error = self.connect_instance(final_command)
            if error:
                return None, [f"An error occurred while fetching the Kubernetes cluster list. {error}"]

            if response_str:
                err = self._parse_response(response_str, include_map, cluster_map)
                if err:
                    error_list.append("Failed while processing query response. Please contact support for further details.")
                    return cluster_map, error_list
            invalid_include = [key for key, value in include_map.items() if not value]

            if not response_str and not error:
                return None, []

            for key, _ in exclude_map.items():
                if key in cluster_map:
                    cluster_map.pop(key)
                    exclude_map[key] = True

            invalid_exclude = [key for key, value in exclude_map.items() if not value]

            if invalid_include:
                error_list.append("Failed to fetch the following included cluster(s): " + ", ".join(invalid_include))
            if invalid_exclude:
                error_list.append("Failed to fetch the following excluded cluster(s): " + ", ".join(invalid_exclude))

            return cluster_map, error_list

        except (KeyError, ValueError) as e:
            return None, ["Failed to fetch cluster context details. Please contact support for further details"]

    
    def _build_grep_command(self, clusters, cluster_map, is_include):
        
        if not clusters:
            return ''
        grep_option = "grep" if is_include else "grep -v"
        if "*" in clusters:
            cluster_map["*"] = True
            return ''
        command = f" | {grep_option} '" + "\\|".join(clusters) + "'"
        cluster_map.update({cluster: False for cluster in clusters})
        return command

    
    def _parse_response(self, response_str, include_map, cluster_map):
        try:
            split_by_new_line = response_str.split('\n')
            for data in split_by_new_line:
                cluster_with_context = data.split('\t')
                if len(cluster_with_context) == 2:
                    cluster_name, context = cluster_with_context
                    cluster_name = cluster_name.split("/")[-1]
                    if cluster_name in include_map or "*" in include_map:
                        include_map[cluster_name] = True
                        cluster_map[cluster_name] = context
            # Remove the first cluster if '*' is in include_map
            if "*" in include_map:
                first_key = next(iter(cluster_map), None)
                if first_key is not None:
                    del cluster_map[first_key]
            
            return ''
        except IndexError:
            return 'Failed to parse response'
