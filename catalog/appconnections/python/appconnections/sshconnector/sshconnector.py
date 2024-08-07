import paramiko
import urllib.parse
import io
import base64
import paramiko.ssh_exception
from datetime import datetime

class SSH:
    user_name: str
    ssh_key: str

    def __init__(self, user_name: str, ssh_key: str) -> None:
        self.user_name = user_name
        self.ssh_key = ssh_key

    @staticmethod
    def from_dict(obj) -> 'SSH':
        user_name, ssh_key = "", ""
        if isinstance(obj, dict):
            user_name = obj.get("UserName", "")
            ssh_key = obj.get("SSHKey", "")

        return SSH(user_name, ssh_key)

    def to_dict(self) -> dict:
        result: dict = {}
        result["UserName"] = self.user_name
        result["SSHKey"] = self.ssh_key
        return result

    def validate_attributes(self) -> str:
        emptyAttrs = []
        if not self.user_name:
            emptyAttrs.append("UserName")

        if not self.ssh_key:
            emptyAttrs.append("SSHKey")

        return "Invalid Credentials: " + ", ".join(
            emptyAttrs) + " is empty" if emptyAttrs else ""


class UserDefinedCredentials:
    ssh: SSH

    def __init__(self, ssh: SSH) -> None:
        self.ssh = ssh

    @staticmethod
    def from_dict(obj) -> 'UserDefinedCredentials':
        ssh = None
        if isinstance(obj, dict):
            ssh = SSH.from_dict(obj.get("SSH", None))
        return UserDefinedCredentials(ssh)

    def to_dict(self) -> dict:
        result: dict = {}
        result["SSH"] = self.ssh.to_dict()
        return result

class SSHConnector:
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
        self.ssh_client = None

    def __del__(self):
        self.close_ssh_connection()

    @staticmethod
    def from_dict(obj) -> 'SSHConnector':
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

        return SSHConnector(app_url, app_port, user_defined_credentials)

    def to_dict(self) -> dict:
        result: dict = {}
        result["AppURL"] = self.app_url
        result["AppPort"] = self.app_port
        result[
            "UserDefinedCredentials"] = self.user_defined_credentials.to_dict(
            )
        return result

    def validate(self) -> bool and str:
        # validate attributes
        error = self.user_defined_credentials.ssh.validate_attributes()
        if error:
            return False, error
        
        # validate credentials by running a simple command
        _, error, _ = self.exec_command("pwd")
        if error:
            return False, error
        return True, None
    
    @property
    def app_url_netloc(self):
        netloc = urllib.parse.urlparse(self.app_url).netloc
        # remove port from netloc if it exists
        netloc = netloc.split(":")[0]
        return netloc
    
    def get_current_datetime(self):
        current_time = datetime.utcnow()
        formatted_time = current_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        return formatted_time
    
    def establish_ssh_connection(self):
        # validate attributes
        error = self.user_defined_credentials.ssh.validate_attributes()
        if error:
            return error
        
        try:
            # establish connection only if ssh_client is not connected
            if not self.ssh_client or self.ssh_client.get_transport() is None:
                ssh_key_str = base64.b64decode(self.user_defined_credentials.ssh.ssh_key).decode('utf-8')
                ssh_key = paramiko.RSAKey.from_private_key(io.StringIO(ssh_key_str))

                ssh_client = paramiko.SSHClient()
                ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                if not self.app_port:
                    return "Port not specified"
                # Connect to the server using the private key
                ssh_client.connect(
                    hostname=self.app_url_netloc,
                    port=self.app_port,
                    username=self.user_defined_credentials.ssh.user_name,
                    pkey=ssh_key,
                    timeout=60
                )

                self.ssh_client = ssh_client
            return None
        except paramiko.ssh_exception.AuthenticationException:
            return "Invalid UserName or SSHKey"
        except UnicodeDecodeError:
            return "Invalid SSHKey"
        except paramiko.ssh_exception.SSHException:
            return "Invalid SSHKey"
        except paramiko.ssh_exception.NoValidConnectionsError:
            return "Invalid URL"
        except TimeoutError:
            return "Invalid URL"
        
    def close_ssh_connection(self):
        # check if ssh_client is valid, and connected
        if self.ssh_client and self.ssh_client.get_transport() is not None:
            self.ssh_client.close()

    def exec_command(self, command: str):
        error = self.establish_ssh_connection()
        if error:
            return None, error, -1
        
        _, stdout, stderr = self.ssh_client.exec_command(command, get_pty=True)

        # Read command output
        output = stdout.read().decode('utf-8')

        exit_status = stdout.channel.recv_exit_status()

        # check if exit status is not 0, which means execution failed
        error = None
        if not exit_status == 0:
            error = stderr.read().decode('utf-8')

        return output, error, exit_status

    def write_to_remote_file(self,remote_path, content):
        try:
            error = self.establish_ssh_connection()
            if error:
                return False, error

            sftp = self.ssh_client.open_sftp()
            with sftp.open(remote_path, 'w') as file:
                file.write(content)
            sftp.close()
            self.ssh_client.close()
            return True, None
        except paramiko.AuthenticationException as e:
            return False, f'Authentication failed: {e}'
        except paramiko.SSHException as e:
            return False, f'SSH error: {e}'
        except IOError as e:
            return False, f'IO error: {e}'

    def remove_remote_file(self,remote_path):
        try:
            error =self.establish_ssh_connection()
            if error:
                return False,error
            sftp = self.ssh_client.open_sftp()
            sftp.remove(remote_path)
            sftp.close()
            self.ssh_client.close()
            return True,None
        except paramiko.AuthenticationException as e:
            return False, f'Authentication failed: {e}'
        except paramiko.SSHException as e:
            return False, f'SSH error: {e}'
        except IOError as e:
            return False, f'IO error: {e}'
# INFO : You can implement methods (to access the application) which can be then invoked from your task code
