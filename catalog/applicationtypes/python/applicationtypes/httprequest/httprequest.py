from typing import Tuple, Any, Dict, Tuple, Optional, Union
import requests
import json
from time import sleep
import hashlib
import hmac
from urllib.parse import urljoin, urlparse, urlencode
import datetime
import base64
import re
import subprocess
import tempfile
import boto3
import botocore.exceptions
import jq
from compliancecowcards.utils import cowdictutils
import shlex
from http import HTTPMethod
import jwt
import celpy
import celpy.celtypes
import time
import random
from compliancecowcards.structs import cards

from botocore.awsrequest import AWSRequest
from botocore.auth import SigV4Auth
from botocore.credentials import Credentials, ReadOnlyCredentials
from botocore.exceptions import BotoCoreError, NoCredentialsError

logger = cards.Logger()


class OAuth:
    validation_curl: str
    client_id: str
    client_secret: str

    def __init__(
        self, validation_curl: str, client_id: str, client_secret: str
    ) -> None:
        self.validation_curl = validation_curl
        self.client_id = client_id
        self.client_secret = client_secret

    @staticmethod
    def from_dict(obj) -> "OAuth":
        validation_curl, client_id, client_secret = "", "", ""
        if isinstance(obj, dict):
            validation_curl = obj.get("ValidationCURL", "")
            client_id = obj.get("ClientID", "")
            client_secret = obj.get("ClientSecret", "")

        return OAuth(validation_curl, client_id, client_secret)

    def to_dict(self) -> dict:
        result: dict = {}
        result["ValidationCURL"] = self.validation_curl
        result["ClientID"] = self.client_id
        result["ClientSecret"] = self.client_secret
        return result


class CustomType:
    validation_curl: str
    credential_json: str

    def __init__(self, validation_curl: str, credential_json: str) -> None:
        self.validation_curl = validation_curl
        self.credential_json = credential_json

    @staticmethod
    def from_dict(obj) -> "CustomType":
        validation_curl, credential_json = "", ""
        if isinstance(obj, dict):
            validation_curl = obj.get("ValidationCURL", "")
            credential_json = obj.get("CredentialJson", "")

        return CustomType(validation_curl, credential_json)

    def to_dict(self) -> dict:
        result: dict = {}
        result["ValidationCURL"] = self.validation_curl
        result["CredentialJson"] = self.credential_json
        return result


class APIKey:
    validation_curl: str
    api_key: str

    def __init__(self, validation_curl: str, api_key: str) -> None:
        self.validation_curl = validation_curl
        self.api_key = api_key

    @staticmethod
    def from_dict(obj) -> "APIKey":
        validation_curl, api_key = "", ""
        if isinstance(obj, dict):
            validation_curl = obj.get("ValidationCURL", "")
            api_key = obj.get("APIKey", "")

        return APIKey(validation_curl, api_key)

    def to_dict(self) -> dict:
        result: dict = {}
        result["ValidationCURL"] = self.validation_curl
        result["APIKey"] = self.api_key
        return result


class NoAuth:

    def __init__(
        self,
    ) -> None:
        pass

    @staticmethod
    def from_dict(obj) -> "NoAuth":
        return NoAuth()

    def to_dict(self) -> dict:
        result: dict = {}

        return result


class JWTBearer:
    algorithm: str
    private_key: str
    payload: str
    validation_curl: str

    def __init__(
        self, algorithm: str, private_key: str, payload: str, validation_curl: str
    ) -> None:
        self.algorithm = algorithm
        self.private_key = private_key
        self.payload = payload
        self.validation_curl = validation_curl

    @staticmethod
    def from_dict(obj) -> "JWTBearer":
        algorithm, private_key, payload, validation_curl = "", "", "", ""
        if isinstance(obj, dict):
            algorithm = obj.get("Algorithm", "")
            private_key = obj.get("PrivateKey", "")
            payload = obj.get("Payload", "")
            validation_curl = obj.get("ValidationCURL", "")

        return JWTBearer(algorithm, private_key, payload, validation_curl)

    def to_dict(self) -> dict:
        result: dict = {}
        result["Algorithm"] = self.algorithm
        result["PrivateKey"] = self.private_key
        result["Payload"] = self.payload
        result["ValidationCURL"] = self.validation_curl
        return result


class AWSSignature:
    validation_curl: str
    access_key: str
    secret_key: str

    def __init__(self, validation_curl: str, access_key: str, secret_key: str) -> None:
        self.validation_curl = validation_curl
        self.access_key = access_key
        self.secret_key = secret_key

    @staticmethod
    def from_dict(obj) -> "AWSSignature":
        validation_curl, access_key, secret_key = "", "", ""
        if isinstance(obj, dict):
            validation_curl = obj.get("ValidationCURL", "")
            access_key = obj.get("AccessKey", "")
            secret_key = obj.get("SecretKey", "")

        return AWSSignature(validation_curl, access_key, secret_key)

    def to_dict(self) -> dict:
        result: dict = {}
        result["ValidationCURL"] = self.validation_curl
        result["AccessKey"] = self.access_key
        result["SecretKey"] = self.secret_key
        return result


class BearerToken:
    validation_curl: str
    token: str

    def __init__(self, validation_curl: str, token: str) -> None:
        self.validation_curl = validation_curl
        self.token = token

    @staticmethod
    def from_dict(obj) -> "BearerToken":
        validation_curl, token = "", ""
        if isinstance(obj, dict):
            validation_curl = obj.get("ValidationCURL", "")
            token = obj.get("Token", "")

        return BearerToken(validation_curl, token)

    def to_dict(self) -> dict:
        result: dict = {}
        result["ValidationCURL"] = self.validation_curl
        result["Token"] = self.token
        return result


class BasicAuthentication:
    validation_curl: str
    user_name: str
    password: str

    def __init__(self, validation_curl: str, user_name: str, password: str) -> None:
        self.validation_curl = validation_curl
        self.user_name = user_name
        self.password = password

    @staticmethod
    def from_dict(obj) -> "BasicAuthentication":
        validation_curl, user_name, password = "", "", ""
        if isinstance(obj, dict):
            validation_curl = obj.get("ValidationCURL", "")
            user_name = obj.get("UserName", "")
            password = obj.get("Password", "")

        return BasicAuthentication(validation_curl, user_name, password)

    def to_dict(self) -> dict:
        result: dict = {}
        result["ValidationCURL"] = self.validation_curl
        result["UserName"] = self.user_name
        result["Password"] = self.password
        return result

    def validate_attributes(self) -> str:
        emptyAttrs = []
        if not self.algorithm:
            emptyAttrs.append("Algorithm")

        if not self.private_key:
            emptyAttrs.append("PrivateKey")

        if not self.payload:
            emptyAttrs.append("Payload")

        if not self.validation_curl:
            emptyAttrs.append("ValidationCURL")

        if not self.access_key:
            emptyAttrs.append("AccessKey")

        if not self.secret_key:
            emptyAttrs.append("SecretKey")

        if not self.validation_curl:
            emptyAttrs.append("ValidationCURL")

        if not self.token:
            emptyAttrs.append("Token")

        if not self.validation_curl:
            emptyAttrs.append("ValidationCURL")

        if not self.user_name:
            emptyAttrs.append("UserName")

        if not self.password:
            emptyAttrs.append("Password")

        return (
            "Invalid Credentials: " + ", ".join(emptyAttrs) + " is empty"
            if emptyAttrs
            else ""
        )


class UserDefinedCredentials:
    o_auth: OAuth
    custom_type: CustomType
    api_key: APIKey
    no_auth: NoAuth
    jwt_bearer: JWTBearer
    aws_signature: AWSSignature
    bearer_token: BearerToken
    basic_authentication: BasicAuthentication

    def __init__(
        self,
        o_auth: OAuth,
        custom_type: CustomType,
        api_key: APIKey,
        no_auth: NoAuth,
        jwt_bearer: JWTBearer,
        aws_signature: AWSSignature,
        bearer_token: BearerToken,
        basic_authentication: BasicAuthentication,
    ) -> None:
        self.o_auth = o_auth
        self.custom_type = custom_type
        self.api_key = api_key
        self.no_auth = no_auth
        self.jwt_bearer = jwt_bearer
        self.aws_signature = aws_signature
        self.bearer_token = bearer_token
        self.basic_authentication = basic_authentication

    @staticmethod
    def from_dict(obj) -> "UserDefinedCredentials":
        (
            o_auth,
            custom_type,
            api_key,
            no_auth,
            jwt_bearer,
            aws_signature,
            bearer_token,
            basic_authentication,
        ) = (None, None, None, None, None, None, None, None)
        if isinstance(obj, dict):
            o_auth = OAuth.from_dict(obj.get("OAuth", None))
            custom_type = CustomType.from_dict(obj.get("CustomType", None))
            api_key = APIKey.from_dict(obj.get("APIKey", None))
            no_auth = NoAuth.from_dict(obj.get("NoAuth", None))
            jwt_bearer = JWTBearer.from_dict(obj.get("JWTBearer", None))
            aws_signature = AWSSignature.from_dict(obj.get("AWSSignature", None))
            bearer_token = BearerToken.from_dict(obj.get("BearerToken", None))
            basic_authentication = BasicAuthentication.from_dict(
                obj.get("BasicAuthentication", None)
            )
        return UserDefinedCredentials(
            o_auth,
            custom_type,
            api_key,
            no_auth,
            jwt_bearer,
            aws_signature,
            bearer_token,
            basic_authentication,
        )

    def to_dict(self) -> dict:
        result: dict = {}
        result["OAuth"] = self.o_auth.to_dict()
        result["CustomType"] = self.custom_type.to_dict()
        result["APIKey"] = self.api_key.to_dict()
        result["NoAuth"] = self.no_auth.to_dict()
        result["JWTBearer"] = self.jwt_bearer.to_dict()
        result["AWSSignature"] = self.aws_signature.to_dict()
        result["BearerToken"] = self.bearer_token.to_dict()
        result["BasicAuthentication"] = self.basic_authentication.to_dict()
        return result


class HttpRequest:
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
    def from_dict(obj) -> "HttpRequest":
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
                if "NoAuth" in user_defined_credentials_dict:
                    user_defined_credentials_dict = UserDefinedCredentials(
                        o_auth=None,
                        custom_type=None,
                        api_key=None,
                        no_auth=NoAuth(),
                        jwt_bearer=None,
                        aws_signature=None,
                        bearer_token=None,
                        basic_authentication=None,
                    )
            else:
                user_defined_credentials_dict = UserDefinedCredentials(
                    o_auth=None,
                    custom_type=None,
                    api_key=None,
                    no_auth=NoAuth(),
                    jwt_bearer=None,
                    aws_signature=None,
                    bearer_token=None,
                    basic_authentication=None,
                )

        return HttpRequest(app_url, app_port, user_defined_credentials)

    def to_dict(self) -> dict:
        result: dict = {}
        result["AppURL"] = self.app_url
        result["AppPort"] = self.app_port
        result["UserDefinedCredentials"] = self.user_defined_credentials.to_dict()

        return result

    def validate(self) -> bool and dict:

        if self.user_defined_credentials is None:
            return True, None

        creds_jwt_bearer = self.user_defined_credentials.jwt_bearer
        if all(
            (
                creds_jwt_bearer.algorithm,
                creds_jwt_bearer.payload,
                creds_jwt_bearer.private_key,
            )
        ):
            return self.validate_jwt_bearer()

        custom_type = self.user_defined_credentials.custom_type
        if custom_type.validation_curl:
            return self.validate_custom_type()

        creds_api_key = self.user_defined_credentials.api_key
        if creds_api_key.api_key:
            is_valid, error = self.validate_credentials_type(
                "APIKey", creds_api_key.validation_curl
            )
            if error:
                return False, error
            return self.validate_api_key()

        creds_aws_signature = self.user_defined_credentials.aws_signature
        if all((creds_aws_signature.access_key, creds_aws_signature.secret_key)):
            return self.validate_aws_signature()

        creds_bearer_token = self.user_defined_credentials.bearer_token
        if creds_bearer_token.token:
            is_valid, error = self.validate_credentials_type(
                "BearerToken", creds_bearer_token.validation_curl
            )
            if error:
                return False, error
            return self.validate_bearer_token()

        creds_basic_auth = self.user_defined_credentials.basic_authentication
        if all((creds_basic_auth.user_name, creds_basic_auth.password)):
            is_valid, error = self.validate_credentials_type(
                "BasicAuthentication", creds_basic_auth.validation_curl
            )
            if error:
                return False, error
            return self.validate_basic_auth()

        creds_o_auth = self.user_defined_credentials.o_auth
        if all((creds_o_auth.client_id, creds_o_auth.client_secret)):
            is_valid, error = self.validate_credentials_type(
                "OAuth", creds_o_auth.validation_curl
            )
            if error:
                return False, error
            return self.validate_o_auth()

        creds_no_auth = self.user_defined_credentials.no_auth
        if isinstance(creds_no_auth, object) and creds_no_auth != None:
            return True, None

        return False, "Invalid credential type"

    def validate_jwt_bearer(self):

        validation_curl = self.user_defined_credentials.jwt_bearer.validation_curl
        if validation_curl.strip() == "":
            return False, {"Error": "ValidationCURL cannot be empty."}

        payload = self.user_defined_credentials.jwt_bearer.payload
        private_key = self.user_defined_credentials.jwt_bearer.private_key
        algorithm = self.user_defined_credentials.jwt_bearer.algorithm

        token, error = self.generate_jwt_token(algorithm, private_key, payload)
        if error:
            return False, {"Error": error}

        validation_curl = validation_curl.replace("<<JWTBearer>>", token)

        return self.validate_curl(validation_curl)

    def validate_custom_type(self):

        validation_curl = self.user_defined_credentials.custom_type.validation_curl
        if validation_curl.strip() == "":
            return False, {"Error": "ValidationCURL cannot be empty."}
        credentials_json = {}

        if self.user_defined_credentials.custom_type.credential_json:
            credentials_json_bytes = base64.b64decode(
                self.user_defined_credentials.custom_type.credential_json
            ).decode("utf-8")
            try:
                credentials_json = json.loads(credentials_json_bytes)
            except json.JSONDecodeError as e:
                return False, {
                    "Error": 'Error while reading "CredentialJson" data, Invalid JSON data.'
                }

        parsed_curl, error = self.replace_placeholder(
            validation_curl, "CustomType", credentials_json
        )
        if error:
            return False, {"Error": "Error while processing place holders."}

        return self.validate_curl(parsed_curl)

    def validate_aws_signature(self):

        iam_session = self.create_aws_session_with_accesskey()
        try:
            iam_client = iam_session.client("iam")
            iam_client.get_account_authorization_details()
            return True, None
        except botocore.exceptions.ClientError as error:
            error_message = (
                "An error occurred while getting account authorization details."
            )
            if (
                error.response
                and isinstance(error.response, dict)
                and cowdictutils.is_valid_key(error.response, "Error")
                and cowdictutils.is_valid_key(error.response["Error"], "Message")
                and cowdictutils.is_valid_key(error.response["Error"], "Code")
            ):
                if error.response["Error"]["Code"] == "InvalidClientTokenId":
                    error_message = "Invalid AccessKey"
                elif error.response["Error"]["Code"] == "SignatureDoesNotMatch":
                    error_message = "Invalid SecretKey"
                else:
                    error_message = error.response["Error"]["Message"]
            return False, error_message

    def create_aws_session_with_accesskey(self, region=None):
        aws_signature = self.user_defined_credentials.aws_signature
        iam_session = boto3.Session(
            region_name=region,
            aws_access_key_id=aws_signature.access_key,
            aws_secret_access_key=aws_signature.secret_key,
        )
        return iam_session

    def validate_basic_auth(self):

        validation_curl = (
            self.user_defined_credentials.basic_authentication.validation_curl
        )
        if validation_curl.strip() == "":
            return False, {"Error": "ValidationCURL cannot be empty."}
        parsed_curl, error = self.replace_placeholder(
            validation_curl,
            "BasicAuthentication",
            self.user_defined_credentials.basic_authentication.to_dict(),
        )
        if error:
            return False, {"Error": "Error while processing place holders."}

        if "<<BasicAuthentication>>" in parsed_curl:
            headers, error = self.generate_basic_auth()
            if error:
                return False, "Invalid 'UserName' or 'Password'."

            parsed_curl = parsed_curl.replace(
                "<<BasicAuthentication>>", headers["Authorization"]
            )

        return self.validate_curl(parsed_curl)

    def validate_api_key(self):

        validation_curl = self.user_defined_credentials.api_key.validation_curl

        parsed_curl, error = self.replace_placeholder(
            validation_curl, "APIKey", self.user_defined_credentials.api_key.to_dict()
        )
        if error:
            return False, {"Error": "Error while processing place holders."}

        if "<<APIKey>>" in parsed_curl:
            headers, error = self.generate_api_key()
            if error:
                return False, {"Error": "Invalid 'Token'."}

            parsed_curl = parsed_curl.replace("<<APIKey>>", headers["Authorization"])

        return self.validate_curl(parsed_curl)

    def validate_bearer_token(self):

        validation_curl = self.user_defined_credentials.bearer_token.validation_curl
        if validation_curl.strip() == "":
            return False, {"Error": "ValidationCURL cannot be empty."}
        parsed_curl, error = self.replace_placeholder(
            validation_curl,
            "BearerToken",
            self.user_defined_credentials.bearer_token.to_dict(),
        )
        if error:
            return False, {"Error": "Error while processing place holders."}

        if "<<BearerToken>>" in parsed_curl:
            headers, error = self.generate_bearer_token()
            if error:
                return False, "Invalid 'Token'."

            parsed_curl = parsed_curl.replace(
                "<<BearerToken>>", headers["Authorization"]
            )

        return self.validate_curl(parsed_curl)

    def validate_o_auth(self):

        validation_curl = self.user_defined_credentials.o_auth.validation_curl
        if validation_curl.strip() == "":
            return False, {"Error": "ValidationCURL cannot be empty."}
        parsed_curl, error = self.replace_placeholder(
            validation_curl, "OAuth", self.user_defined_credentials.o_auth.to_dict()
        )
        if error:
            return False, {"Error": "Error while processing place holders."}

        return self.validate_curl(parsed_curl)

    def validate_credentials_type(self, credential_type, validation_curl):

        if not validation_curl.strip():
            return False, {"Error": "ValidationCURL cannot be empty."}

        #  CHECK-1 : If the curl has any placeholder with credential type
        if f"<<{credential_type}" in validation_curl:
            return True, None

        #  CHECK-2 : Using 'AppURL' and 'credential_type'create a curl template and compare with the one user given
        tokens = shlex.split(validation_curl)
        if credential_type == "BasicAuthentication":
            result, error = self.generate_basic_auth()
            if error:
                return False, "Error while generating 'BasicAuthentication'"
            for i, token in enumerate(tokens):
                token = self.handle_quotes_if_present(token)
                if token.lower() == "-h" or token.lower() == "--header":
                    if i + 1 <= len(tokens):
                        if "Basic" in tokens[i + 1]:
                            if result["Authorization"] in tokens[i + 1]:
                                return True, ""
                            return (
                                False,
                                "Credentials in ValidationCURL and Credential miss match",
                            )

        elif credential_type == "BearerToken":
            bearer_token = self.user_defined_credentials.bearer_token.token
            for i, token in enumerate(tokens):
                token = self.handle_quotes_if_present(token)
                if token.lower() == "-h" or token.lower() == "--header":
                    if "Bearer" in tokens[i + 1]:
                        if bearer_token in tokens[i + 1]:
                            return True, ""
                        return (
                            False,
                            "Token in ValidationCURL and Credential miss match",
                        )

        elif credential_type == "APIKey":
            apikey = self.user_defined_credentials.api_key.api_key
            for i, token in enumerate(tokens):
                token = self.handle_quotes_if_present(token)
                if token.lower() == "-h" or token.lower() == "--header":
                    if apikey in tokens[i + 1]:
                        return True, ""
                    return False, "APIKey in ValidationCURL and Credential miss match"

        elif credential_type == "OAuth":

            client_secret_pattern = r"(?i)\b(client[\W_]*secret|secret[\W_]*client)\b"
            client_id_pattern = r"(?i)\b(client[\W_]*id|id[\W_]*client)\b"

            client_secret = self.user_defined_credentials.o_auth.client_secret
            client_id = self.user_defined_credentials.o_auth.client_id

            body_data = None
            if "--data" in validation_curl:
                body_data = validation_curl.split("--data", 1)[1].strip()
            elif "-d" in validation_curl:
                body_data = validation_curl.split("-d", 1)[1].strip()
            elif "--form" in validation_curl:
                body_data = validation_curl.split("--form", 1)[1].strip()

            # Ensure the body data is properly extracted (handle quotes if present)
            body_data = self.handle_quotes_if_present(body_data)
            if not body_data:
                return (
                    False,
                    "ValidationCURL has no request body, OAuth expecte the 'url-encoded' request body.",
                )

            valid_client_secret = False
            valid_client_id = False

            miss_match_cred = []
            # Check for client secret and client id patterns in the body data
            if re.search(client_secret_pattern, body_data):
                client_secret_full_pattern = (
                    rf"{client_secret_pattern}\s*=\s*{re.escape(client_secret)}"
                )
                if re.search(client_secret_full_pattern, body_data):
                    valid_client_secret = True
                if not valid_client_secret:
                    miss_match_cred.append("ClientSecret")
            if re.search(client_id_pattern, body_data):
                client_id_full_pattern = (
                    rf"{client_id_pattern}\s*=\s*{re.escape(client_id)}"
                )
                if re.search(client_id_full_pattern, body_data):
                    valid_client_id = True
                if not valid_client_id:
                    miss_match_cred.append("ClientID")

            if miss_match_cred:
                return (
                    False,
                    f"{' and '.join(miss_match_cred)} miss match in ValidationCURL and Credential.",
                )
            if valid_client_id and valid_client_secret:
                return True, None

        return False, "ValidationCURL and CredentialType miss match"

    def handle_quotes_if_present(self, data):
        if data:
            if data.startswith(("'", '"')):
                data = data[1:]
            if data.endswith(("'", '"')):
                data = data[:-1]
        return data.strip()

    def validate_curl(self, parsed_curl):

        status_code, response_body, error = self.execute_curl(parsed_curl)
        if error:
            return False, {
                "Error": "CURL command failed. Please check the URL and parameters."
            }

        successful_statues = ["200", "201", "202", "204"]
        is_resp_valid = True if status_code in successful_statues else False
        if is_resp_valid:
            return True, None
        else:
            error_messages = {
                "400": "Bad Request - The server could not understand the request due to invalid syntax.",
                "401": "Unauthorized - Check the Authorization header or credentials.",
                "403": "Forbidden - You do not have the necessary permissions to access this resource.",
                "404": "Not Found - The requested resource could not be found.",
                "405": "Method Not Allowed - The request method is not supported for the requested resource.",
                "408": "Request Timeout - The server timed out waiting for the request.",
                "429": "Too Many Requests - You have sent too many requests in a given amount of time.",
                "500": "Internal Server Error - The server encountered an error and could not complete your request.",
                "502": "Bad Gateway - The server received an invalid response from the upstream server.",
                "503": "Service Unavailable - The server is not ready to handle the request.",
                "504": "Gateway Timeout - The server did not receive a timely response from the upstream server.",
            }
            error_message = error_messages.get(
                status_code,
                f"CURL command failed with HTTP status code {status_code}. {response_body}",
            )
            return False, {"Error": error_message}

    def execute_curl(
        self, curl_cmd: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Executes a curl command to retrieve the status code and body
        """

        curl_cmd = (
            curl_cmd.replace("\\", "")
            .replace("\n", " ")
            .replace("<<application.AppURL>>", self.app_url)
        )

        try:
            # Execute the curl command to get the status code
            result = subprocess.run(
                curl_cmd + ' -s -o /dev/null -w "%{http_code}"',  # Get the status code
                shell=True,  # Use shell to execute the command
                check=True,  # Raise an error on non-zero exit status
                stdout=subprocess.PIPE,  # Capture standard output
                stderr=subprocess.PIPE,  # Capture standard error
                text=True,  # Return output as string
            )

            # Get the status code from the output
            status_code = result.stdout.strip()

            # Create a temporary file to capture the body response
            with tempfile.NamedTemporaryFile() as temp_file:
                # Use -o to write the body response to the temporary file
                body_cmd = curl_cmd + f" -s -o {temp_file.name}"
                subprocess.run(body_cmd, shell=True, check=True)

                # Read the body response from the temporary file
                temp_file.seek(0)  # Ensure we're at the beginning of the file
                response_body = temp_file.read()

            return status_code, response_body, None

        except subprocess.CalledProcessError as e:
            # Return error message if the curl command fails
            return None, None, f"An error occurred: {e.stderr}"

    def make_api_call(self, request_data: Dict[str, Any]) -> Tuple[Any, Optional[str]]:
        # Extract the data from request_info
        url = request_data["URL"]
        method = request_data["Method"].upper()
        headers = request_data.get("Headers", {})
        params = request_data.get("Params", {})
        body_info = request_data.get("Body", {})
        content_type = request_data["ContentType"]
        timeout = request_data.get("TimeOut", 30)  # Default timeout is 30 seconds
        retries = request_data.get("Retries", 3)  # Default retries is 3
        verify = request_data.get("Verify", True)
        retry_on_status = request_data.get("RetryOnStatus", [])
        allow_redirects = request_data.get("Redirect", False)
        body = None
        if request_data["Method"] != HTTPMethod.GET:
            if content_type == "application/x-www-form-urlencoded":
                body = urlencode(body_info)
            else:
                body = body_info
        files = request_data.get("Files", None)

        # Attempt to send the request with retries
        response, error = self.send_request_with_retries(
            method,
            url,
            headers,
            params,
            body,
            timeout,
            retries,
            verify,
            retry_on_status,
            allow_redirects,
            files,
        )

        successful_statues = [200, 201, 202, 204]

        if error and not response:
            return None, error
        elif error and response.status_code in successful_statues:
            return response, error

        if response.status_code in successful_statues:
            return response, None

        error_messages = {
            400: "Bad Request - The server could not understand the request due to invalid syntax.",
            401: "Unauthorized - Check the Authorization header or credentials.",
            403: "Forbidden - You do not have the necessary permissions to access this resource.",
            404: "Not Found - The requested resource could not be found.",
            405: "Method Not Allowed - The request method is not supported for the requested resource.",
            408: "Request Timeout - The server timed out waiting for the request.",
            429: "Too Many Requests - You have sent too many requests in a given amount of time.",
            500: "Internal Server Error - The server encountered an error and could not complete your request.",
            502: "Bad Gateway - The server received an invalid response from the upstream server.",
            503: "Service Unavailable - The server is not ready to handle the request.",
            504: "Gateway Timeout - The server did not receive a timely response from the upstream server.",
        }
        error_message = error_messages.get(response.status_code, response.text)

        return None, error_message

    def parse_content(
        self, content: Union[str, dict]
    ) -> Tuple[Optional[Dict], Optional[str]]:
        if isinstance(content, str):
            if content == "":
                return {}, None
            try:
                # If content is a string, parse it as JSON
                return json.loads(content), None
            except json.JSONDecodeError:
                return None, "Invalid JSON string provided."
        elif isinstance(content, dict):
            return content, None
        else:
            return None, "Content must be either a string or a dictionary."

    def send_request_with_retries(
        self,
        method: str,
        url: str,
        headers: Dict[str, Any],
        params: Dict[str, Any],
        body: Any,
        timeout: int,
        retries: Any,
        verify: bool,
        retry_on_status: list,
        allow_redirects: bool,
        files: Any,
    ) -> Tuple[Any, Optional[str]]:
        """Send the API request and retry if needed based on status codes."""
        error = ""
        attempt = 0
        max_retries = 0
        delay = 0
        condition_field = ""
        condition_value = ""
        base_delay = 2
        retry_max_delay = 60

        response = {}

        if retries and isinstance(retries, int):
            max_retries = retries
        elif retries and isinstance(retries, dict):
            max_retries = retries.get("RetryOnCondition", {}).get("MaxRetries", 3)
            condition_field = retries.get("RetryOnCondition", {}).get(
                "ConditionField", ""
            )
            base_delay = retries.get("RetryOnCondition", {}).get(
                "RetryBaseDelay", 2
            )  # Use RetryBaseDelay for delay base
            retry_max_delay = retries.get("RetryOnCondition", {}).get(
                "RetryMaxDelay", 60
            )

        while (attempt < max_retries) or (max_retries == 0 and attempt == 0):
            try:

                response = self.send_request(
                    method,
                    url,
                    headers,
                    params,
                    body,
                    timeout,
                    allow_redirects,
                    files,
                    verify,
                )
                if isinstance(retries, int):
                    if (response.status_code in retry_on_status) or (
                        response.status_code in [502, 504, 429]
                    ):
                        print(
                            f"Received status {response.status_code}. Retrying... ({attempt + 1}/{max_retries})"
                        )
                        attempt += 1
                        if delay == 0:
                            delay = self.wait_random_exponential_custom(
                                attempt,
                                exp_base=base_delay,
                                max_delay=retry_max_delay,
                            )
                        sleep(delay)  # Delay before retry
                    else:
                        return response, None

                elif isinstance(retries, dict) and (
                    "<<" in condition_field and ">>" in condition_field
                ):
                    condition_value = retries.get("RetryOnCondition", {}).get(
                        "ConditionValue", ""
                    )
                    delay = retries.get("RetryOnCondition", {}).get("TimeInterval", 0)
                    modified_condition_field = (
                        condition_field.replace("responsebody", ".body")
                        .replace("response", "")
                        .replace("<<", "")
                        .replace(">>", "")
                    )

                    response_dict = {
                        "body": {},
                        "status_code": response.status_code,
                        "headers": dict(response.headers),
                        "cookies": dict(response.cookies),
                        "url": response.url,
                    }

                    content_type = response.headers.get("Content-Type", "")

                    if (
                        "application/json" in content_type
                        or "application/ld+json" in content_type
                    ):
                        response_dict["body"] = response.json()
                    elif ".body" in modified_condition_field:
                        return (
                            None,
                            f"Expected 'application/json' or 'application/ld+json' for .body access, but received: '{content_type}'.",
                        )

                    try:
                        if not modified_condition_field:
                            modified_condition_field = "."
                        condition_field_response = (
                            jq.compile(modified_condition_field)
                            .input(response_dict)
                            .first()
                        )
                    except ValueError as e:
                        return (
                            None,
                            f"Error while parsing the condition field: {str(e)}",
                        )

                    if str(condition_field_response) in condition_value.split("|") or (
                        response.status_code in [502, 504, 429]
                    ):
                        fallback_delay = self.wait_random_exponential_custom(
                            attempt, exp_base=base_delay, max_delay=retry_max_delay
                        )
                        if isinstance(delay, int) and delay > 0:
                            pass
                        elif not isinstance(delay, int):
                            header_key = delay.replace(
                                "<<response.headers.", ""
                            ).replace(">>", "")
                            retry_after = response.headers.get(header_key)
                            logger.log_data(
                                {
                                    f"Received status {response.status_code}, Retry After: ": retry_after
                                }
                            )

                            if retry_after:
                                try:
                                    delay = int(retry_after)
                                except ValueError:
                                    try:
                                        delay = max(
                                            0,
                                            int(float(retry_after)) - int(time.time()),
                                        )
                                    except ValueError:
                                        delay = fallback_delay
                            else:
                                delay = fallback_delay
                                logger.log_data(
                                    {
                                        f"Received status {response.status_code}, Delay after increasing: ": delay
                                    }
                                )
                        else:
                            delay = fallback_delay

                        print(
                            f"Received status {response.status_code}. Retrying... ({attempt + 1}/{max_retries}) after {delay}s"
                        )
                        logger.log_data(
                            {
                                f"Retrying on status {response.status_code} (attempt {attempt + 1})": f"Delay: {delay}s"
                            }
                        )

                        attempt += 1
                        delay = fallback_delay
                        sleep(delay)
                    else:
                        return response, None  # Return successful or non-retry status
                else:
                    return response, None

            except requests.exceptions.RequestException as e:
                print(
                    f"Request failed: {str(e)}. Retrying... ({attempt + 1}/{retries})"
                )
                error = f"Request failed: {str(e)}."
                attempt += 1
                if attempt < max_retries:
                    delay = self.wait_random_exponential_custom(
                        attempt, exp_base=base_delay, max_delay=retry_max_delay
                    )
                    sleep(delay)  # Delay before retry
                logger.log_data(
                    {
                        f"Request failed": f"{str(e)}. Retrying... ({attempt + 1}/{retries}) after {delay}"
                    }
                )

        if attempt == max_retries and isinstance(retries, dict):
            error = f"MaxRetries limit reached. The maximum limit of {max_retries} retries has been reached based on '{condition_field}' with value '{condition_value}'. The last received response has been returned."

        return response, error

    def wait_random_exponential_custom(
        self, attempt: int, exp_base: int, max_delay: int
    ) -> float:
        """Calculate the delay based on exponential backoff with jitter."""
        base_delay = exp_base**attempt
        delay = random.uniform(0, min(base_delay, max_delay))
        return delay

    def send_request(
        self,
        method: str,
        base_url: str,
        headers: Optional[Dict],
        params: Optional[Dict],
        body: Optional[Any],
        timeout: Optional[Any],
        allow_redirects: bool,
        files: Optional[Dict],
        verify: Any,
    ) -> Any:
        """Send the actual HTTP request based on the method."""
        return requests.request(
            method=method,
            url=base_url,
            headers=headers,
            params=params,
            data=body,
            files=files,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=verify,
        )

    def generate_aws_iam_signature(
        self,
        region,
        service,
        method,
        url,
        params=None,
        body=None,
        headers=None
        ):
        access_key = self.user_defined_credentials.aws_signature.access_key
        secret_key = self.user_defined_credentials.aws_signature.secret_key

        try:
            if params:
                if not isinstance(params, dict):
                    raise TypeError("params must be a dictionary")
                url = f"{url}?{urlencode(params, doseq=True)}"

            if body and not isinstance(body, (str, bytes)):
                raise TypeError("body must be str or bytes")

            body_bytes = body.encode("utf-8") if isinstance(body, str) else (body or b"")

            content_hash = hashlib.sha256(body_bytes).hexdigest()

            headers = headers.copy() if headers else {}
            headers["X-Amz-Content-Sha256"] = content_hash

            request = AWSRequest(
                method=method.upper(),
                url=url,
                data=body_bytes,
                headers=headers
            )

            if not access_key or not secret_key:
                raise NoCredentialsError()

            credentials = Credentials(access_key, secret_key)
            SigV4Auth(credentials, service, region).add_auth(request)

            return dict(request.headers), None

        except (BotoCoreError, NoCredentialsError, TypeError) as e:
            return None, str(e)

    def generate_jwt_token(
        self, algorithm: str, private_key: str, payload_str: str
    ) -> Tuple[str, str]:
        """
        Generates a JWT token using a specified algorithm, private key, and payload.
        """

        try:
            updated_payload, error = self.replace_function_placeholders(
                str(payload_str)
            )
            if error:
                return "", error
            payload = {}
            try:
                payload = json.loads(updated_payload)
            except json.JSONDecodeError as e:
                return "", 'Error while reading "Payload" data, Invalid JSON data.'

            private_key_decode = base64.b64decode(private_key).decode("utf-8")
            token = jwt.encode(payload, private_key_decode, algorithm=algorithm)
            return token, ""
        except Exception as e:
            return "", f"Error generating JWT: {e}"

    def generate_jwt_bearer(self) -> Tuple[Optional[Union[dict, str]], Optional[str]]:

        validation_curl = self.user_defined_credentials.jwt_bearer.validation_curl

        payload = self.user_defined_credentials.jwt_bearer.payload
        private_key = self.user_defined_credentials.jwt_bearer.private_key
        algorithm = self.user_defined_credentials.jwt_bearer.algorithm

        token, error = self.generate_jwt_token(algorithm, private_key, payload)
        if error:
            return False, {"Error": error}

        validation_curl = validation_curl.replace("<<JWTBearer>>", token)

        status_code, response_body, error = self.execute_curl(validation_curl)
        if error:
            return None, "Error while generating authorization."
        successful_statues = ["200", "201", "202", "204"]
        is_resp_valid = True if status_code in successful_statues else False
        if is_resp_valid:
            return response_body, None
        else:
            return (
                None,
                f"CURL command failed with HTTP status code {status_code}. {response_body}",
            )

    def generate_basic_auth(self) -> Tuple[dict, str]:
        """
        Generates a Basic authentication token using the provided username and password.
        """

        user_name = self.user_defined_credentials.basic_authentication.user_name
        password = self.user_defined_credentials.basic_authentication.password

        if user_name == "" or password == "":
            return "", "user_name or password is empty in application."

        credentials = f"{user_name}:{password}"
        token = base64.b64encode(credentials.encode()).decode("utf-8")
        return {"Authorization": f"Basic {token}"}, None

    def generate_api_key(self) -> Tuple[dict, str]:
        """
        Generates an API key for authorization purposes.
        """

        if self.user_defined_credentials.api_key.api_key == "":
            return "", "Error while getting api key."
        return {
            "Authorization": f"{self.user_defined_credentials.api_key.api_key}"
        }, None

    def generate_bearer_token(self):
        """
        Generates a bearer token for authorization using user-defined credentials.
        """

        if self.user_defined_credentials.bearer_token.token == "":
            return "", "Error while getting bearer token."
        return {
            "Authorization": f"Bearer {self.user_defined_credentials.bearer_token.token}"
        }, None

    def generate_o_auth(self) -> Tuple[Optional[Union[str, dict]], Optional[str]]:
        """
        Generates an OAuth token by executing a cURL command and handling potential errors.
        """

        validation_curl = self.user_defined_credentials.o_auth.validation_curl

        parsed_curl, error = self.replace_placeholder(
            validation_curl, "OAuth", self.user_defined_credentials.o_auth.to_dict()
        )
        if error:
            return None, "Error while processing place holders."

        status_code, response_body, error = self.execute_curl(parsed_curl)
        if error:
            return None, "Error while generating authorization."
        successful_statues = ["200", "201", "202", "204"]
        is_resp_valid = True if status_code in successful_statues else False
        if is_resp_valid:
            return response_body, None
        else:
            return (
                None,
                f"CURL command failed with HTTP status code {status_code}. {response_body}",
            )

    def generate_custom_type(self) -> Tuple[Optional[Union[str, dict]], Optional[str]]:
        """
        Generates a custom type based on user-defined credentials and returns the response
        body or an error message.
        """

        validation_curl = self.user_defined_credentials.custom_type.validation_curl

        credentials_json = {}
        if self.user_defined_credentials.custom_type.credential_json:
            credentials_json, error = self.get_credential_json_data()
            if error:
                return None, error
        parsed_curl, error = self.replace_placeholder(
            validation_curl, "CustomType", credentials_json
        )
        if error:
            return None, "Error while processing place holders."

        status_code, response_body, error = self.execute_curl(parsed_curl)
        if error:
            return None, "Error while generating authorization."
        successful_statues = ["200", "201", "202", "204"]
        is_resp_valid = True if status_code in successful_statues else False
        if is_resp_valid:
            return response_body, None
        else:
            return (
                None,
                f"CURL command failed with HTTP status code {status_code}. {response_body}",
            )

    def get_credential_json_data(self) -> Tuple[Optional[Dict], Optional[str]]:
        """
        Decodes and loads JSON data from a base64 encoded string.
        """
        credentials_json = {}
        if self.user_defined_credentials.custom_type.credential_json:
            credentials_json_bytes = base64.b64decode(
                self.user_defined_credentials.custom_type.credential_json
            ).decode("utf-8")
            try:
                credentials_json = json.loads(credentials_json_bytes)
            except json.JSONDecodeError as e:
                return (
                    None,
                    'Error while reading "CredentialJson" data, Invalid JSON data.',
                )
        return credentials_json, None

    def extract_service_and_region_from_arn(self, role_arn):

        arn_parts = role_arn.split(":")

        if len(arn_parts) < 6:
            return None, "Invalid ARN format"

        service = arn_parts[2]  # The service name is always the 3rd part in an ARN

        region = None
        if service != "iam" and service != "sts":
            # For services like S3, EC2, etc., the region is part of the ARN
            # The 4th part of the ARN may contain region info if applicable
            region = arn_parts[3] if arn_parts[3] else None

        return {"service": service, "region": region}, None

    def replace_empty_dicts_with_none(self, json_obj):
        if isinstance(json_obj, dict):
            for key, value in json_obj.items():
                if isinstance(value, dict):
                    if not value:
                        json_obj[key] = None
                    else:
                        self.replace_empty_dicts_with_none(value)
                elif isinstance(value, list):
                    for item in value:
                        self.replace_empty_dicts_with_none(item)
        elif isinstance(json_obj, list):
            for item in json_obj:
                self.replace_empty_dicts_with_none(item)
        return json_obj

    def replace_placeholder(
        self, target_str: str, placeholder_prefix: str, value_dict: dict
    ) -> Tuple[str, Optional[Dict]]:
        """
        Replaces placeholders in the target string with values from the provided dictionary.
        """
        pattern = f"<<{placeholder_prefix}([^>]+)>>"
        matches = re.findall(pattern, target_str)

        if not matches:
            return target_str, None

        for placeholder_key in matches:
            query = placeholder_key.strip()
            if not query.startswith("."):
                query = f".{placeholder_key.strip()}"
            parsed_value = self.jq_filter_query(query, value_dict)
            if parsed_value is not None:
                target_str = target_str.replace(
                    f"<<{placeholder_prefix}{placeholder_key}>>",
                    str(parsed_value).strip(),
                )
            else:
                file_type = placeholder_prefix[:-1]
                if file_type == "inputfile":
                    file_type = "InputFile"
                else:
                    file_type = "AppInfo"

                return "", {
                    "Error": f"Cannot resolve query '{placeholder_prefix}{placeholder_key}'. {file_type} has no field {placeholder_key}."
                }

        return target_str, None

    def evaluate_cel_expression(
        self, expression: str, context: dict = {}
    ) -> Tuple[celpy.celtypes.Value, str]:
        try:
            cel_env = celpy.Environment()
            cel_ast = cel_env.compile(expression.replace("<<", "").replace(">>", ""))
            result = cel_env.program(cel_ast).evaluate(celpy.json_to_cel(context))

            return result, ""
        except (celpy.CELParseError, celpy.CELEvalError) as e:
            return None, str(e)

    def replace_function_placeholders(self, string: str) -> Tuple[str, str]:
        """
        Replaces placeholders in the form of {{FUNCTION_NAME}} with their corresponding
        values. It currently supports 'CURRENT_TIME' and 'CURRENT_DATE'.
        """
        functions = {
            "CURRENT_TIME": int(time.time()),
            "CURRENT_DATE": datetime.datetime.now().isoformat(),
        }

        updated_value = string
        placeholder_matches = re.findall("<<(.*?)>>", updated_value)
        for match in placeholder_matches:
            try:
                result, error = self.evaluate_cel_expression(match, functions)
                if error:
                    return (
                        "",
                        f"An error occurred while replacing '<<{match}>>' :: {error}",
                    )
                updated_value = updated_value.replace(f"<<{match}>>", str(result))
            except Exception as e:
                return updated_value, f"Error: {e}"

        return updated_value, ""

    def extract_value(self, query, json_data):
        if query.startswith("<<") and query.endswith(">>"):
            clean_query = query[2:-2]
            keys = clean_query.split(".")

            try:
                current_data = json_data

                for key in keys:
                    if key == "":
                        continue
                    if isinstance(current_data, dict):
                        if "[" in key and "]" in key:
                            key_name, index = key.split("[")
                            index = index[:-1]

                            if index == "x":
                                temp_results = []
                                for sub_item in current_data[key_name]:
                                    sub_query = ".".join(keys[keys.index(key) + 1 :])
                                    result, err = self.extract_value(
                                        f"<<{sub_query}>>", sub_item
                                    )
                                    if err:
                                        return None, err
                                    temp_results.append(result)
                                return temp_results, None
                            else:
                                index = int(index)
                                current_data = current_data[key_name][index]
                        else:
                            current_data = current_data[key]
                    else:
                        return (
                            None,
                            f"Expected dict but got {type(current_data).__name__}",
                        )

                return current_data, None
            except (KeyError, IndexError, TypeError) as e:
                return None, f"Error: {e} - Invalid query or JSON structure"
        else:
            return query, None

    def validate_credetials_type(self, task_credential_type):

        custom_type = self.user_defined_credentials.custom_type
        creds_aws_signature = self.user_defined_credentials.aws_signature
        creds_bearer_token = self.user_defined_credentials.bearer_token
        creds_basic_auth = self.user_defined_credentials.basic_authentication
        creds_o_auth = self.user_defined_credentials.o_auth
        creds_api_key = self.user_defined_credentials.api_key
        creds_jwt_bearer = self.user_defined_credentials.jwt_bearer

        if custom_type.validation_curl and "CustomType" == task_credential_type:
            return True
        elif (
            all((creds_aws_signature.access_key, creds_aws_signature.secret_key))
            and "AWSSignature" == task_credential_type
        ):
            return True
        elif creds_bearer_token.token and "BearerToken" == task_credential_type:
            return True
        elif (
            all((creds_basic_auth.user_name, creds_basic_auth.password))
            and "BasicAuthentication" == task_credential_type
        ):
            return True
        elif (
            all((creds_o_auth.client_id, creds_o_auth.client_secret))
            and "OAuth" == task_credential_type
        ):
            return True
        elif creds_api_key.api_key and "APIKey" == task_credential_type:
            return True
        elif "NoAuth" == task_credential_type:
            return True
        elif (
            creds_jwt_bearer.algorithm
            and creds_jwt_bearer.payload
            and creds_jwt_bearer.private_key
            and "JWTBearer" == task_credential_type
        ):
            return True
        else:
            return False

    def jq_filter_query(self, query: str, value_dict: Optional[Dict]) -> Optional[Any]:

        query = query + ' // "Query not found"'
        parsed_values = ["Query not found"]
        # Run the jq query
        if value_dict:
            parsed_values = jq.compile(query).input(value_dict).all()

        # Check the result
        if parsed_values and len(parsed_values) == 1:
            if parsed_values[0] == "Query not found":
                return ""
            else:
                return parsed_values[0]
        else:
            return parsed_values


# INFO : You can implement methods (to access the application) which can be then invoked from your task code
