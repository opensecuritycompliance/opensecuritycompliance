# from sys import exception
import base64
import time
import re
import json
import requests
from urllib.parse import urlencode
import json
import pandas as pd
import numpy as np
import datetime
from datetime import timezone
from http import HTTPStatus 
from datetime import datetime
from compliancecowcards.utils import cowdictutils
import logging
from requests.exceptions import RequestException
import base64

SUPPORT_MSG = "Please contact support and review logs for further details"
USER_REG_ERR_MSG = "Failed to fetch user registration details"
ROLE_ASSIG_ERR_MSG = "Failed to fetch role assignment details"
ROLE_ERR_MSG = "Failed to fetch role details"
GRP_ERR_MSG = "Failed to fetch user group details"

class Azure:
    client_secret: str
    tenant_id: str
    subscription_id: str
    client_id: str

    def __init__(
        self, client_secret: str, tenant_id: str, subscription_id: str, client_id: str
    ) -> None:
        self.client_secret = client_secret
        self.tenant_id = tenant_id
        self.subscription_id = subscription_id
        self.client_id = client_id

    @staticmethod
    def from_dict(obj) -> "Azure":
        client_secret, tenant_id, subscription_id, client_id = "", "", "", ""
        if isinstance(obj, dict):
            client_secret = obj.get("clientSecret", "")
            tenant_id = obj.get("tenantID", "")
            subscription_id = obj.get("subscriptionID", "")
            client_id = obj.get("clientID", "")

        return Azure(client_secret, tenant_id, subscription_id, client_id)

    def to_dict(self) -> dict:
        result: dict = {}
        result["clientSecret"] = self.client_secret
        result["tenantID"] = self.tenant_id
        result["subscriptionID"] = self.subscription_id
        result["clientID"] = self.client_id
        return result


class UserDefinedCredentials:
    azure: Azure

    def __init__(self, azure: Azure) -> None:
        self.azure = azure

    @staticmethod
    def from_dict(obj) -> "UserDefinedCredentials":
        azure = None
        if isinstance(obj, dict):
            azure = Azure.from_dict(obj.get("Azure", None))
        return UserDefinedCredentials(azure)

    def to_dict(self) -> dict:
        result: dict = {}
        result["Azure"] = self.azure.to_dict()
        return result


class AzureAppConnector:
    app_url: str
    app_port: int
    user_defined_credentials: UserDefinedCredentials
    management_api_scope = "https://management.azure.com"
    graph_api_scope = "https://graph.microsoft.com"
    loganalytics_api_scope = "https://api.loganalytics.io"
    domain_name = ''

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
    def from_dict(obj) -> "AzureAppConnector":
        app_url, app_port, user_defined_credentials = "", "", None
        if isinstance(obj, dict):
            app_url = obj.get("AppURL", "")
            if not app_url:
                app_url = obj.get("appURL", "")
            app_port = obj.get("AppPort", 0)
            if not app_port:
                app_port = obj.get("appPort", 0)
            user_defined_credentials_dict = obj.get(
                "UserDefinedCredentials", None)
            if user_defined_credentials_dict is None:
                user_defined_credentials_dict = obj.get(
                    "userDefinedCredentials", None)
            if bool(user_defined_credentials_dict):
                user_defined_credentials = UserDefinedCredentials.from_dict(
                    user_defined_credentials_dict
                )

        return AzureAppConnector(app_url, app_port, user_defined_credentials)

    def to_dict(self) -> dict:
        result: dict = {}
        result["AppURL"] = self.app_url
        result["AppPort"] = self.app_port
        result["UserDefinedCredentials"] = self.user_defined_credentials.to_dict()
        return result

    def validate(self) -> bool and dict:
        err = self.validate_azure_credentials()
        if err is not None:
            return False, err
        return True, None

    def get_api_response(self, azure_api_vo):
        if azure_api_vo.get("method", "") == "":
            return None, {"error": "method is missing"}

        if azure_api_vo.get("url", "") == "":
            return None, {"error": "url is missing"}

        if azure_api_vo.get("access_token", "") == "":
            return None, {"error": "method is missing"}

        response = None

        if azure_api_vo["method"] == "POST":
            if azure_api_vo.get("body", "") == "":
                return None, {"error": "body is missing"}

            data = json.dumps(azure_api_vo["body"])
            headers = {
                "Content-Type": "application/json",
                "Authorization": azure_api_vo["access_token"],
            }
            response = requests.post(
                azure_api_vo["url"], headers=headers, json=data)

        else:
            headers = {
                "Content-Type": "application/json",
                "Authorization": azure_api_vo["access_token"],
            }

            response = requests.get(azure_api_vo["url"], headers=headers)

        resBody = response.json()
        if response.status_code == 200 or response.status_code == 201:
            return resBody, None
        else:
            errNew = resBody.get("error")
            if not  errNew:
                errNew = resBody
            return None, errNew

    def get_azure_access_token(self, azure_api_vo):
        access_token = ""
        url = (
            f"https://login.microsoftonline.com/{azure_api_vo['tenantID']}/oauth2/token"
        )
        form = {
            "grant_type": "client_credentials",
            "client_id": azure_api_vo["clientID"],
            "client_secret": azure_api_vo["clientSecret"],
            "resource": azure_api_vo["scope"],
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = requests.post(url, data=urlencode(form), headers=headers)
        if response.status_code == 200:
            credential = json.loads(response.text)
            access_token = "Bearer " + credential["access_token"]
            return access_token, None
        else:
            return None, response.text

    def get_azure_credentials(self):
        creds = []
        if self.user_defined_credentials is None:
            return ValueError("UserInputs is empty")
        if self.user_defined_credentials.azure is None:
            return ValueError("couldn't find azure in user defined credentials")
        client_id = self.user_defined_credentials.azure.client_id
        if not client_id:
            creds.append("clientID is empty")
        client_secret = self.user_defined_credentials.azure.client_secret
        if not client_secret:
            creds.append("clientSecret is empty")
        tenant_id = self.user_defined_credentials.azure.tenant_id
        if not tenant_id:
            creds.append("tenantID is empty")
        subscription_id = self.user_defined_credentials.azure.subscription_id
        if not subscription_id:
            creds.append("subscriptionID is empty")

        if len(creds) > 0:
            return "", "", "", "", ValueError(", ".join(creds))

        return client_id, client_secret, tenant_id, subscription_id, None

    def get_access_token(self, scope='https://management.azure.com/.default'):
        try:
            token_url = f"https://login.microsoftonline.com/{self.user_defined_credentials.azure.tenant_id}/oauth2/v2.0/token"
            token_data = {
                'grant_type': 'client_credentials',
                'client_id': self.user_defined_credentials.azure.client_id,
                'client_secret': self.user_defined_credentials.azure.client_secret,
                'scope': scope
            }
            token_r = requests.post(token_url, data=token_data)
            if token_r.status_code == 200:
                token = token_r.json().get('access_token')
                return token, None
            elif "unauthorized_client" in token_r.text:
                return None, " Invalid ClientID"
            elif "invalid_client" in token_r.text:
                return None, " Invalid ClientSecret"
            elif "invalid_request" in token_r.text:
                return None, " Invalid TenantID"
            else:
                return None, f"Failed to get access token.status code: {token_r.status_code}"
        except Exception as e:
            return None, format(e)

    def validate_azure_credentials(self):
        _, _, _, _, err = self.get_azure_credentials()
        if err:
            return f"Error in getting azure credentials.{err}"
        token, err = self.get_access_token()

        if err:
            return f"Error in creating access token.{err}"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        try:
            subscription_id = self.user_defined_credentials.azure.subscription_id
            resource_groups_url = f"https://management.azure.com/subscriptions/{subscription_id}/resourcegroups?api-version=2021-04-01"
            resource_groups_r = requests.get(
                resource_groups_url, headers=headers)
            if resource_groups_r.status_code == 200:
                return None
            elif "InvalidSubscriptionId" in str(resource_groups_r.text):
                return "Invalid SubscriptionId"
            else:
                return f"Failed to validate Azure credentials. Status code: {resource_groups_r.status_code}"
        except Exception as e:
            return f"Error occurred while validating Azure credentials: {format(e)}"

    def get_azure_container_registries_data(self):
        token, err = self.get_access_token()
        if err:
            return f"Error in creating access token.{err}"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'}
        registries_url = f"https://management.azure.com/subscriptions/{self.user_defined_credentials.azure.subscription_id}/providers/Microsoft.ContainerRegistry/registries?api-version=2019-05-01"
        registries_data = []
        retries = 3
        backoff = 1

        while retries > 0:
            try:
                registries_r = requests.get(
                    registries_url, headers=headers)
                if registries_r.status_code != 200:
                    return None, f"Failed to get container registries data.status code: {registries_r.status_code}"
                registries_json = registries_r.json()
                value = registries_json.get('value')
                if value is None:
                    return None, "value is missing in container registries response"
                registries_data.extend(value)
                registries_url = registries_json.get('nextLink')
                if not registries_url:
                    break
            except requests.exceptions.RequestException as e:
                retries -= 1
                if retries == 0:
                    return None, f"Failed to fetch container registries data after multiple retries.{format(e)}"
                time.sleep(backoff)
                backoff *= 2
        return registries_data, None
        
    def get_repository_list_using_registry(self, registry_name):
        try:
            repo_list_url = f"https://{registry_name}.azurecr.io/acr/v1/_catalog"

            client_id = self.user_defined_credentials.azure.client_id
            client_secret = self.user_defined_credentials.azure.client_secret

            basic_auth_value = f"{client_id}:{client_secret}"
            encoded_basic_auth = base64.b64encode(basic_auth_value.encode('utf-8')).decode('utf-8')
            headers = {
                'Authorization': f'Basic {encoded_basic_auth}'
            }
            
            repo_response = requests.get(repo_list_url, headers=headers)
            repo_response.raise_for_status()
            
            repositories = repo_response.json().get('repositories')
            if repositories is not None:
                return repositories, None
            else:
                return None, f"Failed to retrieve repositories from registry '{registry_name}'. The field 'repositories' was not found in the response."

        except requests.exceptions.HTTPError as http_err:
            return None, f"HTTP error occurred while fetching repositories from registry '{registry_name}': {http_err}"
        except requests.exceptions.ConnectionError as conn_err:
            return None, f"Connection error occurred while fetching repositories from registry '{registry_name}': {conn_err}"
        except requests.exceptions.Timeout as timeout_err:
            return None, f"Request timed out while fetching repositories from registry '{registry_name}': {timeout_err}"
        except requests.exceptions.RequestException as req_err:
            return None, f"An error occurred while fetching repositories from registry '{registry_name}': {req_err}"
        except KeyError:
            return None, "Unexpected response format: The 'repositories' field is missing."
        
    def get_tags_data_using_registry_and_repository(self, registry_name, repository_name):
        try:
            tag_list_url = f"https://{registry_name}.azurecr.io/acr/v1/{repository_name}/_tags"

            client_id = self.user_defined_credentials.azure.client_id
            client_secret = self.user_defined_credentials.azure.client_secret

            basic_auth_value = f"{client_id}:{client_secret}"
            encoded_basic_auth = base64.b64encode(basic_auth_value.encode('utf-8')).decode('utf-8')
            headers = {
                'Authorization': f'Basic {encoded_basic_auth}'
            }
            
            response = requests.get(tag_list_url, headers=headers)
            response.raise_for_status()
            tags = response.json()

            if tags is not None:
                return tags, None
            else:
                return None, f"Failed to retrieve tags from registry '{registry_name}' in repository '{repository_name}'. The field 'tags' was not found in the response."
            
        except requests.exceptions.HTTPError as http_err:
            return None, f"HTTP error occurred while fetching tags from registry '{registry_name}' in repository '{repository_name}': {http_err}"
        except requests.exceptions.ConnectionError as conn_err:
            return None, f"Connection error occurred while fetching tags from registry '{registry_name}' in repository '{repository_name}': {conn_err}"
        except requests.exceptions.Timeout as timeout_err:
            return None, f"Request timed out while fetching tags from registry '{registry_name}' in repository '{repository_name}': {timeout_err}"
        except requests.exceptions.RequestException as req_err:
            return None, f"An error occurred while fetching tags from registry '{registry_name}' in repository '{repository_name}': {req_err}"
        except KeyError:
            return None, "Unexpected response format: The 'tags' field is missing."

    def get_diagnostic_settings_data(self, kub_df=pd.DataFrame()):
        token, err = self.get_access_token()
        if err:
            return f"Error in creating access token.{err}"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        for index, row in kub_df.iterrows():
            rec_id = row["Id"]
            diagnostics_settings_url = f"https://management.azure.com/{rec_id}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview"
            retries = 3
            backoff = 1
            while retries > 0:
                try:
                    vms_r = requests.get(
                        diagnostics_settings_url, headers=headers)
                    if vms_r.status_code != 200:
                        return None, f"Failed to get diagnostic settings data for {rec_id} .status code: {vms_r.status_code}"
                    vms_json = vms_r.json()
                    value = vms_json.get('value')
                    if value:
                        kub_df.at[index, "Values"] = value
                    diagnostics_settings_url = vms_json.get('nextLink')
                    if not diagnostics_settings_url:
                        break
                except requests.exceptions.RequestException as e:
                    retries -= 1
                    if retries == 0:
                        return None, f"Failed to get diagnostic settings data for {rec_id} even after multiple retries.{format(e)}"
                    time.sleep(backoff)
                    backoff *= 2
        return kub_df, None

    def get_azure_key_vaults_data(self):
        token, err = self.get_access_token()
        if err:
            return None, f"Error in creating access token.{err}"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        subscription_id = self.user_defined_credentials.azure.subscription_id
        key_vaults_url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.KeyVault/vaults?api-version=2022-07-01"
        key_vaults_list = []

        retries = 3
        backoff = 1
        while retries > 0:
            try:
                key_vaults_r = requests.get(
                    key_vaults_url, headers=headers)
                if key_vaults_r.status_code != 200:
                    return None, f"Failed to get key vaults data.status code: {key_vaults_r.status_code}"

                key_vaults_r.raise_for_status()
                key_vaults_json = key_vaults_r.json()
                value = key_vaults_json.get('value')
                if value is None:
                    return None, f"value is missing in key vaults response"
                key_vaults_list.extend(value)
                key_vaults_url = key_vaults_json.get('nextLink')
                if not key_vaults_url:
                    break
            except requests.exceptions.RequestException as e:
                retries -= 1
                if retries == 0:
                    return None, f"Failed to fetch key vaults data even after multiple retries.{format(e)}"
                time.sleep(backoff)
                backoff *= 2
        return key_vaults_list, None

    def get_azure_kubernetes_clusters_data(self):
        token, err = self.get_access_token()
        if err:
            return None, f"Error in creating access token.{err}"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        subscription_id = self.user_defined_credentials.azure.subscription_id
        clusters_url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.ContainerService/managedClusters?api-version=2021-07-01"
        clusters_data = []
        retries = 3
        backoff = 1
        while retries > 0:
            try:
                clusters_r = requests.get(clusters_url, headers=headers)
                if clusters_r.status_code != 200:
                    return None, f"Failed to fetch cluster data.stats code: {clusters_r.status_code}"

                clusters_json = clusters_r.json()
                value = clusters_json.get('value')
                if value is None:
                    return None, f"Failed to get azure kubernetes clusters data.status code: {clusters_r.status_code}"
                clusters_data.extend(value)
                clusters_url = clusters_json.get('nextLink')
                if not clusters_url:
                    break
            except requests.RequestException as e:
                retries -= 1
                if retries == 0:
                    return None, F"Failed to fetch kubernetes cluster data even after multiple tries.{format(e)}"
                time.sleep(backoff)
                backoff *= 2
        return clusters_data, None

    def get_azure_policy_run_result(self):
        token, err = self.get_access_token()

        if err:
            return None, f"Error in creating access token.{err}"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        subscription_id = self.user_defined_credentials.azure.subscription_id
        policy_run_results_url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults?api-version=2019-10-01"
        policy_run_result_json = []

        retries = 3
        backoff = 1

        while retries > 0:
            try:
                policy_run_results_r = requests.post(policy_run_results_url, headers=headers, json={
                    "scope": f"/subscriptions/{subscription_id}"
                })
                if policy_run_results_r.status_code != 200:
                    return None, f"Failed to get policy run result.status code: {policy_run_results_r.status_code}"
                policy_run_result_data = policy_run_results_r.json()
                value = policy_run_result_data.get('value')
                if value is None:
                    return None, "value is missing in policy run result"
                policy_run_result_json.extend(value)
                policy_run_results_url = policy_run_result_data.get(
                    'nextLink')
                if not policy_run_results_url:
                    break
            except requests.exceptions.requests.RequestException as e:
                retries -= 1
                if retries == 0:
                    return None, F"Failed to get policy run results even after multiple tries.{format(e)}"
                time.sleep(backoff)
                backoff *= 2
        return policy_run_result_json, None

    def get_azure_service_bus_namespaces_data(self):
        subscription_id = self.user_defined_credentials.azure.subscription_id
        url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.ServiceBus/namespaces?api-version=2015-08-01"
        err_msg = "failed to get service bus name spaces"
        data, err = self.get_azure_request_response(url, err_msg)
        if err:
            return None, err
        return data, None

    def get_service_bus_namespaces_diagnostic_settings_data(self, service_bus_namespaces_df=pd.DataFrame()):
        # return a df
        if "Values" not in service_bus_namespaces_df.columns:
            service_bus_namespaces_df["Values"] = [
                []]*len(service_bus_namespaces_df)
        for index, row in service_bus_namespaces_df.iterrows():
            rec_id = row["Id"]
            name = row["Name"]
            err_msg = f"failed to get diagnostic settings for service bus {name}"
            diagnostic_settings_url = f"https://management.azure.com{rec_id}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview"
            data, err = self.get_azure_request_response(
                diagnostic_settings_url, err_msg)
            if err:
                return None, err
            if data:
                service_bus_namespaces_df.at[index, "Values"] = data
        return service_bus_namespaces_df, None

    def get_azure_logic_apps_data(self):
        subscription_id = self.user_defined_credentials.azure.subscription_id
        url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Logic/workflows?api-version=2016-06-01"
        err_msg = "failed to get azure logic apps"
        data, err = self.get_azure_request_response(url, err_msg)
        if err:
            return None, err
        return data, None

    def get_logic_apps_diagnostic_settings_data(self, logic_apps_df=pd.DataFrame()):
        # return a df
        if "Values" not in logic_apps_df.columns:
            logic_apps_df["Values"] = [
                []]*len(logic_apps_df)
        for index, row in logic_apps_df.iterrows():
            rec_id = row["Id"]
            name = row["Name"]
            err_msg = f"failed to get diagnostic settings for logic apps {name}"
            diagnostic_settings_url = f"https://management.azure.com{rec_id}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview"
            data, err = self.get_azure_request_response(
                diagnostic_settings_url, err_msg)
            if err:
                return None, err
            if data:
                logic_apps_df.at[index, "Values"] = data
        return logic_apps_df, None

    def get_azure_storage_accounts_data(self):
        token, err = self.get_access_token()
        if err:
            return None, f"Error in creating access token.{err}"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        storage_accounts_url = f"https://management.azure.com/subscriptions/{self.user_defined_credentials.azure.subscription_id}/providers/Microsoft.Storage/storageAccounts?api-version=2021-04-01"
        retries = 3
        backoff = 1
        storage_accounts_data = []
        while retries > 0:
            try:
                storage_accounts_r = requests.get(
                    storage_accounts_url, headers=headers)
                if storage_accounts_r.status_code != 200:
                    return None, f"Failed to get storage accounts data.status code: {storage_accounts_r.status_code}"

                storage_accounts_json = storage_accounts_r.json()
                value = storage_accounts_json.get('value')
                if value is None:
                    return None, "value is missing in storage accounts response"
                storage_accounts_data.extend(value)
                storage_accounts_url = storage_accounts_json.get(
                    'nextLink')
                if not storage_accounts_url:
                    break
            except requests.exceptions.RequestException as e:
                retries -= 1
                if retries == 0:
                    return None, f"Failed to fetch storage accounts data even after multiple tries.{format(e)}"
                time.sleep(backoff)
                backoff *= 2

        return storage_accounts_data, None

    def get_azure_ad_users_signin_data(self):

        token_url = f"https://login.microsoftonline.com/{self.user_defined_credentials.azure.tenant_id}/oauth2/token"
        token_data = {
            'grant_type': 'client_credentials',
            'client_id': self.user_defined_credentials.azure.client_id,
            'client_secret': self.user_defined_credentials.azure.client_secret,
            'resource': 'https://graph.microsoft.com'
        }
        token_r = requests.post(token_url, data=token_data)
        if token_r.status_code != 200:
            return None, f"Failed to get access token.status code: {token_r.status_code}"
        token = token_r.json().get('access_token')
        headers = {
            "Authorization": f"Bearer {token}",
            'Content-Type': 'application/json'

        }
        user_url = 'https://graph.microsoft.com/beta/users?$select=displayName,userPrincipalName,signInActivity'
        users_data_json = []

        retries = 3
        backoff = 1
        while retries > 0:
            try:
                users_r = requests.get(user_url, headers=headers)
                if users_r.status_code != 200:
                    return None, f"Failed to get azure ad user signin data.status code: {users_r.status_code}"

                users_json = users_r.json()
                value = users_json.get("value")
                if value is None:
                    return None, "value is missing in azure signin response"
                users_data_json.extend(value)
                user_url = users_json.get("@data.nextLink")
                if not user_url:
                    break
            except requests.exceptions.RequestException as e:
                retries -= 1
                if retries == 0:
                    return None, f"Failed get user data even after multiple tries.{format(e)}"
                time.sleep(backoff)
                backoff *= 2
        return users_data_json, None
    def get_azure_ad_users_with_specific_fields(self,fields:list[str]):
        query_params = ','.join(fields) 
        token_url = f"https://login.microsoftonline.com/{self.user_defined_credentials.azure.tenant_id}/oauth2/token"
        token_data = {
            'grant_type': 'client_credentials',
            'client_id': self.user_defined_credentials.azure.client_id,
            'client_secret': self.user_defined_credentials.azure.client_secret,
            'resource': 'https://graph.microsoft.com'
        }
        token_r = requests.post(token_url, data=token_data)
        if token_r.status_code != 200:
            return None, f"Failed to get access token.status code: {token_r.status_code}"
        token = token_r.json().get('access_token')
        headers = {
            "Authorization": f"Bearer {token}",
            'Content-Type': 'application/json'

        }
        user_url = f'https://graph.microsoft.com/beta/users?$select={query_params}'
        users_data_json = []

        retries = 3
        backoff = 1
        while retries > 0:
            try:
                users_r = requests.get(user_url, headers=headers)
                if users_r.status_code != 200:
                    return None, f"Failed to get azure ad user signin data.status code: {users_r.status_code}"

                users_json = users_r.json()
                value=None
                if cowdictutils.is_valid_key(users_json,'value'):
                    value = users_json.get("value")
                if value is None:
                    return None, "value is missing in azure signin response"
                users_data_json.extend(value)
                user_url=None
                if cowdictutils.is_valid_key(users_json,'@data.nextLink'):
                     user_url = users_json.get("@data.nextLink")
                if not user_url:
                    break
            except requests.exceptions.RequestException as e:
                retries -= 1
                if retries == 0:
                    return None, f"Failed get user data even after multiple tries.{format(e)}"
                time.sleep(backoff)
                backoff *= 2
        return users_data_json, None

    def get_azure_user_authentication_data(self):
        token, err = self.get_access_token(
            scope='https://graph.microsoft.com/.default'
        )
        if err:
            return f"Error in creating access token.{err}"
        headers = {
            "Authorization": f"Bearer {token}",
            'Content-Type': 'application/json'
        }
        graph_url = "https://graph.microsoft.com/beta/reports/credentialUserRegistrationDetails"
        users_auth_data = []
        retries = 3
        backoff = 1
        while retries > 0:
            try:
                users_r = requests.get(graph_url, headers=headers)
                if users_r.status_code != 200:
                    return None, f"Failed to get user authentication data.status code: {users_r.status_code}"
                users_data = users_r.json()
                value = users_data.get('value')
                if value is None:
                    return None, "value is missing in user authentication data."
                users_auth_data.extend(value)
                graph_url = users_data.get('@odata.nextLink')
                if not graph_url:
                    break
            except requests.exceptions.RequestException as e:
                retries -= 1
                if retries == 0:
                    return None, f"Failed to get user auth data even after multiple retries.{format(e)}"
                time.sleep(backoff)
                backoff *= 2
        return users_auth_data, None

    def get_azure_virtual_machines_data(self):
        token, err = self.get_access_token()
        if err:
            return f"Error in creating access token.{err}"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        subscription_id = self.user_defined_credentials.azure.subscription_id
        vms_url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Compute/virtualMachines?api-version=2021-04-01"
        vms_data = []
        retries = 3
        backoff = 1
        while retries > 0:
            try:
                vms_r = requests.get(vms_url, headers=headers)
                if vms_r.status_code != 200:
                    return None, f"Failed to get virtual machine data.status code: {vms_r.status_code}"
                vms_json = vms_r.json()
                value = vms_json.get('value')
                if value is None:
                    return None, "value is missing in virtual machine response."
                vms_data.extend(value)
                vms_url = vms_json.get('nextLink')
                if not vms_url:
                    break
            except requests.exceptions.RequestException as e:
                retries -= 1
                if retries == 0:
                    return None, f"Failed to get virtual machines data even after multiple retries.{format(e)}"
                time.sleep(backoff)
                backoff *= 2
        return vms_data, None

    def get_vm_extensions_data(self, vm_df=pd.DataFrame()):
        token, err = self.get_access_token()
        if err:
            return f"Error in creating access token.{err}"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        for index, row in vm_df.iterrows():
            rec_id = row["Id"]
            vm_extensions_url = f"https://management.azure.com{rec_id}/extensions?api-version=2021-04-01"
            retries = 3
            backoff = 1
            while retries > 0:
                try:
                    vms_r = requests.get(vm_extensions_url, headers=headers)
                    if vms_r.status_code != 200:
                        return None, f"Failed to get virtual machine extensions data.status code: {vms_r.status_code}"
                    vms_json = vms_r.json()
                    value = vms_json.get('value')
                    if value:
                        vm_df.at[index, "Values"] = value
                    vm_extensions_url = vms_json.get('nextLink')
                    if not vm_extensions_url:
                        break
                except requests.exceptions.RequestException as e:
                    retries -= 1
                    if retries == 0:
                        return None, f"Failed to get virtual machine extensions data even after multiple retries.{format(e)}"
                    time.sleep(backoff)
                    backoff *= 2
        return vm_df, None

    def get_vm_scaleset_data(self):
        token, err = self.get_access_token()
        if err:
            return f"Error in creating access token.{err}"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        vm_scaleset_data = []
        subscription_id = self.user_defined_credentials.azure.subscription_id
        vm_scaleset_url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Compute/virtualMachineScaleSets?api-version=2023-09-01"
        retries = 3
        backoff = 1
        while retries > 0:
            try:
                vms_r = requests.get(vm_scaleset_url, headers=headers)
                if vms_r.status_code != 200:
                    return None, f"Failed to get vm scaleset data.status code: {vms_r.status_code}"
                vms_json = vms_r.json()
                value = vms_json.get('value')
                if value:
                    vm_scaleset_data.extend(value)
                vm_scaleset_url = vms_json.get('nextLink')
                if not vm_scaleset_url:
                    break
            except requests.exceptions.RequestException as e:
                retries -= 1
                if retries == 0:
                    return None, f"Failed to get virtual machine extensions data even after multiple retries.{format(e)}"
                time.sleep(backoff)
                backoff *= 2
        return vm_scaleset_data, None

    def get_azure_virtual_network_details(self):

        url = "https://management.azure.com/subscriptions/<<subscription_id>>/providers/Microsoft.Network/virtualNetworks?api-version=2023-05-01"

        resource_details, error = self.get_azure_api_response(
            url, self.management_api_scope)
        if error:
            return None, error

        return resource_details, None

    def get_azure_virtual_machine_details(self):

        url = "https://management.azure.com/subscriptions/<<subscription_id>>/providers/Microsoft.Compute/virtualMachines?api-version=2023-07-01"

        resource_details, error = self.get_azure_api_response(
            url, self.management_api_scope)
        if error:
            return None, error

        return resource_details, None

    def get_azure_namespace_details(self):

        url = "https://management.azure.com/subscriptions/<<subscription_id>>/providers/Microsoft.NotificationHubs/namespaces?api-version=2023-09-01"

        resource_details, error = self.get_azure_api_response(
            url, self.management_api_scope)
        if error:
            return None, error

        return resource_details, None

    def get_azure_key_vault_details(self):

        url = "https://management.azure.com/subscriptions/<<subscription_id>>/providers/Microsoft.KeyVault/vaults?api-version=2022-07-01"

        resource_details, error = self.get_azure_api_response(
            url, self.management_api_scope)
        if error:
            return None, error

        return resource_details, None

    def get_azure_cluster_details(self):

        url = "https://management.azure.com/subscriptions/<<subscription_id>>/providers/Microsoft.ContainerService/managedClusters?api-version=2024-02-01"

        resource_details, error = self.get_azure_api_response(
            url, self.management_api_scope)
        if error:
            return None, error

        return resource_details, None
    
    
    #https://learn.microsoft.com/en-us/rest/api/virtualnetwork/firewall-policies?view=rest-virtualnetwork-2023-09-01
    def get_azure_firewall_policies_details(self):

        url = "https://management.azure.com/subscriptions/<<subscription_id>>/providers/Microsoft.Network/firewallPolicies?api-version=2023-09-01"

        resource_details, error = self.get_azure_api_response(
            url, self.management_api_scope)
        if error:
            return None, f'Error occurred while making API call : {error}'

        return resource_details, None
    
    def get_aks_cluster_agent_pools_upgrade_profile(self):
        
        output = []
        error_list = []
        
        cluster_list, error =self.get_azure_cluster_details()
        if error:
            error_list.append(f'Error occurred while listing clusters : {error}')
            return None, error_list
        
        for cluster in cluster_list :
            if not cowdictutils.is_valid_key(cluster , "id") :
                error_list.append("Invalid cluster ")
                continue
            resource_uri =  cluster.get("id")
            cluster_name = cluster.get("name")
            
            if not cowdictutils.is_valid_key(cluster , "properties") :
                error_list.append(f"The {cluster_name} cluster properties is null.")
                continue
            properties = cluster.get("properties")
            
            if not cowdictutils.is_valid_key(properties , "agentPoolProfiles") :
                error_list.append(f"The {cluster_name} agentPoolProfiles properties is null")
                continue
            agent_pool_profiles = properties.get("agentPoolProfiles")
            
            for agent in agent_pool_profiles :
                
                agent_name = agent.get("name")
            
                agent_pools_url = f"https://management.azure.com{resource_uri}/agentPools/{agent_name}/upgradeProfiles/default?api-version=2024-02-01"

                agent_upgrade_profile_details, error = self.get_azure_api_response(
                    agent_pools_url, self.management_api_scope , None)
                if error:
                    error_list.append(f"Error occurred while making API call : {error}")
                    continue
                
                agent_upgrade_profile_details = [
                        {**item, "nodeImageVersion": agent.get("nodeImageVersion"), 
                        "location": cluster.get("location")}
                        for item in agent_upgrade_profile_details
                    ]

                output.extend(agent_upgrade_profile_details)
            
        return output, error_list

    # https://learn.microsoft.com/en-us/rest/api/cognitiveservices/accountmanagement/accounts/list?view=rest-cognitiveservices-accountmanagement-2023-05-01&tabs=HTTP
    def get_cognitive_service_account_details(self):

        url = "https://management.azure.com/subscriptions/<<subscription_id>>/providers/Microsoft.CognitiveServices/accounts?api-version=2023-05-01"

        resource_details, error = self.get_azure_api_response(url)
        if error:
            return None, error

        return resource_details, None

    # https://learn.microsoft.com/en-us/rest/api/defenderforcloud/assessments/list?view=rest-defenderforcloud-2020-01-01&tabs=HTTP
    def get_security_assessments(self):

        url = "https://management.azure.com/subscriptions/<<subscription_id>>/providers/Microsoft.Security/assessments?api-version=2020-01-01"

        resource_details, error = self.get_azure_api_response(url)
        if error:
            return None, error

        return resource_details, None

    def create_field_meta_data(self, data_df):
        if not data_df.empty:
            field_meta_data = {
                'srcConfig': []
            }
            src_config_list = []
            for index, (column_name, column_data) in enumerate(data_df.items()):
                if pd.api.types.is_string_dtype(column_data):
                    column_type = 'STRING'
                elif pd.api.types.is_bool_dtype(column_data):
                    column_type = 'BOOLEAN'
                elif pd.api.types.is_numeric_dtype(column_data):
                    if pd.api.types.is_integer_dtype(column_data):
                        column_type = 'INTEGER'
                    elif pd.api.types.is_float_dtype(column_data):
                        column_type = 'FLOAT'
                elif pd.api.types.is_datetime64_any_dtype(column_data):
                    column_type = 'TIMESTAMP'
                else:
                    column_type = 'RECORD'

                src_config_entry = {
                    'mode': 'NULLABLE',
                    'name': column_name,
                    'type': column_type,
                    'fieldName': column_name,
                    'fieldDisplayName': column_name,
                    'isFieldIndexed': True,
                    'isFieldVisible': True,
                    'isFieldVisibleForClient': True,
                    'canUpdate': False,
                    'isRequired': True,
                    'isRepeated': False,
                    'htmlElementType': column_type,
                    'fieldDataType': column_type,
                    'fieldOrder': index
                }
                src_config_list.append(src_config_entry)

            field_meta_data['srcConfig'] = src_config_list
            return field_meta_data
        return {}

    def get_azure_app_service_details(self):

        url = "https://management.azure.com/subscriptions/<<subscription_id>>/providers/Microsoft.Web/sites?api-version=2022-03-01"

        resource_details, error = self.get_azure_api_response(
            url, self.management_api_scope)
        if error:
            return None, error

        return resource_details, None

    def list_azure_groups(self):

        url = "https://graph.microsoft.com/v1.0/groups"

        resource_details, error = self.get_azure_api_response(
            url, self.graph_api_scope)
        if error:
            return None, error

        return resource_details, None

    def list_azure_users(self):

        url = "https://graph.microsoft.com/v1.0/users"

        resource_details, error = self.get_azure_api_response(
            url, self.graph_api_scope)
        if error:
            return None, error

        return resource_details, None
    def list_azure_deleted_users(self):

        url = "https://graph.microsoft.com/beta/directory/deletedItems/microsoft.graph.user"

        resource_details, error = self.get_azure_api_response(
            url, self.graph_api_scope)
        if error:
            return None, error

        return resource_details, None
    
    def list_azure_conditional_access_policies(self):
        url = "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"


        resource_details, error = self.get_azure_api_response(
            url, self.graph_api_scope)
        if error:
            return None, error

        return resource_details, None

    def list_azure_directory_audits(self, from_date: datetime = None, to_date: datetime = None):

        url = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits"

        if from_date and to_date:
            from_date_str = from_date.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            to_date_str = to_date.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            url = f"{url}?$filter=activityDateTime ge {from_date_str} and activityDateTime le {to_date_str}"

        resource_details, error = self.get_azure_api_response(
            url, self.graph_api_scope)
        if error:
            return None, error

        return resource_details, None

    def list_azure_user_memberships(self, userPrincipalName):

        url = f"https://graph.microsoft.com/v1.0/users/{userPrincipalName}/memberOf"

        resource_details, error = self.get_azure_api_response(
            url, self.graph_api_scope)
        if error:
            return None, error

        return resource_details, None
    
    def list_azure_user_registered_devices(self, userPrincipalName):

        url = f"https://graph.microsoft.com/v1.0/users/{userPrincipalName}/registeredDevices"

        resource_details, error = self.get_azure_api_response(
            url, self.graph_api_scope)
        if error:
            return None, error

        return resource_details, None

    def list_azure_service_principals(self):

        url = "https://graph.microsoft.com/v1.0/servicePrincipals"

        resource_details, error = self.get_azure_api_response(
            url, self.graph_api_scope)
        if error:
            return None, error

        return resource_details, None

    def list_azure_role_definitions(self):

        url = "https://management.azure.com/subscriptions/<<subscription_id>>/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01"

        resource_details, error = self.get_azure_api_response(
            url, self.management_api_scope)
        if error:
            return None, error

        return resource_details, None

    def get_role_assignments_details(self):

        url = "https://management.azure.com/subscriptions/<<subscription_id>>/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"

        resource_details, error = self.get_azure_api_response(
            url, self.management_api_scope)
        if error:
            return None, error

        return resource_details, None

    def get_azure_log_analytics_workspace_details(self):

        url = "https://management.azure.com/subscriptions/<<subscription_id>>/providers/Microsoft.OperationalInsights/workspaces?api-version=2022-10-01"

        resource_details, error = self.get_azure_api_response(
            url, self.management_api_scope)
        if error:
            return None, error

        return resource_details, None

    def get_azure_resource_list(self):

        url = "https://management.azure.com/subscriptions/<<subscription_id>>/resources?api-version=2021-04-01"
        

        resource_details,error = self.get_azure_api_response(url , self.management_api_scope)
        if error:
            return None, error

        return resource_details, None
    
    def get_diagnostic_settings(self,resource_uri):

        url = "https://management.azure.com<<resource_uri>>/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview"
        url = url.replace("<<resource_uri>>" , resource_uri )

        resource_details,error = self.get_azure_api_response(url , self.management_api_scope)
        if error:
            return None, error

        return resource_details, None
    
    def get_log_analytics_workspace_hearbeat_report(self ,workspace_id):

        url = "https://api.loganalytics.io/v1/workspaces/<<workspace_id>>/query?query=Heartbeat | summarize arg_max(TimeGenerated, *) by ResourceId"
        url = url.replace("<<workspace_id>>" , workspace_id )

        resource_details,error = self.get_azure_api_response(url , self.loganalytics_api_scope , response_field = "tables")
        if error:
            return None, error

        return resource_details, None

    def get_azure_api_response(self,url,scope,response_field = "value"):

        resource_details = []
        client_id, client_secret, tenant_id, subscription_id, error = self.get_azure_credentials()
        if error:
            return None, {"error": error}

        url = url.replace("<<subscription_id>>", subscription_id)

        azure_api_vo_to_generate_access_token = {
            "clientID": client_id,
            "clientSecret": client_secret,
            "tenantID": tenant_id,
            "scope": scope
        }

        access_token, error = self.get_azure_access_token(
            azure_api_vo_to_generate_access_token)
        if error:
            return None, error

        while True:

            azure_api_vo = {
                "method": "GET",
                "url": url,
                "body": "",
                "access_token": access_token,
                "loginUrl": "management.azure.com"
            }

            res_body, error = self.get_api_response(azure_api_vo)
            if error:
                if error.get("code", "") == "AuthenticationFailed":
                    access_token, error = self.get_azure_access_token(
                        azure_api_vo_to_generate_access_token)
                    res_body, error = self.get_api_response(azure_api_vo)
                    if error:
                        return None, error

                else:
                    return None, error
                
                
            if response_field == None :
                resource_details.append([res_body])
                break
            res_body_value = res_body.get(response_field)
            url = ""
            resource_details.append(res_body_value)

            if res_body.get('nextLink') is not None:
                url = res_body.get("nextLink")
            elif res_body.get('@odata.nextLink') is not None:
                url = res_body.get("@odata.nextLink")

            if not url:
                break

        resource_details = np.concatenate(resource_details).tolist()
        return resource_details, None

    #  https://learn.microsoft.com/en-us/rest/api/virtualnetwork/network-security-groups/list-all?view=rest-virtualnetwork-2023-06-01&tabs=HTTP

    def get_azure_security_groups(self):
        token, err = self.get_access_token()
        if err:
            return None, f"Error in creating access token.{err}"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        subscription_id = self.user_defined_credentials.azure.subscription_id
        nsg_url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-06-01"
        nsg_details_json = []
        retries = 3
        backoff = 1
        while retries > 0:
            try:
                nsg_response = requests.get(nsg_url, headers=headers)
                if nsg_response.status_code != 200:
                    return None, f"Failed to get security group details. Status code: {nsg_response.status_code}"
                nsg_data = nsg_response.json()
                value = nsg_data.get('value')
                if value:
                    nsg_details_json.extend(value)
                nsg_url = nsg_data.get('nextLink')
                if not nsg_url:
                    break

            except requests.exceptions.RequestException as e:
                retries -= 1
                if retries == 0:
                    return None, f"Failed to get security group details even after multiple tries. {format(e)}"
                time.sleep(backoff)
                backoff *= 2

        return nsg_details_json, None

    # https://learn.microsoft.com/en-us/rest/api/defenderforcloud/assessments/list?view=rest-defenderforcloud-2020-01-01&tabs=HTTP
    def get_azure_security_assessments(self):
        token, err = self.get_access_token()
        if err:
            return None, f"Error in creating access token.{err}"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        subscription_id = self.user_defined_credentials.azure.subscription_id
        assessments_url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Security/assessments?api-version=2020-01-01"
        assessments_details_json = []
        retries = 3
        backoff = 1
        while retries > 0:
            try:
                assessments_response = requests.get(
                    assessments_url, headers=headers)
                if assessments_response.status_code != 200:
                    return None, f"Failed to get security assessments. Status code: {assessments_response.status_code}"
                assessments_data = assessments_response.json()
                value = assessments_data.get('value')
                if value:
                    assessments_details_json.extend(value)
                assessments_url = assessments_data.get('nextLink')
                if not assessments_url:
                    break

            except requests.exceptions.RequestException as e:
                retries -= 1
                if retries == 0:
                    return None, f"Failed to get security assessments even after multiple tries. {format(e)}"
                time.sleep(backoff)
                backoff *= 2

        return assessments_details_json, None

    # https://learn.microsoft.com/en-us/rest/api/cognitiveservices/accountmanagement/accounts/list?view=rest-cognitiveservices-accountmanagement-2023-05-01&tabs=HTTP
    def get_azure_cognitive_services_accounts(self):
        token, err = self.get_access_token()
        if err:
            return None, f"Error in creating access token. {err}"

        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }

        subscription_id = self.user_defined_credentials.azure.subscription_id
        cognitive_services_url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.CognitiveServices/accounts?api-version=2023-05-01"
        cognitive_services_details_json = []
        retries = 3
        backoff = 1
        while retries > 0:
            try:
                cognitive_services_response = requests.get(
                    cognitive_services_url, headers=headers)
                if cognitive_services_response.status_code != 200:
                    return None, f"Failed to get Cognitive Services account details. Status code: {cognitive_services_response.status_code}"
                cognitive_services_data = cognitive_services_response.json()
                value = cognitive_services_data.get('value')
                if value:
                    cognitive_services_details_json.extend(value)
                cognitive_services_url = cognitive_services_data.get(
                    'nextLink')
                if not cognitive_services_url:
                    break

            except requests.exceptions.RequestException as e:
                retries -= 1
                if retries == 0:
                    return None, f"Failed to get Cognitive Services account details even after multiple tries. {format(e)}"
                time.sleep(backoff)
                backoff *= 2

        return cognitive_services_details_json, None

    # https://learn.microsoft.com/en-us/rest/api/defenderforcloud/pricings/list?view=rest-defenderforcloud-2024-01-01&tabs=HTTP
    def get_azure_defender_pricings(self):
        token, err = self.get_access_token()
        if err:
            return None, f"Error in creating access token. {err}"

        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        subscription_id = self.user_defined_credentials.azure.subscription_id
        azure_defender_pricings_url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Security/pricings?api-version=2024-01-01"
        azure_defender_pricings_json = []
        retries = 3
        backoff = 1
        while retries > 0:
            try:
                azure_defender_pricings_response = requests.get(
                    azure_defender_pricings_url, headers=headers)
                if azure_defender_pricings_response.status_code != 200:
                    return None, f"Failed to get Azure Defender pricing details. Status code: {azure_defender_pricings_response.status_code}"
                azure_defender_pricings_data = azure_defender_pricings_response.json()
                value = azure_defender_pricings_data.get('value')
                if value:
                    azure_defender_pricings_json.extend(value)
                azure_defender_pricings_url = azure_defender_pricings_data.get(
                    'nextLink')
                if not azure_defender_pricings_url:
                    break

            except requests.exceptions.RequestException as e:
                retries -= 1
                if retries == 0:
                    return None, f"Failed to get Azure Defender pricing details even after multiple tries. {format(e)}"
                time.sleep(backoff)
                backoff *= 2

        return azure_defender_pricings_json, None

    def flatten_json(self, json_obj, parent_key='', level=0):
        flattened_dict = {}
        for key, value in json_obj.items():
            key = key[0].upper() + key[1:]
            if key == "Id":
                key = "ResourceID"
            parent_key = parent_key.capitalize()
            new_key = f"{parent_key}{key}" if parent_key else key
            if isinstance(value, dict) and level != 1:
                flattened_dict.update(self.flatten_json(
                    value, new_key, level=level+1))
            else:
                flattened_dict[new_key] = value
        return flattened_dict

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

    def get_resource_url(self, resource_id):
        try:
            url = "https://portal.azure.com/#@<<domain_name>>/resource<<resource_id>>/overview"
            if not self.domain_name:
                err = self.get_domain_name()
                if err:
                    return None, err
            modified_url = url.replace("<<resource_id>>", resource_id).replace(
                "<<domain_name>>", self.domain_name)
            return modified_url, None
        except Exception as e:
            return None, f"exception while fetching resource url for the resource id - {resource_id} :: {format(e)}"

    def get_domain_name(self):
        try:
            token, err = self.get_access_token(
                scope='https://graph.microsoft.com/.default')
            if err:
                return f'error while fetching access token :: {err}'
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            response = requests.get(
                'https://graph.microsoft.com/v1.0/domains', headers=headers)
            if response.status_code != 200:
                return f"failed to fetch domain name. Status code :: {response.status_code}"
            response_data = response.json()
            value = response_data.get('value')
            for domain in value:
                if domain['isDefault'] == True:
                    self.domain_name = domain['id']
                    return None
            return f"unable to fetch the default domain name for the tenant ID :: {self.user_defined_credentials.azure.tenant_id}"
        except Exception as e:
            return f"exception while fetching domain name :: {format(e)}"
        
    def get_azure_user_url(self, user_principal_name: str = "", user_id: str = ""):
        if not user_id:
            if not user_principal_name:
                return "", "UserID and UserPrincipalName are empty"
            
            token, err = self.get_access_token(scope='https://graph.microsoft.com/.default')
            if err:
                return "", f'error while fetching access token :: {err}'
            
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }

            response = requests.get(
                url=f"https://graph.microsoft.com/v1.0/users/{user_principal_name}",
                headers=headers
            )

            if not response.ok:
                return "", f"Response status: {response.status_code}"
            
            try:
                user = response.json()
            except requests.JSONDecodeError:
                return "", "Unable to get user"

            if not cowdictutils.is_valid_key(user, "id"):
                return "", "Unable to get user"
            
            user_id = user['id']
        
        url = f"https://portal.azure.com/#view/Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/overview/userId/{user_id}"
        
        return url, None

    def get_current_datetime(self):
        current_time = datetime.now(timezone.utc)
        formatted_time = current_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        return formatted_time

    def get_azure_request_response(self, url, err_msg):
        token, err = self.get_access_token()
        if err:
            return f"Error in creating access token.{err}"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        data = []
        retries = 3
        backoff = 1
        while retries > 0:
            try:
                res = requests.get(url, headers=headers)
                if res.status_code != 200:
                    return None, f"url: {url}. message: {err_msg}. status code: {res.status_code}"
                res_json = res.json()
                value = res_json.get('value')
                if value:
                    data.extend(value)
                url = res_json.get('nextLink')
                if not url:
                    break
            except requests.exceptions.RequestException as e:
                retries -= 1
                if retries == 0:
                    return None, f"request exception happened for url: {url} .{format(e)}"
                time.sleep(backoff)
                backoff *= 2
        return data, None
    
    def get_share_point_drive_id(self, drive_name):
        try:
            token, err = self.get_access_token(scope='https://graph.microsoft.com/.default')
            if err:
                return None, f'Error while fetching access token.{err}'
            headers = {
                'Authorization': f'Bearer {token}',
            }
            response = requests.get(
                'https://graph.microsoft.com/v1.0/drives', headers=headers)
            if response.status_code != HTTPStatus.OK:
                return None, f"failed to fetch drive details. Status code :: {response.status_code}"
            response_data = response.json()
            value = response_data.get('value')
            for drive in value:
                if drive['name'] == drive_name:
                    return drive['id'], None
            return None, f"unable to fetch the drive id for drive name :: {drive_name}"
        except Exception as e:
            return None, f"exception while fetching drive details name :: {e}"
        
    def get_root_parent_id(self, drive_id):
        try:
            token, err = self.get_access_token(scope='https://graph.microsoft.com/.default')
            if err:
                return None, f'Error while fetching access token.{err}'
            headers = {
                'Authorization': f'Bearer {token}',
            }
            response = requests.get(
                f"https://graph.microsoft.com/v1.0/drives/{drive_id}/root", headers=headers)
            if response.status_code != HTTPStatus.OK:
                return None, f"failed to fetch parent details. Status code :: {response.status_code}"
            response_data = response.json()
            if response_data['id'] != '':
                    return response_data['id'], None
            return None, f"unable to fetch the parent id for drive id :: {drive_id}"
        except Exception as e:
            return None, f"exception while fetching parent id :: {e}"    
        
    def get_sharepoint_site_id(self, site_name):
        try:
            token, err = self.get_access_token(scope='https://graph.microsoft.com/.default')
            if err:
                return None, f'Error while fetching access token.{err}'
            headers = {
                'Authorization': f'Bearer {token}',
            }
            response = requests.get(
                f"https://graph.microsoft.com/v1.0/sites", headers=headers)
            if response.status_code != HTTPStatus.OK:
                return None, f"failed to fetch sharepoint site details. Status code :: {response.status_code}"
            response_data = response.json()
            value = response_data.get('value')
            for site in value:
                site_name_value = site.get('name', None)
                if site_name_value !=  None and site_name_value == site_name:
                    return site['id'], None
            return None, f"unable to fetch the site id for site :: {site_name}"
        except Exception as e:
            return None, f"exception while fetching site id :: {e}"    
        
    def get_list_id(self, list_name, site_id):
        try:
            token, err = self.get_access_token(scope='https://graph.microsoft.com/.default')
            if err:
                return None, f'Error while fetching access token.{err}'
            headers = {
                'Authorization': f'Bearer {token}',
            }
            response = requests.get(
                f"https://graph.microsoft.com/v1.0/sites/{site_id}/lists", headers=headers)
            if response.status_code != HTTPStatus.OK:
                return None, f"failed to fetch sharepoint list details. Status code :: {response.status_code}"
            response_data = response.json()
            value = response_data.get('value')
            for list in value:
                list_name_value = list.get('name', None)
                if list_name_value !=  None and list_name_value == list_name:
                    return list['id'], None
            return None, f"unable to fetch the list id for list :: {list_name}"
        except Exception as e:
            return None, f"exception while fetching list id :: {e}" 
        
    def upload_file_in_sharepoint_drive(self, file_upload_details_vo):
        try:
            token, err = self.get_access_token(scope='https://graph.microsoft.com/.default')
            if err:
                return None, f'Error while fetching access token.{err}'
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type' : 'text/plain'
            }
            response = requests.put(
                f"https://graph.microsoft.com/v1.0/drives/{file_upload_details_vo['driveID']}/items/{file_upload_details_vo['parentID']}:/{file_upload_details_vo['fileName']}:/content", headers=headers, data=file_upload_details_vo['fileContent'])
            if response.status_code not in (HTTPStatus.CREATED, HTTPStatus.OK):
                return None, f"failed to fetch upload file in sharepoint. Status code :: {response.status_code}"
            return response.json(), None
        except Exception as e:
            return None, f"exception while adding file to sharepoint drive :: {e}"
        
    def upload_file_in_sharepoint_list(self, list_upload_details_vo):
        try:
            token, err = self.get_access_token(scope='https://graph.microsoft.com/.default')
            if err:
                return None, f'Error while fetching access token.{err}'
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            payload = json.dumps({
                   "fields": {
                       "ItemName":         list_upload_details_vo['ItemName'],
                       "ItemLink":         list_upload_details_vo['ItemLink'],
                       "CreatedDateTime":      list_upload_details_vo['CreatedDate'],
                       }
                    })
            response = requests.request( 
                "POST", f"https://graph.microsoft.com/v1.0/sites/{list_upload_details_vo['siteID']}/lists/{list_upload_details_vo['listID']}/items", headers=headers, data=payload)
            if response.status_code != HTTPStatus.CREATED:
                return None, f"failed to fetch upload file in sharepoint list. Status code :: {response.status_code}"
            return response.json(), None
        except Exception as e:
            return None, f"exception while adding file to sharepoint list :: {e}"
        

    def get_user_registration_details(self):
        try:
            token, err = self.get_access_token(scope='https://graph.microsoft.com/.default')
            if err:
                return None, f"Error while fetching access token. {err}"
            headers = {
                'Authorization': f'{token}',
            }
            response = requests.request( 
                "GET", "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails", headers=headers)
            logging.info("User registered details response info : %s", str(response))
            if response.status_code != HTTPStatus.OK:
                return None, f"{USER_REG_ERR_MSG}. Status code : {response.status_code}. Reason : {response.reason}. {SUPPORT_MSG}."
            response_dict = response.json()
            # invalid response
            if not 'value' in response_dict:
                return None, f"{USER_REG_ERR_MSG}. Invalid user registration response. {SUPPORT_MSG}."
            if len(response_dict['value']) == 0:
                return "User registration details is empty for given azure credentials", None
            return response_dict['value'], None
        except requests.exceptions.HTTPError as e:
            logging.exception("An http exception occured while fetching user registration details: %s", str(e))
            return None, f"{USER_REG_ERR_MSG}. Http exception occured. {SUPPORT_MSG}."
        except RequestException as e:
            logging.exception("A request exception occurred while fetching user registration details: %s", str(e))
            return None, f"{USER_REG_ERR_MSG}. Request exception occured. {SUPPORT_MSG}."
        except KeyError as e:
            logging.exception("A keyError exception occurred while fetching user registration details: %s", str(e))
            return None, f"{USER_REG_ERR_MSG}. KeyError exception occured. {SUPPORT_MSG}."
        

    def get_role_definitions(self):
        try:
            token, err = self.get_access_token(scope='https://graph.microsoft.com/.default')
            if err:
                return None, f"Error while fetching access token. {err}"
            headers = {'Authorization': f'{token}',}
            response = requests.request( 
                "GET", "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions", headers=headers)
            logging.info("Role definition response info : %s", str(response))
            if response.status_code != HTTPStatus.OK:
                return None, f"{ROLE_ERR_MSG}. Status code : {response.status_code}. Reason : {response.reason}. {SUPPORT_MSG}"
            response_dict = response.json()
            # invalid response
            if not 'value' in response_dict:
                return None, f"{ROLE_ERR_MSG}. Invalid role definition response. {SUPPORT_MSG}."
            if len(response_dict['value']) == 0:
                return "Role definition is empty for given azure credentials", None
            return response_dict['value'], None
        except requests.exceptions.HTTPError as e:
            logging.exception("An http exception occured while fetching role definition details: %s", str(e))
            return None, f"{ROLE_ERR_MSG}. Http exception occured. {SUPPORT_MSG}."
        except RequestException as e:
            logging.exception("A request exception occurred while fetching role definition details: %s", str(e))
            return None, f"{ROLE_ERR_MSG}. Request exception occured. {SUPPORT_MSG}."
        except KeyError as e:
            logging.exception("A keyError exception occurred while fetching role definition details: %s", str(e))
            return None, f"{ROLE_ERR_MSG}. KeyError exception occured. {SUPPORT_MSG}."    


        
    def get_user_role_assignments(self, user_id):
        try:
            token, err = self.get_access_token(scope='https://graph.microsoft.com/.default')
            if err:
                return None, f"Error while fetching access token. {err}"
            headers = {'Authorization': f'{token}',}
            user_id = f"'{user_id}'"
            response = requests.request( 
                "GET", f"https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$filter=principalId+eq+{user_id}", headers=headers)
            logging.info("UserId (%s). Role assignments response info : %s", user_id, str(response))
            # role assignments is not success
            if response.status_code != HTTPStatus.OK:
                return None, f"{ROLE_ASSIG_ERR_MSG}. User id : {user_id}. Status code : {response.status_code}. Reason : {response.reason}. {SUPPORT_MSG}."
            response_dict = response.json()
            # invalid response
            if not 'value' in response_dict:
                return None, f"{ROLE_ASSIG_ERR_MSG}. User id : {user_id}. Invalid role assignments response. {SUPPORT_MSG}."
            if len(response_dict['value']) == 0:
                return ["No roles attached"], None
            # collect roleDefinitionIds of a user
            role_assignments = response_dict['value']
            role_assignments_json = self.replace_empty_dicts_with_none(role_assignments)
            role_assignments_df = pd.json_normalize(role_assignments_json)
            role_definition_ids = role_assignments_df['roleDefinitionId']
            # fetch role definitions
            role_definitions, err = self.get_role_definitions()
            if err:
                return None, err
            role_definitions_df = pd.json_normalize(role_definitions)
            # filtering role names from role definition for respective roleDefinitionIds
            filtered_role_definitions_df = role_definitions_df[role_definitions_df['id'].isin(role_definition_ids)]
            if not filtered_role_definitions_df.empty:
                return filtered_role_definitions_df['displayName'].values.tolist(),  None
            return ["No roles attached"], None
        except requests.exceptions.HTTPError as e:
            logging.exception("An http exception occured while fetching role details for userid is - %s: %s", str(user_id), str(e))
            return None, f"{ROLE_ASSIG_ERR_MSG}. Http exception occured. {SUPPORT_MSG}."
        except RequestException as e:
            logging.exception("A request exception occurred while fetching role details for userid is - %s: %s", str(user_id), str(e))
            return None, f"{ROLE_ASSIG_ERR_MSG}. Request exception occured. {SUPPORT_MSG}."
        except KeyError as e:
            logging.exception("A keyError exception occurred while fetching role details for userid is - %s: %s", str(user_id), str(e))
            return None, f"{ROLE_ASSIG_ERR_MSG}. KeyError exception occured. {SUPPORT_MSG}."    

    def get_user_role_with_permission(self, user_id):
        try:
            token, err = self.get_access_token(scope='https://graph.microsoft.com/.default')
            if err:
                return None, f"Error while fetching access token. {err}"
            headers = {'Authorization': f'{token}',}
            user_id = f"'{user_id}'"
            response = requests.request( 
                "GET", f"https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$filter=principalId+eq+{user_id}", headers=headers)
            logging.info("UserId (%s). Role assignments response info : %s", user_id, str(response))
            # role assignments is not success
            if response.status_code != HTTPStatus.OK:
                return None, f"{ROLE_ASSIG_ERR_MSG}. User id : {user_id}. Status code : {response.status_code}. Reason : {response.reason}. {SUPPORT_MSG}."
            response_dict = response.json()
            # invalid response
            if not 'value' in response_dict:
                return None, f"{ROLE_ASSIG_ERR_MSG}. User id : {user_id}. Invalid role assignments response. {SUPPORT_MSG}."
            if len(response_dict['value']) == 0:
                return [{"Role" :  "No roles attached"}], None
            # collect roleDefinitionIds of a user
            role_assignments = response_dict['value']
            role_assignments_json = self.replace_empty_dicts_with_none(role_assignments)
            role_assignments_df = pd.json_normalize(role_assignments_json)
            role_definition_ids = role_assignments_df['roleDefinitionId']
            # fetch role definitions
            role_definitions, err = self.get_role_definitions()
            if err:
                return [], err
            role_definitions_df = pd.json_normalize(role_definitions)
            # filtering role names from role definition for respective roleDefinitionIds
            filtered_role_definitions_df = role_definitions_df[role_definitions_df['id'].isin(role_definition_ids)]
            role_with_permission = []
            if not filtered_role_definitions_df.empty:
                for _, row in filtered_role_definitions_df.iterrows():   
                    role_actions = []
                    for permission in row['rolePermissions']:
                        allowed_resource_actions = permission['allowedResourceActions']
                        for action in allowed_resource_actions:
                            role_actions.append(action)
                    permissions = ', '.join(map(str, role_actions))
                    role_with_permission.append({
                        "Role" : row['displayName'],
                        "Permissions" : permissions
                    })
            return role_with_permission, None
        except requests.exceptions.HTTPError as e:
            logging.exception("An http exception occured while fetching role details for userid is - %s: %s", str(user_id), str(e))
            return None, f"{ROLE_ASSIG_ERR_MSG}. Http exception occured. {SUPPORT_MSG}."
        except RequestException as e:
            logging.exception("A request exception occurred while fetching role details for userid is - %s: %s", str(user_id), str(e))
            return None, f"{ROLE_ASSIG_ERR_MSG}. Request exception occured. {SUPPORT_MSG}."
        except KeyError as e:
            logging.exception("A keyError exception occurred while fetching role details for userid is - %s: %s", str(user_id), str(e))
            return None, f"{ROLE_ASSIG_ERR_MSG}. KeyError exception occured. {SUPPORT_MSG}."    

    def get_user_groups(self, user_id):
        try:
            token, err = self.get_access_token(scope='https://graph.microsoft.com/.default')
            if err:
                return None, f"Error while fetching access token. {err}"
            headers = {'Authorization': f'{token}',}
            response = requests.request( 
                "GET", f"https://graph.microsoft.com/v1.0/users/{user_id}/memberOf/$/microsoft.graph.group", headers=headers)
            logging.info("UserId (%s) group details response info : %s", user_id, str(response))
            # fetching user groups is not success
            if response.status_code != HTTPStatus.OK:
                return None, f"{GRP_ERR_MSG}. User id : {user_id}. Status code : {response.status_code}. Reason : {response.reason}. {SUPPORT_MSG}."
            response_dict = response.json()
            # invalid response
            if not 'value' in response_dict:
                return None, f"{GRP_ERR_MSG}. User id : {user_id}. Invalid group response. {SUPPORT_MSG}."
            if len(response_dict['value']) == 0:
                return ["No groups attached"], None
            res_df = pd.DataFrame(response_dict['value'])
            return res_df['displayName'].values.tolist(), None
        except requests.exceptions.HTTPError as e:
            logging.exception("An http exception occured while fetching group details for user - %s: %s", str(user_id), str(e))
            return None, f"{GRP_ERR_MSG}. Http exception occured. {SUPPORT_MSG}."
        except RequestException as e:
            logging.exception("A request exception occurred while fetching group details for user - %s: %s", str(user_id), str(e))
            return None, f"{GRP_ERR_MSG}. Request exception occured. {SUPPORT_MSG}."
        except KeyError as e:
            logging.exception("A keyError exception occurred while fetching group details for user - %s: %s", str(user_id), str(e))
            return None, f"{GRP_ERR_MSG}. KeyError exception occured. {SUPPORT_MSG}."
        
    def get_user_details_by_userid(self, user_ids: list[str]):

        user_details = []
        error_details = []

        if len(user_ids) == 0:
            error_details.append({"Error" : "Please provide atlease one user id"})
            return user_details, error_details
        
        token, err = self.get_access_token(scope='https://graph.microsoft.com/.default')
        if err:
            return None, error_details.append({"Error" : f"Error while fetching access token. {err}"})
        headers = {'Authorization': f'{token}',}

        try:
            for user_id in user_ids:
                url = f"https://graph.microsoft.com/v1.0/users/{user_id}"
                response = requests.get(url, headers=headers)
                resBody = response.json()
                if response.status_code != HTTPStatus.OK:
                    error_details.append({"Error" : f"Failed to fetch user details for userid - {user_id}"})
                    user_details.append({"UserId" : user_id})
                user_details.append({
                    "Name" : resBody.get('displayName'),
                    "UserId" : user_id
                })
            return user_details, error_details
        except requests.exceptions.HTTPError as e:
            logging.exception("An http exception occured while fetching user details for user - %s: %s", str(user_id), str(e))
            return user_details, error_details
        except RequestException as e:
            logging.exception("A request exception occurred while fetching user details for user - %s: %s", str(user_id), str(e))
            return user_details, error_details
        except KeyError as e:
            logging.exception("A keyError exception occurred while fetching user details for user - %s: %s", str(user_id), str(e))
            return user_details, error_details
        
    def get_audit_logs_for_user(self, user_id, from_date, to_date):
        retries = 3
        backoff = 10
        while retries > 0:
            try:
                token, err = self.get_access_token(scope='https://graph.microsoft.com/.default')
                if err:
                    return None, f"Error while fetching access token. {err}"
                
                headers = {'Authorization': f'Bearer {token}'}
                
                from_date_str = from_date.isoformat().replace("+00:00", "Z")
                to_date_str = to_date.isoformat().replace("+00:00", "Z")
               
                response = requests.request(
                    "GET", 
                    f"https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$filter=initiatedBy/user/id eq '{user_id}' and activityDateTime ge {from_date_str} and activityDateTime le {to_date_str}",
                    headers=headers
                )
                if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                    time.sleep(backoff)
                    backoff *= 2
                    retries -= 1
                    continue

                if response.status_code != HTTPStatus.OK:
                    return None, f"Error fetching audit logs. User id: {user_id}. Status code: {response.status_code}. Reason: {response.reason}."
                                      
                response_dict = response.json()
                
                if 'value' not in response_dict:
                    return None, f"Invalid audit logs response. User id: {user_id}."
                
                if len(response_dict['value']) == 0:
                    return [{"Message": "No audit logs found"}], None
                
                audit_logs = response_dict['value']
                return audit_logs, None
            
            except requests.exceptions.HTTPError as e:
                logging.exception("An HTTP exception occurred while fetching audit logs for user id: %s: %s", str(user_id), str(e))
                return None, f"HTTP exception occurred while fetching audit logs. {SUPPORT_MSG}."
            
            except requests.exceptions.RequestException as e:
                logging.exception("A request exception occurred while fetching audit logs for user id: %s: %s", str(user_id), str(e))
                return None, f"Request exception occurred while fetching audit logs. {SUPPORT_MSG}."
            
            except KeyError as e:
                logging.exception("A KeyError occurred while processing audit logs for user id: %s: %s", str(user_id), str(e))
                return None, f"Key error while processing audit logs. {SUPPORT_MSG}."

        return None, f"Failed to fetch audit logs for user id: {user_id} after multiple attempts due to rate limiting."


    def get_policy_named_locations(self):

        error_details = []
        
        token, err = self.get_access_token(scope='https://graph.microsoft.com/.default')
        if err:
            return None, error_details.append({"Error" : f"Error while fetching access token. {err}"})
        headers = {'Authorization': f'{token}'}

        try:
            url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations"
            response = requests.get(url, headers=headers)
            resBody = response.json()
            if response.status_code != HTTPStatus.OK:
                error_details.append({"Error" : f"Failed to fetch nmaed location policy"})
                return None, error_details
            return resBody, error_details
        except requests.exceptions.HTTPError as e:
            logging.exception("An http exception occured while fetching user details for policy name location : %s", str(e))
            error_details.append({"Error" : f"An http exception occured. Failed to fetch nmaed location policy"})
            return resBody, error_details
        except RequestException as e:
            logging.exception("A request exception occurred while fetching user details for policy name location : %s", str(e))
            error_details.append({"Error" : f"An request exception occured. Failed to fetch nmaed location policy"})
            return resBody, error_details
        except KeyError as e:
            logging.exception("A keyError exception occurred while fetching user details for policy name location : %s", str(e))
            error_details.append({"Error" : f"An keyError exception occured. Failed to fetch nmaed location policy"})
            return resBody, error_details
        

    def get_policy_locations_by_loc_id(self, location_ids: list[str]):

        location_details = []
        error_details = []

        if len(location_ids) == 0:
            error_details.append({"Error" : "Please provide atlease one policy location id"})
            return location_details, error_details
        
        policy_location_details, error = self.get_policy_named_locations()
        policy_location_df = pd.json_normalize(policy_location_details['value'])
        if error:
            error_details.append(error)
            return location_details, error_details

        try:
            for location_id in location_ids:
                location_info = policy_location_df[policy_location_df['id'] == location_id]
                if location_info.empty:
                    error_details.append({"Error" : f"Failed to fetch policy location details. LocationId: {location_id}"})
                    location_details_obj = {
                        "id" : location_id
                    }
                else:
                    # Extract cidrAddress values
                    cidr_addresses = policy_location_df['ipRanges'].apply(lambda ip_ranges: [ip_range['cidrAddress'] for ip_range in ip_ranges])
                    # Flatten the list of lists and convert to a comma-separated string
                    comma_separated_cidr = ','.join([cidr for sublist in cidr_addresses for cidr in sublist])

                    location_details_obj = {
                        "Name" : location_info['displayName'][0],
                        "isTrusted" : location_info['isTrusted'][0],
                        "Address" : comma_separated_cidr,
                        "id" : location_id
                    }
                location_details.append(location_details_obj)                
            return location_details, error_details
        except requests.exceptions.HTTPError as e:
            logging.exception("An http exception occured while fetching user details for user - %s: %s", str(location_id), str(e))
            return location_details, error_details
        except RequestException as e:
            logging.exception("A request exception occurred while fetching user details for user - %s: %s", str(location_id), str(e))
            return location_details, error_details
        except KeyError as e:
            logging.exception("A keyError exception occurred while fetching user details for user - %s: %s", str(location_id), str(e))
            return location_details, error_details
        
    
    def get_user_role_with_permission(self, user_id):
        try:
            token, err = self.get_access_token(scope='https://graph.microsoft.com/.default')
            if err:
                return None, f"Error while fetching access token. {err}"
            headers = {'Authorization': f'{token}',}
            user_id = f"'{user_id}'"
            response = requests.request( 
                "GET", f"https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$filter=principalId+eq+{user_id}", headers=headers)
            logging.info("UserId (%s). Role assignments response info : %s", user_id, str(response))
            # role assignments is not success
            if response.status_code != HTTPStatus.OK:
                return None, f"{ROLE_ASSIG_ERR_MSG}. User id : {user_id}. Status code : {response.status_code}. Reason : {response.reason}. {SUPPORT_MSG}."
            response_dict = response.json()
            # invalid response
            if not 'value' in response_dict:
                return None, f"{ROLE_ASSIG_ERR_MSG}. User id : {user_id}. Invalid role assignments response. {SUPPORT_MSG}."
            if len(response_dict['value']) == 0:
                return [{"Role" :  "No roles attached"}], None
            # collect roleDefinitionIds of a user
            role_assignments = response_dict['value']
            role_assignments_json = self.replace_empty_dicts_with_none(role_assignments)
            role_assignments_df = pd.json_normalize(role_assignments_json)
            role_definition_ids = role_assignments_df['roleDefinitionId']
            # fetch role definitions
            role_definitions, err = self.get_role_definitions()
            if err:
                return [], err
            role_definitions_df = pd.json_normalize(role_definitions)
            # filtering role names from role definition for respective roleDefinitionIds
            filtered_role_definitions_df = role_definitions_df[role_definitions_df['id'].isin(role_definition_ids)]
            role_with_permission = []
            if not filtered_role_definitions_df.empty:
                for _, row in filtered_role_definitions_df.iterrows():   
                    role_actions = []
                    for permission in row['rolePermissions']:
                        allowed_resource_actions = permission['allowedResourceActions']
                        for action in allowed_resource_actions:
                            role_actions.append(action)
                    permissions = ', '.join(map(str, role_actions))
                    role_with_permission.append({
                        "Role" : row['displayName'],
                        "Permissions" : permissions
                    })
            return role_with_permission, None
        except requests.exceptions.HTTPError as e:
            logging.exception("An http exception occured while fetching role details for userid is - %s: %s", str(user_id), str(e))
            return None, f"{ROLE_ASSIG_ERR_MSG}. Http exception occured. {SUPPORT_MSG}."
        except RequestException as e:
            logging.exception("A request exception occurred while fetching role details for userid is - %s: %s", str(user_id), str(e))
            return None, f"{ROLE_ASSIG_ERR_MSG}. Request exception occured. {SUPPORT_MSG}."
        except KeyError as e:
            logging.exception("A keyError exception occurred while fetching role details for userid is - %s: %s", str(user_id), str(e))
            return None, f"{ROLE_ASSIG_ERR_MSG}. KeyError exception occured. {SUPPORT_MSG}."
    def download_file_from_url(self,url):
        token, err = self.get_access_token(scope='https://graph.microsoft.com/.default')
        if err:
            return "", f'Error while fetching access token :: {err}'
            
        headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
        item_id=self.extract_item_id_from_url(url=url)
        response = requests.get(
                url=f"https://graph.microsoft.com/v1.0/shares/{self.encode_share_url(url)}/driveItem",
                headers=headers
            )
        if not response.ok:
            return None,f"{response.text}"
        fileMetaData = response.json()
        drive_id = ""
        item_id = ""
        if cowdictutils.is_valid_key(fileMetaData,'parentReference') and cowdictutils.is_valid_key(fileMetaData['parentReference'],'driveId'):
            drive_id = fileMetaData['parentReference']['driveId'] 
        if cowdictutils.is_valid_key(fileMetaData,'id'):
            item_id = fileMetaData['id']
            
        file_name = ""
        mime_type =""
        if cowdictutils.is_valid_key(fileMetaData,'name'):
            file_name = fileMetaData['name']
        if cowdictutils.is_valid_key(fileMetaData,'file') and cowdictutils.is_valid_key(fileMetaData["file"],'mimeType'):
             mime_type = fileMetaData['file']['mimeType']
        download_url = f"https://graph.microsoft.com/v1.0/drives/{drive_id}/items/{item_id}/content"
        fileResponse = requests.get(download_url, headers=headers)
        if not fileResponse.ok:
            return None,f"{fileResponse.text}"
        fileDataObj = {
            "FileName":file_name,
            "FileType":mime_type,
            "FileContent":fileResponse.content
        }
        
        return fileDataObj,None
        
    def extract_item_id_from_url(self,url):
        pattern = r'\/p\/[^\/]+\/([^\/\?]+)'
        match = re.search(pattern, url)

        if match:
            return match.group(1)
        return None
    def encode_share_url(self,share_url):
        encoded_url = base64.b64encode(share_url.encode()).decode('utf-8')
        encoded_url = encoded_url.rstrip('=')
        encoded_url = encoded_url.replace('/', '_').replace('+', '-')
        return f'u!{encoded_url}'