from compliancecowcards.structs import cards
from applicationtypes.privacybisonconnector import privacybisonconnector
import urllib.parse
from typing import List, Tuple
import uuid
import base64
import pandas as pd
from datetime import datetime
import json


class Task(cards.AbstractTask):

    def execute(self) -> dict:

        error = self.check_inputs()
        if error:
            return self.upload_log_file_panic({"Error": error})
        
        app = privacybisonconnector.PrivacyBisonConnector(
            app_url=self.task_inputs.user_object.app.application_url,
            app_port=self.task_inputs.user_object.app.application_port,
            user_defined_credentials=privacybisonconnector.UserDefinedCredentials.from_dict(
                self.task_inputs.user_object.app.user_defined_credentials)
        )

        har, error = self.download_json_file_from_minio_as_dict(self.task_inputs.user_inputs.get('HarFile'))
        if error:
            return self.upload_log_file_panic({"Error": error})
        
        if not app.is_valid_har(har):
            return self.upload_log_file_panic({"Error": 'HarFile is in an invalid format, please check'})
        
        company_name, _ = app.get_company_name_from_har_file(har)

        har_info = {}

        for entry in har["log"]["entries"]:
            url = urllib.parse.urlparse(entry["request"]["url"])
            url_info = {
                "URI": url.geturl(),
                "Host": url.netloc,
                "Path": url.path,
                "QueryString": entry["request"]["queryString"]
            }

            if "URIs" in har_info:
                har_info["URIs"].append(url_info)
            else:
                har_info["URIs"] = [url_info]

        queries = {}
        for i in range(len(har_info["URIs"])):
            uri_info = har_info["URIs"][i]
            for query in uri_info["QueryString"]:
                if query["name"] in queries:
                    query_info = queries[query["name"]]
                else:
                    query_info = [[] for _ in range(len(har_info["URIs"]))]
                query_in_uri = query_info[i]
                if not query_in_uri:
                    query_in_uri = []
                query_in_uri.append(query["value"])
                query_info[i] = query_in_uri
                queries[query["name"]] = query_info

        # Get invalid queries
        invalid_query_names = []
        for key, values in queries.items():
            actions = ["check", "guid_token", "jwt_token", "api_key"]

            for action in actions:
                ignore, invalid = self.check_for(action, key, values)
                if ignore:
                    break

                if invalid:
                    invalid_query_names.append(key)
                    break

        # Find URIs with invalid queries
        uris_with_token_in_query = []
        for uri_info in har_info["URIs"]:

            invalid_query_names_in_uri = []
            for query in uri_info["QueryString"]:
                query_name = query["name"]
                if query_name in invalid_query_names:
                    invalid_query_names_in_uri.append(query_name)

            uri_with_token_in_query = {
                # Meta
                "System": company_name,
                "Source": "compliancecow",

                # Resource info
                "ResourceID": uri_info["URI"],
                "ResourceName": "N/A",
                "ResourceType": "Web Application",
                "ResourceURL": 'N/A',
                "ResourceLocation": "N/A",
                "ResourceTags": "N/A",

                # Data
                "Host": uri_info["Host"],
                "InvalidQueryNames": invalid_query_names_in_uri,
                "Status": "Passed",
                "Remediation": "N/A",

                # Compliance details
                "ValidationStatusCode": "NO_TOKEN_FOUND",
                "ValidationStatusNotes": "No tokens were found",
                "ComplianceStatus": "COMPLIANT",
                "ComplianceStatusReason": "No tokens were found",
                "EvaluatedTime": self.get_current_datetime(),

                # User editable data
                "UserAction": "",

                # Action editable data
                "ActionStatus": "",
                "ActionResponseURL": ""
            }

            if invalid_query_names_in_uri:
                invalid_query_names_in_uri_str = ", ".join(invalid_query_names_in_uri)
                reason = f"Tokens were found in the following queries: {invalid_query_names_in_uri_str}"
                uri_with_token_in_query.update({
                    "Status": "Failed",
                    "Remediation": f"Move these queries to the header: {invalid_query_names_in_uri_str}",

                    "ValidationStatusCode": "TOKENS_FOUND",
                    "ValidationStatusNotes": reason,
                    "ComplianceStatus": "NON_COMPLIANT",
                    "ComplianceStatusReason": reason,
                })

            uris_with_token_in_query.append(uri_with_token_in_query)
                

        compliancePCT, complianceStatus = app.get_compliance_status(
            compliant_count=len([uri_with_token_in_query for uri_with_token_in_query in uris_with_token_in_query 
                                    if uri_with_token_in_query.get("ComplianceStatus") == "COMPLIANT"]),
            non_compliant_count=len([uri_with_token_in_query for uri_with_token_in_query in uris_with_token_in_query 
                                    if uri_with_token_in_query.get("ComplianceStatus") == "NON_COMPLIANT"]),
        )

        data_df = pd.DataFrame.from_dict(uris_with_token_in_query)
        if data_df.empty:
            return self.upload_log_file_panic({"Error": 'No URLs found in the HAR file.'})
        
        file_url, error = self.upload_df_as_json_file_to_minio(data_df, 'URIsWithTokenInQuery')
        if error:
            return {"Error": f"Error uploading file to Minio: {error}"}

        response = {
            "ComplianceStatus_": complianceStatus, # The possible values for the 'Status' field should be one of the following: 'COMPLIANT' 'NON_COMPLIANT,' or 'NOT_DETERMINED.'
            "CompliancePCT_": compliancePCT,
            "URIsWithTokenInQuery": file_url,
        }

        return response
    
    def check_inputs(self):
        task_inputs = self.task_inputs
        if task_inputs is None:
            return 'Task inputs are missing'
        user_object = self.task_inputs.user_object
        if (
            user_object is None
            or user_object.app is None
            or user_object.app.application_url is None
            or user_object.app.user_defined_credentials is None
        ):
            return 'User defined credentials are missing"'
        if self.task_inputs.user_inputs is None:
            return 'User inputs are missing'
        if self.task_inputs.user_inputs.get("HarFile") is None:
            return 'HarFile is missing!'
        return None
    

    def check_name_and_count(self, key: str, values: List[str]):
        ignore = ["lang", "language"]
        if key in ignore:
            return True, False
            
        if values:
            for value in values:
                if len(value) > 1:
                    return True, False
        
        return False, False

    def check_with(self, values: List[str], do):
        count = 0
        unique_values = {}
        for value in values:
            if value:
                count += 1
                query = {}
                for v in value:
                    query[v] = True
                for k in query:
                    unique_values_count = unique_values[k] if k in unique_values else 0
                    unique_values_count += 1
                    unique_values[k] = unique_values_count

        if (count*100)/len(values) < 50:
            return False, False
        
        repeating_value = ""

        for k, v in unique_values.items():
            if len(unique_values) == 1 or v > 1:
                repeating_value = k
                break

        return do(repeating_value)


    def check_guid(self, value: str):
        try:
            uuid.UUID(value)
        except ValueError:
            return False, False
        
        return False, True
        
    def check_jwt(self, value: str):
        token_split = value.split(".")

        if not len(token_split) == 3:
            return False, False

        for i in range(2):
            val = token_split[i]
            
            need = len(val) % 4
            val += "=" * need

            try:
                base64.standard_b64decode(val)
            except:
                return True, False
            
            return False, True
            
    def check_api_key(self, value: str):
        if len(value) not in [32, 64, 128]:
            return False, False
        
        try:
            bytes.fromhex(value)
        except ValueError:
            return False, False
        
        return False, True

    def check_for(self, action: str, key: str, values: str):
        if action == "check":
            return self.check_name_and_count(key, values)
        if action == "guid_token":
            return self.check_with(values, self.check_guid)
        if action == "jwt_token":
            return self.check_with(values, self.check_jwt)
        if action == "api_key":
            return self.check_with(values, self.check_api_key)
        return False, False
    
    def get_current_datetime(self):
        current_time = datetime.utcnow()
        formatted_time = current_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        return formatted_time
    
    def upload_log_file(self, error_data) -> Tuple[str, dict]:
        if not isinstance(error_data, list):
            error_data = [error_data]
        file_url, error = self.upload_file_to_minio(
            file_content=error_data,
            file_name=f"LogFile-{str(uuid.uuid4())}.json",
            content_type="application/json"
        )
        if error:
            return None, {"Error": f"Error while uploading LogFile :: {error}"}
        return file_url, None
    
    def upload_log_file_panic(self, error_data) -> dict:
        file_url, error = self.upload_log_file(error_data)
        if error:
            return error
        return { 'LogFile': file_url }
    
    def upload_output_file(self, output_data, file_name) -> Tuple[str, dict]:
        if not output_data:
            return None, None
        
        file_url, error = self.upload_df_as_parquet_file_to_minio(
            df=pd.DataFrame(output_data),
            file_name=file_name
        )
        if error:
            return None, { 'error': f"Error while uploading {file_name} file :: {error}" }
        return file_url, None
