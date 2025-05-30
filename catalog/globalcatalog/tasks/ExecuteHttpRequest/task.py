from typing import overload
from compliancecowcards.structs import cards
#As per the selected app, we're importing the app package 
from applicationtypes.httprequest import httprequest
import http
from compliancecowcards.utils import cowdictutils
import json
import xmltodict
import uuid
import toml
import re
from urllib.parse import   parse_qs
import pandas as pd
import urllib.parse
import os
import requests
import jq
import base64
import copy
from http import HTTPMethod
import io
import magic
import gzip
import tarfile

class Task(cards.AbstractTask):

    auth_responses: dict[str, bytes|None] = {}

    def execute(self) -> dict:
        
        log_file = self.task_inputs.user_inputs.get("LogFile" , "")
        data_file = self.task_inputs.user_inputs.get("InputFile"  , "")
        error_details = []
        
        if not(log_file == "" or log_file == "<<MINIO_FILE_PATH>>" or log_file == None ): 
            if data_file == "" or data_file == "<<MINIO_FILE_PATH>>" or data_file == None :
                return {'LogFile' : log_file}
            else:
                input_log_details, error = self.download_log_file(log_file)
                error_details = input_log_details
                
        error = self.validate_inputs()
        if error :
            error_details.append({"Error" : error})
            return self.upload_log_file(error_details)
        
        http_request_file = self.task_inputs.user_inputs.get("RequestConfigFile" , "")
        http_response_file = self.task_inputs.user_inputs.get("ResponseConfigFile" , "")
        
        
        http_request_file_data,error = self.download_http_request_input_data(http_request_file)
        if error :
            error_details.append(error)
            return self.upload_log_file(error_details)
        
        http_response_file_data,error = self.download_http_response_input_data(http_response_file)
        if error :
            error_details.append(error)
            return self.upload_log_file(error_details) 
        
        resource_data,error = self.download_resource_data(data_file)
        if error :
            error_details.append(error)
            return self.upload_log_file(error_details)
        
        self.http_connector =  httprequest.HttpRequest(
                app_url=self.task_inputs.user_object.app.application_url,
                app_port=self.task_inputs.user_object.app.application_port,
                user_defined_credentials=httprequest.UserDefinedCredentials.from_dict(
                    self.task_inputs.user_object.app.user_defined_credentials)
                )
        
        http_request_file_data,error = self.resolve_config_placeholders(http_request_file_data)
        if error :
            error_details.append(error)
            return self.upload_log_file(error_details)
        
        is_valid_req , request_query_info = self.validate_request_data(http_request_file_data)
        if not is_valid_req :
            error_details.append({"Error" : request_query_info})
            return self.upload_log_file(error_details) 
        
        is_valid_credential_type = self.http_connector.validate_credetials_type(http_request_file_data.get("Request").get("CredentialType"))
        if not is_valid_credential_type:
            error_details.append({"Error" : "Invalid credentials or CredentialType mismatch between the application and RequestConfigFile.toml."})
            return self.upload_log_file(error_details)
        
        http_request_file_data = request_query_info 
        is_valid_res , error = self.validate_ruleset(http_response_file_data)
        if not is_valid_res :
            error_details.append(error)
            return self.upload_log_file(error_details) 
        
        
        output = []
        if not resource_data :
            resource_data.append({})
            
        for data in resource_data :
            http_request_file_data_copy = copy.deepcopy(http_request_file_data)
            http_response_ , content_type, error = self.process_api_request_and_responce(
                http_request_file_data_copy ,data , http_response_file_data )
            if error :
                error_details.append({"Error" : error})
            if isinstance(http_response_ , list) :
                output.extend(http_response_)
            else :
                output = http_response_
                
        if isinstance(http_response_, (dict, list)):
            processed_output = self.http_connector.replace_empty_dicts_with_none(output)
        else:
            processed_output = http_response_
        response = {}
        if len(processed_output) > 0 :
            response = self.upload_output_file(file_content = processed_output ,file_name = "OutputFile",content_type = content_type)
        if len(error_details) > 0:
            log_file_response = self.upload_log_file(error_details)
            if cowdictutils.is_valid_key(log_file_response, 'LogFile'):
                response['LogFile'] = log_file_response["LogFile"]
            elif cowdictutils.is_valid_key(log_file_response, "Error"):
                return log_file_response
        
        return response


    def process_api_request_and_responce(self, 
        http_request_data , data_file,http_response_query ) -> tuple[list, str, list]: 
        
        result = []
        error_details = []
        
        response , error = self.process_api_request(
                http_request_data ,data_file,http_response_query 
                )
        if error :
            if response == None :
                return [], '', error
            error_details.extend(error)
            
        http_response_ = response.get('body', {} )
        content_type = response.get('headers', {} ).get("Content-Type","")
        
        if isinstance(http_response_, (dict, list)):
            if isinstance(http_response_ , list) :
                result.extend(http_response_)
            else :
                result.append(http_response_)
        else :
            result = http_response_
        
        if isinstance(http_response_, (dict, list)):
            http_response_,error = self.apply_input_rulesets_to_output(
                http_request_data , response , http_response_query , data_file)
            if error :
                error_details.extend(error)
                return [] , '', error_details
            result.extend(http_response_)
        else:
            if len(http_response_query.get("Response",{}).get("RuleSet",{}).get("PaginationCondition",{}).get("ConditionField",{})) > 0:
                error_details.extend([{"Error":f"The content type '{response.get('headers', {}).get('Content-Type', '')}' does not support pagination. This feature is only supported for 'application/json' and 'application/ld+json'."}])
            result = http_response_
        
        return result, response.get('response_file_type',''), error_details
    
    def apply_input_rulesets_to_output(
            self, http_request_data, response, http_response_query , data_file):
        
        result = []
        error_details = []
        
        request_data = http_request_data.get("Request", {})
        response_data = http_response_query.get("Response", {})
        
        pagination_condition = response_data.get("RuleSet", {}).get("PaginationCondition", {})
        proceed_append_column = True
        
        condition_field =  pagination_condition.get("ConditionField")
        if condition_field :
            parsed_value = ""
            if condition_field.startswith("<<response.") :
                value = f'.{condition_field.replace("response." , "")}'
                value = re.sub(r"<<(.*?)>>", r"\1", value)
                parsed_value = self.jq_filter_query(value, response)
                if not parsed_value :
                    proceed_append_column = False
            elif condition_field.startswith("<<responsebody.") :
                value = f'.{condition_field.replace("responsebody." , "")}'
                value = re.sub(r"<<(.*?)>>", r"\1", value)
                parsed_value = self.jq_filter_query(value, response.get("body" , {}))
                if not parsed_value :
                    proceed_append_column = False
                    
            if f"{parsed_value}" == f"{pagination_condition['ConditionValue']}" :
                proceed_append_column = False
                
        if not proceed_append_column :
            return result ,error_details
        
        pagination = response_data.get("RuleSet", {}).get("Pagination", {})
        if pagination:
            required_pagination_call = False

            context_dict = {
                'fromdate': self.task_inputs.from_date.strftime("%Y-%m-%d"),
                'todate': self.task_inputs.to_date.strftime("%Y-%m-%d"),
                'inputfile': data_file,
                'response': response
            }

            has_next_url, error_details = self.response_query_handle_next_url(pagination, request_data, error_details, context_dict)
            if error_details:
                return None, error_details

            has_header ,error_details = self.response_query_handle_headers(
                pagination, request_data, error_details, context_dict)
            if error_details:
                return None, error_details

            has_body ,error_details = self.response_query_handle_body(
                pagination, request_data, error_details, context_dict)
            if error_details:
                return None, error_details

            has_params, error_details = self.response_query_handle_params(
                pagination, request_data, error_details, context_dict)
            if error_details:
                return None, error_details
            
            if has_next_url or has_header or has_body or has_params :
                required_pagination_call = True
            
            if required_pagination_call :
            # Process API request and response
                http_response, _, error = self.process_api_request_and_responce(
                    http_request_data, data_file, http_response_query)
                if error:
                    error_details.append({"Error": error})
                    return result, error_details
                if isinstance(http_response, list):
                    result.extend(http_response)
                else:
                    result.append(http_response)
                
        return result, error_details

    def response_query_handle_next_url(self, pagination, request_data, error_details, context_dict):
        if not (value := str(pagination.get('URL', ''))):
            return False, error_details

        updated_value = self.response_query_replace_placeholders(value, context_dict, replace_double_quotes=False)
        request_data['URL'] = updated_value if updated_value else request_data['URL']

        return bool(updated_value), error_details

    def response_query_handle_headers(self, pagination, request_data, error_details, context_dict):
        has_header = False
        request_headers = {}
        if 'Header' in pagination:
            query_header = pagination.get("Header", {})
            # Initialize request_data["Headers"] if not present
            if "Headers" in request_data :
                request_data_headers = request_data.get("Headers", {})
            else:
                request_data["Headers"] = {}
                request_data_headers = {}

            query_header_str = json.dumps(query_header)

            if query_header_str:
                query_header_str = self.response_query_replace_placeholders(query_header_str, context_dict)
                
            request_headers, error = self.load_json(
                query_header_str,
                "Invalid placeholder/value provided in 'ResponseConfigFile.Response.RuleSet.Pagination.Header'",
                error_details)
            if error:
                error_details.append({'Error': error})
                return has_header, error_details
            
            if request_headers :
                request_headers_temp = copy.deepcopy(request_headers)
                for key, value in request_headers.items() :
                    if value == "" or value == None :
                        request_headers_temp.pop(key)
                        
                if request_headers_temp :
                    request_data_headers.update(request_headers_temp)
                    request_data["Headers"] = request_data_headers
                    has_header = True
        return has_header,error_details

    def response_query_handle_body(self, pagination, request_data, error_details, context_dict):
        has_body =False
        body_type = next(
            (key for key in ["URLEncoded", "FormData", "Raw", "Binary"] 
             if key in pagination.get("Data", {})),
            ""
        )
        if  body_type == "URLEncoded" :
            request_data["ContentType"] = "application/x-www-form-urlencoded"
        elif  body_type == "FormData" :
            request_data["ContentType"] = "multipart/form-data"
        elif  body_type == "Raw" :
            request_data["ContentType"] = "application/json"
        elif  body_type == "Binary" :
            request_data["ContentType"] = "application/octet-stream"
            
        if body_type:
             # Initialize request_data["Data"] if not present
            if "Data" in request_data and body_type in request_data.get("Data", {}):
                request_data_body = request_data["Data"].get(body_type, {})
                if body_type == "Raw" :
                    request_data_body, body_error = self.load_json(
                        request_data_body.get("Value" , ""),
                        "Invalid JSON string provided in 'RequestConfigFile.Request.Data.Raw'",
                        error_details
                    )
                    if body_error:
                        return has_body, error_details
            else:
                request_data["Data"] = {body_type: {}}
                request_data_body = {}

            request_body = {}
            query_body = pagination["Data"].get(body_type, {})

            if body_type == "Raw" :
                query_body_str = str(query_body.get('Value', ''))
            else:
                query_body_str = json.dumps(query_body)

            updated_query_body_str = self.response_query_replace_placeholders(query_body_str, context_dict)

            request_body, body_error = self.load_json(
                updated_query_body_str,
                "Invalid value provided in response body :: 'ResponseConfigFile.RuleSet.Pagination.Data'",
                error_details
            )
            if body_error:
                return has_body, error_details

            if request_body :
                request_body_temp = copy.deepcopy(request_body)
                for key, value in request_body.items() :
                    if value == "" or value == None :
                        request_body_temp.pop(key)
                        
                if request_body_temp :
                    request_data_body.update(request_body_temp)
                    if body_type == "Raw" :
                        request_data["Data"]["Raw"] = { "Value" :json.dumps(request_data_body) }
                    else:
                        request_data["Data"][body_type] = request_data_body
                    has_body = True
                    
        return has_body,error_details

    def response_query_handle_params(self, pagination, request_data, error_details, context_dict):
        has_param =False
        if 'Params' in pagination:
            request_params = {}
            query_params = pagination.get("Params", {})
            # Initialize request_data["Params"] if not present
            if "Params" in request_data:
                request_data_params = request_data.get("Params", {})
            else:
                request_data["Params"] = {}
                request_data_params = {}
                
            query_params_str = json.dumps(query_params)

            if query_params_str:
                query_params_str = self.response_query_replace_placeholders(query_params_str, context_dict)
                
            request_params, error = self.load_json(
                query_params_str,
                "Invalid placeholder/value provided in 'ResponseConfigFile.Response.RuleSet.Pagination.Params'",
                error_details)
            if error:
                error_details.append({'Error': error})
                return has_param, error_details
            
            if request_params :
                request_params_temp = copy.deepcopy(request_params)
                for key, value in request_params.items() :
                    if value == "" or value == None :
                        request_params_temp.pop(key)
                        
                if request_params_temp :
                    request_data_params.update(request_params_temp)
                    request_data["Params"] = request_data_params
                    has_param = True
        return has_param ,error_details

    def response_query_replace_placeholders(self, value_string: str, context_dict: dict, replace_double_quotes = True):
        updated_value_string = value_string
        placeholder_matches: list[str] = re.findall(r'<<(.+?)>>', value_string)
        for match in placeholder_matches:
            path = match.strip()
            if not path.startswith('.'):
                path = '.' + path
            parsed_value = self.jq_filter_query(path, context_dict)
            parsed_value = str(parsed_value).replace('"', "'") if replace_double_quotes else str(parsed_value)
            updated_value_string = str(updated_value_string).replace(f'<<{match}>>', parsed_value)
        
        return updated_value_string
    
    def response_query_handle_append_columns_handler(self,
            response , response_json, request_data ,rule_set, data_file):
        
        if isinstance(response_json , list) :
            updated_response_json = []
            for response_json_obj in response_json :
                updated_response_json_obj, error = self.response_query_handle_append_columns(
                    response, response_json_obj, request_data, rule_set, data_file
                )
                if error :
                    return None ,error
                updated_response_json.append(updated_response_json_obj)
            return updated_response_json,None
        else:
            return self.response_query_handle_append_columns(
                    response, response_json, request_data, rule_set, data_file
                )

    
    def response_query_handle_append_columns(self,
            response , response_json, request_data ,rule_set, data_file):

        modified_response = copy.deepcopy(response)  
        if "response_file_type" in modified_response:
            del modified_response["response_file_type"]

        context_dict = {
            'inputfile': data_file,
            'request': request_data,
            'response': modified_response,
            'responsebody': modified_response.get("body" , {})
        }

        proceed_append_column = False
        condition = rule_set.get("AppendColumnCondition")
        if condition :
            condition_field =  condition["ConditionField"]
            if condition_field != "" :
                parsed_value = ""
                condition_field = condition_field.strip()
                if condition_field.startswith('<<'):
                    condition_field_path = condition_field.strip('<>')
                    if not condition_field_path.startswith('.'):
                        condition_field_path = '.' + condition_field_path
                    parsed_value = self.jq_filter_query(condition_field_path, context_dict)
                    
                if f"{parsed_value}" == f"{condition['ConditionValue']}" :
                    proceed_append_column = True
            else:    
                proceed_append_column = True
                
        if not proceed_append_column :
            return response_json ,"'AppendColumn' query does not satisfied."
        
        append_column = rule_set.get("AppendColumn", {})
        if append_column["IncludeAllInputFields"] :
            response_json.update(data_file)
        
        append_column_fields = append_column['Fields']
        if append_column_fields:
            append_columns_str = json.dumps(append_column_fields)
            append_columns_str = self.response_query_replace_placeholders(append_columns_str, context_dict)

            try:
                updated_append_column_fields = json.loads(append_columns_str)
            except json.JSONDecodeError:
                return response_json, "Invalid value provided in one of 'ResponseConfigFile.Response.RuleSet.AppendColumn.Fields'"

            response_json.update(updated_append_column_fields)
        
        return response_json ,None
    
    def process_api_request(self, http_request_data, data_file, http_response_query):
        request_data = http_request_data.get('Request', {})
        error_details = []
        request_data["Method"] = request_data["Method"].upper()
        
        body = {}
        if request_data["Method"] !=  HTTPMethod.GET  :
            body, error = self.prepare_body(request_data["ContentType"], request_data["Data"], data_file)
            if error:
                return None, [{"Error": error}]

        for i in range(2):
            response, error = self.generate_auth_and_make_api_call(request_data, data_file, body)
            if error:
                if i == 0 and isinstance(error, str) and error.startswith('Unauthorized - ') and self.auth_responses:
                    # Try resetting existing auth_responses, to force creating new one, in case of 'Unauthorized' response
                    self.auth_responses = {}
                    continue
                if response:
                    error_details.append({"Error": error})
                else:
                    return None, [{'Error': error}] if isinstance(error, str) else error
            break
        
        converted_response, response_file_type, error = self.convert_response(response)
        if error:
            return None, [{"Error": error}]
        
        request_data = http_request_data.get("Request", {})
        input_response_data = http_response_query.get("Response", {})
        
        append_column = input_response_data.get("RuleSet", {})
        required_append_column_call = bool(append_column)
        
        response_dict = {
                'body': converted_response,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'cookies': dict(response.cookies),
                'url': response.url,
                'links': response.links,
                'response_file_type' : response_file_type
            }
        if (required_append_column_call and not("<<responsebody." in str(append_column)) and isinstance(converted_response, (dict, list))):
            converted_response, error = self.response_query_handle_append_columns_handler(
                response_dict, converted_response, request_data, append_column, data_file
            )
            if error:
                error_details.append({"Error": f"Invalid data in ResponseConfigFile.RuleSet.AppendColumns: {error}"})
        elif required_append_column_call:
                error_details.append({"Error":f"The content type '{response.headers.get('Content-Type', '')}' does not support appending column fields. This feature is only supported for 'application/json' and 'application/ld+json'."})
        
        return response_dict, error_details

    def resolve_config_placeholders(self , http_request_data) :
        
        constant_variables = http_request_data.get('Variables', {})
        request_data_json = http_request_data.get('Request', {})
        
        error_message = []
        for key, value in constant_variables.items():
            if not isinstance(value, str): 
                error_message.append(f"Key: {key}, Value: {value} is of type {type(value)}")
        
        if error_message :
            return None , {"Error" : f"Only 'string' type values are allowed in request_config_file['variable'] :: {','.join(error_message)}"}
                
        request_data_str = json.dumps(request_data_json)
        matches = re.findall(r"<<((?!response\.|responsebody\.|validationCURLresponse\.|application\.|inputfile\.)[^>]+)>>", request_data_str)

        missing_variable = []
        for placeholder_key in matches:
            placeholder_key = placeholder_key.strip()
            
            # We are skipping the JWTBearer placeholder since the authorization is handled through the placeholder in the header. 
            # This placeholder will be replaced in the `generate_auth_and_form_url_and_body()` function.
            if placeholder_key == "" or placeholder_key == "JWTBearer" :
                continue
            if placeholder_key == "fromdate"  :
                request_data_str = request_data_str.replace( "<<fromdate>>" , self.task_inputs.from_date.strftime("%Y-%m-%d"))
            elif placeholder_key == "todate" :
                request_data_str = request_data_str.replace( "<<todate>>" , self.task_inputs.to_date.strftime("%Y-%m-%d"))
            elif placeholder_key == "random_uuid4" :
                request_data_str = request_data_str.replace( "<<random_uuid4>>" ,str(uuid.uuid4()))
            else:
                parsed_value = self.jq_filter_query(f".{placeholder_key}", constant_variables)
                if parsed_value  : 
                    request_data_str = request_data_str.replace(f"<<{placeholder_key}>>" , parsed_value)
                else:
                    missing_variable.append(placeholder_key)

        error_obj = {}
        if missing_variable :
            if len(missing_variable) == 1:
                error_obj["Error"]  =  f"'{missing_variable[0]}' is missing in request_config variables"
            else:
                fields = ", ".join(missing_variable[:-1]) + " and " + missing_variable[-1]
                error_obj["Error"] =  f"'{fields}' are missing in request_config variables"

        request_data_json = {}
        try :
            request_data_json = json.loads(request_data_str)
        except json.JSONDecodeError as e: 
            return None,  {"Error" : f'Invalid JSON format - {e}'}
        http_request_data['Request'] = request_data_json
        
        return http_request_data , error_obj 
    
    def generate_auth_and_form_url_and_body(
        self ,request_data ,data_file , body  ) :


        credential_type = request_data["CredentialType"]
        url_endpoint = request_data["URL"] 
        params_obj = request_data.get("Params" ,{})
        params = json.dumps(params_obj)      
        auth_header = request_data.get("Headers" , {})
        header = json.dumps(auth_header)      
        parsed_url = ""
        parsed_body = {}
        parsed_params = {}
        error_details = []

        existing_auth_response = self.auth_responses.get(credential_type)
        
        app_info = self.task_inputs.user_object.app.user_defined_credentials.get(credential_type, {}) or {}
        if not app_info and credential_type != 'NoAuth':
            return auth_header, parsed_url, parsed_body, parsed_params, [{"Error": f"Could not find '{credential_type}' credential type in Application."}]

        app_info["AppURL"] = self.task_inputs.user_object.app.application_url
       
        if credential_type == "NoAuth" :
            pass
        elif credential_type == "BasicAuthentication" :
            basic_auth_header ,error = self.http_connector.generate_basic_auth()
            if error :
                error_details.append({"Error" : error})
                return auth_header, parsed_url ,parsed_body ,parsed_params,  error_details
            if '<<BasicAuthentication>>' in header :
                header_ = header.replace('<<BasicAuthentication>>' , basic_auth_header['Authorization'] )
                auth_header = json.loads(header_) if header_ else {}
            else:
                auth_header['Authorization'] = basic_auth_header['Authorization'] 
        
        elif credential_type == "APIKey" :
            api_key_header ,error = self.http_connector.generate_api_key()
            if error :
                error_details.append({"Error" : error})
                return auth_header, parsed_url ,parsed_body ,parsed_params,  error_details           
            if '<<APIKey>>' in header :
                header_ = header.replace('<<APIKey>>' , api_key_header['Authorization'] )
                auth_header = json.loads(header_) if header_ else {}
            else:
                auth_header['Authorization'] = api_key_header['Authorization'] 
                    
        elif credential_type == "BearerToken" :
            bearer_token_header ,error = self.http_connector.generate_bearer_token()
            if error :
                error_details.append({"Error" : error})
                return auth_header, parsed_url ,parsed_body ,parsed_params,  error_details
            if '<<BearerToken>>' in header :
                header_ = header.replace('<<BearerToken>>' , bearer_token_header['Authorization'] )
                auth_header = json.loads(header_) if header_ else {}
            else:
                auth_header['Authorization'] = bearer_token_header['Authorization'] 
        
        elif credential_type == "JWTBearer" :
            if "<<JWTBearer>>" in header:
                payload =self.task_inputs.user_object.app.user_defined_credentials.get('JWTBearer', {}).get('Payload', {})
                private_key = self.task_inputs.user_object.app.user_defined_credentials.get('JWTBearer', {}).get("PrivateKey", '')
                algorithm = self.task_inputs.user_object.app.user_defined_credentials.get('JWTBearer', {}).get('Algorithm', '')
                
                token, error =  self.http_connector.generate_jwt_token(algorithm , private_key , payload)
                if error :
                    error_details.append({"Error" : error})
                    return auth_header, parsed_url ,parsed_body ,parsed_params,  error_details
                auth_header = header.replace("<<JWTBearer>>", token)
                auth_header = json.loads(auth_header) if auth_header else {}
            else:
                # If self.auth_responses is not empty, we try to re-use the auth response value from that
                if existing_auth_response:
                    raw_response = existing_auth_response
                else:   
                    raw_response ,error = self.http_connector.generate_jwt_bearer()
                    if error :
                        error_details.append({"Error" : error})
                        return auth_header, parsed_url ,parsed_body ,parsed_params,  error_details
                    self.auth_responses[credential_type] = raw_response

                auth_header ,error = self.update_curl_resp_in_headers( header , raw_response)
                if error :
                    error_details.append({"Error" : error})
                
        elif credential_type == "OAuth" :
            # If self.auth_responses is not empty, we try to re-use the auth response value from that
            if existing_auth_response:
                raw_response = existing_auth_response
            else:
                raw_response ,error = self.http_connector.generate_o_auth()
                if error :
                    error_details.append({"Error" : error})
                    return auth_header, parsed_url ,parsed_body ,parsed_params,  error_details
                self.auth_responses[credential_type] = raw_response
            auth_header ,error = self.update_curl_resp_in_headers( header , raw_response)
            if error :
                error_details.append({"Error" : error})
                
                
        elif credential_type == "CustomType" :
            # If self.auth_responses is not empty, we try to re-use the auth response value from that
            if existing_auth_response:
                raw_response = existing_auth_response
            else:
                raw_response ,error = self.http_connector.generate_custom_type()
                if error :
                    error_details.append({"Error" : error})
                    return auth_header, parsed_url ,parsed_body ,parsed_params,  error_details
                self.auth_responses[credential_type] = raw_response

            if raw_response and header :
                auth_header ,error = self.update_curl_resp_in_headers( header , raw_response)
                if error :
                    error_details.append({"Error" : error})
            
            # Error handling not required
            app_info_,error_ = self.http_connector.get_credential_json_data()
            app_info.update(app_info_)
                
        elif credential_type == "AWSSignature":
            
            url_endpoint, error = self.replace_placeholders(url_endpoint, credential_type , app_info, data_file)
            if error :
                error_details.extend(error)
            
            service_name,region , error = self.extract_service_region(url_endpoint)
            if error : 
                error_details.append(
                    {"Error" : "Invalid 'AWS' endpoint could able to find service and region from given url."})
                return auth_header, parsed_url ,parsed_body ,parsed_params,  error_details
            
            parsed_params = {}
            if params :
                try:
                    params = params.replace("None", '""')
                    parsed_params_temp,error =  self.replace_placeholders(
                        params, credential_type , app_info, data_file)
                    if error :
                        error_details.extend(error)
                    parsed_params = json.loads(parsed_params_temp) if parsed_params_temp else {}
                except json.JSONDecodeError as e:
                    error_details.append({"Error" : "Invalid JSON string provided in 'RequestConfigFile.Params'"})
                    return auth_header, parsed_url ,parsed_body ,parsed_params,  error_details

            query_string = ""
            if parsed_params :
                query_string = urllib.parse.urlencode(parsed_params)
            auth_header_ ,error = self.http_connector.generate_aws_iam_signature( auth_header,
                service_name ,region ,url_endpoint ,body, query_string , request_data["Method"])
            if error :
                error_details.append({"Error" : error})
            auth_header = auth_header_ | auth_header
        else:
            error_details.append({"Error" :  "Invalid credential type supported types are 'Azure, BasicAuthentication, APIKey, AWSIAM, AWSRole'."})
            return auth_header, parsed_url ,parsed_body ,parsed_params ,error_details
        
        parsed_url , parsed_body ,parsed_params,error = self.parse_request_info(
            credential_type ,app_info ,data_file, url_endpoint , body , params
        )
        if error :
            error_details.extend(error)
            
        parsed_header,error  = self.replace_placeholders(json.dumps(auth_header), None , app_info, data_file)
        if error :
            return None, parsed_url ,parsed_body ,parsed_params,  [{"Error" : error}]
        
        auth_header = {}
        try:
            auth_header  = json.loads(parsed_header)
        except json.JSONDecodeError as e:
            return None, parsed_url ,parsed_body ,parsed_params,  [{"Error" : f'Invalid JSON format - {e}'}]
        return auth_header, parsed_url ,parsed_body ,parsed_params,  error_details

    def generate_auth_and_make_api_call(self, request_data, data_file, body):
        auth_header, parsed_url, parsed_body, parsed_params, error_info = self.generate_auth_and_form_url_and_body(
            request_data, data_file, body )
        if error_info:
            return None, error_info
        
        parsed_headers, error = self.create_request_header(
            request_data.get("Headers", {}).get("Headers", {}),
            request_data.get("ContentType", ""),
            auth_header
        )
        if error:
            return None, [{"Error": error}]
        
        api_request_info = {
            "URL": parsed_url,
            "Method": request_data.get("Method", ""),
            "Redirect": request_data.get("Redirect", False),
            "Verify" : request_data.get("Verify", True),
            "CredentialType": request_data.get("CredentialType", ""),
            "ContentType": request_data.get("ContentType", ""),
            "Params": parsed_params,
            "Body": parsed_body,
            "Headers": parsed_headers,
            "Retries": request_data.get("Retries", 3),
            "RetryOnStatus": request_data.get("RetryOnStatus", []),
            "TimeOut": request_data.get("TimeOut", 30),
            "Files": {}
        }
        
        
        if request_data.get("ContentType", "") in ["multipart/form-data", "application/x-www-form-urlencoded"]:
            files = {}
            temp_body = parsed_body.copy()
            if parsed_body:
                number_of_file = 1
                for key, value in parsed_body.items():
                    if isinstance(value, str) and (value.startswith("https://") or value.startswith("http://")):
                        file_name = os.path.basename(value)
                        file_content, error = self.download_file_from_minio(value)
                        if error:
                            return None, [{"Error": f"Error while downloading {request_data['ContentType']} files, "
                                                "assuming all the file paths are MinIO file paths."}]
                        files[f"file{number_of_file}"] = (file_name, file_content)
                        number_of_file += 1
                        del temp_body[key]
        
            api_request_info["Files"] = files if files else None
            api_request_info["Body"] = temp_body if files else parsed_body  
            
        return self.http_connector.make_api_call(api_request_info)
    
    def parse_request_info(self ,app_type ,app_info ,data_file, raw_url , body , params) :
        
        parsed_body ,parsed_params = {} ,{}
        error_details = []
        
        parsed_url,error  = self.replace_placeholders(raw_url, app_type , app_info, data_file)
        if error :
            error_details.extend(error)
        
        if isinstance(body , bytes ) :
            parsed_body = body
        elif body :
            parsed_body_temp,error  = self.replace_placeholders(json.dumps(body), app_type , app_info, data_file)
            if error :
                error_details.extend(error)
            parsed_body = json.loads(parsed_body_temp) if parsed_body_temp else {}
        if params :
            try:
                params = params.replace("None", '""')
                parsed_params_temp,error =  self.replace_placeholders(params, app_type , app_info, data_file)
                if error :
                    error_details.extend(error)
                parsed_params = json.loads(parsed_params_temp) if parsed_params_temp else {}
            except json.JSONDecodeError as e:
                error_details.append({"Error" : "Invalid JSON string provided in 'RequestConfigFile.Params'"})
                return  parsed_url ,parsed_body ,parsed_params ,error_details
        
        return parsed_url, parsed_body ,parsed_params , error_details
    
    def update_curl_resp_in_headers(self ,header , raw_response) :
        
        response_json = {}
        try:
            response_json = json.loads(raw_response) if raw_response else {}
        except json.JSONDecodeError as e:
            # handle only json response body
            pass
        
        place_holder = "validationCURLresponse"
        if "<<response." in header and "<<validationCURLresponse." not in header:
            place_holder = "response"
            
        parsed_header, error = self.http_connector.replace_placeholder(
            header ,
            place_holder, response_json
            )
        if error :
            return None , {'Error': 'Error while processing place holders.'} 
        try:
            auth_header = json.loads(parsed_header) if parsed_header else {}
        except json.JSONDecodeError as e:
            return  None, {"Error": f"Failed to decode JSON: {e}"}
        
        return auth_header , None
    
    def download_http_request_input_data(self,http_request_file) :
        
        toml_bytes, error = self.download_file_from_minio(http_request_file)
        if error:
            return None, {"Error" : error}

        http_request_data =  toml.loads(toml_bytes.decode('utf-8'))
        
        return http_request_data, None
        
    def download_http_response_input_data(self,http_response_file) :
        
        default_response_data = {
            "Response": {
                "RuleSet": {}
            }
        }
        
        http_response_data = None
        if http_response_file == None or http_response_file == "" or http_response_file == "<<MINIO_FILE_PATH>>": 
            http_response_data = default_response_data
        else:
            toml_bytes, error = self.download_file_from_minio(http_response_file)
            if error:
                return None,  {"Error" : error}
            
            http_response_data =  toml.loads(toml_bytes.decode('utf-8'))
         
        if http_response_data == {} :
            http_response_data = default_response_data
            
        return http_response_data ,None
    
    def download_resource_data(self,data_file) :
        
        data_file_json_formate = [{}]
        
        if not(data_file == None or data_file == "" or data_file == "<<MINIO_FILE_PATH>>"): 
        
            data_file_bytes, error = self.download_file_from_minio(file_url=data_file)
            if error != None :
                return None,  {"Error" : error}

            try :
                data_file_json_formate = json.loads(data_file_bytes)
            except json.JSONDecodeError as e: 
                return None,  {"Error" : f'Invalid JSON format - {e}'}
            if not data_file_json_formate :
                data_file_json_formate = [{}]
            
            if isinstance(data_file_json_formate, dict):
                data_file_json_formate = [data_file_json_formate]
        
        return data_file_json_formate,None
    
    def create_request_header(self,headers, content_type ,auth_header ):
        
        parsed_headers , error = self.http_connector.parse_content(headers)
        if error :
            return None, error
        
        for key, value in auth_header.items():
            parsed_headers[key] = value
        if 'Content-Type' not in parsed_headers and content_type != "" :
            parsed_headers['Content-Type'] = content_type
            
        return parsed_headers ,None

    def replace_placeholders(self,target_str, app_type , app_data, data_file):
        error_details = []
        
        
        # Replace App placeholders
        target_str, error = self.http_connector.replace_placeholder(target_str, "application.", app_data)
        if error :
            error_details.append(error)
            
        # Replace InputFile placeholders
        target_str ,error= self.http_connector.replace_placeholder(target_str, "inputfile.", data_file)
        if error :
            error_details.append(error)
            
        if "<<fromdate>>" in target_str :
            target_str = target_str.replace( "<<fromdate>>" , self.task_inputs.from_date.strftime("%Y-%m-%d"))
        
        if "<<todate>>" in target_str :
            target_str = target_str.replace( "<<todate>>" , self.task_inputs.to_date.strftime("%Y-%m-%d"))
        
        return target_str, error_details
    
    def validate_request_data(self , request_query):
        if isinstance(request_query, str):
            try:
                request_query = json.loads(request_query)
            except json.JSONDecodeError:
                return False, "Invalid JSON format"

        # Check for the Request field
        request_data = request_query.get("Request")
        if not isinstance(request_data, dict):
            return False, "Field 'Request' must be a dictionary"
        
        # Ensure Data, Headers, and Params fields exist and set default values if missing
        if "Data" not in request_data:
            request_data["Data"] = {}  # Default to an empty dictionary
        if "Headers" not in request_data:
            request_data["Headers"] = {}  # Default to an empty headers structure
        if "Params" not in request_data:
            request_data["Params"] = {}  # Default to an empty params structure

        
        # Define mandatory fields and their requirements
        mandatory_fields = {
            "Method": ["GET", "POST", "PUT", "DELETE", "PATCH"],
            "URL": str,
            "CredentialType": ["AWSSignature", "BasicAuthentication", "BearerToken", "CustomType", "OAuth" , "APIKey","JWTBearer", "NoAuth"],
            "ContentType": [None, "", "multipart/form-data", "application/x-www-form-urlencoded", "application/json", "application/octet-stream"],
            "Redirect": bool,
            "Verify" : bool
        }

        # Validate mandatory fields
        for field, expected in mandatory_fields.items():
            if field not in request_data:
                return False, f"Missing mandatory field: '{field}'"
            
            value = request_data[field]
            if field == "Method":
                value = value.upper()

            if isinstance(expected, list):  # If the expected type is a list of valid values
                if value not in expected:
                    return False, f"Field '{field}' must be one of {expected}"
            elif not isinstance(value, expected):  # Validate type
                return False, f"Field '{field}' must be of type {expected.__name__}"

        return True, request_query

    
    def validate_ruleset(self, response_query):
        if isinstance(response_query, str):
            try:
                response_query = json.loads(response_query)
            except json.JSONDecodeError:
                return False, "Invalid format 'ResponseConfigFile'"
        
        json_data = response_query.get("Response", {})
        if not json_data:
            return False, "Missing mandatory field: 'Response' in 'ResponseConfigFile'"
        
        # Validate the 'RuleSet' field
        rule_set = json_data.get("RuleSet")
        if not isinstance(rule_set, dict):
            return False, "Field 'RuleSet' must be a dictionary in 'ResponseConfigFile.Response.RuleSet'"
        
        # Validate 'AppendColumnCondition'
        append_column_condition = rule_set.get("AppendColumnCondition")
        if append_column_condition:
            if not isinstance(append_column_condition, dict):
                return False, "'AppendColumnCondition' must be a dictionary in 'ResponseConfigFile.Response.RuleSet'"
            required_fields = {"ConditionField": str, "ConditionValue": str}
            for field, expected_type in required_fields.items():
                if field not in append_column_condition:
                    return False, f"Missing '{field}' in 'AppendColumnCondition'"
                if not isinstance(append_column_condition[field], expected_type):
                    return False, f"Field '{field}' in 'AppendColumnCondition' must be of type {expected_type.__name__}"

        # Validate 'AppendColumn'
        append_column = rule_set.get("AppendColumn")
        if append_column:
            if not isinstance(append_column, dict):
                return False, "'AppendColumn' must be a dictionary in 'ResponseConfigFile.Response.RuleSet'"
            if "IncludeAllInputFields" not in append_column or not isinstance(append_column["IncludeAllInputFields"], bool):
                return False, "'IncludeAllInputFields' must be a boolean in 'AppendColumn'"
            fields = append_column.get("Fields")
            if not isinstance(fields, dict):
                return False, "'Fields' must be a dictionary in 'AppendColumn'"

        # Validate 'PaginationCondition'
        pagination_condition = rule_set.get("PaginationCondition")
        if pagination_condition:
            if not isinstance(pagination_condition, dict):
                return False, "'PaginationCondition' must be a dictionary in 'ResponseConfigFile.Response.RuleSet'"
            required_fields = {"ConditionField": str, "ConditionValue": str}
            for field, expected_type in required_fields.items():
                if field not in pagination_condition:
                    return False, f"Missing '{field}' in 'PaginationCondition'"
                if not isinstance(pagination_condition[field], expected_type):
                    return False, f"Field '{field}' in 'PaginationCondition' must be of type {expected_type.__name__}"

        # Validate 'Pagination'
        pagination = rule_set.get("Pagination")
        if pagination:
            if not isinstance(pagination, dict):
                return False, "'Pagination' must be a dictionary in 'ResponseConfigFile.Response.RuleSet'"
            header = pagination.get("Header")
            if header and not isinstance(header, dict):
                return False, "'Header' must be a dictionary in 'Pagination'"
            query_params = pagination.get("Params")
            if query_params and not isinstance(query_params, dict):
                return False, "'QueryParams' must be a dictionary in 'Pagination'"
            
            request_body = pagination.get("Data")
            if request_body :
                data_url_encoded = request_body.get("URLEncoded")
                if data_url_encoded and not isinstance(data_url_encoded, dict):
                    return False, "'URLEncoded' must be a dictionary in 'Pagination'"
                form_data = request_body.get("FormData")
                if form_data and not isinstance(form_data, dict):
                    return False, "'FormData' must be a dictionary in 'Pagination'"
                data_raw = request_body.get("Raw",{}).get("Value" , "")
                if data_raw and not isinstance(data_raw, str):
                    return False, "'Raw.Value' must be a string in 'Pagination'"
                binary_data = request_body.get("Binary")
                if binary_data and not isinstance(binary_data, dict):
                    return False, "'Binary' must be a dictionary in 'Pagination'"
                

        return True, None

    def convert_response(self, response):
        
        successful_statues = [http.HTTPStatus.OK,http.HTTPStatus.ACCEPTED , http.HTTPStatus.NO_CONTENT ,http.HTTPStatus.CREATED]
        if not (response.status_code in successful_statues):
            return None, "", [{"Error": response.text}]

        content_type = response.headers.get('Content-Type', '').lower()
                        
        # Handle binary/octet-stream, application/octet-stream response 
        if 'octet-stream' in content_type:
            try:
                try:
                    if len(response.content) > 0:
                        response_data = response.content 
                    else:
                        response_data = response.text
                except Exception as e:
                    return None, "", f"Error processing api response: {e}"

                mime = magic.Magic(mime=True)    
                mime_type = mime.from_buffer(response_data)
                if mime_type:
                    content_type = mime_type
                else:
                    content_type = "text/plain"
            except Exception as e:
                content_type = "text/plain"
                                
        # Handle empty response
        if content_type == "" :
            data = {}
        # Handle JSON response
        elif ("application/" in content_type or "text/" in content_type) and "json" in content_type:
            try:
                data = response.json()
                if not data:
                    data = {"data": response.text}
            except requests.exceptions.JSONDecodeError:
                data = {"data": response.text}
            except ValueError as e:
                return None, "", f"Error parsing api response JSON: {e}"
        
        else:
            try:
                if len(response.content) > 0:
                    data = response.content 
                else:
                    data = response.text 
            except Exception as e:
                return None, "", f"Error processing api response: {e}"

        return data, content_type, None

    def formate_response(self, response, content_type):

        if content_type == "" :
            if not (response and isinstance(response, list)):
                response = {}
            response_df = pd.DataFrame(response)
            return (response_df).to_json(orient='records').encode('utf-8'), "json", None          
        
        elif 'text/csv'in content_type or 'application/csv' in content_type :
            try:
                bytes_io = io.BytesIO(response)
                return pd.read_csv(bytes_io), "csv", None
            except Exception as e:
                return None, None, f"Error processing API response with Content-Type: {content_type}. Details: {e}."
        
        elif 'application/x-yaml' in content_type or 'application/yaml' in content_type :
            return response, "yaml", None
        
        elif 'application/x-tar' in content_type or 'application/tar' in content_type :
            return response, "tar", None
        
        elif 'application/xml' in content_type or 'xml' in content_type:
            return response, "xml", None
        
        elif 'application/x-gzip' in content_type or 'application/gzip' in content_type:
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(response)) as gz_file:
                    decompressed_data = gz_file.read()
                    
                    # Check if the decompressed data is a TAR archive
                    if tarfile.is_tarfile(io.BytesIO(decompressed_data)):
                        return response, "tar.gz", None
                    else:
                        return response, "gz", None
            except Exception as e:
                return None, None, f"Error processing API response with Content-Type: {content_type}. Details: {e}."
        
        elif 'application/zip' in content_type or 'application/x-zip' in content_type:
            return response, "zip", None
        
        elif 'text/plain' in content_type or 'text'in content_type:
            try:
                extension=""
                if "text/plain" in content_type:
                    extension = "txt"
                elif "javascript" in content_type:
                    extension = "js"
                else:
                    extension = content_type.split("/")[-1] if "/" in content_type and len(content_type.split("/")) > 1 else "txt"
                return response, extension, None
            except Exception as e:
                return None, None, f"Error processing API response with Content-Type: {content_type}. Details: {e}."
            
        elif ("application/json" in content_type or "application/ld+json" in content_type) or isinstance(response, (dict, list)):
            try:
                extension = "json"
                response_df = pd.DataFrame(response)
                if "application/ld+json" in content_type:
                    extension = "jsonld"
                return (response_df).to_json(orient='records').encode('utf-8'), extension, None
            except Exception as e:
                return None, None, f"Error processing API response with Content-Type: {content_type}. Details: {e}."
        else:
            return None, None, f"Unsupported API response Content-Type: {content_type}."

    
    def extract_service_region(self,url):

        # Pattern for standard AWS service URLs with region
        pattern_service_with_region = r"(?P<service>[\w\-]+)\.(?P<region>[\w\-]+)\.amazonaws\.com"
        # Pattern for global services without region (e.g., IAM, global S3 URLs)
        pattern_global_service = r"(?P<service>[\w\-]+)\.amazonaws\.com"
        # Pattern for S3 bucket with region (e.g., <bucket-name>.s3.<region>.amazonaws.com/?publicAccessBlock=null/?publicAccessBlock=null)
        pattern_s3_with_region = r"(?P<bucket>[\w\-]+)\.(?P<service>s3)\.(?P<region>[\w\-]+)\.amazonaws\.com"
        # Pattern for global S3 bucket without region (e.g., <bucket-name>.s3.amazonaws.com/?publicAccessBlock=null/?publicAccessBlock=null)
        pattern_s3_global = r"(?P<bucket>[\w\-]+)\.(?P<service>s3)\.amazonaws\.com"
        # Check if URL matches S3 bucket with region
        match_s3_with_region = re.search(pattern_s3_with_region, url)
        if match_s3_with_region:
            service = match_s3_with_region.group('service')
            region = match_s3_with_region.group('region')
            return service, region ,None

        # Check if URL matches S3 global bucket without region
        match_s3_global = re.search(pattern_s3_global, url)
        if match_s3_global:
            service = match_s3_global.group('service')
            return service, "us-east-1" ,None

        # Check if URL matches standard service with region
        match_service_with_region = re.search(pattern_service_with_region, url)
        if match_service_with_region:
            service = match_service_with_region.group('service')
            region = match_service_with_region.group('region')
            return service, region , None

        # Check if URL matches global services (no region)
        match_global_service = re.search(pattern_global_service, url)
        if match_global_service:
            service = match_global_service.group('service')
            return service, "us-east-1" , None

        return None, None,  "Invalid AWS endpoint format"
        
    def load_json(self, data, error_message, error_details):
        try:
            return json.loads(data) if data else {}, None
        except json.JSONDecodeError:
            error_details.append({"Error": error_message})
            return None, error_message
        
    def prepare_body(self ,content_type, body_info, data_file):
        """Prepare the body based on the content type."""
        body = None
        error = None
        body_info_ = body_info
        if content_type == "" :
            return body , error
        
        if content_type == 'multipart/form-data':
            if "FormData" in body_info :
                body = body_info["FormData"]
        elif content_type == 'application/json':
            if "Raw" in body_info :
                body_info_ = body_info["Raw"].get("Value" , "")
            parsed_content,error = self.http_connector.parse_content(body_info_)
            if not error :
                body = json.dumps(parsed_content) if "Error" not in parsed_content else parsed_content
        elif content_type == 'application/x-www-form-urlencoded':
            if "URLEncoded" in body_info :
                body = body_info["URLEncoded"]
        elif content_type == 'application/octet-stream':
            if "Binary" in body_info :
                body_info_ = body_info["Binary"].get("Value" , "")
            if body_info_ :
                try:
                    # Replace InputFile placeholders
                    target_str ,error= self.http_connector.replace_placeholder(body_info_, "inputfile.", data_file)
                    if error:
                       return None , "Invalid Base64 input. Please check your payload."
                    body = base64.b64decode(target_str)
                except base64.binascii.Error:
                    return None , "Invalid Base64 input. Please check your payload."
        else:
            error =f"Unsupported content type: {content_type}"
        
        return body , error
    
    def flatten_data(self ,data):
        error_list = []
        for error in data :
            if not isinstance(error.get("Error" , ""), str) and error.get("Error" , None) is not None:
                modified_error = self.process_error(error)
                error_list.extend([{"Error": value} for value in modified_error])
            else:
                error_list.append(error)
        
        return error_list

    def process_error(self ,data, parent_key='', last_key='', sep='_'):

        flattened = set()
        if isinstance(data, dict):
            for key, value in data.items():
                flattened.update(self.process_error(value, parent_key, key, sep))
        elif isinstance(data, list):
            for i, value in enumerate(data):
                flattened.update(self.process_error(value, parent_key, last_key, sep))
        else:
            flattened.add(data)

        return flattened
    
    def validate_inputs(self):
        task_inputs = self.task_inputs
        if not task_inputs:
            return 'missing: Task inputs'

        user_object = self.task_inputs.user_object
        if (
            not user_object
            or not user_object.app
            or not user_object.app.user_defined_credentials
        ):
            return 'missing: User defined credentials'

        if not self.task_inputs.user_inputs: 
            return 'missing: User inputs'
        
        
        input_validation_report = ""
        
        http_request_file = self.task_inputs.user_inputs.get("RequestConfigFile" , "")
        if http_request_file == None or http_request_file == "" or http_request_file == "<<MINIO_FILE_PATH>>": 
            input_validation_report = "'RequestConfigFile' cannot be empty."
        
        if input_validation_report == "" :
            return None
        
        return input_validation_report
    
    def jq_filter_query(self, query, value_dict) :
        
        query = query + " // \"Query not found\""
        parsed_values = ["Query not found"]
        # Run the jq query
        if value_dict :
            parsed_values = jq.compile(query).input(value_dict).all()

        # Check the result
        if parsed_values and len(parsed_values) == 1 :
            if parsed_values[0] == "Query not found":
                return ""
            else: 
                return parsed_values[0]
        else:
            return parsed_values
    
    def upload_output_file(self, file_content=None , file_name=None,content_type=None):
        
        formatted_response, file_type, error = self.formate_response(file_content,content_type.lower())
        if error:
            return self.upload_log_file([{"Error" : error}])

        absolute_file_path, error = self.upload_file_to_minio(
            file_content = formatted_response,
            file_name = f'{file_name}-{str(uuid.uuid4())}.{file_type}',
            content_type = content_type
        )
        
        if error:
            return {"Error": error}
        return {'OutputFile': absolute_file_path}
    

    def upload_log_file(self, error_msg):
        
        flattened_data = self.flatten_data(error_msg)

        absolute_file_path, error = self.upload_file_to_minio(
            file_name=f'LogFile-{str(uuid.uuid4())}.json',
            file_content=json.dumps(flattened_data).encode(),
            content_type='application/json',
        )
        if error:
            return {"Error": error}
        return {'LogFile': absolute_file_path}

    def download_log_file(self, log_file):
        
        file_content, error = self.download_file_from_minio(
                    file_url=log_file)
        if error:
            return None, error
        json_string = file_content.decode('utf-8')
        json_data = json.loads(json_string) if json_string else {}

        return json_data , None
