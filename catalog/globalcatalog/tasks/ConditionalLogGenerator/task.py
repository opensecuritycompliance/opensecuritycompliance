
from typing import Tuple, overload
from compliancecowcards.structs import cards
import uuid
import toml
import json
import pandas as pd
import jq
import re

logger = cards.Logger() # Initializes a Logger instance to log data, use logger.log_data(dict) to log a data

class ConditionChecker:
    
    def __init__(self):
        
        self.condition_type_mapping = {
            'EMPTY': self.check_empty,
            'NOT_EMPTY': self.check_not_empty,
            'CONTAINS': self.check_contains, 
            'NOT_CONTAINS': self.check_not_contains, 
            'CONTAINS_ANY': self.check_contains_any, 
            'REGEX': self.check_regex, 
            'EQUALS': self.check_equals, 
            'NOT_EQUALS': self.check_not_equals, 
            'LESSER_THAN': self.check_lesser_than, 
            'GREATER_THAN': self.check_greater_than, 
            'LESSER_THAN_OR_EQUALS': self.check_lesser_than_or_equals, 
            'GREATER_THAN_OR_EQUALS': self.check_greater_than_or_equals, 
            'LT': self.check_lesser_than, 
            'GT': self.check_greater_than, 
            'LT_EQ': self.check_lesser_than_or_equals, 
            'GT_EQ': self.check_greater_than_or_equals, 
        }
      
    def evaluate_condition(self, condition_type, value, condition_value) -> Tuple[bool|None, str|None]:
        func = self.condition_type_mapping.get(condition_type)
        if func:
            return func(value, condition_value, condition_type)
        else:
            return None, f"Unsupported condition type: {condition_type}"
        
    def check_not_empty(self, value_to_check, condition_value, condition_type) -> Tuple[bool|None, str|None]:
        if isinstance(value_to_check, (int, float)):
            value_to_check = str(value_to_check)
        elif isinstance(value_to_check, str):
            value_to_check = value_to_check.strip()
        elif isinstance(value_to_check, (pd.DataFrame, pd.Series)):
            return bool(value_to_check.empty), None
        
        return bool(value_to_check), None
    
    def check_empty(self, value_to_check, condition_value, condition_type) -> Tuple[bool|None, str|None]:
        condition_status, error = self.check_not_empty(value_to_check, condition_value, condition_type)
        if error:
            return None, error
        
        return not condition_status, None
        
    def check_contains(self, value_to_check, condition_value, condition_type) -> Tuple[bool|None, str|None]:
        if not isinstance(value_to_check, (list, str, dict, pd.Series)):
            return None, f"Cannot check {condition_type}, as ConditionField value is of an unsupported type :: Expected 'list', 'dict' or 'string', but got '{type(value_to_check)}' instead"
        
        if isinstance(condition_value, str):
            return condition_value in value_to_check, None
        elif isinstance(condition_value, list):
            return all([value in value_to_check for value in condition_value]), None
        else:
            return None, f"Cannot check {condition_type}, as ConditionValue is of an unsupported type :: Expected 'list, str' but got {type(condition_value)} instead"
        
    def check_not_contains(self, value_to_check, condition_value, condition_type) -> Tuple[bool|None, str|None]:
        condition_status, error = self.check_contains(value_to_check, condition_value, condition_type)
        if error:
            return None, error
        
        return not condition_status, None
        
    def check_contains_any(self, value_to_check, condition_value, condition_type) -> Tuple[bool|None, str|None]:
        if not isinstance(value_to_check, (list, str, dict, pd.Series)):
            return None, f"Cannot check {condition_type}, as ConditionField value is of an unsupported type :: Expected 'list', 'dict' or 'string', but got '{type(value_to_check)}' instead"

        if isinstance(condition_value, list):
            return any([value in value_to_check for value in condition_value]), None
        else:
            return None, f"Cannot check {condition_type}, as ConditionValue is of an unsupported type :: Expected 'list' but got {type(condition_value)} instead"
    
    def check_equals(self, value_to_check, condition_value, _ ) -> Tuple[bool|None, str|None]:
        return value_to_check == condition_value, None
    
    def check_not_equals(self, value_to_check, condition_value, _) -> Tuple[bool|None, str|None]:
        return value_to_check != condition_value, None
    
    def check_lesser_than(self, value_to_check, condition_value, _) -> Tuple[bool|None, str|None]:
        if not isinstance(value_to_check, (int, float)) or not isinstance(condition_value, (int, float)):
            return None, "Please ensure that ConditionValue & ConditionField values in the toml file are either INTEGER or FLOAT types"
        
        return value_to_check < condition_value, None
    
    def check_greater_than(self, value_to_check, condition_value, _) -> Tuple[bool|None, str|None]:
        if not isinstance(value_to_check, (int, float)) or not isinstance(condition_value, (int, float)):
            return None, "Please ensure that ConditionValue & ConditionField values in the toml file are either INTEGER or FLOAT types"
        
        return value_to_check > condition_value, None
    
    def check_lesser_than_or_equals(self, value_to_check, condition_value, _) -> Tuple[bool|None, str|None]:
        condition_status, error = self.check_lesser_than(value_to_check, condition_value, _)
        if error:
            return None, error
        
        return condition_status or value_to_check == condition_value, None

    def check_greater_than_or_equals(self, value_to_check, condition_value, _) -> Tuple[bool|None, str|None]:
        condition_status, error = self.check_greater_than(value_to_check, condition_value, _)
        if error:
            return None, error
        
        return condition_status or value_to_check == condition_value, None
    
    def check_regex(self, value_to_check, condition_value, _) -> Tuple[bool|None, str|None]:
        if not isinstance(condition_value, str):
            return None, "Please ensure that ConditionValue & ConditionField values in the toml file are of STRING type"
        
        return bool(re.search(pattern=condition_value, string=str(value_to_check))), None


class Task(cards.AbstractTask):
    
    def execute(self) -> dict:
        
        log_file = self.task_inputs.user_inputs.get("LogFile", None)
        data_file = self.task_inputs.user_inputs.get("InputFile" , None)
        log_config_file = self.task_inputs.user_inputs.get("LogConfigFile", "")
        proceed_if_log_exists = self.task_inputs.user_inputs.get("ProceedIfLogExists", True)
        response = {}
        error_details = []
        self.prev_log_data = []
        
        resource_data, error = self.download_resource_data(data_file)
        if error :
            error_details.append(error)
        
        self.prev_log_data, error = self.download_resource_data(log_file)
        if error :
            error_details.append(error)
        
        log_config_file_data, error = self.download_toml_input_data(log_config_file)
        if error :
            error_details.append(error)
        
        error = self.validate_input_files()
        if error :
            error_details.append(error)
            
        if error_details:
            return self.upload_log_file_panic(error_details)
        
        if not any(resource_data) and any(self.prev_log_data):
            response['LogFile'] = log_file
            return response
                
        if isinstance(resource_data, dict):
            resource_data = [resource_data]
                
        checker = ConditionChecker()
        for index, data in enumerate(resource_data):
            for condition in log_config_file_data.get("ConditionRules", []):
                condition_type = condition.get("Condition", "")
                condition_field = condition.get("ConditionField", "").replace('<<inputfile', '').replace('>>', '')
                condition_value = condition.get("ConditionValue", "") 
                error_message = condition.get("ErrorMessage", "") 
                condition_field_response = ''
                
                if condition_field.startswith('.['):
                    pattern = r"\[\s*(\d+)\s*\]"
                    match = re.search(pattern, condition_field)
                    condition_field = re.sub(r"\.\[\d*\]", "", condition_field, count=1)
                    if match and index != int(match.group(1)):
                        continue
                    
                if condition.get("ConditionField", "") == "<<inputfile>>":
                    condition_field = '.'

                condition_field = condition_field.lstrip().lstrip('|').lstrip()

                try:
                    condition_field_response = jq.compile(condition_field).input(data).first()
                except ValueError as e:
                    error_details.append({"Error": f"Error while evaluating ConditionField: {condition_field} :: {e}"})
                    return self.upload_log_file_panic(error_details)

                if condition_field_response is None:
                    error_details.append({"Error": f"ConditionField '{condition_field}' is invalid or empty"})
                    return self.upload_log_file_panic(error_details)


                result, error = checker.evaluate_condition(condition_type, condition_field_response, condition_value)
                if error:
                    error_details.append({"Error": error})

                if result:
                    modified_error, error = self.replace_placeholder(error_message, "inputfile.", data)
                    if error :
                        error_details.append(error)
                    error_details.append({"Error": modified_error})
            
        if proceed_if_log_exists or proceed_if_log_exists is None or not (self.prev_log_data and all(self.prev_log_data) or error_details) :
            response['OutputFile'] = data_file
        if  error_details or (self.prev_log_data and all(self.prev_log_data)):
            response['LogFile'], error = self.upload_log_file(error_details)
        if error:
            return self.upload_log_file_panic(error)
                
        return response
    
    def download_resource_data(self, data_file) :
        
        data_file_json_formate = [{}]
        
        if not(data_file == None or data_file == "" or data_file == "<<MINIO_FILE_PATH>>"): 
        
            data_file_df, error = self.download_file_from_minio_as_df(file_url=data_file)
            if error != None :
                return None, {"Error" : error}

            try :
                data_file_json = data_file_df.to_json(orient='records', force_ascii=False)
                data_file_json_formate = json.loads(data_file_json)
            except json.JSONDecodeError as e: 
                return None, {"Error" : f'Invalid JSON format - {e}'}
            if not data_file_json_formate :
                data_file_json_formate = [{}]
            
            if isinstance(data_file_json_formate, dict):
                data_file_json_formate = [data_file_json_formate]
        
        return data_file_json_formate, None
    
    def download_toml_input_data(self, response_file) :
        
        default_response_data = {}
        response_data = None
        
        if response_file == None or response_file == "" or response_file == "<<MINIO_FILE_PATH>>": 
            response_data = default_response_data
        else:
            toml_bytes, error = self.download_file_from_minio(response_file)
            if error:
                return None,  {"Error" : error}
            
            response_data =  toml.loads(toml_bytes.decode('utf-8'))
         
        if response_data == {} :
            response_data = default_response_data
            
        return response_data , None
    
    def upload_log_file_panic(self, error_data) -> dict:

        file_url, error = self.upload_log_file(error_data)
        if error:
            return error
        
        return { 'LogFile': file_url }
    
    def upload_log_file(self, error_data) -> Tuple[dict, dict | None]:
        
        if isinstance(error_data, str):
            error_data = [{"Error": error_data}]
            
        if not isinstance(error_data, list):
            error_data = [error_data]
            
        if self.prev_log_data and all(self.prev_log_data):
            self.prev_log_data.extend(error_data)
        else:
            self.prev_log_data = error_data
        
        file_url, error = self.upload_df_as_json_file_to_minio(
            df = pd.DataFrame(self.prev_log_data), 
            file_name = 'LogFile'
        )
        if error:
            return '', {'Error': f"Error while uploading LogFile :: {error}"}
        
        return file_url, None
    
    def validate_input_files(self):
        
        task_inputs = self.task_inputs
        if not task_inputs:
            return 'missing: Task inputs'
        
        if not self.task_inputs.user_inputs: 
            return 'missing: User inputs'
        
        input_validation_report = ""
        
        request_file = self.task_inputs.user_inputs.get("LogConfigFile" , "")
        if request_file == None or request_file == "" or request_file == "<<MINIO_FILE_PATH>>": 
            input_validation_report = "'LogConfigFile' cannot be empty."
        
        if input_validation_report == "" :
            return None
        
        return input_validation_report
        
        
    def replace_placeholder(self, error_message, placeholder_prefix, data_file):
        pattern = f"<<{placeholder_prefix}([^>]+)>>"
        matches = re.findall(pattern, error_message)
        if not matches:
            return error_message, None
        
        for placeholder_key in matches:
            modified_placeholder_key = re.sub(r"\[\s*\d*\s*\]", "", placeholder_key, count=1)
            query = modified_placeholder_key.strip()
            if not query.startswith(".") :
                query = f".{modified_placeholder_key.strip()}"
                
            try:
                parsed_value = self.jq_filter_query( query, data_file)
            except Exception as e:
                return "", {"Error": f"Error while parsing placeholder '<<{placeholder_prefix}{placeholder_key}>>' : {e}"}
                
            if parsed_value is not None  :
                error_message = error_message.replace(f"<<{placeholder_prefix}{placeholder_key}>>" , str(parsed_value).strip())
            else:
                file_type = placeholder_prefix[:-1]
                if file_type == "inputfile":
                    file_type = "InputFile"
                    
                return "", {"Error": f"Cannot resolve query '{placeholder_prefix}{placeholder_key}'. {file_type} has no field {placeholder_key}."}
        
        return error_message, None

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