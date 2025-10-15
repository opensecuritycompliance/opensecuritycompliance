
from typing import Tuple, Literal, List, Callable, Any
from compliancecowcards.structs import cards
from datetime import datetime
from dateutil.relativedelta import relativedelta
from dateutil import parser as dateparser
import pandas as pd
import re
import copy
from compliancecowcards.utils import cowdictutils
import celpy
import celpy.celtypes
import numpy as np

logger = cards.Logger() # Initializes a Logger instance to log data, use logger.log_data(dict) to log a data

class Task(cards.AbstractTask):

    def execute(self) -> dict:

        self.prev_log_data = []

        error = self.check_inputs()
        if error:
            return self.upload_log_file_panic(error)
        
        prev_log_file_url = ''
        data_file_url = ''
        if cowdictutils.is_valid_key(self.task_inputs.user_inputs, 'LogFile'):
            prev_log_file_url = self.task_inputs.user_inputs['LogFile']
        if cowdictutils.is_valid_key(self.task_inputs.user_inputs, 'InputFile'):
            data_file_url = self.task_inputs.user_inputs['InputFile']

        if prev_log_file_url and not data_file_url:
            return {'LogFile': prev_log_file_url}
        
        if prev_log_file_url and data_file_url:
            self.prev_log_data, error = self.download_json_file_from_minio_as_iterable(prev_log_file_url)
            if error:
                return error
            
        if not data_file_url:
            return self.upload_log_file_panic('InputFile is missing in user inputs.')

        file_download_func = {
            'json': self.download_json_file_from_minio_as_df,
            'ndjson': self.download_ndjson_file_from_minio_as_df,
            'csv': self.download_csv_file_from_minio_as_df,
            'parquet': self.download_parquet_file_from_minio_as_df
        }

        file_extension = data_file_url.split('.')[-1]
        if file_extension not in file_download_func:
            return self.upload_log_file_panic(
                f"The provided InputFile is of an unsupported file type :: Expected a file with one of '{', '.join(file_download_func.keys())}' extensions, got '{file_extension}' instead."
            )

        data_df, error = file_download_func[file_extension](data_file_url)
        if error:
            return self.upload_log_file_panic(f"Error occurred while downloading InputFile :: {error}")
        if data_df.empty:
            return self.upload_log_file_panic("Provided InputFile has no content, please check.")
        
        # Handle Custom Inputs - (cin)
        cin_file_url: str = self.task_inputs.user_inputs.get('CustomInputs', '')
        custom_inputs = {}
        if cin_file_url:
            cin_file_extension = cin_file_url.split('.')[-1]
            if cin_file_extension not in file_download_func:
                return self.upload_log_file_panic(
                    f"The provided InputFile is of an unsupported file type :: Expected a file with one of '{', '.join(file_download_func.keys())}' extensions, got '{cin_file_extension}' instead."
                )
            
            cin_df = pd.DataFrame()
            if cin_file_extension != 'json':
                cin_df, error = file_download_func[cin_file_extension](cin_file_url)
            else:
                cin_dict, error = self.download_json_file_from_minio_as_dict(cin_file_url)
                if not error:
                    if isinstance(cin_dict, list):
                        cin_df = pd.DataFrame(cin_dict)
                    elif isinstance(cin_dict, dict):
                        cin_df = pd.DataFrame([cin_dict])
                    else:
                        error = f"File data is in an invalid format. Expecting data to be a 'list' or a 'dict', got {type(cin_dict)} instead"
            if error:
                return self.upload_log_file_panic(f"Error occurred while downloading CustomInputs file :: {error}")
            if cin_df.empty:
                return self.upload_log_file_panic("Provided CustomInputs file has no content, please check.")
            custom_inputs = cin_df.iloc[0].to_dict()
        
        # Handle ConditionConfig.toml
        condition_rules_toml_data, error = self.download_toml_file_from_minio_as_dict(self.task_inputs.user_inputs['ConditionConfig'])
        if error:
            return self.upload_log_file_panic(f"Error occurred while downloading ConditionConfig file :: {error}")
        if not condition_rules_toml_data:
            return self.upload_log_file_panic("Provided ConditionConfig file has no content, please check.")

        # Validate ConditionConfig.toml
        required_toml_tables = {'ConditionRules', 'ConditionRulesConfig'}
        missing_tables = required_toml_tables.difference(set(condition_rules_toml_data.keys()))
        if missing_tables:
            return self.upload_log_file_panic(f"The following tables are missing in ConditionConfig toml file: '{missing_tables}'")

        # Validate ConditionRules from toml
        condition_rules_df = pd.DataFrame(condition_rules_toml_data.get('ConditionRules', []))
        if condition_rules_df.empty:
            return self.upload_log_file_panic("No conditions were found in the provided toml file")
        required_columns = {'ConditionLabel', 'Condition'}
        missing_columns = required_columns.difference(set(condition_rules_df.columns))
        condition_rules_df = condition_rules_df.fillna('')
        
        # Check ConditionValue field in ConditionConfig toml
        single_value_condition_types = ['EMPTY', 'NOT_EMPTY', 'FROM_RULE_DATE', 'TO_RULE_DATE', 'RULE_DATE_RANGE']
        cond_val_required_condition_rules_df = condition_rules_df[~condition_rules_df['Condition'].isin(single_value_condition_types)]
        if not cond_val_required_condition_rules_df.empty and 'ConditionValue' not in condition_rules_df.columns:
            missing_columns.add('ConditionValue')

        # Validate ConditionField if there are conditions that are not CEL_CONDITION
        cond_field_required_condition_rules_df = condition_rules_df[condition_rules_df['Condition'] != 'CEL_CONDITION']
        if not cond_field_required_condition_rules_df.empty and 'ConditionField' not in condition_rules_df.columns:
            missing_columns.add('ConditionField')

        if missing_columns:
            return self.upload_log_file_panic(f"The following fields are missing in ConditionRules: '{', '.join(missing_columns)}'")
        
        # Check if ConditionLabel is missing in any conditions
        condition_rules_without_condition_label = condition_rules_df[(condition_rules_df['ConditionLabel'].isna() | (condition_rules_df['ConditionLabel'] == ''))]
        if not condition_rules_without_condition_label.empty:
            condition_rules_without_condition_label['Error'] = 'Condition does not have a ConditionLabel, please check the toml file'
            error_file_url, error = self.upload_df_as_json_file_to_minio(condition_rules_without_condition_label, 'LogFile')
            if error: return error
            return {'LogFile': error_file_url}
        
        # Check if ConditionLabel is duplicated in any conditions
        condition_rules_with_duplicate_condition_label = condition_rules_df[condition_rules_df['ConditionLabel'].duplicated()]
        if not condition_rules_with_duplicate_condition_label.empty:
            condition_rules_with_duplicate_condition_label['Error'] = "This condition has a duplicate ConditionLabel. All ConditionLabel values must be unique, please check."
            error_file_url, error = self.upload_df_as_json_file_to_minio(condition_rules_with_duplicate_condition_label, 'LogFile')
            if error: return error
            return {'LogFile': error_file_url}
        
        # Validate ConditionRulesConfig
        condition_rules_config = condition_rules_toml_data.get('ConditionRulesConfig', {})
        if not condition_rules_config or not cowdictutils.is_valid_key(condition_rules_config, 'ConditionsCriteria'):
            return self.upload_log_file_panic("ConditionsCriteria in ConditionRulesConfig was not found in the provided toml file")
        
        condition_rules_criteria: str = condition_rules_config['ConditionsCriteria']
        
        # Validate ConditionFieldUpdates if it exists in toml file
        condition_field_updates_list = condition_rules_toml_data.get('ConditionFieldUpdates', [])
        if condition_field_updates_list:
            condition_field_update_errors: list[dict] = []

            if isinstance(condition_field_updates_list, list):
                for field_update_row in condition_field_updates_list:
                    if not isinstance(field_update_row, dict):
                        condition_field_updates_list.append({
                            'ConditionFieldUpdate': field_update_row,
                            'Error': 'This ConditionFieldUpdate is in an invalid format, please check the toml file'
                        })

                    # Convert ConditionFieldUpdates.pass, ConditionFieldUpdates.fAiL, etc to ConditionFieldUpdates.PASS and ConditionFieldUpdates.FAIL
                    for key, value in list(field_update_row.items()):
                        upper_key = str(key).upper()
                        if upper_key in ['PASS', 'FAIL']:
                            field_update_row[upper_key] = value
                    
                    field_update_columns = list(field_update_row.keys())

                    missing_field_update_columns = []
                    if 'ConditionsCriteria' not in field_update_columns: missing_field_update_columns.append('ConditionsCriteria')
                    if ('PASS' not in field_update_columns) and ('FAIL' not in field_update_columns):
                        missing_field_update_columns.append('ConditionFieldUpdates.PASS or ConditionFieldUpdates.FAIL')

                    if missing_field_update_columns:
                        condition_field_update_errors.append({
                            **field_update_row,
                            'Error': f"The following fields are missing for this ConditionFieldUpdate in the toml file: '{', '.join(missing_field_update_columns)}'"
                        })
            else:
                condition_field_update_errors.append({'Error': "'ConditionFieldUpdates' is in an invalid format, please check the toml file"})

            if condition_field_update_errors:
                return self.upload_log_file_panic(condition_field_update_errors)
        
        # Process conditions for each record one by one
        condition_passed_data = []
        condition_failed_data = []
        condition_error_data = []
        for _, data_row in data_df.iterrows():
            init_data_row = data_row.copy(deep=True)
            
            # Check conditions for a record
            condition_checker = CheckCondition(self)
            data_errors = []
            condition_errors = []
            for _, condition_rules_row in condition_rules_df.iterrows():
                condition_label = str(condition_rules_row.get('ConditionLabel', ''))
                condition_field = str(condition_rules_row.get('ConditionField', ''))

                condition_type = condition_rules_row.get('Condition', '')
                is_cel_condition = condition_type == 'CEL_CONDITION'
                if is_cel_condition:
                    condition_field_value = {
                        'data': {**data_row},
                        'inputfile': {**data_row},
                        'custominputs': custom_inputs
                    }
                else:
                    if re.findall('<<data.*?>>', condition_field):
                        condition_field_value, error = self.replace_placeholders_with_values(condition_field, 'data', data_row)
                        if error:
                            condition_checker.add_condition(Condition(condition_label, condition_error=error))
                            continue
                    elif re.findall('<<inputfile.*?>>', condition_field):
                        condition_field_value, error = self.replace_placeholders_with_values(condition_field, 'inputfile', data_row)
                        if error:
                            condition_checker.add_condition(Condition(condition_label, condition_error=error))
                            continue
                    else:
                        condition_field_value = condition_field

                condition_value = condition_rules_row.get('ConditionValue', '')
                if not is_cel_condition:
                    # Check if ConditionValue accesses InputFile data :: <<data.FieldName>> or CustomInputs data :: <<custominputs.FieldName>>
                    condition_value, error = self.replace_data_cin_with_values(condition_value, 'ConditionValue', data_row, custom_inputs)
                    if error:
                        condition_checker.add_condition(Condition(condition_label, condition_error=error))
                        continue
                    
                condition_checker.check_and_add_condition(
                    condition_type=condition_type,
                    condition_label=condition_label,
                    value_to_check=condition_field_value,
                    condition_value=condition_value,
                    date_format=condition_rules_row.get('DateFormat', '')
                )

            # Perform ConditionFieldUpdates
            if condition_field_updates_list:
                field_update_errors = []
                field_update_condition_errors = []
                for field_update in copy.deepcopy(condition_field_updates_list):
                    condition_status, error, error_conditions = condition_checker.check_condition_criteria(field_update['ConditionsCriteria'])
                    if error:
                        field_update_errors.append(error)
                    if error_conditions:
                        field_update_condition_errors.extend(error_conditions)
                        
                    value_to_set: dict = field_update.get(condition_status, {})
                    if value_to_set and isinstance(value_to_set, dict):
                        # Check if any field accesses InputFile data :: <<data.FieldName>> or CustomInputs data :: <<custominputs.FieldName>>
                        for key, value in value_to_set.items():
                            if isinstance(value, str):
                                updated_value, error = self.replace_data_cin_with_values(value, key, data_row, custom_inputs)
                                if error:
                                    field_update_errors.append(error)
                                value_to_set[key] = updated_value
                            
                        data_row = {
                            **data_row,
                            **value_to_set
                        }

                if field_update_errors:
                    data_errors.extend(field_update_errors)
                if field_update_condition_errors:
                    condition_errors.extend(field_update_condition_errors)

            # Check ConditionRulesConfig for a record
            condition_status, error, error_conditions = condition_checker.check_condition_criteria(condition_rules_criteria)
            if error:
                data_errors.append(error)
            if error_conditions:
                condition_errors.extend(error_conditions)

            data_row = data_row.to_dict() if isinstance(data_row, pd.Series) else data_row
            if condition_status == 'PASS': 
                condition_passed_data.append(data_row)
            elif condition_status == 'FAIL':
                condition_failed_data.append(data_row)
            
            if data_errors or condition_errors:
                error_data = {**init_data_row}
                if data_errors:
                    error_data['Errors'] = ', '.join(set(data_errors))
                if condition_errors:
                    error_data['ConditionErrors'] = ', '.join(set(condition_errors))
                return self.upload_log_file_panic(error_data)

        response = {
            'MatchedConditionFile': '',
            'UnmatchedConditionFile': '',
            'LogFile': prev_log_file_url
        }

        if condition_passed_data:
            passed_data_file_url, error = self.upload_df_as_parquet_file_to_minio(
                df=pd.DataFrame(condition_passed_data),
                file_name='MatchedConditionFile'
            )
            if error:
                return error
            
            response['MatchedConditionFile'] = passed_data_file_url

        if condition_failed_data:
            failed_data_file_url, error = self.upload_df_as_parquet_file_to_minio(
                df=pd.DataFrame(condition_failed_data),
                file_name='UnmatchedConditionFile'
            )
            if error:
                return error
            
            response['UnmatchedConditionFile'] = failed_data_file_url
        
        if condition_error_data:
            error_data_file_url, error = self.upload_log_file(condition_error_data)
            if error:
                return error
            
            response['LogFile'] = error_data_file_url

        return response
    
    def get_dict_value_from_path_string(self, field_path: str, data):
        # Remove the '<<' and '>>' markers from the field path
        field_path = field_path.strip('<>')
        field_path_as_list = field_path.split('.')[1:]

        field_value = data
        for field in field_path_as_list:
            try:
                field_value = field_value[field]
            except (KeyError, TypeError) as e:
                return None, f"Error occurred while accessing '{field}' (ConditionField: {field_path}) :: {e}"
            
        return field_value, None
    
    def replace_placeholders_with_values(self, string: str, placeholder: str, data: dict | pd.Series):
        if not isinstance(string, str):
            return string, ''
        
        # Check for placeholders that access whole placeholder data. eg: <<data>>
        placeholder_matches = list(set(re.findall(f'<<({placeholder})>>', string)))
        
        # Check for placeholders that access specific fields. eg: <<data.field.name>>
        placeholder_matches += list(set(re.findall(fr'<<({placeholder}\..+?)>>', string)))

        updated_value = string
        if placeholder_matches:
            if (isinstance(data, pd.Series) and data.empty) or (isinstance(data, dict) and not data):
                return '', 'Data is empty'
            for match in placeholder_matches:
                match_value, error = self.get_dict_value_from_path_string(match, data)
                if error:
                    return '', error
                if string == f'<<{match}>>':
                    updated_value = match_value
                else:
                    updated_value = str(updated_value).replace(f'<<{match}>>', str(match_value))

        return updated_value, ''
    
    def replace_data_cin_with_values(
            self, 
            string: str, 
            field_name: str,
            input_file_data: dict | pd.Series, 
            custom_inputs: dict
        ) -> Tuple[str | None, str]:
        # Check if string accesses InputFile data :: <<data.FieldName>>
        updated_value, error = self.replace_placeholders_with_values(string, 'data', input_file_data)
        if error:
            return updated_value, error
        
        # Check if string accesses InputFile data :: <<inputfile.FieldName>>
        updated_value, error = self.replace_placeholders_with_values(updated_value, 'inputfile', input_file_data)
        if error:
            return updated_value, error
        
        # Check if string accesses CustomInputs data :: <<custominputs.FieldName>>
        updated_value, error = self.replace_placeholders_with_values(updated_value, 'custominputs', custom_inputs)
        if error:
            if error == 'Data is empty':
                error = f'CustomInputs file is missing, but is used in {field_name}'
            return updated_value, error
        
        return updated_value, ''
    
    def set_dict_value_from_path_string(self, field_path: str, data: dict | pd.Series, value_to_set):
        field_path = field_path.strip('<>')
        field_path_as_list = field_path.split('.')[1:]

        for field in field_path_as_list[:-1]:
            if field not in data:
                data[field] = {}
            data = data[field]
        
        data[field_path_as_list[-1]] = value_to_set

    def check_inputs(self):
        if self.task_inputs is None:
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
        
        required_inputs = {'ConditionConfig'}
        missing_inputs = []
        for input in required_inputs:
            if not cowdictutils.is_valid_key(self.task_inputs.user_inputs, input):
                missing_inputs.append(input)

        return "The following inputs: " + ", ".join(missing_inputs) + " is/are empty" if missing_inputs else ""
    
    def upload_log_file(self, error_data) -> Tuple[str, dict | None]:
        if not isinstance(error_data, list):
            error_data = [error_data]

        self.prev_log_data.extend(error_data)

        file_url, error = self.upload_df_as_json_file_to_minio(
            df=pd.DataFrame(self.prev_log_data),
            file_name='LogFile'
        )
        if error:
            return '', {'error': f"Error while uploading LogFile :: {error}"}
        return file_url, None
    
    def upload_log_file_panic(self, error_data) -> dict:
        if isinstance(error_data, str):
            error_data = {'Error': error_data}
        file_url, error = self.upload_log_file(error_data)
        if error:
            return error
        return { 'LogFile': file_url }
    
class Condition:
    ConditionStatusType = Literal['PASS', 'FAIL', 'ERROR']
    __id: str
    __status: ConditionStatusType
    __error: str

    def __init__(self, condition_label: str, condition_status: ConditionStatusType = 'ERROR', condition_error: str = ''):
        self.__id = condition_label
        self.__status = condition_status
        self.__error = condition_error

    def get_status(self):
        return self.__status
    
    def set_status(self, status: ConditionStatusType):
        self.__status = status

    def get_error(self):
        return self.__error
    
    def set_error(self, error: str):
        self.__error = error

    def get_id(self):
        return self.__id
    
class CheckCondition:

    def __init__(self, task_obj: Task) -> None:
        self.__conditions: List[Condition] = []
        self.condition_type_utils = ConditionTypeUtils(task_obj)

    # Parameters:
    #   condition_type -> tyoe of condition to check, refer ConditionConfig.toml file
    #   value_to_check -> value that has to be checked with condition_value (ConditionField in toml)
    #   condition_value -> value to consider for the condition (ConditionValue in toml)
    #   date_format -> (OPTIONAL) format of date to extract date from fields, if condition_type requires checking date
    def check(self, condition_type: str, value_to_check, condition_value, date_format: Any = '') -> Tuple[bool|None, str]:
        self.condition_type_utils.set_values(value_to_check, condition_value, date_format)
        condition_func, error = self.condition_type_utils.get_condition_func(condition_type)
        if error:
            return None, error

        return condition_func()

    def check_and_add_condition(self, condition_type: str, condition_label: str, value_to_check, condition_value, date_format: Any = ''):
        condition = Condition(condition_label)
        condition_status, error = self.check(condition_type, value_to_check, condition_value, date_format)
        if error:
            condition.set_error(error)
            self.add_condition(condition)
            return
        
        condition.set_status('PASS' if condition_status else 'FAIL')
        self.add_condition(condition)
    
    def add_condition(self, condition: Condition):
        self.__conditions.append(condition)

    def get_condition_labels_by_status(self, status: Condition.ConditionStatusType | Literal['ALL']) -> List[str]:
        condition_data = []
        for condition in self.__conditions:
            if condition.get_status() == status:
                if status == 'ERROR':
                    condition_data.append(f"{condition.get_id()} :: {condition.get_error()}")
                else:
                    condition_data.append(condition.get_id())
            elif status == 'ALL':
                condition_data.append(condition.get_id())
        return condition_data
    
    def check_condition_criteria(self, criteria: Any) -> Tuple[Condition.ConditionStatusType, str, List[str]]:
        if isinstance(criteria, str):
            condition_data = {}
            error_conditions = []

            for condition in self.__conditions:
                condition_id = condition.get_id()
                if condition.get_status() == 'PASS':
                    condition_data[condition_id] = True
                elif condition.get_status() == 'FAIL':
                    condition_data[condition_id] = False
                elif condition.get_status() == 'ERROR' and condition_id in criteria:
                    error_conditions.append(f"{condition_id} :: {condition.get_error()}")
                    
            condition_data = {
                **condition_data,
                'condition': condition_data
            }

            self.condition_type_utils.set_values(
                value_to_check=condition_data,
                condition_value=criteria
            )
            condition_func, error = self.condition_type_utils.get_condition_func('CEL_CONDITION')
            if error:
                return 'ERROR', error, error_conditions
            
            has_criteria_passed, error = condition_func()
            if error:
                error_condition_match = re.search(r"'(.+)>>(.+)'", error)
                if error_condition_match and len(error_condition_match.groups()) == 2:
                    error_condition_id, condition_error = error_condition_match.groups()
                    return 'ERROR', f"Got an error in this condition: '{error_condition_id}' :: {condition_error}", error_conditions

                return 'ERROR', error, error_conditions
            
            return 'PASS' if has_criteria_passed else 'FAIL', '', []
        if isinstance(criteria, list):
            return self.check_condition_criteria_as_list(criteria)
        else:
            return 'ERROR', f'Expected ConditionCriteria to be a string or a list, but got {type(criteria)} instead', []
    
    # ConditionCriteria as list is now deprecated, use the CEL version in the check_condition_criteria() method
    def check_condition_criteria_as_list(self, criteria_list: list) -> Tuple[Condition.ConditionStatusType, str, List[str]]:
        logger.log_data({'Warning': 'ConditionCriteria as list is now deprecated, please check the template file for the updated version'})
        condition_labels = self.get_condition_labels_by_status('ALL')
        invalid_config_condition_labels = set([config.strip('!') for config in criteria_list]).difference(condition_labels)
        if invalid_config_condition_labels:
            return 'ERROR', f"The following ConditionLabel(s) found in the provided ConditionsCriteria do not have any conditions attached: '{', '.join(invalid_config_condition_labels)}'", []
        
        error_conditions = self.get_condition_labels_by_status('ERROR')
        if error_conditions:
            return 'ERROR', '', error_conditions

        conditions_to_fail = [config.strip("!") for config in criteria_list if "!" in config]
        conditions_to_pass = [config for config in criteria_list if "!" not in config]

        failed_conditions = self.get_condition_labels_by_status('FAIL')
        passed_conditions = self.get_condition_labels_by_status('PASS')

        if all([condition_label in failed_conditions for condition_label in conditions_to_fail]) and \
           all([condition_label in passed_conditions for condition_label in conditions_to_pass]):
            return 'PASS', '', []
        else:
            return 'FAIL', '', []


class ConditionTypeUtils:
    def __init__(self, task_obj: Task) -> None:
        self.value_to_check = ''
        self.condition_value = ''
        self.condition_type = ''
        self.task_obj: Task = task_obj

        self.__single_value_condition_type_mapping = {
            'EMPTY': self.check_empty,
            'NOT_EMPTY': self.check_not_empty,

            # RULE DATE CONDITIONS
            'FROM_RULE_DATE': self.check_from_rule_date,
            'TO_RULE_DATE': self.check_to_rule_date,
            'RULE_DATE_RANGE': self.check_rule_date_range,
        }

        self.__condition_type_mapping = {
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
            'NUMBER_RANGE': self.check_number_range,
            'CEL_CONDITION': self.check_cel
        }

        self.__date_condition_type_mapping = {
            'FROM_DATE': self.check_from_date,
            'TO_DATE': self.check_to_date,
            'DATE_RANGE': self.check_date_range,
            'FROM_DATE_OFFSET': self.check_from_date_offset,
            'TO_DATE_OFFSET': self.check_to_date_offset,
            'DATE_OFFSET_RANGE': self.check_date_offset_range
        }
    
    def set_values(self, value_to_check, condition_value, date_format: str = ''):
        if self.is_none(value_to_check):
            value_to_check = ''
        if self.is_none(condition_value):
            condition_value = ''

        self.value_to_check = value_to_check
        self.condition_value = condition_value
        self.date_format = date_format
    
    def is_none(self, value: Any) -> bool:
        # Check if the value is a pandas Series or DataFrame
        if isinstance(value, (pd.Series, pd.DataFrame)):
            # For pandas objects, use .empty to check if they are empty
            return value.empty
        # For numpy arrays, check the size
        if isinstance(value, np.ndarray):
            return value.size == 0

        if isinstance(value, list):
            return len(value) == 0
        
        # For other cases, use pd.isna to check if the value is NaN or None
        is_none = pd.isna(value)
        return is_none if isinstance(is_none, bool) else all(is_none)

    def get_condition_func(self, condition_type: str) -> Tuple[Callable[[], tuple[bool|None, str]], str]:

        self.condition_type = condition_type.upper()

        if condition_type in self.__single_value_condition_type_mapping:
            return self.__single_value_condition_type_mapping[self.condition_type], str('')
        
        if condition_type in self.__condition_type_mapping:
            return self.__condition_type_mapping[self.condition_type], ''
        
        if condition_type in self.__date_condition_type_mapping:
            self.condition_value, error = self.add_or_subtract_date_value_string(self.condition_value)
            if error:
                return None, f'Error while evaluating ConditionValue field :: {error}'
            return self.__date_condition_type_mapping[self.condition_type], ''

        return None, f"Provided condition '{condition_type}' is not valid"


    # All functions return these 2 values:
    #   condition_status: bool -> true if condition is met, else false
    #   error: str -> error information, if any

    ################################ SINGLE VALUE CONDITIONS ################################

    def check_not_empty(self) -> Tuple[bool, str]:
        if isinstance(self.value_to_check, (int, float)):
            self.value_to_check = str(self.value_to_check)
        elif isinstance(self.value_to_check, str):
            self.value_to_check = self.value_to_check.strip()
        elif isinstance(self.value_to_check, (pd.DataFrame, pd.Series)):
            return bool(self.value_to_check.empty), ''
        
        return bool(self.value_to_check), ''
    
    def check_empty(self) -> Tuple[bool|None, str]:
        condition_status, error = self.check_not_empty()
        if error:
            return None, error
        
        return not condition_status, ''
    
    ################################ COMMON CONDITIONS ################################
    
    def check_contains(self) -> Tuple[bool|None, str]:
        if not isinstance(self.value_to_check, (list, str, dict, pd.Series, np.ndarray)):
            return None, f"Cannot check {self.condition_type}, as ConditionField value is of an unsupported type :: Expected 'list', 'dict' or 'string', but got '{type(self.value_to_check)}' instead"
        
        if isinstance(self.condition_value, str):
            return self.condition_value in self.value_to_check, ''
        elif isinstance(self.condition_value, (list, np.ndarray)):
            return all([value in self.value_to_check for value in self.condition_value]), ''
        else:
            return None, f"Cannot check {self.condition_type}, as ConditionValue is of an unsupported type :: Expected 'list, str' but got {type(self.condition_value)} instead"
        
    def check_not_contains(self) -> Tuple[bool|None, str]:
        condition_status, error = self.check_contains()
        if error:
            return None, error
        
        return not condition_status, ''
        
    def check_contains_any(self) -> Tuple[bool|None, str]:
        if not isinstance(self.value_to_check, (list, str, dict, pd.Series, np.ndarray)):
            return None, f"Cannot check {self.condition_type}, as ConditionField value is of an unsupported type :: Expected 'list', 'dict' or 'string', but got '{type(self.value_to_check)}' instead"

        if isinstance(self.condition_value, (list, np.ndarray)):
            return any([value in self.value_to_check for value in self.condition_value]), ''
        else:
            return None, f"Cannot check {self.condition_type}, as ConditionValue is of an unsupported type :: Expected 'list' but got {type(self.condition_value)} instead"
    
    def check_equals(self) -> Tuple[bool|None, str]:
        return self.value_to_check == self.condition_value, ''
    
    def check_not_equals(self) -> Tuple[bool|None, str]:
        return self.value_to_check != self.condition_value, ''
    
    def check_lesser_than(self) -> Tuple[bool|None, str]:
        if not isinstance(self.value_to_check, (int, float)) or not isinstance(self.condition_value, (int, float)):
            return None, "Please ensure that ConditionValue & ConditionField values in the toml file are either INTEGER or FLOAT types"
        
        return self.value_to_check < self.condition_value, ''
    
    def check_greater_than(self) -> Tuple[bool|None, str]:
        if not isinstance(self.value_to_check, (int, float)) or not isinstance(self.condition_value, (int, float)):
            return None, "Please ensure that ConditionValue & ConditionField values in the toml file are either INTEGER or FLOAT types"
        
        return self.value_to_check > self.condition_value, ''
    
    def check_lesser_than_or_equals(self) -> Tuple[bool|None, str]:
        condition_status, error = self.check_lesser_than()
        if error:
            return None, error
        
        return condition_status or self.value_to_check == self.condition_value, ''

    def check_greater_than_or_equals(self) -> Tuple[bool|None, str]:
        condition_status, error = self.check_greater_than()
        if error:
            return None, error
        
        return condition_status or self.value_to_check == self.condition_value, ''
    
    def check_regex(self) -> Tuple[bool|None, str]:
        if not isinstance(self.value_to_check, str) or not isinstance(self.condition_value, str):
            return None, "Please ensure that ConditionValue & ConditionField values in the toml file are of STRING type"
        
        return bool(re.search(pattern=self.condition_value, string=self.value_to_check)), ''
    
    def check_number_range(self) -> Tuple[bool|None, str]:
        if not isinstance(self.value_to_check, (int, float)):
            return None, f"Cannot check {self.condition_type}, as ConditionField is of an unsupported type :: Expected 'int' or 'float' but got {type(self.value_to_check)} instead"
        
        start_value, end_value, error = self.get_range_values()
        if error:
            return None, error
        
        if not start_value and not end_value:
            return None, f"Cannot check {self.condition_type}, because the range values of ConditionValue is empty, please add valid range values"
        
        condition_status = True
        try:
            if start_value:
                start_value = float(start_value)
                condition_status = condition_status and self.value_to_check >= start_value
                
            if end_value:
                end_value = float(end_value)
                condition_status = condition_status and self.value_to_check <= end_value
        except (TypeError, ValueError) as e:
            return None, f"Cannot check {self.condition_type}, because the range values of ConditionValue is incorrect :: Error detail: {e}"
        
        return condition_status, ''
    
    def check_cel(self) -> Tuple[bool|None, str]:
        if not isinstance(self.value_to_check, dict):
            return None, f"INTERNAL_ERROR: Cannot check {self.condition_type}, as value_to_check is of an unsupported type :: Expected 'dict', but got '{type(self.value_to_check)}' instead"
        if not isinstance(self.condition_value, str):
            return None, f"Cannot check {self.condition_type}, as ConditionValue is of an unsupported type :: Expected 'str', but got '{type(self.condition_value)}' instead"
        try:
            cel_env = celpy.Environment()
            cel_ast = cel_env.compile(self.condition_value.replace('<<', '').replace('>>', ''))
            result = cel_env.program(cel_ast).evaluate(celpy.json_to_cel(self.value_to_check))

            if isinstance(result, celpy.celtypes.BoolType):
                return bool(result), ''
            else:
                return None, f"The provided CEL Expression must return a boolean value. Received this value from the result instead '{result}'"
        except celpy.CELParseError as e:
            logger.log_data({'CELError': f"CELExpression: {self.condition_value} :: Error: {e}"})
            return None, f'Please check the syntax of the CEL expression: {self.condition_value}'
        except celpy.CELEvalError as e:
            logger.log_data({'CELError': f"CELExpression: {self.condition_value} :: Error: {e}"})
            return None, f"Please check whether all fields in the expression ('{self.condition_value}') are available"
    
    ################################ DATE CONDITIONS ################################

    def check_from_date(self) -> Tuple[bool|None, str]:
        if not isinstance(self.condition_value, str):
            return None, f"Cannot check {self.condition_type}, as ConditionValue is of an unsupported type :: Expected 'str' but got {type(self.condition_value)} instead"
        
        condition_value_date, error = self.get_datetime_from_str(self.condition_value)
        if error:
            return None, error

        if not isinstance(self.value_to_check, str):
            return None, f"Cannot check {self.condition_type}, as ConditionField is of an unsupported type :: Expected 'str' but got {type(self.value_to_check)} instead"
        
        date_to_check, error = self.get_datetime_from_str(self.value_to_check)
        if error:
            return None, error
        
        return date_to_check >= condition_value_date, ''
    
    def check_to_date(self) -> Tuple[bool|None, str]:
        if not isinstance(self.condition_value, str):
            return None, f"Cannot check {self.condition_type}, as ConditionValue is of an unsupported type :: Expected 'str' but got {type(self.condition_value)} instead"
        
        condition_value_date, error = self.get_datetime_from_str(self.condition_value)
        if error:
            return None, error

        if not isinstance(self.value_to_check, str):
            return None, f"Cannot check {self.condition_type}, as ConditionField is of an unsupported type :: Expected 'str' but got {type(self.value_to_check)} instead"
        
        date_to_check, error = self.get_datetime_from_str(self.value_to_check)
        if error:
            return None, error
        
        return date_to_check <= condition_value_date, ''
    
    def check_date_range(self) -> Tuple[bool|None, str]:
        if not isinstance(self.value_to_check, str):
            return None, f"Cannot check {self.condition_type}, as ConditionField is of an unsupported type :: Expected 'str' but got {type(self.value_to_check)} instead"
        
        date_to_check, error = self.get_datetime_from_str(self.value_to_check)
        if error:
            return None, error
        
        start_date, end_date, error = self.get_range_values(separator_string="->")
        if error:
            return None, error
        
        if not start_date and not end_date:
            return None, f"Cannot check {self.condition_type}, because the range values of ConditionValue is empty, please add valid range values"
        
        condition_status = True
        if start_date:
            start_date, error = self.get_datetime_from_str(start_date)
            if error: return None, error

            condition_status = condition_status and date_to_check >= start_date
            
        if end_date:
            end_date, error = self.get_datetime_from_str(end_date)
            if error: return None, error

            if start_date and start_date > end_date:
                return None, f"Cannot check {self.condition_type}, because the range value provided in ConditionValue is invalid, please check"

            condition_status = condition_status and date_to_check <= end_date
        
        return condition_status, ''
    
    def check_from_rule_date(self) -> Tuple[bool|None, str]:
        self.condition_value = self.convert_datetime_to_str(self.task_obj.task_inputs.from_date)
        condition_status, error = self.check_from_date()
        if error:
            return None, error
        return condition_status, ''
    
    def check_to_rule_date(self) -> Tuple[bool|None, str]:
        self.condition_value = self.convert_datetime_to_str(self.task_obj.task_inputs.to_date)
        condition_status, error = self.check_to_date()
        if error:
            return None, error
        return condition_status, ''
    
    def check_rule_date_range(self) -> Tuple[bool|None, str]:
        from_date_str = self.convert_datetime_to_str(self.task_obj.task_inputs.from_date)
        to_date_str = self.convert_datetime_to_str(self.task_obj.task_inputs.to_date)
        self.condition_value = f"{from_date_str}->{to_date_str}"
        
        condition_status, error = self.check_date_range()
        if error:
            return None, error
        return condition_status, ''
    
    def check_from_date_offset(self) -> Tuple[bool|None, str]:
        date_offset, error = self.get_timedelta_from_date_offset(self.condition_value)
        if error:
            return None, error
        
        should_subtract = str(self.condition_value).startswith('-')
        from_date = (datetime.now() - date_offset) if should_subtract else (datetime.now() + date_offset)
        if not isinstance(self.value_to_check, str):
            return None, f"Cannot check {self.condition_type}, as ConditionField is of an unsupported type :: Expected 'str' but got {type(self.value_to_check)} instead"
        
        date_to_check, error = self.get_datetime_from_str(self.value_to_check)
        if error:
            return None, error
        
        return date_to_check >= from_date, ''
    
    def check_to_date_offset(self) -> Tuple[bool|None, str]:
        date_offset, error = self.get_timedelta_from_date_offset(self.condition_value)
        if error:
            return None, error
        
        should_subtract = str(self.condition_value).startswith('-')
        to_date = (datetime.now() - date_offset) if should_subtract else (datetime.now() + date_offset)
        if not isinstance(self.value_to_check, str):
            return None, f"Cannot check {self.condition_type}, as ConditionField is of an unsupported type :: Expected 'str' but got {type(self.value_to_check)} instead"
        
        date_to_check, error = self.get_datetime_from_str(self.value_to_check)
        if error:
            return None, error
        
        return date_to_check <= to_date, ''
    
    def check_date_offset_range(self) -> Tuple[bool|None, str]:
        if not isinstance(self.value_to_check, str):
            return None, f"Cannot check {self.condition_type}, as ConditionField is of an unsupported type :: Expected 'str' but got {type(self.value_to_check)} instead"
        
        date_to_check, error = self.get_datetime_from_str(self.value_to_check)
        if error:
            return None, error
        
        start_date_offset_str, end_date_offset_str, error = self.get_range_values()
        if error:
            return None, error
        
        if not start_date_offset_str and not end_date_offset_str:
            return None, f"Cannot check {self.condition_type}, because the syntax of ConditionValue is invalid, please check"
        
        condition_status = True
        start_date = None
        if start_date_offset_str:
            start_date = datetime.now()
            if start_date_offset_str != "now":
                should_subtract = start_date_offset_str.startswith("-")
                start_date_offset, error = self.get_timedelta_from_date_offset(start_date_offset_str)
                if error:
                    return None, error
                start_date = (start_date - start_date_offset) if should_subtract else (start_date + start_date_offset)
            condition_status = condition_status and date_to_check >= start_date
            
        if end_date_offset_str:
            end_date = datetime.now()
            if end_date_offset_str != "now":
                should_subtract = end_date_offset_str.startswith("-")
                end_date_offset, error = self.get_timedelta_from_date_offset(end_date_offset_str)
                if error:
                    return None, error
                end_date = (end_date - end_date_offset) if should_subtract else (end_date + end_date_offset)

            if start_date and start_date > end_date:
                return None, f"Cannot check {self.condition_type}, because the range value provided in ConditionValue is invalid, please check"
            
            condition_status = condition_status and date_to_check <= end_date
        
        return condition_status, ''
    
    ################################ OTHER FUNCTIONS ################################
    
    def get_datetime_from_str(self, string: str) -> Tuple[datetime, str]:
        if not self.date_format or isinstance(self.date_format, dict):
            return self.get_datetime_using_parser_config(string)

        return self.get_datetime_using_date_format(string)

    def get_datetime_using_parser_config(self, string: str) -> Tuple[datetime, str]:
        parser_info = dateparser.parserinfo()

        if isinstance(self.date_format, dict):
            parser_info.dayfirst = self.date_format.get('IsDayFirst')

        try:
            return dateparser.parse(string, parserinfo=parser_info, ignoretz=True), ''
        except (dateparser.ParserError, OverflowError) as e:
            return None, f'Cannot check {self.condition_type}, as an error occurred while parsing date :: {e}'

    def get_datetime_using_date_format(self, string: str) -> Tuple[datetime|None, str]:
        if string == "now":
            return datetime.now(), ''
        try:
            return datetime.strptime(string, self.date_format), ''
        except ValueError as e:
            return None, f'Cannot check {self.condition_type}, as an error occurred while parsing date :: {e}'

    def convert_datetime_to_str(self, date: datetime) -> str:
        if self.date_format and isinstance(self.date_format, str):
            return date.strftime(self.date_format)
        return date.isoformat()
        
    # ConditionValue Syntax: <years>y <months>m <days>d <hours>H <minutes>M <seconds>S
    def get_timedelta_from_date_offset(self, date_offset: str) -> Tuple[relativedelta, str]:
        if not isinstance(self.condition_value, str):
            return None, f"Cannot check {self.condition_type}, as ConditionValue is of an unsupported type :: Expected 'str' but got {type(self.condition_value)} instead"
        
        years_match = re.search(r'(\d+)y', date_offset)
        years = int(years_match.group(1)) if years_match else 0
        
        months_match = re.search(r'(\d+)m', date_offset)
        months = int(months_match.group(1)) if months_match else 0

        days_match = re.search(r'(\d+)d', date_offset)
        days = int(days_match.group(1)) if days_match else 0

        hours_match = re.search(r'(\d+)H', date_offset)
        hours = int(hours_match.group(1)) if hours_match else 0

        minutes_match = re.search(r'(\d+)M', date_offset)
        minutes = int(minutes_match.group(1)) if minutes_match else 0

        seconds_match = re.search(r'(\d+)S', date_offset)
        seconds = int(seconds_match.group(1)) if seconds_match else 0

        if years == months == days == hours == minutes == seconds == 0:
            return None, f"Cannot check {self.condition_type}, as the syntax of ConditionValue is invalid. Please check :: Correct syntax: <years>y <months>m <days>d <hours>H <minutes>M <seconds>S"
        
        return relativedelta(years=years, months=months, days=days, hours=hours, minutes=minutes, seconds=seconds), ''

    def get_range_values(self, separator_string: str = ':') -> Tuple[str, str, str]:
        if not isinstance(self.condition_value, str):
            return '', '', f"Cannot check {self.condition_type}, as ConditionValue is of an unsupported type :: Expected 'str' but got {type(self.condition_value)} instead"
        
        range_data_split = f" {self.condition_value} ".split(separator_string)
        if len(range_data_split) != 2:
            return '', '', f"Cannot check {self.condition_type}, because the syntax of ConditionValue is incorrect. Please check."
        
        return range_data_split[0].strip(), range_data_split[1].strip(), ''
    
    def add_or_subtract_date_value_string(self, value_string: str) -> Tuple[str, str]:
        if ' + ' not in value_string and ' - ' not in value_string:
            return value_string, ''
        
        def get_date_expression_operands(operator: Literal[' + ', ' - ']) -> Tuple[datetime, relativedelta, str]:
            operands = value_string.split(operator)
            if len(operands) != 2:
                return None, None, f'You can have only 2 operands, received {len(operands)}'
            
            operand1, error = self.get_datetime_from_str(operands[0])
            if error:
                return None, None, error
            
            operand2, error = self.get_timedelta_from_date_offset(operands[1])
            if error:
                return None, None, error
            
            return operand1, operand2, ''
        
        if ' + ' in value_string:
            operand1, operand2, error = get_date_expression_operands(' + ')
            if error:
                return '', error
            
            return self.convert_datetime_to_str((operand1 + operand2)), ''
        if ' - ' in value_string:
            operand1, operand2, error = get_date_expression_operands(' - ')
            if error:
                return '', error
            
            return self.convert_datetime_to_str((operand1 + operand2)), ''

        return '', "Provided date expression is invalid, please check the readme for more info."
