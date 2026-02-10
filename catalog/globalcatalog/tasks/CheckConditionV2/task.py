import io
import json
from typing import List, Any, Dict
import uuid
from compliancecowcards.utils import cowjqutils
from compliancecowcards.structs import cards
import pandas as pd
import pathlib
from condition import CheckCondition, Condition
import re
import copy


logger = cards.Logger() # Initializes a Logger instance to log data, use logger.log_data(dict) to log a data

class Task(cards.AbstractTask):

    def execute(self) -> dict:
        user_inputs = self.task_inputs.user_inputs
        
        default_log_config_filepath = str(pathlib.Path(__file__).parent.joinpath('LogConfig_default.toml').resolve())
        custom_log_config_url = self.task_inputs.user_inputs.get('LogConfig')
        output_file_format = user_inputs.get('OutputFileFormat', 'PARQUET')
        
        should_proceed_on_error = self._get_boolean_value_from_input('ProceedIfErrorExists')
        self.set_log_file_name('LogFile' if should_proceed_on_error else 'Errors')
        
        self.log_manager, error = cards.LogConfigManager.from_minio_file_url(
            custom_log_config_url if self._is_valid_file_input(custom_log_config_url) else '',
            self.download_toml_file_from_minio_as_dict,
            default_log_config_filepath,
            default_context_data={
                'fromdate': self.task_inputs.from_date.strftime('%d/%m/%Y %H:%M'),
                'todate': self.task_inputs.to_date.strftime('%d/%m/%Y %H:%M')
            }
        )
        if error:
            return self._panic(error)
        
        inputfile_url: str | None = user_inputs.get('InputFile')
        custominputs_url: str | None = user_inputs.get('CustomInputs')
        condition_config_url: str | None = user_inputs.get('ConditionConfig')
        prev_log_file_url: str | None = user_inputs.get('LogFile')
        
        response = self.handle_logfile(prev_log_file_url)
        if response:
            return response
            
        condition_config = {}
        if self._is_valid_file_input(condition_config_url):
            condition_config, error = self._download_toml(str(condition_config_url))
            if error:
                return self._panic(
                    self.log_manager.get_error_message('CheckCondition.Inputs.ConditionConfig.download_error', {'error': error})
                )
        else:
            return self._panic(self.log_manager.get_error_message('CheckCondition.Inputs.ConditionConfig.missing'))
                
        if not condition_config:
            return self._panic(self.log_manager.get_error_message('CheckCondition.Inputs.ConditionConfig.empty_content'))
            
        condition_config_validator = ConditionConfigValidator(condition_config, self.log_manager)
        errors = condition_config_validator.validate()
        if errors:
            return self._panic(errors)
        
        inputfile_df = pd.DataFrame()
        if self._is_valid_file_input(inputfile_url):
            inputfile_df, error = self._download_df(str(inputfile_url))
            if error:
                return self._panic(
                    self.log_manager.get_error_message('CheckCondition.Inputs.InputFile.download_error', {'error': error})
                )
        else:
            return self._panic(self.log_manager.get_error_message('CheckCondition.Inputs.InputFile.missing'))
                
        if inputfile_df.empty:
            return self._panic(self.log_manager.get_error_message('CheckCondition.Inputs.InputFile.empty_content'))
        
        cin_df = pd.DataFrame()
        if self._is_valid_file_input(custominputs_url):
            cin_df, error = self._download_df(str(custominputs_url))
            if error:
                return self._panic(
                    self.log_manager.get_error_message('CheckCondition.Inputs.CustomInputs.download_error', {'error': error})
                )
                
        input_data, errors = self.handle_file_input_validation({
            'InputFile': inputfile_df,
            'CustomInputs': cin_df
        })
        if errors:
            return self._panic(errors)

        inputfile_df = input_data['InputFile']
        cin_df = input_data['CustomInputs']
        cin_list = cin_df.to_dict(orient='records')
        
        condition_rules_criteria: str = condition_config['ConditionRulesConfig']['ConditionsCriteria']
        condition_field_updates_list: list[dict] = condition_config.get('ConditionFieldUpdates', [])
        condition_rules_df = pd.DataFrame(condition_config['ConditionRules']).fillna('')
        
        condition_passed_data = []
        condition_failed_data = []
        
        try:
            inputfile_df.apply(
                self.process_condition_for_record, 
                axis=1, 
                result_type='expand',
                condition_rules_criteria=condition_rules_criteria,
                condition_field_updates_list=condition_field_updates_list,
                condition_rules_df=condition_rules_df,
                cin_list=cin_list,
                condition_passed_data=condition_passed_data,
                condition_failed_data=condition_failed_data
            )
        except ConditionCriteriaEvalError as e:
            return self._panic(e.errors_list)
        
        response = {
            'MatchedConditionFile': '',
            'UnmatchedConditionFile': '',
            'LogFile': prev_log_file_url if self._is_valid_file_input(prev_log_file_url) else ''
        }
        
        if condition_passed_data:
            passed_data_file_url, error = self.handle_output_file_upload(
                result_df = pd.DataFrame(condition_passed_data),
                output_file_format = output_file_format,
                file_name='MatchedConditionFile'
            )
            if error:
                return error
            
            response['MatchedConditionFile'] = passed_data_file_url

        if condition_failed_data:
            failed_data_file_url, error = self.handle_output_file_upload(
                result_df = pd.DataFrame(condition_failed_data),
                output_file_format = output_file_format,
                file_name='UnmatchedConditionFile'
            )
            if error:
                return error
            
            response['UnmatchedConditionFile'] = failed_data_file_url

        return response

    def handle_output_file_upload(
        self, result_df: pd.DataFrame, output_file_format: str, file_name: str
    ) -> tuple[str, dict | None]:
        upload_funcs = {
            "PARQUET": self.upload_df_as_parquet_file_to_minio,
            "CSV": self.upload_df_as_csv_file_to_minio,
            "JSON": self.upload_df_as_json_file_to_minio
        }

        output_file_format = output_file_format.upper() if output_file_format else "PARQUET"

        if result_df.empty:
            return '', None

        if output_file_format not in upload_funcs:
            # RETURN ERROR
            return '', {
                'Error': self.log_manager.get_error_message('CheckCondition.Outputs.OutputFileFormat.invalid', {'output_file_format': output_file_format})
            }
        
        upload_func = upload_funcs[output_file_format]
        return upload_func(result_df, file_name)
        
    def handle_logfile(self, log_file_url: str | None) -> dict:
        should_proceed_on_log = self._get_boolean_value_from_input('ProceedIfLogExists')
        
        is_valid_log_url = self._is_valid_file_input(log_file_url)
            
        if not should_proceed_on_log and is_valid_log_url:
            return {'LogFile': log_file_url}
            
        if is_valid_log_url:
            prev_log_data, error =  self._download_json(str(log_file_url))
            if error:
                return {
                    'Error': self.log_manager.get_error_message('CheckCondition.Inputs.LogFile.download_error', {'error': f'{error}'})
                }
            if isinstance(prev_log_data, list):
                self.set_prev_log_data(prev_log_data)
            
        return {}
        
    def handle_file_input_validation(self, input_data: dict[str, pd.DataFrame]) -> tuple[dict[str, pd.DataFrame], List[dict[str, str]]]:
        errors_list = []
        
        validation_config_url: str | None = self.task_inputs.user_inputs.get('InputFileValidationConfig')
        if not self._is_valid_file_input(validation_config_url):
            return input_data, errors_list
            
        validation_config_list, error = self._download_json(str(validation_config_url))
        if error:
            errors_list.append({'Error': self.log_manager.get_error_message('CheckCondition.Inputs.InputFileValidationConfig.download_error', {'error': error})})
            return input_data, errors_list
            
        if not validation_config_list:
            errors_list.append({'Error': self.log_manager.get_error_message('CheckCondition.Inputs.InputFileValidationConfig.empty_content', {'error': error})})
            return input_data, errors_list

        for validation_config in validation_config_list:
            file_name: str | None = validation_config.get('FileName')
            required_fields: list[str] | None = validation_config.get('RequiredFields')
            should_remove_duplicates: bool | None = validation_config.get('RemoveDuplicates')
            if file_name in input_data:
                file_df = input_data[file_name]
                if not file_df.empty:
                    
                    if required_fields:
                        missing_fields = set(required_fields).difference(file_df.columns)
                        if missing_fields:
                            errors_list.append({
                                'Error': self.log_manager.get_error_message(f'CheckCondition.InputFileValidationConfig.Validation.{file_name}.missing_fields', {
                                    'missing_fields': ', '.join(missing_fields)
                                })
                            })
                            continue
                    
                    if should_remove_duplicates:
                        file_df = file_df.drop_duplicates()
                        input_data[file_name] = file_df
                        
        return input_data, errors_list
    
    def process_condition_for_record(
        self,
        record: pd.Series,
        cin_list: list[dict],
        condition_rules_criteria: str,
        condition_field_updates_list: list[dict],
        condition_rules_df: pd.DataFrame,
        condition_passed_data: list[dict],
        condition_failed_data: list[dict]
    ) -> None:
        context_data = {
            'inputfile': {**record},
            'custominputs': cin_list
        }
        
        condition_checker = CheckCondition(self, logger, self.log_manager)
        
        # Check conditions rules for a record
        condition_rules_df.apply(
            self.process_condition_rule, 
            axis=1, 
            result_type='expand',
            context_data=context_data,
            condition_checker=condition_checker,
        )
        
        updated_record, data_errors, condition_errors = self.process_condition_field_updates(
            record,
            condition_field_updates_list,
            condition_checker,
            context_data
        )
        
        # Check ConditionRulesConfig for a record
        condition_status, error, error_conditions = condition_checker.check_condition_criteria(condition_rules_criteria)
        if error:
            data_errors.append(error)
        if error_conditions:
            condition_errors.extend(error_conditions)
            
        if condition_status == 'PASS':
            condition_passed_data.append(updated_record)
        if condition_status == 'FAIL':
            condition_failed_data.append(updated_record)
        
        if data_errors or condition_errors:
            error_set = set(condition_errors)
            if not condition_errors:
                error_set.update(set(data_errors))
            
            errors_list = [
                {
                    'Error': error_item
                } for error_item in error_set
            ]
            
            raise ConditionCriteriaEvalError('Error occurred while evaluating condition.', errors_list)
        
    def process_condition_rule(
        self,
        condition_rules_row: pd.Series,
        context_data: dict[str, Any],
        condition_checker: CheckCondition
    ) -> None:
        condition_label = str(condition_rules_row.get('ConditionLabel', ''))
        condition_field = str(condition_rules_row.get('ConditionField', ''))
        condition_value = condition_rules_row.get('ConditionValue', '')
        
        condition_type = str(condition_rules_row.get('Condition', ''))
        is_cel_condition = condition_type == 'CEL_CONDITION'
        should_replace_cel_conditionvalue_placeholders = False
        if is_cel_condition:
            condition_field_value = context_data.copy()
            
            condition_value_placeholders = self._get_placeholder_matches_from_string(condition_value)
            should_replace_cel_conditionvalue_placeholders = len(condition_value_placeholders) == 1 and (
                condition_value in [r'{{{{{match}}}}}'.format(match=condition_value_placeholders[0]), f'<<{condition_value_placeholders[0]}>>']
            )
        else:
            condition_field_value, error = self._replace_placeholders(condition_field, context_data, 'CheckCondition.ConditionExecution.ConditionField')
            if error:
                condition_checker.add_condition(Condition(condition_label, condition_error=error))
                return
            
        if (not is_cel_condition) or (is_cel_condition and should_replace_cel_conditionvalue_placeholders):
            condition_value, error = self._replace_placeholders(condition_value, context_data, 'CheckCondition.ConditionExecution.ConditionValue')
            if error:
                condition_checker.add_condition(Condition(condition_label, condition_error=error))
                return
            
        condition_checker.check_and_add_condition(
            condition_type=condition_type,
            condition_label=condition_label,
            value_to_check=condition_field_value,
            condition_value=condition_value,
            date_format=condition_rules_row.get('DateFormat', '')
        )
        
    def process_condition_field_updates(
        self,
        record: pd.Series,
        condition_field_updates_list: list[dict],
        condition_checker: CheckCondition,
        context_data: dict[str, Any],
    ) -> tuple[dict, list[str], list[str]]:
        updated_record: dict = {**record}
        field_update_errors: list[str] = []
        field_update_condition_errors: list[str] = []
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
                        updated_value, error = self._replace_placeholders(value, context_data, f'CheckCondition.ConditionExecution.ConditionFieldUpdates')
                        if error:
                            field_update_errors.append(error)
                        value_to_set[key] = updated_value
                    
                updated_record.update(value_to_set)
                
        return updated_record, field_update_errors, field_update_condition_errors
        
    def _replace_placeholders(self, string: str | Any, context_data: dict, base_error_type: str) -> tuple[Any|str, str]:
        if not isinstance(string, str):
            return string, ''
            
        placeholder_matches = self._get_placeholder_matches_from_string(string)
        missing_placeholders: list[str] = []
        
        updated_string = string
        for match in set(placeholder_matches):
            match_value, error = cowjqutils.evaluate_jq_filter(
                context_data,
                jq_expression=f'.{match}' if not match.startswith('.') else match
            )
            if error:
                return '', self.log_manager.get_error_message(f'{base_error_type}.evaluation_error', {
                    'error': error,
                    'placeholder': match
                })
            if match_value is None:
                missing_placeholders.append(match)
                continue
                
            if string == r'{{{{{match}}}}}'.format(match=match) or string == f'<<{match}>>':
                return match_value, ''
                
            updated_string = updated_string.replace(r'{{{{{match}}}}}'.format(match=match), str(match_value))
            updated_string = updated_string.replace(f'<<{match}>>', str(match_value))
            
        if missing_placeholders:
            return '', self.log_manager.get_error_message(f'{base_error_type}.missing_placeholders', {
                'missing_placeholders': ', '.join(missing_placeholders)
            })

        return updated_string, ''
        
    def _get_placeholder_matches_from_string(self, string: str | Any) -> list[str]:
        placeholder_matches = re.findall(r'{{(.+?)}}', string)
        placeholder_matches.extend(re.findall(r'<<(.+?)>>', string))
        
        return placeholder_matches

    def _get_boolean_value_from_input(self, input_name: str) -> bool:
        value = self.task_inputs.user_inputs.get(input_name)
        
        if isinstance(value, str):
            return value.lower() == 'true'
        
        # Return True if value is None or value is truthy
        return value is None or bool(value)
        
    def _is_valid_file_input(self, input_url: str | Any = '', input_name: str = '') -> bool:
        if input_name and not input_url:
            input_url = self.task_inputs.user_inputs.get(input_name)
            
        return bool(input_url and input_url != '<<MINIO_FILE_PATH>>')
        
    def _download_df(self, file_url: str):
        return self.download_file_from_minio_as_df(file_url)
        
    def _download_json(self, file_url: str):
        return self.download_json_file_from_minio_as_iterable(file_url)
        
    def _download_toml(self, file_url: str):
        return self.download_toml_file_from_minio_as_dict(file_url)
        
    def _panic(self, error_message: str|list|dict):
        return self.upload_log_file_panic(
            error_message,
            logger
        )
            
        
class ConditionCriteriaEvalError(Exception):
    def __init__(self, message: str, errors_list: list[dict[str, str]]) -> None:
        super().__init__(message)
        self.errors_list = errors_list
        
        
class ConditionConfigValidator:
    CONDITION_FIELDS = {
        "EMPTY": ["Condition", "ConditionField"],
        "NOT_EMPTY": ["Condition", "ConditionField"],
        "FROM_RULE_DATE": ["Condition", "ConditionField"],
        "TO_RULE_DATE": ["Condition", "ConditionField"],
        "RULE_DATE_RANGE": ["Condition", "ConditionField"],

        "CEL_CONDITION": ["Condition", "ConditionValue"],

        "CONTAINS": ["Condition", "ConditionValue", "ConditionField"],
        "NOT_CONTAINS": ["Condition", "ConditionValue", "ConditionField"],
        "CONTAINS_ANY": ["Condition", "ConditionValue", "ConditionField"],
        "REGEX": ["Condition", "ConditionValue", "ConditionField"],
        "EQUALS": ["Condition", "ConditionValue", "ConditionField"],
        "NOT_EQUALS": ["Condition", "ConditionValue", "ConditionField"],
        "LESSER_THAN": ["Condition", "ConditionValue", "ConditionField"],
        "GREATER_THAN": ["Condition", "ConditionValue", "ConditionField"],
        "LESSER_THAN_OR_EQUALS": ["Condition", "ConditionValue", "ConditionField"],
        "GREATER_THAN_OR_EQUALS": ["Condition", "ConditionValue", "ConditionField"],
        "LT": ["Condition", "ConditionValue", "ConditionField"],
        "GT": ["Condition", "ConditionValue", "ConditionField"],
        "LT_EQ": ["Condition", "ConditionValue", "ConditionField"],
        "GT_EQ": ["Condition", "ConditionValue", "ConditionField"],
        "NUMBER_RANGE": ["Condition", "ConditionValue", "ConditionField"],

        "FROM_DATE": ["Condition", "ConditionValue", "ConditionField"],
        "TO_DATE": ["Condition", "ConditionValue", "ConditionField"],
        "DATE_RANGE": ["Condition", "ConditionValue", "ConditionField"],
        "FROM_DATE_OFFSET": ["Condition", "ConditionValue", "ConditionField"],
        "TO_DATE_OFFSET": ["Condition", "ConditionValue", "ConditionField"],
        "DATE_OFFSET_RANGE": ["Condition", "ConditionValue", "ConditionField"]
    }

    def __init__(self, condition_config: dict, log_manager: cards.LogConfigManager) -> None:
        self.log_manager = log_manager
        self.condition_config = condition_config
    

    def validate(self):
        errors: list[dict[str, str]] = []

        condition_rules = self.condition_config.get('ConditionRules')
        if not condition_rules or not isinstance(condition_rules, list):
            errors.append({'Error': self.log_manager.get_error_message('CheckCondition.ConditionConfig.Validation.ConditionRules.invalid')})
        else:
            condition_rules_errors = self.__validate_condition_rules(condition_rules)
            errors.extend(condition_rules_errors)

        condition_rules_config = self.condition_config.get('ConditionRulesConfig')
        if not condition_rules_config or not isinstance(condition_rules_config, dict):
            errors.append({
                'Error': self.log_manager.get_error_message('CheckCondition.ConditionConfig.Validation.ConditionRulesConfig.invalid')
            })
        elif condition_rules_config.get('ConditionsCriteria') is None:
            errors.append({
                'Error': self.log_manager.get_error_message('CheckCondition.ConditionConfig.Validation.ConditionRulesConfig.ConditionsCriteria.missing')
            })
        elif not isinstance(condition_rules_config.get('ConditionsCriteria'), str):
            errors.append({
                'Error': self.log_manager.get_error_message('CheckCondition.ConditionConfig.Validation.ConditionRulesConfig.ConditionsCriteria.invalid')
            })

        condition_field_updates = self.condition_config.get('ConditionFieldUpdates')
        if condition_field_updates and not isinstance(condition_field_updates, list):
            errors.append({
                'Error': self.log_manager.get_error_message('CheckCondition.ConditionConfig.Validation.ConditionFieldUpdates.invalid')
            })
        elif condition_field_updates:
            condition_field_updates_errors = self.__validate_condition_field_updates(condition_field_updates)
            errors.extend(condition_field_updates_errors)

        return errors


    def __validate_condition_rules(self, condition_rules: list[dict]) -> list[dict[str, str]]:
        errors: list[dict[str, str]] = []
        seen_labels = set()
        duplicate_labels = set()

        for condition_rule in condition_rules:
            label = condition_rule.get("ConditionLabel")
            condition = condition_rule.get("Condition")

            if not label:
                errors.append({
                    'Error': self.log_manager.get_error_message('CheckCondition.ConditionConfig.Validation.ConditionRules.ConditionLabel.missing')
                })
                return errors
            
            # Check for duplicate ConditionLabel
            if label in seen_labels:
                duplicate_labels.add(label)
                continue
            else:
                seen_labels.add(label)

            # Check if condition is valid
            if condition not in self.CONDITION_FIELDS:
                errors.append({
                    'Error': self.log_manager.get_error_message(
                        'CheckCondition.ConditionConfig.Validation.ConditionRules.Condition.unknown',
                        {'condition': condition, 'label': label}
                    )
                })
                continue  # No point checking required fields if Condition is invalid

            # Check for required fields
            required_fields = self.CONDITION_FIELDS[condition]
            missing = [field for field in required_fields if field not in condition_rule]
            if missing:
                errors.append({
                    'Error': self.log_manager.get_error_message(
                        'CheckCondition.ConditionConfig.Validation.ConditionRules.missing_fields',
                        {'condition': condition, 'label': label, 'missing_fields': ', '.join(missing)}
                    )
                })

            date_format = condition_rule.get('DateFormat')
            if date_format and not isinstance(date_format, (str, dict)):
                errors.append({'Error': self.log_manager.get_error_message(
                    'CheckCondition.ConditionConfig.Validation.ConditionRules.DateFormat.invalid',
                    {'condition': condition, 'label': label}
                )})

        if duplicate_labels:
            errors.append({
                'Error': self.log_manager.get_error_message(
                    'CheckCondition.ConditionConfig.Validation.ConditionRules.DateFormat.invalid',
                    {'duplicate_labels': ', '.join(duplicate_labels)}
                )
            })

        return errors

    def __validate_condition_field_updates(self, condition_field_updates: list[dict[str, Any]]) -> list[dict[str, str]]:
        errors: list[dict[str, str]] = []
        for condition_field_update in condition_field_updates:
            conditions_criteria = condition_field_update.get('ConditionsCriteria')
            if not conditions_criteria:
                errors.append({
                    'Error': self.log_manager.get_error_message('CheckCondition.ConditionConfig.Validation.ConditionFieldUpdates.ConditionsCriteria.missing')
                })

            has_pass_or_fail = False
            for key, value in list(condition_field_update.items()):
                upper_key = key.upper()
                if upper_key in ['PASS', 'FAIL']:
                    condition_field_update[upper_key] = value
                    has_pass_or_fail = True

            if not has_pass_or_fail:
                errors.append({
                    'Error': self.log_manager.get_error_message('CheckCondition.ConditionConfig.Validation.ConditionFieldUpdates.pass_and_fail_missing')
                })

        return errors
