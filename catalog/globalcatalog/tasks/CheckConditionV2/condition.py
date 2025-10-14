
from typing import Tuple, Literal, List, Callable, Any, Optional
from compliancecowcards.structs import cards
from datetime import datetime
from dateutil.relativedelta import relativedelta
from dateutil import parser as dateparser
import pandas as pd
import re
from compliancecowcards.structs.cards import AbstractTask as Task, Logger, LogConfigManager
import celpy
import celpy.celtypes
from celpy.evaluation import CELEvalError, CELSyntaxError
from celpy.celparser import CELParseError
from celpy.adapter import json_to_cel
import numpy as np

SENTINEL_DATETIME = datetime.min
SENTINEL_RELATIVEDELTA = relativedelta()

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

    def __init__(self, task_obj: Task, logger: Logger, log_manager: LogConfigManager) -> None:
        self.__conditions: List[Condition] = []
        self.logger = logger
        self.log_manager = log_manager
        self.condition_type_utils = ConditionTypeUtils(task_obj, logger, log_manager)

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
            
        if not condition_func:
            return None, f'Developer error: No implementation found for condition with type: {condition_type}'

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
                    
            if not condition_data:
                return 'ERROR', '', error_conditions
                
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
            
            if not condition_func:
                return 'ERROR', 'Developer error: No value found for condition with type: CEL_CONDITION', error_conditions
            
            has_criteria_passed, error = condition_func()
            if error:
                return 'ERROR', error, error_conditions
            
            return 'PASS' if has_criteria_passed else 'FAIL', '', []
        else:
            return 'ERROR', f'Expected ConditionCriteria to be a string, but got {type(criteria)} instead', []


class ConditionTypeUtils:
    def __init__(self, task_obj: Task, logger: Logger, log_manager: LogConfigManager) -> None:
        self.value_to_check = ''
        self.condition_value = ''
        self.condition_type = ''
        self.task_obj: Task = task_obj
        self.logger = logger
        self.log_manager = log_manager

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

    def get_condition_func(self, condition_type: str) -> Tuple[Callable[[], tuple[bool|None, str]] | None, str]:

        self.condition_type = condition_type.upper()

        if self.condition_type in self.__single_value_condition_type_mapping:
            return self.__single_value_condition_type_mapping[self.condition_type], str('')
        
        if self.condition_type in self.__condition_type_mapping:
            return self.__condition_type_mapping[self.condition_type], ''
        
        if self.condition_type in self.__date_condition_type_mapping:
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
        if not isinstance(self.value_to_check, (list, str, dict, pd.Series)):
            return None, self.log_manager.get_error_message(f'CheckCondition.ConditionExecution.ConditionType.{self.condition_type}.ConditionField.type_error', {
                'expected_types': 'list, dict, str',
                'actual_type': type(self.value_to_check).__name__
            })
        
        if isinstance(self.condition_value, str):
            return self.condition_value in self.value_to_check, ''
        elif isinstance(self.condition_value, list):
            return all([value in self.value_to_check for value in self.condition_value]), ''
        else:
            return None, self.log_manager.get_error_message(f'CheckCondition.ConditionExecution.ConditionType.{self.condition_type}.ConditionValue.type_error', {
                'expected_types': 'list, str',
                'actual_type': type(self.condition_value).__name__
            })
        
    def check_not_contains(self) -> Tuple[bool|None, str]:
        condition_status, error = self.check_contains()
        if error:
            return None, error
        
        return not condition_status, ''
        
    def check_contains_any(self) -> Tuple[bool|None, str]:
        if not isinstance(self.value_to_check, (list, str, dict, pd.Series)):
            return None, self.log_manager.get_error_message('CheckCondition.ConditionExecution.ConditionType.CONTAINS_ANY.ConditionField.type_error', {
                'expected_types': 'list, dict, str',
                'actual_type': type(self.value_to_check).__name__
            })

        if isinstance(self.condition_value, list):
            return any([value in self.value_to_check for value in self.condition_value]), ''
        else:
            return None, self.log_manager.get_error_message('CheckCondition.ConditionExecution.ConditionType.CONTAINS_ANY.ConditionValue.type_error', {
                'expected_types': 'list',
                'actual_type': type(self.condition_value).__name__
            })
    
    def check_equals(self) -> Tuple[bool|None, str]:
        return self.value_to_check == self.condition_value, ''
    
    def check_not_equals(self) -> Tuple[bool|None, str]:
        return self.value_to_check != self.condition_value, ''
    
    def check_lesser_than(self) -> Tuple[bool|None, str]:
        if not isinstance(self.value_to_check, (int, float)) or not isinstance(self.condition_value, (int, float)):
            return None, self.log_manager.get_error_message('CheckCondition.ConditionExecution.ConditionType.LESSER_THAN.type_error')
        
        return self.value_to_check < self.condition_value, ''
    
    def check_greater_than(self) -> Tuple[bool|None, str]:
        if not isinstance(self.value_to_check, (int, float)) or not isinstance(self.condition_value, (int, float)):
            return None, self.log_manager.get_error_message('CheckCondition.ConditionExecution.ConditionType.GREATER_THAN.type_error')
        
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
            return None, self.log_manager.get_error_message('CheckCondition.ConditionExecution.ConditionType.REGEX.type_error')
        
        return bool(re.search(pattern=self.condition_value, string=self.value_to_check)), ''
    
    def check_number_range(self) -> Tuple[bool|None, str]:
        if not isinstance(self.value_to_check, (int, float)):
            return None, self.log_manager.get_error_message('CheckCondition.ConditionExecution.ConditionType.NUMBER_RANGE.ConditionField.type_error', {
                'expected_types': 'int, float',
                'actual_type': type(self.value_to_check).__name__
            })
        
        start_value, end_value, error = self.get_range_values()
        if error:
            return None, error
        
        if not start_value and not end_value:
            return None, self.log_manager.get_error_message('CheckCondition.ConditionExecution.ConditionType.NUMBER_RANGE.ConditionValue.empty_range_values')
        
        condition_status = True
        try:
            if start_value:
                start_value = float(start_value)
                condition_status = condition_status and self.value_to_check >= start_value
                
            if end_value:
                end_value = float(end_value)
                condition_status = condition_status and self.value_to_check <= end_value
        except (TypeError, ValueError) as e:
            return None, self.log_manager.get_error_message('CheckCondition.ConditionExecution.ConditionType.NUMBER_RANGE.ConditionValue.invalid_range_values', {
                'error': e
            })
        
        return condition_status, ''
    
    def check_cel(self) -> Tuple[bool|None, str]:
        if not isinstance(self.value_to_check, dict):
            return None, f"INTERNAL_ERROR: Cannot check {self.condition_type}, as value_to_check is of an unsupported type :: Expected 'dict', but got '{type(self.value_to_check)}' instead"
        if not isinstance(self.condition_value, str):
            return None, self.log_manager.get_error_message('CheckCondition.ConditionExecution.ConditionType.CEL_CONDITION.ConditionValue.type_error', {
                'expected_types': 'list',
                'actual_type': type(self.condition_value).__name__
            })
        try:
            cel_env = celpy.Environment()
            cel_ast = cel_env.compile(self.condition_value.replace('<<', '').replace('>>', ''))
            activation = json_to_cel(self.value_to_check)
            result = cel_env.program(cel_ast).evaluate(activation) # type: ignore

            if isinstance(result, celpy.celtypes.BoolType):
                return bool(result), ''
            else:
                return None, self.log_manager.get_error_message('CheckCondition.ConditionExecution.ConditionType.CEL_CONDITION.invalid_result', {
                    'result_value': result,
                    'result_value_type': type(result).__name__
                })
        except (CELParseError, CELSyntaxError) as e:
            self.logger.log_data({'CELError': f"CELExpression: {self.condition_value} :: Error: {e}"})
            return None, self.log_manager.get_error_message('CheckCondition.ConditionExecution.ConditionType.CEL_CONDITION.ConditionValue.syntax_error', {
                'expression': self.condition_value
            })
        except CELEvalError as e:
            self.logger.log_data({'CELError': f"CELExpression: {self.condition_value} :: Error: {e}"})
            return None, self.log_manager.get_error_message('CheckCondition.ConditionExecution.ConditionType.CEL_CONDITION.evaluation_error', {
                'expression': self.condition_value
            })
    
    ################################ DATE CONDITIONS ################################

    def check_from_date(self) -> Tuple[bool|None, str]:
        if not isinstance(self.condition_value, str):
            return None, self.log_manager.get_error_message(f'CheckCondition.ConditionExecution.ConditionType.{self.condition_type}.ConditionValue.type_error', {
                'expected_types': 'str',
                'actual_type': type(self.condition_value).__name__
            })
        
        condition_value_date, error = self.get_datetime_from_expression(self.condition_value, f'CheckCondition.ConditionExecution.ConditionType.{self.condition_type}.ConditionValue')
        if error:
            return None, error

        if not isinstance(self.value_to_check, str):
            return None, self.log_manager.get_error_message(f'CheckCondition.ConditionExecution.ConditionType.{self.condition_type}.ConditionField.type_error', {
                'expected_types': 'str',
                'actual_type': type(self.value_to_check).__name__
            })
        
        date_to_check, error = self.get_datetime_from_expression(self.value_to_check, f'CheckCondition.ConditionExecution.ConditionType.{self.condition_type}.ConditionField')
        if error:
            return None, error
        
        return date_to_check >= condition_value_date, ''
    
    def check_to_date(self) -> Tuple[bool|None, str]:
        if not isinstance(self.condition_value, str):
            return None, self.log_manager.get_error_message(f'CheckCondition.ConditionExecution.ConditionType.{self.condition_type}.ConditionValue.type_error', {
                'expected_types': 'str',
                'actual_type': type(self.condition_value).__name__
            })
        
        condition_value_date, error = self.get_datetime_from_expression(self.condition_value, f'CheckCondition.ConditionExecution.ConditionType.{self.condition_type}.ConditionValue')
        if error:
            return None, error

        if not isinstance(self.value_to_check, str):
            return None, self.log_manager.get_error_message(f'CheckCondition.ConditionExecution.ConditionType.{self.condition_type}.ConditionField.type_error', {
                'expected_types': 'str',
                'actual_type': type(self.value_to_check).__name__
            })
        
        date_to_check, error = self.get_datetime_from_expression(self.value_to_check, f'CheckCondition.ConditionExecution.ConditionType.{self.condition_type}.ConditionField')
        if error:
            return None, error
        
        return date_to_check <= condition_value_date, ''
    
    def check_date_range(self) -> Tuple[bool|None, str]:
        if not isinstance(self.value_to_check, str):
            return None, self.log_manager.get_error_message(f'CheckCondition.ConditionExecution.ConditionType.{self.condition_type}.ConditionField.type_error', {
                'expected_types': 'str',
                'actual_type': type(self.value_to_check).__name__
            })
        
        date_to_check, error = self.get_datetime_from_expression(self.value_to_check, f'CheckCondition.ConditionExecution.ConditionType.{self.condition_type}.ConditionField')
        if error:
            return None, error
        
        start_date, end_date, error = self.get_range_values(separator_string="->")
        if error:
            return None, error
        
        if not start_date and not end_date:
            return None, self.log_manager.get_error_message(f'CheckCondition.ConditionExecution.ConditionType.{self.condition_type}.ConditionValue.empty_range_values')
        
        condition_status = True
        if start_date:
            start_date, error = self.get_datetime_from_expression(start_date, f'CheckCondition.ConditionExecution.ConditionType.{self.condition_type}.ConditionValue.StartDate')
            if error: return None, error

            condition_status = condition_status and date_to_check >= start_date
            
        if end_date:
            end_date, error = self.get_datetime_from_expression(end_date, f'CheckCondition.ConditionExecution.ConditionType.{self.condition_type}.ConditionValue.EndDate')
            if error: return None, error

            if start_date and start_date > end_date:
                return None, self.log_manager.get_error_message(f'CheckCondition.ConditionExecution.ConditionType.{self.condition_type}.ConditionValue.invalid_range_values')

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
        if not isinstance(self.condition_value, str):
            return None, self.log_manager.get_error_message(f'CheckCondition.ConditionExecution.ConditionType.{self.condition_type}.ConditionValue.type_error', {
                'expected_types': 'str',
                'actual_type': type(self.condition_value).__name__
            })
            
        date_offset, error = self.__get_relativedelta_from_delta_str(self.condition_value, f'CheckCondition.ConditionExecution.ConditionType.{self.condition_type}.ConditionValue')
        if error:
            return None, error
        
        should_subtract = str(self.condition_value).startswith('-')
        from_date = (datetime.now() - date_offset) if should_subtract else (datetime.now() + date_offset)
        if not isinstance(self.value_to_check, str):
            return None, self.log_manager.get_error_message(f'CheckCondition.ConditionExecution.ConditionType.{self.condition_type}.ConditionField.type_error', {
                'expected_types': 'str',
                'actual_type': type(self.value_to_check).__name__
            })
        
        date_to_check, error = self.get_datetime_from_expression(self.value_to_check, f'CheckCondition.ConditionExecution.ConditionType.{self.condition_type}.ConditionField')
        if error:
            return None, error
        
        return date_to_check >= from_date, ''
    
    def check_to_date_offset(self) -> Tuple[bool|None, str]:
        if not isinstance(self.condition_value, str):
            return None, self.log_manager.get_error_message(f'CheckCondition.ConditionExecution.ConditionType.{self.condition_type}.ConditionValue.type_error', {
                'expected_types': 'str',
                'actual_type': type(self.condition_value).__name__
            })
            
        date_offset, error = self.__get_relativedelta_from_delta_str(self.condition_value, f'CheckCondition.ConditionExecution.ConditionType.{self.condition_type}.ConditionValue')
        if error:
            return None, error
        
        should_subtract = str(self.condition_value).startswith('-')
        to_date = (datetime.now() - date_offset) if should_subtract else (datetime.now() + date_offset)
        if not isinstance(self.value_to_check, str):
            return None, self.log_manager.get_error_message(f'CheckCondition.ConditionExecution.ConditionType.{self.condition_type}.ConditionField.type_error', {
                'expected_types': 'str',
                'actual_type': type(self.value_to_check).__name__
            })
        
        date_to_check, error = self.get_datetime_from_expression(self.value_to_check, f'CheckCondition.ConditionExecution.ConditionType.{self.condition_type}.ConditionField')
        if error:
            return None, error
        
        return date_to_check <= to_date, ''
        
    def check_date_offset_range(self) -> Tuple[bool|None, str]:
        if not isinstance(self.value_to_check, str):
            return None, self.log_manager.get_error_message(f'CheckCondition.ConditionExecution.ConditionType.{self.condition_type}.ConditionField.type_error', {
                'expected_types': 'str',
                'actual_type': type(self.value_to_check).__name__
            })
        
        date_to_check, error = self.get_datetime_from_expression(self.value_to_check, f'CheckCondition.ConditionExecution.ConditionType.{self.condition_type}.ConditionField')
        if error:
            return None, error
        
        start_date_offset_str, end_date_offset_str, error = self.get_range_values()
        if error:
            return None, error
        
        if not start_date_offset_str and not end_date_offset_str:
            return None, self.log_manager.get_error_message(f'CheckCondition.ConditionExecution.ConditionType.{self.condition_type}.ConditionValue.empty_range_values')
        
        condition_status = True
        start_date = None
        if start_date_offset_str:
            start_date, error = self.get_datetime_from_expression(
                f"{'now +' if not start_date_offset_str.startswith(('+', '-')) else 'now'} {start_date_offset_str}" if start_date_offset_str != "now" or start_date_offset_str != 'current_date' else start_date_offset_str,
                f'CheckCondition.ConditionExecution.ConditionType.{self.condition_type}.ConditionValue.StartDate'
            )
            if error:
                return None, error
            
            condition_status = date_to_check >= start_date
        
        if end_date_offset_str and condition_status:
            end_date, error = self.get_datetime_from_expression(
                f"{'now +' if not end_date_offset_str.startswith(('+', '-')) else 'now'} {end_date_offset_str}" if end_date_offset_str != "now" or start_date_offset_str != 'current_date' else end_date_offset_str,
                f'CheckCondition.ConditionExecution.ConditionType.{self.condition_type}.ConditionValue.EndDate'
            )
            if error:
                return None, error
                
            if start_date and start_date > end_date:
                return None, self.log_manager.get_error_message(f'CheckCondition.ConditionExecution.ConditionType.{self.condition_type}.ConditionValue.invalid_range_values')
            
            condition_status = date_to_check <= end_date
        
        return condition_status, ''
    
    ################################ OTHER FUNCTIONS ################################
    
    def convert_datetime_to_str(self, date: datetime) -> str:
        if self.date_format and isinstance(self.date_format, str):
            return date.strftime(self.date_format)
        return date.isoformat()

    def get_range_values(self, separator_string: str = ':') -> Tuple[str, str, str]:
        if not isinstance(self.condition_value, str):
            return '', '', self.log_manager.get_error_message(f'CheckCondition.ConditionExecution.ConditionType.{self.condition_type}.ConditionValue.type_error', {
                'expected_types': 'str',
                'actual_type': type(self.condition_value).__name__
            })
        
        range_data_split = f" {self.condition_value} ".split(separator_string)
        if len(range_data_split) != 2:
            return '', '', self.log_manager.get_error_message(f'CheckCondition.ConditionExecution.ConditionType.{self.condition_type}.ConditionValue.syntax_error')
        
        return range_data_split[0].strip(), range_data_split[1].strip(), ''
    
    def get_datetime_from_date_string(self, date_string: str, error_type_prefix: str) -> tuple[datetime, str]:
        parsed_date = None
        
        if date_string == 'now':
            return datetime.now(), ''
            
        if date_string == 'current_date':
            return datetime.combine(datetime.now().date(), datetime.min.time()), ''
                
        try:
            if not self.date_format or isinstance(self.date_format, dict):
                is_day_first = isinstance(self.date_format, dict) and bool(self.date_format.get('IsDayFirst'))
                parsed_date = dateparser.parse(date_string, dayfirst=is_day_first)
            elif isinstance(self.date_format, str):
                parsed_date = datetime.strptime(date_string, self.date_format)
        except (ValueError, dateparser.ParserError, OverflowError) as e:
            return SENTINEL_DATETIME, self.log_manager.get_error_message(f'{error_type_prefix}.parse_error', {
                'error': e
            })
    
        if not parsed_date:
            return SENTINEL_DATETIME, f"Cannot check {self.condition_type}, as 'DateFormat' is invalid in ConditionConfig'"
    
        return parsed_date, ''
    
    def get_datetime_from_expression(self, date_string: str, error_type_prefix: str) -> tuple[datetime, str]:
        date_expression_match = re.match(r'^\s*(.+)\s+([+-])\s+(.+)$', date_string)
        if date_expression_match:
            base_date_str, operator, delta_str = date_expression_match.groups()
    
            return self.__evaluate_date_expression(
                base_date_str.strip(),
                operator.strip(),
                delta_str.strip(),
                error_type_prefix
            )
    
        return self.get_datetime_from_date_string(date_string, error_type_prefix)
    
    def __evaluate_date_expression(self, base_date_str: str, operator: str, delta_str: str, error_type_prefix: str) -> tuple[datetime, str]:
        parsed_date, error = self.get_datetime_from_date_string(base_date_str, error_type_prefix)
        if error:
            return SENTINEL_DATETIME, error
        
        delta, error = self.__get_relativedelta_from_delta_str(delta_str, error_type_prefix)
        if error:
            return SENTINEL_DATETIME, error
    
        return parsed_date + delta if operator == '+' else parsed_date - delta, ''
    
    def __get_relativedelta_from_delta_str(self, delta_str: str, error_type_prefix: str) -> tuple[relativedelta, str]:
        delta_args: dict[str, Any] = {"years": 0, "months": 0, "days": 0, "hours": 0, "minutes": 0, "seconds": 0}
    
        units = {
            'y': 'years',
            'm': 'months',
            'd': 'days',
            'H': 'hours',
            'M': 'minutes',
            'S': 'seconds'
        }
    
        delta_str_parts = re.findall(r'([+-]?\d+)([a-zA-Z]+)', delta_str)
        if not delta_str_parts:
            return SENTINEL_RELATIVEDELTA, self.log_manager.get_error_message(f'{error_type_prefix}.DateExpression.syntax_error')
    
        # Parse components like "1d", "2S", "3m"
        for part in delta_str_parts:
            value, unit = part
            if unit not in units:
                return SENTINEL_RELATIVEDELTA, self.log_manager.get_error_message(f'{error_type_prefix}.DateExpression.unknown_time_unit', {
                    'unit': unit
                })
            delta_args[units[unit]] += int(value)
    
        return relativedelta(**delta_args), ''
