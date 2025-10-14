import json
import math
import os
import pathlib
import re
import urllib.parse
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

import jmespath
import numpy as np
import pandas as pd
import toml
# As per the selected app, we're importing the app package
from applicationtypes.nocredapp import nocredapp
from compliancecowcards.structs import cards

MINIO_FILE_PATH = "<<MINIO_FILE_PATH>>"


class TransformType(Enum):
    """Enum to define transformation modes."""

    ADD_COLUMN = "AddColumn"
    UPDATE_COLUMN = "UpdateColumn"
    DELETE_COLUMN = "DeleteColumn"
    REORDER_COLUMN = "ReorderColumn"
    REMOVE_DUPLICATES = "RemoveDuplicates"


class AddColumnType(Enum):
    """Enum to define types of column addition."""

    BY_CONDITION = "ByCondition"
    AS_OBJECT = "AsObject"
    BY_FUNCTION = "ByFunction"
    BY_MAP = "ByMap"
    AS_LIST = "AsList"
    BY_CONTAINS = "ByContains"  # Add this line


class UpdateColumnType(Enum):
    """Enum to define types of column update."""

    CONCAT = "Concat"
    APPEND = "Append"
    SPLIT = "Split"
    REPLACE = "Replace"
    CHANGE_PATH = "ChangePath"


class Task(cards.AbstractTask):

    def __init__(self) -> None:
        """Initialize the Task with empty log data."""
        super().__init__()
        self.prev_log_data: List[Dict[str, Any]] = []

    """Task class to transform data based on configuration and input files."""

    """Initialize the Task with an empty error message tracker."""
    err_msg = ""

    def execute(self) -> Dict[str, str]:
        """Execute the task to transform data and upload results to MinIO.

        Returns:
            Dict[str, str]: Dictionary containing output file URLs or log file with errors.
        """

        user_inputs = self.task_inputs.user_inputs

        # Create LogConfigManager instance
        default_log_config_filepath = str(
            pathlib.Path(__file__).parent.joinpath("LogConfig_default.toml").resolve()
        )
        custom_log_config_url = self.task_inputs.user_inputs.get("LogConfig")
        log_manager, error = cards.LogConfigManager.from_minio_file_url(
            (
                custom_log_config_url
                if custom_log_config_url and custom_log_config_url != MINIO_FILE_PATH
                else ""
            ),
            self.download_toml_file_from_minio_as_dict,
            default_log_config_filepath,
            default_context_data={
                'fromdate': self.task_inputs.from_date.strftime('%d/%m/%Y %H:%M'),
                'todate': self.task_inputs.to_date.strftime('%d/%m/%Y %H:%M')
            }
            
        )
        # Exit the task if failed to form LogConfigManager instance
        if error:
            return {
                "Error": f"Error occured while creating instance of 'LogConfigManager' for log_config. {error}"
            }

        # Handle LogFile from previous task
        log_file = user_inputs.get("LogFile", "")
        prev_log_exist = False
        if log_file and log_file != MINIO_FILE_PATH:
            prev_log_exist = True
            """ProceedIfLogExists determines whether to continue and complete the task if a previous log file is found.
            If true: The task continues and returns at the end.
            If false: The task stops immediately and returns the existing log file."""
            if not user_inputs.get("ProceedIfLogExists", True):
                return {"LogFile": log_file}
            else:
                log_data, error = self.download_json_file_from_minio_as_dict(log_file)
                self.prev_log_data = log_data
                if error:
                    return self.upload_log_file_panic(
                        log_manager.get_error_message(
                            "TransformData.Inputs.LogFile.download_error",
                            {"error": error.get("error")},
                        ),
                        log_file_name="Error",
                    )
                # Handle invalid log file
                if any("Error" not in log for log in log_data):
                    return self.upload_log_file_panic(
                        error_data=log_manager.get_error_message(
                            "TransformData.Outputs.LogFile.invalid",
                            {"error": error.get("error")},
                        ),
                        log_file_name="Error",
                    )

        """ProceedIfErrorExists determines whether to proceed with the next task when an error occurs.
            If true: The error is returned as a log file, and execution continues to the next task.
            If false: The rule flow stops immediately."""
        proceed_if_error_exists = user_inputs.get("ProceedIfErrorExists", True)
        self.set_log_file_name("LogFile" if proceed_if_error_exists else "Errors")

        # Perform basic validation
        val_errors = self.validate_inputs(log_manager)
        if val_errors:
            return self.upload_log_file_panic(error_data=val_errors)

        # Download and validate input files
        toml_bytes, input_file2_df, source_data_df, errors = self._download_input_files(
            log_manager
        )
        if errors:
            return self.upload_log_file_panic(error_data=errors)

        # Check for empty files
        empty_files = self._check_empty_files(
            toml_bytes, source_data_df, input_file2_df
        )
        file_error_keys = {
            "TransformConfigFile": "TransformData.Inputs.TransformConfigFile.empty_content",
            "InputFile1": "TransformData.Inputs.InputFile1.empty_content",
            "InputFile2": "TransformData.Inputs.InputFile2.empty_content",
        }
        if empty_files:
            empty_file_error_list = []
            for file_name in empty_files:
                if file_name in file_error_keys:
                    empty_file_error_list.append(
                        {
                            "Error": log_manager.get_error_message(
                                file_error_keys[file_name],
                                error,
                            )
                        }
                    )

            return self.upload_log_file_panic(error_data=empty_file_error_list)

        # Parse TOML configuration
        try:
            toml_data = toml.loads(toml_bytes.decode("utf-8"))
            toml_errors = self.validate_toml_data(toml_data, log_manager)
            if toml_errors:
                return self.upload_log_file_panic(error_data=toml_errors)
        except (UnicodeDecodeError, toml.TomlDecodeError) as e:
            return self.upload_log_file_panic(
                log_manager.get_error_message(
                    "TransformData.Exceptions.TransformConfigFile.toml_parse_error",
                    {"error": str(e)},
                )
            )

        # Process transformations
        pd.options.mode.copy_on_write = True  # Avoid pandas copy-on-write warnings
        error_list: List[Dict] = []
        source_data_df = self._apply_transformations(
            log_manager,
            source_data_df,
            toml_data,
            input_file2_df,
            error_list,
            proceed_if_error_exists,
        )

        # Prepare and upload response
        return self._upload_results(
            log_manager,
            source_data_df,
            error_list,
            user_inputs.get("OutputFileName") or "OutputFile",
            prev_log_exist,
        )

    def _upload_results(
        self,
        log_manager: cards.LogConfigManager,
        source_df: pd.DataFrame,
        error_list: List,
        file_name: str,
        prev_log_exist: bool,
    ) -> Dict[str, str]:
        """Upload transformed data and errors to MinIO.

        Args:
            source_df: Transformed DataFrame.
            error_list: List of errors encountered.
            file_name: Name for the output file.

        Returns:
            Dict[str, str]: Response with file URLs or error.
        """
        response = {}
        if not source_df.empty:
            file_path, error = self.upload_df_as_parquet_file_to_minio(
                source_df, file_name
            )
            if error:
                return self.upload_log_file_panic(
                    log_manager.get_error_message(
                        "TransformData.Outputs.OutputFile.upload_failed",
                        {"error": error.get("error")},
                    )
                )
            response["OutputFile"] = file_path

        # if error_list or prev_log_exist:
        if self.prev_log_data:
            if not error_list:
                self.set_log_file_name("LogFile")
            response.update(self.upload_log_file_panic(error_data=error_list))
        elif error_list:
            response.update(self.upload_log_file_panic(error_data=error_list))

        return response

    def _download_input_files(
        self, log_manager: cards.LogConfigManager
    ) -> Tuple[bytes, pd.DataFrame, pd.DataFrame, List[Dict[str, str]]]:
        """Download input files from MinIO.

        Returns:
            Tuple containing TOML bytes, InputFile2 DataFrame, InputFile1 DataFrame, and errors.
        """
        errors = []
        user_inputs = self.task_inputs.user_inputs

        toml_bytes, error = self.download_file_from_minio(
            user_inputs["TransformConfigFile"]
        )
        if error:
            errors.append(
                {
                    "Error": log_manager.get_error_message(
                        "TransformData.Inputs.TransformConfigFile.download_error",
                        {"error": error.get("error")},
                    )
                }
            )

        input_file2_df = pd.DataFrame()
        input_file2 = user_inputs.get("InputFile2", "")
        if input_file2 and input_file2 != MINIO_FILE_PATH:
            input_file2_df, error = self.download_csv_file_from_minio_as_df(input_file2)
            if error:
                errors.append(
                    {
                        "Error": log_manager.get_error_message(
                            "TransformData.Inputs.InputFile2.download_error",
                            {"error": error.get("error")},
                        )
                    }
                )

        # Download InputFile1
        file_download_func = {
            "json": self.download_json_file_from_minio_as_df,
            "ndjson": self.download_ndjson_file_from_minio_as_df,
            "csv": self.download_csv_file_from_minio_as_df,
            "parquet": self.download_parquet_file_from_minio_as_df,
        }
        file_extension = user_inputs["InputFile1"].split(".")[-1]
        source_data_df, error = file_download_func[file_extension](
            user_inputs["InputFile1"]
        )
        if error:
            errors.append(
                {
                    "Error": log_manager.get_error_message(
                        "TransformData.Inputs.InputFile1.download_error",
                        {"error": error.get("error")},
                    )
                }
            )

        return toml_bytes, input_file2_df, source_data_df, errors

    def _check_empty_files(
        self, toml_bytes: bytes, source_df: pd.DataFrame, input_file2_df: pd.DataFrame
    ) -> List[str]:
        """Check for empty input files.

        Args:
            toml_bytes: Bytes of the TransformConfigFile.
            source_df: DataFrame from InputFile1.
            input_file2_df: DataFrame from InputFile2.

        Returns:
            List[str]: List of empty file names.
        """
        empty_files = []
        if not toml_bytes:
            empty_files.append("TransformConfigFile")
        if source_df.empty:
            empty_files.append("InputFile1")
        if (
            self.task_inputs.user_inputs.get("InputFile2")
            and self.task_inputs.user_inputs.get("InputFile2") != MINIO_FILE_PATH
            and input_file2_df.empty
        ):
            empty_files.append("InputFile2")
        return empty_files

    def _apply_transformations(
        self,
        log_manager: cards.LogConfigManager,
        source_df: pd.DataFrame,
        toml_data: Dict,
        input_file2_df: pd.DataFrame,
        error_list: List,
        proceed_if_error_exists: str,
    ) -> pd.DataFrame:
        """Apply transformations specified in the TOML configuration.

        Args:
            source_df: Source DataFrame to transform.
            toml_data: Parsed TOML configuration.
            input_file2_df: Optional second input DataFrame.
            error_list: List to append errors to.

        Returns:
            pd.DataFrame: Transformed DataFrame.
        """
        transform_methods: Dict[
            str, Callable[..., Tuple[pd.DataFrame, Optional[str]]]
        ] = {
            TransformType.ADD_COLUMN.value: self.add_column,
            TransformType.UPDATE_COLUMN.value: self.update_column,
            TransformType.DELETE_COLUMN.value: self.delete_column,
            TransformType.REORDER_COLUMN.value: self.re_order_column,
            TransformType.REMOVE_DUPLICATES.value: self.remove_duplicates,
        }

        for mode, config in toml_data.items():
            if mode in transform_methods:
                if mode == TransformType.ADD_COLUMN.value:
                    source_df, error = transform_methods[mode](
                        log_manager,
                        source_df,
                        config,
                        input_file2_df,
                    )
                else:
                    source_df, error = transform_methods[mode](
                        log_manager,
                        source_df,
                        config,
                    )
                if error:
                    error_list.append({"Error": f"Error processing '{mode}': {error}"})
                    if not proceed_if_error_exists:
                        break
        return source_df

    def add_column(
        self,
        log_manager: cards.LogConfigManager,
        source_df: pd.DataFrame,
        column_info: Dict,
        input_file2_df: pd.DataFrame,
    ) -> Tuple[pd.DataFrame, Optional[str]]:
        """Add columns to the DataFrame based on TOML configuration.

        Args:
            source_df: Source DataFrame to modify.
            column_info: Configuration for adding columns.
            input_file2_df: Optional second input DataFrame for mapping.

        Returns:
            Tuple[pd.DataFrame, Optional[str]]: Updated DataFrame and potential error.
        """
        try:
            if not column_info or source_df.empty:
                return source_df, None

            for key, value in column_info.items():
                if key == AddColumnType.BY_CONDITION.value and isinstance(value, list):
                    for config in value:
                        if config:
                            source_df = self._handle_by_condition(
                                source_df, config, input_file2_df, log_manager
                            )

                elif key == AddColumnType.AS_OBJECT.value and isinstance(value, list):
                    for config in value:
                        if config:
                            new_col, obj_vals = config.get(
                                "ColumnName", ""
                            ), config.get("ObjectValues", "")

                            source_df = source_df.apply(
                                lambda row: self.add_column_as_object(
                                    row, new_col, obj_vals.split(",")
                                ),
                                axis=1,
                            )

                elif key == AddColumnType.BY_FUNCTION.value and isinstance(value, list):
                    for config in value:
                        if config:
                            new_col = config.get("ColumnName", "")
                            self.add_column_by_function(
                                source_df,
                                new_col,
                                config.get("Source", ""),
                                config["Function"],
                                config,
                            )

                elif key == AddColumnType.BY_MAP.value and isinstance(value, list):
                    for config in value:
                        if config:
                            new_col = config.get("ColumnName", "")
                            is_case_sensitive = config.get("IsCaseSensitive", "")
                            if not is_case_sensitive:
                                is_case_sensitive = False

                            source_df = source_df.apply(
                                lambda row: self.add_column_in_df_by_mapping(
                                    row,
                                    input_file2_df,
                                    new_col,
                                    config["Source"],
                                    config["Target"],
                                    config["TargetMapping"],
                                    is_case_sensitive,
                                ),
                                axis=1,
                            )

                elif key == AddColumnType.AS_LIST.value and isinstance(value, list):
                    for config in value:
                        if config:
                            new_col, source_col, target, list_data = (
                                config.get("ColumnName", ""),
                                config.get("Source", ""),
                                config.get("Target", ""),
                                config.get("ListData", ""),
                            )

                            new_col = config.get("ColumnName", "")
                            if list_data:
                                source_df[new_col] = [list_data.split(",")] * len(
                                    source_df
                                )
                            else:
                                # Apply the mapping function row by row
                                source_df = source_df.apply(
                                    lambda row: self.add_column_as_list(
                                        row, source_col, target, new_col
                                    ),
                                    axis=1,
                                )

                elif key == AddColumnType.BY_CONTAINS.value and isinstance(value, list):
                    for config in value:
                        if config:
                            new_col = config.get("ColumnName", "")
                            source_col = config.get("SourceColumn", "")
                            conditions = config.get("Conditions", [])
                            logical_expression = config.get("LogicalExpression", "")
                            case_sensitive = config.get("CaseSensitive", True)

                            source_df[new_col] = source_df.apply(
                                lambda row: self.check_contains_multi_condition(
                                    row,
                                    source_col,
                                    conditions,
                                    logical_expression,
                                    case_sensitive,
                                ),
                                axis=1,
                            )

                elif isinstance(value, str) and "<<" in value and ">>" in value:
                    source_df[key] = source_df.apply(
                        lambda row: self.get_updated_value(
                            row,
                            self.modify_string(value, ["inputfile1.", "InputFile1."]),
                        ),
                        axis=1,
                    )

                elif isinstance(value, (str, int, float)):
                    source_df[key] = value
                else:
                    source_df[key] = [value] * len(source_df)

            return source_df, None

        except (ValueError, IndexError, Exception) as e:
            err_msg = self.err_msg if self.err_msg else str(e)
            formatted_msg = log_manager.get_error_message(
                "TransformData.Exceptions.TransformConfigFile.add_column_exception",
                {"error": err_msg},
            )
            return pd.DataFrame(), formatted_msg

    def check_contains_multi_condition(
        self,
        row: pd.Series,
        source_col: str,
        conditions: list,
        logical_expression: str,
        case_sensitive: bool,
    ) -> bool:
        """Check multiple contains conditions with logical operators.

        Args:
            row: Row to process.
            source_col: Source column name.
            conditions: List of condition dictionaries.
            logical_expression: Logical expression using condition indices (e.g., "C1 AND C2 OR C3").
            case_sensitive: Whether the comparison is case-sensitive.

        Returns:
            bool: True if the logical expression evaluates to True, False otherwise.
        """
        try:
            # Clean the source column name
            source_col_clean = (
                source_col.replace("inputfile1.", "")
                .replace("InputFile1.", "")
                .replace("<<", "")
                .replace(">>", "")
            )

            # Get the source value
            source_value = self.get_updated_value(row, f"<<{source_col_clean}>>")

            if source_value is None:
                return False

            # Evaluate each condition
            condition_results = {}
            for i, condition in enumerate(conditions):
                condition_id = f"C{i+1}"

                # Get the value to check against
                check_value = None
                if condition.get("Value"):
                    check_value = condition.get("Value")
                elif condition.get("Column"):
                    compare_col_clean = (
                        condition.get("Column")
                        .replace("inputfile1.", "")
                        .replace("InputFile1.", "")
                        .replace("<<", "")
                        .replace(">>", "")
                    )
                    check_value = self.get_updated_value(
                        row, f"<<{compare_col_clean}>>"
                    )

                if check_value is not None:
                    contains_type = condition.get("ContainsType", "string").lower()
                    condition_results[condition_id] = self._check_contains_condition(
                        source_value, check_value, contains_type, case_sensitive
                    )
                else:
                    condition_results[condition_id] = False

            # If only one condition, return its result
            if len(conditions) == 1:
                return condition_results.get("C1", False)

            # Evaluate the logical expression
            return self._evaluate_logical_expression(
                logical_expression, condition_results
            )

        except Exception as e:
            # Log the error but don't break the processing
            return False

    def _evaluate_logical_expression(
        self, expression: str, condition_results: dict
    ) -> bool:
        """Evaluate a logical expression with condition results.

        Args:
            expression: Logical expression (e.g., "C1 AND C2 OR C3").
            condition_results: Dictionary mapping condition IDs to boolean results.

        Returns:
            bool: Result of the logical expression evaluation.
        """
        try:
            # Replace condition IDs with their boolean values
            eval_expression = expression.upper()

            for condition_id, result in condition_results.items():
                eval_expression = eval_expression.replace(
                    condition_id.upper(), str(result)
                )

            # Replace logical operators with Python operators
            eval_expression = eval_expression.replace(" AND ", " and ")
            eval_expression = eval_expression.replace(" OR ", " or ")
            eval_expression = eval_expression.replace(" NOT ", " not ")

            # Add parentheses support
            eval_expression = eval_expression.replace("(", "(").replace(")", ")")

            # Safely evaluate the expression
            return eval(eval_expression)

        except Exception as e:
            # If evaluation fails, return False
            return False

    def _check_contains_condition(
        self, source_value, check_value, contains_type: str, case_sensitive: bool
    ) -> bool:
        """Helper method to check a single contains condition.

        Args:
            source_value: The source value to check in.
            check_value: The value to search for.
            contains_type: Type of contains check ("list" or "string").
            case_sensitive: Whether the comparison is case-sensitive.

        Returns:
            bool: True if contains condition is met, False otherwise.
        """
        if contains_type == "list":
            # List contains list case
            if isinstance(source_value, list):
                # Parse check_value as a list if it's a string representation
                if isinstance(check_value, str):
                    try:
                        # Try to parse as JSON array first
                        import json

                        check_list = json.loads(check_value)
                    except:
                        # If not JSON, split by comma
                        check_list = [item.strip() for item in check_value.split(",")]
                elif isinstance(check_value, list):
                    check_list = check_value
                else:
                    check_list = [check_value]

                # Check if any item in check_list is in source_value
                if case_sensitive:
                    return any(item in source_value for item in check_list)
                else:
                    source_lower = [
                        str(item).lower() if item is not None else ""
                        for item in source_value
                    ]
                    check_lower = [
                        str(item).lower() if item is not None else ""
                        for item in check_list
                    ]
                    return any(item in source_lower for item in check_lower)

            # List contains string case (source is list, check if it contains the string)
            elif isinstance(check_value, str):
                if case_sensitive:
                    return check_value in source_value
                else:
                    source_lower = [
                        str(item).lower() if item is not None else ""
                        for item in source_value
                    ]
                    return check_value.lower() in source_lower

            # List contains another list case (both are lists)
            elif isinstance(check_value, list):
                if case_sensitive:
                    return any(item in source_value for item in check_value)
                else:
                    source_lower = [
                        str(item).lower() if item is not None else ""
                        for item in source_value
                    ]
                    check_lower = [
                        str(item).lower() if item is not None else ""
                        for item in check_value
                    ]
                    return any(item in source_lower for item in check_lower)

        elif contains_type == "string":
            # String contains string case
            if isinstance(source_value, str) and isinstance(check_value, str):
                if case_sensitive:
                    return check_value in source_value
                else:
                    return check_value.lower() in source_value.lower()
            # Handle case where check_value might be from another column (could be list)
            elif isinstance(source_value, str) and isinstance(check_value, list):
                # Check if source string contains any item from the check list
                if case_sensitive:
                    return any(
                        str(item) in source_value
                        for item in check_value
                        if item is not None
                    )
                else:
                    source_lower = source_value.lower()
                    return any(
                        str(item).lower() in source_lower
                        for item in check_value
                        if item is not None
                    )
            
            # Handle case where check_value might be from another column (could be list)
            elif isinstance(source_value, list) and isinstance(check_value, str):
                return check_value in source_value
                

           

        return False

    def _handle_by_condition(
        self,
        source_df: pd.DataFrame,
        config: Dict,
        input_file2_df: pd.DataFrame,
        log_manager: cards.LogConfigManager,
    ) -> pd.DataFrame:
        """Handle conditional column addition.

        Args:
            source_df: Source DataFrame.
            config: Configuration for the condition.
            input_file2_df: Optional second input DataFrame.

        Returns:
            pd.DataFrame: Updated DataFrame.
        """
        condition: Optional[str]
        true_dict: Optional[List[Dict]]
        false_dict: Optional[List[Dict]]
        condition, true_dict, false_dict = (
            config.get("Condition"),
            config.get("True"),
            config.get("False"),
        )

        source_df["original_index"] = source_df.index
        matched_df, unmatched_df, error = self.split_df_based_on_condition(
            source_df, condition
        )
        if error:
            raise ValueError(error)

        if not matched_df.empty and true_dict:
            self.add_column(log_manager, matched_df, true_dict[0], input_file2_df)
        if not unmatched_df.empty and false_dict:
            self.add_column(log_manager, unmatched_df, false_dict[0], input_file2_df)

        if not matched_df.empty and not unmatched_df.empty:
            source_df = pd.concat(
                [matched_df, unmatched_df], ignore_index=True
            ).sort_values(by="original_index")
        elif not matched_df.empty:
            source_df = matched_df
        elif not unmatched_df.empty:
            source_df = unmatched_df

        return source_df.drop(columns="original_index", errors="ignore")

    def update_column(
        self,
        log_manager: cards.LogConfigManager,
        source_df: pd.DataFrame,
        column_info: Dict,
    ) -> Tuple[pd.DataFrame, Optional[str]]:
        """Update columns in the DataFrame based on TOML configuration.

        Args:
            source_df: Source DataFrame to modify.
            column_info: Configuration for updating columns.

        Returns:
            Tuple[pd.DataFrame, Optional[str]]: Updated DataFrame and potential error.
        """
        try:
            if not column_info or source_df.empty:
                return source_df, None

            # Prepare a dictionary for renaming columns
            columns_to_rename = {}

            for key, value in column_info.items():

                if key == UpdateColumnType.CONCAT.value and isinstance(value, list):
                    for config in value:

                        if config:

                            new_col = (
                                config.get("ColumnName", "")
                                .replace("inputfile1.", "")
                                .replace("InputFile1.", "")
                                .replace("<<", "")
                                .replace(">>", "")
                            )

                            # Update the column
                            source_df[new_col] = source_df.apply(
                                lambda row: (
                                    config["ConcatValue"] + row[new_col]
                                    if config["Position"] == "Start"
                                    else row[new_col] + config["ConcatValue"]
                                ),
                                axis=1,
                            )

                elif key == UpdateColumnType.SPLIT.value and isinstance(value, list):

                    for config in value:

                        if config:

                            source = (
                                config.get("Source", "")
                                .replace("inputfile1.", "")
                                .replace("InputFile1.", "")
                                .replace("<<", "")
                                .replace(">>", "")
                            )

                            # Update the column
                            source_df[source] = source_df.apply(
                                lambda row: (
                                    row[source].split(config["Delimiter"])[
                                        config["Index"]
                                    ]
                                    if isinstance(row[source], str)
                                    else None
                                ),
                                axis=1,
                            )

                elif key == UpdateColumnType.REPLACE.value and isinstance(value, list):

                    for config in value:

                        if config:

                            new_col = (
                                config.get("ColumnName", "")
                                .replace("inputfile1.", "")
                                .replace("InputFile1.", "")
                                .replace("<<", "")
                                .replace(">>", "")
                            )

                            regex = config.get("Regex", None)

                            replace_whole = (
                                config.get("ReplaceWholeValue", True) == True
                            )

                            source_df[new_col] = source_df.apply(
                                lambda row: self._replace_value(
                                    row[new_col],
                                    regex,
                                    config["ReplaceValue"],
                                    replace_whole,
                                ),
                                axis=1,
                            )

                elif key == UpdateColumnType.CHANGE_PATH.value and isinstance(
                    value, list
                ):
                    for config in value:
                        if config:
                            source = (
                                config.get("Source", "")
                                .replace("inputfile1.", "")
                                .replace("InputFile1.", "")
                                .replace("<<", "")
                                .replace(">>", "")
                            )
                            target = (
                                config.get("Target", "")
                                .replace("inputfile1.", "")
                                .replace("InputFile1.", "")
                                .replace("<<", "")
                                .replace(">>", "")
                            )

                            # Fetch the source and target path values
                            source_df.apply(
                                lambda row: self._apply_change_path(
                                    row, source, target, config.get("Type")
                                ),
                                axis=1,
                            )

                elif value and isinstance(value, str):
                    clean_col = (
                        value.replace("inputfile1.", "")
                        .replace("InputFile1.", "")
                        .replace("<<", "")
                        .replace(">>", "")
                        .strip()
                    )
                    if clean_col in source_df.columns:
                        columns_to_rename[clean_col] = key
                    else:
                        formatted_msg = log_manager.get_error_message(
                            "TransformData.Exceptions.TransformConfigFile.invalid_update_column",
                            {"error": clean_col},
                        )
                        return source_df, f"Invalid column: formatted_msg"

            # Rename the columns all at once
            if columns_to_rename:
                source_df.rename(columns=columns_to_rename, inplace=True)

            return source_df, None

        except KeyError as e:
            formatted_msg = log_manager.get_error_message(
                "TransformData.Exceptions.TransformConfigFile.update_column_exception",
                {"error": str(e)},
            )
            return pd.DataFrame(), formatted_msg
        except ValueError as e:
            err_msg = self.err_msg if self.err_msg else str(e)
            formatted_msg = log_manager.get_error_message(
                "TransformData.Exceptions.TransformConfigFile.update_column_exception",
                {"error": err_msg},
            )
            return pd.DataFrame(), formatted_msg
        except Exception as e:
            formatted_msg = log_manager.get_error_message(
                "TransformData.Exceptions.TransformConfigFile.update_column_exception",
                {"error": str(e)},
            )
            return pd.DataFrame(), formatted_msg

    def _replace_value(
        self, value: str, regex: Optional[str], replace_value: str, replace_whole: bool
    ) -> str:
        """Replace value based on regex or conditions.

        Args:
            value: Original value to replace.
            regex: Regular expression to match, if any.
            replace_value: Value to replace with.
            replace_whole: Whether to replace the whole value or just matches.

        Returns:
            str: Updated value.
        """
        if regex is None:
            return replace_value if pd.isna(value) else value
        if regex == "":
            return (
                replace_value
                if isinstance(value, str) and re.search(r"^$", value)
                else value
            )
        regex = (
            re.escape(regex)
            if all(char in ".^$*+?{}[]\\|()" for char in regex)
            else regex
        )
        if replace_whole:
            return (
                replace_value
                if isinstance(value, str) and re.search(regex, value)
                else value
            )
        return (
            re.sub(regex, replace_value, value)
            if isinstance(value, str) and re.search(regex, value)
            else value
        )

    def delete_column(
        self,
        log_manager: cards.LogConfigManager,
        source_df: pd.DataFrame,
        column_info: Dict,
    ) -> Tuple[pd.DataFrame, Optional[str]]:
        """
        Delete columns from the DataFrame based on TOML configuration.

        Args:
            source_df: Source DataFrame to modify.
            column_info: Configuration for deleting columns.

        Returns:
            Tuple[pd.DataFrame, Optional[str]]: Updated DataFrame and potential error.
        """
        try:
            if not column_info or source_df.empty:
                return source_df, None

            # Flatten and strip all requested column names
            requested_columns = [
                col.strip()
                for value in column_info.values()
                if value
                for col in value.split(",")
            ]
            # Find invalid columns
            invalid_columns = [
                col for col in requested_columns if col not in source_df.columns
            ]

            formatted_msg = log_manager.get_error_message(
                "TransformData.Exceptions.TransformConfigFile.invalid_delete_column",
                {"error": ", ".join(invalid_columns)},
            )

            if invalid_columns:
                return (
                    source_df,
                    formatted_msg,
                )

            return source_df.drop(columns=requested_columns), None

        except Exception as e:
            formatted_msg = log_manager.get_error_message(
                "TransformData.Exceptions.TransformConfigFile.delete_column_exception",
                {"error": str(e)},
            )
            return source_df, formatted_msg

    def remove_duplicates(
        self,
        log_manager: cards.LogConfigManager,
        source_df: pd.DataFrame,
        column_info: Dict,
    ) -> Tuple[pd.DataFrame, Optional[str]]:
        """Remove duplicate rows based on specified columns.

        Args:
            source_df: Source DataFrame to modify.
            column_info: Configuration for removing duplicates.

        Returns:
            Tuple[pd.DataFrame, Optional[str]]: Updated DataFrame and potential error.
        """
        try:
            if not column_info or source_df.empty:
                return source_df, None

            # Extract and clean column names
            specified_columns = [
                col.strip()
                for cols in column_info.values()
                if cols
                for col in cols.split(",")
            ]

            # Identify invalid columns
            invalid_cols = [
                col for col in specified_columns if col not in source_df.columns
            ]
            formatted_msg = log_manager.get_error_message(
                "TransformData.Exceptions.TransformConfigFile.remove_duplicate_invalid_column",
                {"error": ", ".join(invalid_cols)},
            )
            if invalid_cols:
                return (
                    source_df,
                    formatted_msg,
                )

            # Remove duplicates
            deduped_df = source_df.drop_duplicates(
                subset=specified_columns, keep="first"
            )
            return deduped_df, None

        except Exception as e:
            formatted_msg = log_manager.get_error_message(
                "TransformData.Exceptions.TransformConfigFile.remove_duplicate_exception",
                {"error": str(e)},
            )
            return source_df, formatted_msg

    def re_order_column(
        self,
        log_manager: cards.LogConfigManager,
        source_df: pd.DataFrame,
        column_info: Dict,
    ) -> Tuple[pd.DataFrame, Optional[str]]:
        """Reorder columns in the DataFrame based on TOML configuration.

        Args:
            source_df: Source DataFrame to modify.
            column_info: Configuration for reordering columns.

        Returns:
            Tuple[pd.DataFrame, Optional[str]]: Updated DataFrame and potential error message.
        """
        try:
            if not column_info or source_df.empty:
                return source_df, None

            # Flatten and clean column names from config
            desired_columns = [
                col.strip()
                for values in column_info.values()
                for col in values.split(",")
                if col.strip()
            ]

            # Identify invalid columns
            invalid_columns = [
                col for col in desired_columns if col not in source_df.columns
            ]
            formatted_msg = log_manager.get_error_message(
                "TransformData.Exceptions.TransformConfigFile.reorder_invalid_column",
                {"error": ", ".join(invalid_columns)},
            )
            if invalid_columns:
                return (
                    source_df,
                    formatted_msg,
                )

            return source_df[desired_columns], None

        except Exception as e:
            formatted_msg = log_manager.get_error_message(
                "TransformData.Exceptions.TransformConfigFile.reorder_exception",
                {"error": str(e)},
            )
            return source_df, formatted_msg

    def _apply_change_path(
        self,
        row: pd.Series,
        source_path: str,
        target_path: str,
        operation_type: Optional[str],
    ) -> pd.Series:
        """Apply path changes to a row.

        Args:
            row: Row to modify.
            source_path: Source path to extract value from.
            target_path: Target path to update.
            operation_type: Type of operation (Append or Concat).

        Returns:
            pd.Series: Updated row.
        """
        source_path_full = "<<" + source_path + ">>"
        target_path_full = "<<" + target_path + ">>"
        source_value = self.get_updated_value(row, source_path_full)
        target_value = self.get_updated_value(row, target_path_full)
        if source_value is None or target_value is None:
            return row

        # Extract the key from the last part of the source_path
        key = source_path.split(".")[-1].replace("<<", "").replace(">>", "")
        if isinstance(target_value, list):
            if not operation_type:
                operation_type = UpdateColumnType.APPEND.value
            if operation_type == UpdateColumnType.APPEND.value:
                target_value.append({key: source_value})
            elif operation_type == UpdateColumnType.CONCAT.value:
                for data in target_value:
                    if isinstance(data, dict):
                        data[key] = source_value
            row = self.set_updated_value(row, target_path_full, target_value)
        elif isinstance(target_value, dict):
            target_value[key] = source_value
            row = self.set_updated_value(row, target_path_full, target_value)
        return row

    def set_updated_value(self, row: pd.Series, path: str, value: Any) -> pd.Series:
        """Set a value at a specified path in a row.

        Args:
            row: Row to modify.
            path: Path to set the value at.
            value: Value to set.

        Returns:
            pd.Series: Updated row.
        """
        keys = path.replace("<<", "").replace(">>", "").split(".")
        current = row
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        current[keys[-1]] = value
        return row

    def add_column_as_object(
        self, row: pd.Series, new_col: str, objs: List[str]
    ) -> pd.Series:
        """Add a column as an object to a row.

        Args:
            row: Row to modify.
            new_col: New column name.
            objs: List of object values.

        Returns:
            pd.Series: Updated row.
        """
        data_dict = {}
        for obj in objs:
            clean_obj = obj.strip()
            modified_obj = self.modify_string(clean_obj, ["inputfile1.", "InputFile1."])
            # Get the updated value for the modified object
            value = self.get_updated_value(row, modified_obj)
            # If the value is not None, add it to the dictionary
            if value:
                # Use a list split just once and calculate the index
                key = modified_obj.split(".")[-1].replace("<<", "").replace(">>", "")
                data_dict[key] = value
        row[new_col] = data_dict
        return row

    def add_column_as_list(
        self, row: pd.Series, source: str, target: str, new_col: str
    ) -> pd.Series:
        """Add a column as a list to a row.

        Args:
            row: Row to modify.
            source: Source column/path.
            target: Target field in source data.
            new_col: New column name.

        Returns:
            pd.Series: Updated row.
        """

        # Clean up source and target strings once, not inside the loop
        source_key = (
            source.replace("inputfile1.", "")
            .replace("InputFile1.", "")
            .replace("<<", "")
            .replace(">>", "")
        )
        target_clean = target.replace("Source.", "").replace("<<", "").replace(">>", "")

        # Get the source list
        source_list = self.get_updated_value(row, f"<<{source_key}>>")
        #source_list = self.get_updated_value(row, source_key)
        row[new_col] = []
        if isinstance(source_list, list):
            row[new_col] = [
                jmespath.search(target_clean, data)
                for data in source_list
                if isinstance(data, dict)
            ]
 

        return row

    def add_column_by_function(
        self, df: pd.DataFrame, new_col: str, source: str, function: str, config: Dict
    ) -> None:
        """Add a column using a function.

        Args:
            df: DataFrame to modify.
            new_col: New column name.
            source: Source column/path.
            function: Function to apply.
            config: Configuration for the function.
        """
        if function == "CurrentDateTime":
            format = "%Y-%m-%dT%H:%M:%S.%fZ"
            if config.get("Format", ""):
                format = config.get("Format", "")
            df[new_col] = self.get_current_datetime(format)
        else:
            df[new_col] = df.apply(
                lambda row: self.handle_other_functions(row, source, function, config),
                axis=1,
            )

    def handle_other_functions(
        self, row: pd.Series, path: str, function: str, config: Dict
    ) -> Any:
        """Handle non-datetime functions for column addition.

        Args:
            row: Row to process.
            path: Source path.
            function: Function to apply.
            config: Configuration for the function.

        Returns:
            Any: Result of the function.
        """
        source_value = self.get_updated_value(
            row, self.modify_string(path, ["inputfile1.", "InputFile1."])
        )
        if function == "Length" and isinstance(source_value, list):
            return len(source_value)
        if function == "SplitByDelimiter":
            return self.get_split_value(
                row, path, config.get("Index", ""), config.get("Delimiter", "")
            )
        return "N/A"

    def get_split_value(
        self, row: pd.Series, path: str, index: str, delimiter: str
    ) -> str:
        """Get a split value from a path.

        Args:
            row: Row to process.
            path: Source path.
            index: Index to extract after splitting.
            delimiter: Delimiter to split by.

        Returns:
            str: Split value or "N/A".
        """
        path_value = self.get_updated_value(
            row, self.modify_string(path, ["inputfile1.", "InputFile1."])
        )
        return (
            path_value.split(delimiter)[int(index)]
            if isinstance(path_value, str)
            else "N/A"
        )

    def get_current_datetime(self, format: str) -> str:
        """Get the current UTC datetime in ISO format.

        Returns:
            str: Formatted datetime string.
        """
        return datetime.now(timezone.utc).strftime(format)

    def add_column_in_df_by_mapping(
        self,
        row: pd.Series,
        target_df: pd.DataFrame,
        new_col: str,
        source_col: str,
        target_col: str,
        map_col: str,
        is_case_sensitive: bool,
    ) -> pd.Series:
        """Add a column by mapping from another DataFrame.

        Args:
            row: Row to modify.
            target_df: Target DataFrame for mapping.
            new_col: New column name.
            source_col: Source column in row.
            target_col: Target column in target_df.
            map_col: Mapping column in target_df.

        Returns:
            pd.Series: Updated row.
        """

        if target_df.empty:
            return row

        # Extract the source column value from the row
        source_col = source_col.replace("inputfile1.", "").replace("InputFile1.", "")
        source_column_value = self.get_updated_value(row, source_col)
        target_col = (
            target_col.replace("<<", "").replace(">>", "").replace("inputfile2.", "")
        )
        if not target_col in target_df.columns:
            self.err_msg = self.err_msg = f"Invalid column - '{target_col}'"
            raise ValueError

        # Find the row in the target dataframe where the target column matches the source column value
        target_row = pd.DataFrame()
        if is_case_sensitive:
            target_row = target_df[target_df[target_col] == source_column_value]
        else:
            target_row = target_df[
                target_df[target_col].str.lower() == str(source_column_value).lower()
            ]

        if not target_row.empty:
            # Retrieve the value from the map column
            map_col = (
                map_col.replace("<<", "").replace(">>", "").replace("inputfile2.", "")
            )
            if not map_col in target_row.columns:
                self.err_msg = self.err_msg = f"Invalid column - '{map_col}'"
                raise ValueError
            manager_value = target_row[map_col].values[0]
            row[new_col] = manager_value
        else:
            # Handle cases where there is no match (optional)
            row[new_col] = None

        return row

    def split_df_based_on_condition(
        self, df: pd.DataFrame, condition: Optional[str]
    ) -> Tuple[pd.DataFrame, pd.DataFrame, str]:
        """Split DataFrame based on a condition.

        Args:
            df: DataFrame to split.
            condition: Condition string to evaluate.

        Returns:
            Tuple[pd.DataFrame, pd.DataFrame, str]: Matched DataFrame, unmatched DataFrame, and error.
        """
        try:
            if not condition:
                return pd.DataFrame(), df, ""
            clean_condition = (
                condition.replace("<<", "").replace(">>", "").replace("inputfile1.", "")
            )
            matched_df = df.query(clean_condition)
            unmatched_df = (
                df[~df.index.isin(matched_df.index)] if not matched_df.empty else df
            )
            return matched_df, unmatched_df, ""
        except pd.errors.UndefinedVariableError as e:
            match = re.search(r"'([^']*)'", str(e))
            return (
                pd.DataFrame(),
                pd.DataFrame(),
                f"Invalid column: '{match.group(1)}'" if match else str(e),
            )
        except Exception as e:
            return pd.DataFrame(), pd.DataFrame(), str(e)

    def modify_string(self, key: str, regex_list: List[str]) -> str:
        """Remove specified patterns from a string.

        Args:
            key: String to modify.
            regex_list: List of regex patterns to remove.

        Returns:
            str: Modified string.
        """
        return re.sub("|".join(map(re.escape, regex_list)), "", key)

    def get_updated_value(self, row: pd.Series, path: str) -> str:
        """Get updated value from a row using a path.

        Args:
            row: Row to extract value from.
            path: Path to extract.

        Returns:
            str: Extracted value or empty string.
        """
        matches = re.findall(r"<<([^>]*)>>", path)

        if not matches:
            valid_syntax = "<<inputfile.column_name>>"
            self.err_msg = f"Invalid syntax - {path}. Valid syntax - {valid_syntax}'"
            raise ValueError
        # If there's only one match and it fully matches the path (ignoring the '<<' and '>>')
        if len(matches) == 1 and len(matches[0]) == len(path.strip("<<>>")):
            return self.extract_value_from_data(row, path)
        value = path
        # Replace each match with its corresponding value from the data
        for match in matches:
            extracted = self.extract_value_from_data(row, match)
            match = "<<" + match + ">>"
            value = value.replace(match, str(extracted))
        return value

    def extract_value_from_data(self, row: pd.Series, path: str) -> str:
        """Extract value from a row using a dot-separated path.

        Args:
            row: Row to extract from.
            path: Dot-separated path (e.g., '<<a.b[0].c>>').

        Returns:
            str: Extracted value.

        Raises:
            ValueError: If the path is invalid.
        """
        keys = path.strip("<<>>").split(".")
        value = row

        for key in keys:
            if isinstance(value, list) and "[" in key and "]" in key:
                try:
                    index = int(key[key.find("[") + 1 : key.find("]")])
                    value = value[index]
                except IndexError:
                    self.err_msg = f"Invalid index: '{path}'"
                    raise IndexError
            else:
                if isinstance(value, dict) or isinstance(value, pd.Series):
                   value = value.get(key, "col_not_exist")
                else:
                    value = "col_not_exist"

            if self.is_nan(value):
                value = None

        if value == "col_not_exist":
            self.err_msg = f"Invalid column: '{path}'"
            raise ValueError

        return value

    def is_nan(self, value: Any) -> bool:
        """Check if a value is NaN.

        Args:
            value: Value to check.

        Returns:
            bool: True if NaN, False otherwise.
        """
        return isinstance(value, (float, np.float32, np.float64)) and math.isnan(value)

    def get_file_extension(self, file_path):
        try:
            file_extension = os.path.splitext(file_path)[1]
            return file_extension
        except IndexError:
            return ""

    def upload_log_file(self, errors_list):
        log_file_path, error = self.upload_file_to_minio(
            file_content=json.dumps(errors_list).encode("utf-8"),
            file_name=f"LogFile-{str(uuid.uuid4())}.json",
            content_type="application/json",
        )
        if error:
            return {"Error": error}
        return {"LogFile": log_file_path}

    def is_valid_url(self, url: str) -> bool:
        """Check if a URL is valid.

        Args:
            url: URL to validate.

        Returns:
            bool: True if valid, False otherwise.
        """
        try:
            result = urllib.parse.urlparse(url)
            return bool(result.scheme and result.netloc)
        except ValueError:
            return False

    def get_extension(self, file_path: str) -> str:
        """Get the file extension from a path.

        Args:
            file_path: File path to check.

        Returns:
            str: File extension or empty string.
        """
        return os.path.splitext(file_path)[1]

    def validate_inputs(
        self, log_manager: cards.LogConfigManager
    ) -> List[Dict[str, str]]:
        """Validate task inputs.

        Returns:
            List[Dict[str, str]]: List of validation errors where each error is a dict with an "Error" key.
        """
        if not self.task_inputs:
            return [{"Error": "Task input is missing"}]

        errors = []
        user_inputs = self.task_inputs.user_inputs

        # Define validation rules for each input file
        validation_rules = [
            {
                "input_name": "InputFile1",
                "required": True,
                "valid_extensions": [".json", ".ndjson", ".csv", ".parquet"],
                "error_prefix": "TransformData.Inputs.InputFile1",
            },
            {
                "input_name": "TransformConfigFile",
                "required": True,
                "valid_extensions": [".toml"],
                "error_prefix": "TransformData.Inputs.TransformConfigFile",
            },
            {
                "input_name": "InputFile2",
                "required": False,
                "valid_extensions": [".csv"],
                "error_prefix": "TransformData.Inputs.InputFile2",
            },
        ]

        for rule in validation_rules:
            input_path = user_inputs.get(rule["input_name"], "")

            # Skip validation if input is not required and not provided
            if not rule["required"] and not input_path or input_path == MINIO_FILE_PATH:
                continue

            # Check if required input is missing
            if rule["required"] and not input_path:
                errors.append(
                    {
                        "Error": log_manager.get_error_message(
                            f"{rule['error_prefix']}.missing"
                        )
                    }
                )
                continue

            # # Validate path/URL
            # if not self.is_valid_url(input_path):
            #     errors.append(
            #         {
            #             "Error": log_manager.get_error_message(
            #                 f"{rule['error_prefix']}.invalid_path"
            #             )
            #         }
            #     )
            #     continue

            # Validate file extension
            file_ext = self.get_extension(input_path)
            if file_ext.lower() not in rule.get("valid_extensions", []):
                errors.append(
                    {
                        "Error": log_manager.get_error_message(
                            f"{rule['error_prefix']}.unsupported_extension"
                        )
                    }
                )

        return errors

    def validate_toml_data(
        self, config: Dict, log_manager: cards.LogConfigManager
    ) -> List[dict]:
        errors = []

        # Helper function to add errors
        def add_error(error_key: str, placeholder_dict: Optional[dict] = None) -> None:
            errors.append(
                {"Error": log_manager.get_error_message(error_key, placeholder_dict)}
            )

        # Validate AddColumn section
        if TransformType.ADD_COLUMN.value in config:
            self._validate_add_column(config[TransformType.ADD_COLUMN.value], add_error)

        # Validate UpdateColumn section
        if TransformType.UPDATE_COLUMN.value in config:
            self._validate_update_column(
                config[TransformType.UPDATE_COLUMN.value], add_error
            )

        # Validate simple list-based sections
        self._validate_list_sections(config, add_error)

        return errors

    def _validate_add_column(
        self, add_col_config: Dict, add_error: Callable[[str], Optional[dict]]
    ) -> None:
        """Validate the AddColumn configuration section."""
        # Validate ByFunction items
        for item in add_col_config.get(AddColumnType.BY_FUNCTION.value, []):
            self._validate_by_function(item, add_error)

        # Validate AsObject items
        for item in add_col_config.get(AddColumnType.AS_OBJECT.value, []):
            self._validate_as_object(item, add_error)

        # Validate ByMap items
        for item in add_col_config.get(AddColumnType.BY_MAP.value, []):
            self._validate_by_map(item, add_error)

        # Validate AsList items
        for item in add_col_config.get(AddColumnType.AS_LIST.value, []):
            self._validate_as_list(item, add_error)

        # Validate ByCondition items
        for item in add_col_config.get(AddColumnType.BY_CONDITION.value, []):
            self._validate_by_condition(item, add_error)

        # Add this new validation block
        # Validate ByContains items
        for item in add_col_config.get(AddColumnType.BY_CONTAINS.value, []):
            self._validate_by_contains(item, add_error)

    def _validate_by_contains(
        self, item: Dict, add_error: Callable[[str], Optional[dict]]
    ) -> None:
        """Validate a ByContains configuration item."""
        if not item:
            return

        # Basic required fields
        if not item.get("ColumnName"):
            add_error(
                "TransformData.Inputs.TransformConfigFile.add_column.by_contains.empty_column_name"
            )

        if not item.get("SourceColumn"):
            add_error(
                "TransformData.Inputs.TransformConfigFile.add_column.by_contains.empty_source_column"
            )

        # Check if we have Conditions array
        conditions = item.get("Conditions", [])
        if not conditions:
            add_error(
                "TransformData.Inputs.TransformConfigFile.add_column.by_contains.empty_conditions"
            )
            return

        # Validate each condition
        for i, condition in enumerate(conditions):
            if not condition.get("Value") and not condition.get("Column"):
                add_error(
                    f"TransformData.Inputs.TransformConfigFile.add_column.by_contains.condition_{i}_missing_value_or_column"
                )

            contains_type = condition.get("ContainsType", "").lower()
            if contains_type not in ["list", "string"]:
                add_error(
                    f"TransformData.Inputs.TransformConfigFile.add_column.by_contains.condition_{i}_invalid_contains_type"
                )

        # Validate LogicalExpression
        logical_expression = item.get("LogicalExpression", "")
        if len(conditions) > 1 and not logical_expression:
            add_error(
                "TransformData.Inputs.TransformConfigFile.add_column.by_contains.missing_logical_expression"
            )

    def _validate_by_function(
        self, item: Dict, add_error: Callable[[str], Optional[dict]]
    ) -> None:
        """Validate a ByFunction configuration item."""
        if not item:
            return

        function = item.get("Function")
        column_name = item.get("ColumnName")
        source = item.get("Source")

        if not function:
            add_error(
                "TransformData.Inputs.TransformConfigFile.add_column.by_function.empty_function"
            )
            return

        if function not in {"Length", "CurrentDateTime", "SplitByDelimiter"}:
            add_error(
                "TransformData.Inputs.TransformConfigFile.add_column.by_function.invalid_function",
                {"function": function},
            )
            return

        if not column_name:
            add_error(
                "TransformData.Inputs.TransformConfigFile.add_column.by_function.empty_column_name"
            )

        if not source and (function != "CurrentDateTime"):
            add_error(
                "TransformData.Inputs.TransformConfigFile.add_column.by_function.empty_source"
            )

        if function == "SplitByDelimiter":
            if not item.get("Delimiter"):
                add_error(
                    "TransformData.Inputs.TransformConfigFile.add_column.by_function.empty_Delimiter"
                )
            if not item.get("Index"):
                add_error(
                    "TransformData.Inputs.TransformConfigFile.add_column.by_function.empty_index"
                )

    def _validate_as_object(
        self, item: Dict, add_error: Callable[[str], Optional[dict]]
    ) -> None:
        """Validate an AsObject configuration item."""
        if not item:
            return

        if not item.get("ColumnName"):
            add_error(
                "TransformData.Inputs.TransformConfigFile.add_column.as_object.empty_column_name"
            )
        if not item.get("ObjectValues"):
            add_error(
                "TransformData.Inputs.TransformConfigFile.add_column.as_object.empty_object_values"
            )

    def _validate_by_map(
        self, item: Dict, add_error: Callable[[str], Optional[dict]]
    ) -> None:
        """Validate a ByMap configuration item."""
        if not item:
            return

        required_fields = [
            ("ColumnName", "by_map.empty_column_name"),
            ("Source", "by_map.empty_source"),
            ("Target", "by_map.empty_target"),
            ("TargetMapping", "by_map.empty_target_mapping"),
        ]

        for field, error_suffix in required_fields:
            if not item.get(field):
                add_error(
                    f"TransformData.Inputs.TransformConfigFile.add_column.{error_suffix}"
                )

    def _validate_as_list(
        self, item: Dict, add_error: Callable[[str], Optional[dict]]
    ) -> None:
        """Validate an AsList configuration item."""
        if not item:
            return

        if not item.get("ColumnName"):
            add_error(
                "TransformData.Inputs.TransformConfigFile.add_column.as_list.empty_column_name"
            )

        if not ((item.get("Source") and item.get("Target")) or item.get("ListData")):
            add_error(
                "TransformData.Inputs.TransformConfigFile.add_column.as_list.missing_required_fields"
            )

    def _validate_by_condition(
        self, item: Dict, add_error: Callable[[str], Optional[dict]]
    ) -> None:
        """Validate a ByCondition configuration item."""
        if not item or (item.get("True") == [{}] and item.get("False") == [{}]):
            return

        required_fields = [
            ("Condition", "by_condition.empty_condition"),
            ("True", "by_condition.empty_true_config"),
            ("False", "by_condition.empty_false_config"),
        ]

        for field, error_suffix in required_fields:
            value = item.get(field)
            if not value or (isinstance(value, list) and not value[0]):
                add_error(
                    f"TransformData.Inputs.TransformConfigFile.add_column.{error_suffix}"
                )

    def _validate_update_column(
        self, update_col_config: Dict, add_error: Callable[[str], Optional[dict]]
    ) -> None:
        """Validate the UpdateColumn configuration section."""
        # Validate Concat items
        for item in update_col_config.get(UpdateColumnType.CONCAT.value, []):
            self._validate_concat(item, add_error)

        # Validate Split items
        for item in update_col_config.get(UpdateColumnType.SPLIT.value, []):
            self._validate_split(item, add_error)

        # Validate Replace items
        for item in update_col_config.get(UpdateColumnType.REPLACE.value, []):
            self._validate_replace(item, add_error)

        # Validate ChangePath items
        for item in update_col_config.get(UpdateColumnType.CHANGE_PATH.value, []):
            self._validate_change_path(item, add_error)

    def _validate_concat(
        self, item: Dict, add_error: Callable[[str], Optional[dict]]
    ) -> None:
        """Validate a Concat configuration item."""
        if not item:
            return

        required_fields = [
            ("ColumnName", "concat.empty_column_name"),
            ("ConcatValue", "concat.empty_concat_value"),
            ("Position", "concat.empty_position"),
        ]

        for field, error_suffix in required_fields:
            value = item.get(field)
            if not value:
                add_error(
                    f"TransformData.Inputs.TransformConfigFile.update_column.{error_suffix}"
                )
            elif field == "Position" and value not in {"Start", "End"}:
                add_error(
                    "TransformData.Inputs.TransformConfigFile.update_column.concat.invalid_position",
                    {"position": value},
                )

    def _validate_split(
        self, item: Dict, add_error: Callable[[str], Optional[dict]]
    ) -> None:
        """Validate a Split configuration item."""
        if not item:
            return

        required_fields = [
            ("Source", "Split.empty_source"),
            ("Delimiter", "Split.empty_delimiter"),
            ("Index", "Split.empty_index"),
        ]

        for field, error_suffix in required_fields:
            if not item.get(field):
                add_error(
                    f"TransformData.Inputs.TransformConfigFile.update_column.{error_suffix}"
                )

    def _validate_replace(
        self, item: Dict, add_error: Callable[[str], Optional[dict]]
    ) -> None:
        """Validate a Replace configuration item."""
        if not item:
            return

        if not item.get("ColumnName"):
            add_error(
                "TransformData.Inputs.TransformConfigFile.update_column.replace.empty_column_name"
            )
        if not item.get("ReplaceValue"):
            add_error(
                "TransformData.Inputs.TransformConfigFile.update_column.replace.empty_replace_whole_value"
            )

    def _validate_change_path(
        self, item: Dict, add_error: Callable[[str], Optional[dict]]
    ) -> None:
        """Validate a ChangePath configuration item."""
        if not item:
            return

        if not item.get("Source"):
            add_error(
                "TransformData.Inputs.TransformConfigFile.update_column.change_path.empty_source"
            )
        if not item.get("Target"):
            add_error(
                "TransformData.Inputs.TransformConfigFile.update_column.change_path.empty_target"
            )

        if not item.get("Type"):
            add_error(
                "TransformData.Inputs.TransformConfigFile.update_column.change_path.empty_type"
            )

    def _validate_list_sections(
        self, config: Dict, add_error: Callable[[str], Optional[dict]]
    ) -> None:
        """Validate simple list-based configuration sections."""
        list_sections = [
            (TransformType.DELETE_COLUMN.value, "delete_column.empty_column_list"),
            (TransformType.REORDER_COLUMN.value, "reorder_column.empty_column_list"),
            (
                TransformType.REMOVE_DUPLICATES.value,
                "remove_duplicates.empty_column_list",
            ),
        ]

        for section, error_key in list_sections:
            if not config.get(section):
                continue
            section_config = config.get(section)
            if (
                section in config
                and section_config is not None
                and not section_config.get("ColumnList")
            ):
                add_error(f"TransformData.Inputs.TransformConfigFile.{error_key}")
