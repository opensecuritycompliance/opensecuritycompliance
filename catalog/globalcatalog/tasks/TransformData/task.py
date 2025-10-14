from typing import overload
from compliancecowcards.structs import cards

# As per the selected app, we're importing the app package
from applicationtypes.nocredapp import nocredapp
import uuid
import json
import toml
import pandas as pd
import os
import urllib.parse
import re
from datetime import datetime, timezone
import math
import numpy as np


class Task(cards.AbstractTask):

    # Global variable to track the invalid colmuns
    err_msg = ""

    def execute(self) -> dict:

        if self.task_inputs.user_inputs.get(
            "LogFile"
        ) and not self.task_inputs.user_inputs.get("InputFile1"):
            return {"LogFile": self.task_inputs.user_inputs.get("LogFile")}

        error_list = []
        log_file = self.task_inputs.user_inputs.get("LogFile")
        input_file1 = self.task_inputs.user_inputs.get("InputFile1")
        input_file2 = self.task_inputs.user_inputs.get("InputFile2")
        transform_config_file = self.task_inputs.user_inputs.get("TransformConfigFile")
        output_file_name = self.task_inputs.user_inputs.get("OutputFileName")

        # Handle if both LogFile and InputFile1, TransformConfigFile present
        if log_file and input_file1 and transform_config_file:
            log_file_list, error = self.download_json_file_from_minio_as_dict(
                file_url=log_file
            )
            if error:
                return self.upload_log_file(
                    [{"Error": f"Error while downloading LogFile. {error}"}]
                )
            for log in log_file_list:
               error_list.append(log)

        val_err_list = []
        # Basic validation
        val_err_list = self.validate()
        if val_err_list:
            if error_list:
                for err in error_list:
                    val_err_list.append(err)
            return self.upload_log_file(val_err_list)

        # Download TransformConfigFile
        toml_bytes, error = self.download_file_from_minio(transform_config_file)
        if error:
            val_err_list.append(
                {"Error": f"Error while downloading 'TransformConfigFile'. {error}"}
            )

        input_file2_df = pd.DataFrame()
        # Download InputFile2. It is optional
        if input_file2:
            input_file2_df, error = self.download_csv_file_from_minio_as_df(input_file2)
            if error:
                val_err_list.append(
                    {"Error": f"Error while downloading 'InputFile2'. {error}"}
                )

        # Download InputFile1
        source_data_df, error = self.download_json_file_from_minio_as_df(input_file1)
        if error:
            val_err_list.append(
                {"Error": f"Error while downloading 'InputFile1'. {error}"}
            )

        if val_err_list:
            if error_list:
                for err in error_list:
                    val_err_list.append(err)
            return self.upload_log_file(val_err_list)

        # Hanlde empty input files
        empty_files = []
        if toml_bytes is None:
            empty_files.append("TransformConfigFile")
        if source_data_df.empty:
            empty_files.append("InputFile1")
        if input_file2 and input_file2_df.empty:
            empty_files.append("InputFile2")
        if empty_files:
            return self.upload_log_file(
                [
                    {
                        "Error": f"Empty input file(s): {', '.join(empty_files)}. Please try with valid input file(s)"
                    }
                ]
            )

        toml_data = {}
        try:
            toml_data = toml.loads(toml_bytes.decode("utf-8"))
        except (UnicodeDecodeError, toml.TomlDecodeError) as e:
            return self.upload_log_file(
                [{"Error": f"Error while parsing 'TransformConfigFile' data. {str(e)}"}]
            )

        # https://pandas.pydata.org/pandas-docs/stable/user_guide/indexing.html#returning-a-view-versus-a-copy
        pd.options.mode.copy_on_write = True

        for mode in toml_data.keys():

            if mode == "AddColumn":
                source_data_df, error = self.add_column(
                    source_data_df, toml_data[mode], input_file2_df
                )
                if error:
                    error_list.append(
                        {"Error": f"Error while processing 'AddColumn'. {error}"}
                    )
                    break
                continue

            if mode == "UpdateColumn":
                source_data_df, error = self.update_column(
                    source_data_df, toml_data[mode]
                )
                if error:
                    error_list.append(
                        {"Error": f"Error while processing 'UpdateColumn'. {error}"}
                    )
                    break
                continue

            if mode == "DeleteColumn":
                source_data_df, error = self.delete_column(
                    source_data_df, toml_data[mode]
                )
                if error:
                    error_list.append(
                        {"Error": f"Error while processing 'DeleteColumn'. {error}"}
                    )
                    break
                continue

            if mode == "ReorderColumn":
                source_data_df, error = self.re_order_column(
                    source_data_df, toml_data[mode]
                )
                if error:
                    error_list.append(
                        {"Error": f"Error while processing 'ReorderColumn'. {error}"}
                    )
                    break
                continue

            if mode == "RemoveDuplicates":
                source_data_df, error = self.remove_duplicates(
                    source_data_df, toml_data[mode]
                )
                if error:
                    error_list.append(
                        {"Error": f"Error while processing 'RemoveDuplicates'. {error}"}
                    )
                    break
                continue

        response = {"LogFile": "", "OutputFile": ""}

        file_name = "OutputFile"
        if output_file_name:
            file_name = output_file_name

        if not source_data_df.empty:
            file_path, error = self.upload_df_as_json_file_to_minio(
                df=source_data_df, file_name=file_name
            )
            if error:
                return {"Error": f"Error while uploading OutputFile. {str(error)}"}
            response["OutputFile"] = file_path

        if error_list:
            file_path, error = self.upload_file_to_minio(
                file_content=json.dumps(error_list).encode("utf-8"),
                file_name=f"LogFile-{str(uuid.uuid4())}.json",
                content_type="application/json",
            )
            if error:
                return {"Error": f"Error while uploading Logfile. {str(error)}"}
            response["LogFile"] = file_path

        return response

    def add_column(self, source_data_df, column_info_dict, input_file2_df):

        try:

            if not column_info_dict or source_data_df.empty:
                return source_data_df, None

            for key, value in column_info_dict.items():

                if key == "ByCondition":

                    if isinstance(value, list):

                        # Handle each condition and config
                        for config in value:

                            if config:

                                condition = config.get("Condition")
                                true_dict = config.get("True", None)
                                false_dict = config.get("False", None)

                                if (
                                    condition
                                    and true_dict is None
                                    and false_dict is None
                                ):
                                    return (
                                        source_data_df,
                                        "Either AddColumn.ByCondition.True or AddColumn.ByCondition.False should be added to evaluate the condition.",
                                    )

                                is_valid_true_info = False
                                if true_dict is not None:
                                    is_valid_true_info = (
                                        isinstance(true_dict, list) and true_dict[0]
                                    )
                                is_valid_false_info = False
                                if false_dict is not None:
                                    is_valid_false_info = (
                                        isinstance(false_dict, list) and false_dict[0]
                                    )

                                if (
                                    condition
                                    and not is_valid_true_info
                                    and not is_valid_false_info
                                ):
                                    return (
                                        source_data_df,
                                        "Column details should be added to AddColumn.ByCondition.True or AddColumn.ByCondition.False to evaluate the condition.",
                                    )

                                if (
                                    not condition
                                    and true_dict is not None
                                    and is_valid_true_info
                                    and false_dict is not None
                                    and is_valid_false_info
                                ):
                                    return (
                                        source_data_df,
                                        "Condition cannot be empty. Sample condition: 'inputfile1.column_name == expected_value'",
                                    )

                                if (
                                    not condition
                                    and true_dict is not None
                                    and is_valid_true_info
                                ):
                                    return (
                                        source_data_df,
                                        "Condition cannot be empty. Sample condition: 'inputfile1.column_name == expected_value'",
                                    )

                                if (
                                    not condition
                                    and false_dict is not None
                                    and is_valid_false_info
                                ):
                                    return (
                                        source_data_df,
                                        "Condition cannot be empty. Sample condition: 'inputfile1.column_name == expected_value'",
                                    )

                                # Split the dataframe based on the condition
                                source_data_df["original_index"] = source_data_df.index
                                matched_df, unmatched_df, error = (
                                    self.split_df_based_on_condition(
                                        source_data_df, condition
                                    )
                                )
                                if error:
                                    return source_data_df, error

                                # If matched data is found, apply 'True' behavior and add columns
                                if not matched_df.empty and true_dict is not None:
                                    self.add_column(
                                        matched_df, true_dict[0], input_file2_df
                                    )
                                # If unmatched data is found, apply 'False' behavior and add columns
                                if not unmatched_df.empty and false_dict is not None:
                                    self.add_column(
                                        unmatched_df, false_dict[0], input_file2_df
                                    )

                                # Reassemble the source data dataframe based on the conditions
                                if not matched_df.empty and not unmatched_df.empty:
                                    source_data_df = pd.concat(
                                        [matched_df, unmatched_df], ignore_index=True
                                    )
                                    source_data_df = source_data_df.sort_values(
                                        by="original_index"
                                    )
                                elif not matched_df.empty:
                                    source_data_df = matched_df
                                elif not unmatched_df.empty:
                                    source_data_df = unmatched_df

                                if "original_index" in source_data_df.columns:
                                    source_data_df = source_data_df.drop(
                                        columns="original_index"
                                    )

                elif key == "AsObject":

                    if isinstance(value, list):

                        for config in value:

                            if config:

                                new_col = config.get("ColumnName", "")
                                if not new_col:
                                    return (
                                        source_data_df,
                                        "'ColumnName' cannot be empty for 'AddColumn.AsObject'",
                                    )

                                obj_vals = config.get("ObjectValues", "")
                                if not obj_vals:
                                    return (
                                        source_data_df,
                                        "'ObjectValues' cannot be empty for 'AddColumn.AsObject'",
                                    )

                                # Apply the mapping function row by row
                                obj_vals = obj_vals.split(",")
                                source_data_df = source_data_df.apply(
                                    lambda row: self.add_column_as_object(
                                        row, new_col, obj_vals
                                    ),
                                    axis=1,
                                )

                elif key == "ByFunction":

                    if isinstance(value, list):

                        for config in value:

                            if config:

                                new_col = config.get("ColumnName", "")
                                if not new_col:
                                    return (
                                        source_data_df,
                                        "'ColumnName' cannot be empty for 'AddColumn.ByFunction'",
                                    )

                                source = config.get("Source", "")

                                function = config.get("Function", "")
                                if not function:
                                    return (
                                        source_data_df,
                                        "'Function' cannot be empty for 'AddColumn.ByFunction'",
                                    )

                                if not source and function == "Length":
                                    return (
                                        source_data_df,
                                        "'Source' cannot be empty for 'AddColumn.ByFunction'",
                                    )

                                delimiter = config.get("Delimiter", "")
                                index = config.get("Index", "")

                                if function == "SplitByDelimiter":
                                    if not delimiter and not index:
                                        return (
                                            source_data_df,
                                            "'Delimiter' and 'Index' cannot be empty for 'AddColumn.ByFunction - Split'",
                                        )
                                    if not delimiter:
                                        return (
                                            source_data_df,
                                            "'Delimiter' cannot be empty for 'AddColumn.ByFunction - Split'",
                                        )
                                    if index is None or index == "":
                                        return (
                                            source_data_df,
                                            "'index' cannot be empty for 'AddColumn.ByFunction - Split'",
                                        )

                                self.add_column_by_function(
                                    source_data_df, new_col, source, function, config
                                )

                elif key == "ByMap":

                    if isinstance(value, list):

                        for config in value:

                            if config:

                                new_col = config.get("ColumnName", "")
                                if not new_col:
                                    return (
                                        source_data_df,
                                        "'ColumnName' cannot be empty for 'AddColumn.ByMap'",
                                    )

                                source_col = config.get("Source", "")
                                if not source_col:
                                    return (
                                        source_data_df,
                                        "'Source' cannot be empty for 'AddColumn.ByMap'",
                                    )
                                source_col = (
                                    source_col.replace("<<", "")
                                    .replace(">>", "")
                                    .replace("inputfile1.", "")
                                    .replace("InputFile1.", "")
                                )

                                is_case_sensitive = config.get("IsCaseSensitive", "")
                                if not is_case_sensitive:
                                    is_case_sensitive = False
                                    

                                target_col = config.get("Target", "")
                                if not target_col:
                                    return (
                                        source_data_df,
                                        "'Target' cannot be empty for 'AddColumn.ByMap'",
                                    )
                                target_col = (
                                    target_col.replace("<<", "")
                                    .replace(">>", "")
                                    .replace("inputfile2.", "")
                                )

                                map_col = config.get("TargetMapping", "")
                                if not map_col:
                                    return (
                                        source_data_df,
                                        "'TargetMapping' cannot be empty for 'AddColumn.ByMap'",
                                    )
                                map_col = (
                                    map_col.replace("<<", "")
                                    .replace(">>", "")
                                    .replace("inputfile2.", "")
                                )

                                # Apply the mapping function row by row
                                source_data_df = source_data_df.apply(
                                    lambda row: self.add_column_in_df_by_mapping(
                                        row,
                                        input_file2_df,
                                        new_col,
                                        source_col,
                                        target_col,
                                        map_col,
                                        is_case_sensitive,
                                    ),
                                    axis=1,
                                )

                elif key == "AsList":

                    if isinstance(value, list):

                        for config in value:

                            if config:

                                new_col = config.get("ColumnName", "")
                                if not new_col:
                                    return (
                                        source_data_df,
                                        "'ColumnName' cannot be empty for 'AddColumn.AsList'",
                                    )

                                source_col = config.get("Source", "")
                                target = config.get("Target", "")
                                list_data = config.get("ListData", "")

                                if not source_col and not target and not list_data:
                                    return (
                                        source_data_df,
                                        "Either 'Source', 'Target', or 'ListData' should be provided for 'AddColumn.AsList'.",
                                    )

                                if source_col and not target and not list_data:
                                    return (
                                        source_data_df,
                                        "'Target' cannot be empty for 'AddColumn.AsList'",
                                    )

                                if not source_col and target and not list_data:
                                    return (
                                        source_data_df,
                                        "'Source' cannot be empty for 'AddColumn.AsList'",
                                    )

                                if list_data:
                                    list_data = list_data.split(",")
                                    source_data_df[new_col] = [list_data] * len(
                                        source_data_df
                                    )
                                else:
                                    # Apply the mapping function row by row
                                    source_data_df = source_data_df.apply(
                                        lambda row: self.add_column_as_list(
                                            row, source_col, target, new_col
                                        ),
                                        axis=1,
                                    )

                elif isinstance(value, str) and "<<" in value and ">>" in value:
                    source_data_df[key] = source_data_df.apply(
                        lambda row: self.get_updated_value(
                            row,
                            self.modify_string(value, ["inputfile1.", "InputFile1."]),
                        ),
                        axis=1,
                    )

                else:
                    if isinstance(value, (str, int, float)):
                        source_data_df[key] = value
                    else:
                        # Assigning a single object to the entire column with the length of the DataFrame
                        source_data_df[key] = [value] * len(source_data_df)

            return source_data_df, None

        except ValueError as e:
            if self.err_msg:
                return pd.DataFrame(), self.err_msg
            return source_data_df, str(e)
        except Exception as e:
            return source_data_df, str(e)

    def update_column(self, source_data_df, column_info_dict):
        try:
            if not column_info_dict or source_data_df.empty:
                return source_data_df, None

            # Prepare a dictionary for renaming columns
            columns_to_rename = {}

            for new_col, exis_col in column_info_dict.items():

                if new_col == "Concat":

                    if isinstance(exis_col, list):

                        for config in exis_col:

                            if config:

                                new_col = config.get("ColumnName", "")
                                if not new_col:
                                    return (
                                        source_data_df,
                                        "'ColumnName' cannot be empty for 'UpdateColumn.Concat'",
                                    )
                                new_col = (
                                    new_col.replace("inputfile1.", "")
                                    .replace("InputFile1.", "")
                                    .replace("<<", "")
                                    .replace(">>", "")
                                )

                                concat_val = config.get("ConcatValue", "")
                                if not concat_val:
                                    return (
                                        source_data_df,
                                        "'ConcatValue' cannot be empty for 'UpdateColumn.Concat'",
                                    )

                                position = config.get("Position", "")
                                if not position:
                                    return (
                                        source_data_df,
                                        "'Position' cannot be empty for 'UpdateColumn.Concat'",
                                    )

                                # Update the column
                                source_data_df[new_col] = source_data_df.apply(
                                    lambda row: (
                                        concat_val + row[new_col]
                                        if position == "Start"
                                        else row[new_col] + concat_val
                                    ),
                                    axis=1,
                                )

                elif new_col == "Split":

                    if isinstance(exis_col, list):

                        for config in exis_col:

                            if config:

                                source = config.get("Source", "")
                                if not source:
                                    return (
                                        source_data_df,
                                        "'Source' cannot be empty for 'UpdateColumn.Split'",
                                    )
                                source = (
                                    source.replace("inputfile1.", "")
                                    .replace("InputFile1.", "")
                                    .replace("<<", "")
                                    .replace(">>", "")
                                )

                                delimitter = config.get("Delimiter", "")
                                if not delimitter:
                                    return (
                                        source_data_df,
                                        "'Delimitter' cannot be empty for 'UpdateColumn.Split'",
                                    )

                                index = config.get("Index", "")
                                if not index:
                                    return (
                                        source_data_df,
                                        "'Index' cannot be empty for 'UpdateColumn.Split'",
                                    )

                                # Update the column
                                source_data_df[source] = source_data_df.apply(
                                    lambda row: (
                                        row[source].split(delimitter)[index]
                                        if isinstance(row[source], str)
                                        else None
                                    ),
                                    axis=1,
                                )

                elif new_col == "Replace":

                    if isinstance(exis_col, list):

                        special_chars = r".^$*+?{}[]\|()"

                        for config in exis_col:

                            if config:

                                new_col = config.get("ColumnName", "")
                                if not new_col:
                                    return (
                                        source_data_df,
                                        "'ColumnName' cannot be empty for 'UpdateColumn.Replace'",
                                    )
                                new_col = (
                                    new_col.replace("inputfile1.", "")
                                    .replace("InputFile1.", "")
                                    .replace("<<", "")
                                    .replace(">>", "")
                                )

                                regex = config.get("Regex", None)

                                replace_whole_value = config.get(
                                    "ReplaceWholeValue", None
                                )
                                if replace_whole_value is None:
                                    replace_whole_value = "True"

                                replace_value = config.get("ReplaceValue", "")
                                if not replace_value:
                                    return (
                                        source_data_df,
                                        "'ReplaceValue' cannot be empty for 'UpdateColumn.Replace'",
                                    )

                                if regex is None:
                                    source_data_df[new_col] = source_data_df.apply(
                                        lambda row: (
                                            replace_value
                                            if row[new_col] is None
                                            or pd.isna(row[new_col])
                                            else row[new_col]
                                        ),
                                        axis=1,
                                    )
                                elif regex == "":
                                    source_data_df[new_col] = source_data_df.apply(
                                        lambda row: (
                                            replace_value
                                            if isinstance(row[new_col], str)
                                            and re.search(r"^$", row[new_col])
                                            else row[new_col]
                                        ),
                                        axis=1,
                                    )
                                else:

                                    if regex in special_chars:
                                        regex = re.escape(regex)

                                    if replace_whole_value == "True":
                                        source_data_df[new_col] = source_data_df.apply(
                                            lambda row: (
                                                replace_value
                                                if isinstance(row[new_col], str)
                                                and re.search(regex, row[new_col])
                                                else row[new_col]
                                            ),
                                            axis=1,
                                        )

                                    elif replace_whole_value == "False":
                                        source_data_df[new_col] = source_data_df.apply(
                                            lambda row: (
                                                re.sub(
                                                    regex, replace_value, row[new_col]
                                                )
                                                if isinstance(row[new_col], str)
                                                and re.search(regex, row[new_col])
                                                else row[new_col]
                                            ),
                                            axis=1,
                                        )

                elif new_col == "ChangePath":

                    if isinstance(exis_col, list):
                        for config in exis_col:

                            if config:
                                source_path = config.get("Source", "")
                                if not source_path:
                                    return (
                                        source_data_df,
                                        "'Source' cannot be empty for 'UpdateColumn.ChangePath'",
                                    )
                                source_path = (
                                    source_path.replace("inputfile1.", "")
                                    .replace("InputFile1.", "")
                                    .replace("<<", "")
                                    .replace(">>", "")
                                )

                                target_path = config.get("Target", "")
                                if not target_path:
                                    return (
                                        source_data_df,
                                        "'Target' cannot be empty for 'UpdateColumn.ChangePath'",
                                    )
                                target_path = (
                                    target_path.replace("inputfile1.", "")
                                    .replace("InputFile1.", "")
                                    .replace("<<", "")
                                    .replace(">>", "")
                                )

                                operation_type = config.get(
                                    "Type"
                                )  # Default to 'Append'

                                # Fetch the source and target path values
                                source_data_df.apply(
                                    lambda row: self.apply_change_path(
                                        row, source_path, target_path, operation_type
                                    ),
                                    axis=1,
                                )

                else:
                    # Clean up the column name
                    if exis_col and isinstance(exis_col, str):
                        exis_col = (
                            exis_col.replace("inputfile1.", "")
                            .replace("InputFile1.", "")
                            .replace("<<", "")
                            .replace(">>", "")
                            .strip()
                        )

                        # Check if the column exists in the DataFrame
                        if exis_col in source_data_df.columns:
                            columns_to_rename[exis_col] = new_col
                        else:
                            return source_data_df, f"Invalid column - {exis_col}"

            # Rename the columns all at once
            if columns_to_rename:
                source_data_df.rename(columns=columns_to_rename, inplace=True)

            return source_data_df, None

        except KeyError as e:
            return source_data_df, f"Invalid column - {str(e)}"
        except ValueError as e:
            if self.err_msg:
                return pd.DataFrame(), self.err_msg
            return source_data_df, str(e)
        except Exception as e:
            return source_data_df, str(e)

    def delete_column(self, source_data_df, column_info_dict):
        try:
            if not column_info_dict or source_data_df.empty:
                return source_data_df, None

            columns_to_drop = []

            for _, value in column_info_dict.items():
                if value:
                    # Split and clean up column names
                    value_parts = [part.strip() for part in value.split(",")]

                    for part in value_parts:
                        if part in source_data_df.columns:
                            columns_to_drop.append(part)
                        else:
                            return source_data_df, f"Invalid column - {part}"

            # Drop the valid columns
            source_data_df = source_data_df.drop(columns=columns_to_drop)

            return source_data_df, None

        except KeyError as e:
            return source_data_df, f"Invalid column - {str(e)}"
        except Exception as e:
            return source_data_df, str(e)

    def remove_duplicates(self, source_data_df, column_info_dict):

        try:

            if not column_info_dict or source_data_df.empty:
                return source_data_df, None

            unique_columns = []

            for _, value in column_info_dict.items():
                if value:
                    # Split and clean up column names
                    value_parts = [part.strip() for part in value.split(",")]

                    # Add valid columns to reorder list, and track invalid columns
                    for part in value_parts:
                        if part in source_data_df.columns:
                            unique_columns.append(part)
                        else:
                            return source_data_df, f"Invalid column - {part}"

            # Remove rows where duplicates exist based on the provided columns
            source_data_df = source_data_df.drop_duplicates(
                subset=unique_columns, keep="first"
            )  # 'first' keeps the first occurrence

            return source_data_df, None

        except Exception as e:
            return source_data_df, str(e)

    def re_order_column(self, source_data_df, column_info_dict):
        try:
            if not column_info_dict or source_data_df.empty:
                return source_data_df, None

            columns_to_reorder = []

            for _, value in column_info_dict.items():
                if value:
                    # Split and clean up column names
                    value_parts = [part.strip() for part in value.split(",")]

                    # Add valid columns to reorder list, and track invalid columns
                    for part in value_parts:
                        if part in source_data_df.columns:
                            columns_to_reorder.append(part)
                        else:
                            return source_data_df, f"Invalid column - {part}"

            # Reorder the columns
            source_data_df = source_data_df[columns_to_reorder]

            return source_data_df, None

        except Exception as e:
            return source_data_df, str(e)

    def apply_change_path(self, row, source_path, target_path, operation_type):
        # Get the source and target values using the get_updated_value method
        source_value = self.get_updated_value(row, f"<<{source_path}>>")
        target_value = self.get_updated_value(row, f"<<{target_path}>>")

        # If source value is None or empty, return the row as is
        if not source_value:
            return row

        # Extract the key from the source path to understand what to update
        key = source_path.split(".")[-1]

        # If target value doesn't exist
        if target_value is None:
            return row

        # If target_value is a list, handle the operation
        if isinstance(target_value, list):
            if operation_type == "Append":
                target_value.append({key: source_value})
                return self.set_updated_value(row, target_path, target_value)
            elif operation_type == "Concat":
                # Assuming that each element in the list is a dictionary and you want to modify it
                for data in target_value:
                    if isinstance(data, dict):
                        data[key] = source_value
                return self.set_updated_value(row, target_path, target_value)
        elif isinstance(target_value, dict):
            # If the target value is a dictionary, set the key-value pair directly
            target_value[key] = source_value
            self.set_updated_value(row, target_path, target_value)

        # Return the updated row
        return row

    def set_updated_value(self, row, path, value):

        keys = path.split(".")

        # Traverse through the row, create dictionaries if necessary
        for key in keys[:-1]:  # All but the last key
            if key in row:
                row = row[key]

        # Set the final value at the last key in the path
        row[keys[-1]] = value
        return row

    def clean_space(self, str_data, list_data):
        cleaned_str_data = str_data.strip() if str_data else ""
        cleaned_list_data = [data.strip() for data in list_data] if list_data else []

        return cleaned_str_data, cleaned_list_data

    def add_column_as_object(self, row, new_col, objs):
        # Creating the dictionary by iterating over the objects
        data_dict = {}

        for obj in objs:
            # Modify the object string only once
            clean_obj, _ = self.clean_space(obj, [])

            modified_obj = self.modify_string(clean_obj, ["inputfile1.", "InputFile1."])

            # Get the updated value for the modified object
            value = self.get_updated_value(row, modified_obj)

            # If the value is not None, add it to the dictionary
            if value:
                # Use a list split just once and calculate the index
                modified_obj_parts = modified_obj.split(".")
                index = len(modified_obj_parts) - 1
                key = (
                    self.get_index_element(modified_obj_parts, index)
                    .replace("<<", "")
                    .replace(">>", "")
                )
                data_dict[key] = value

        # Assign the created dictionary to the new column in the row
        row[new_col] = data_dict
        return row

    def add_column_as_list(self, row, source, target, new_col):

        # Clean up source and target strings once, not inside the loop
        source_key = source.replace("inputfile1.", "")
        target = target.replace("Source.", "").replace("<<", "").replace(">>", "")

        # Get the source list
        source_list = self.get_updated_value(row, source_key)

        # If there's no source list, directly assign an empty list to the new column
        if not source_list:
            row[new_col] = []
            return row

        # Use list comprehension to filter the data
        output_list = [data[target] for data in source_list if target in data]

        # Assign the result to the new column
        row[new_col] = output_list
        return row

    def add_column_by_function(self, input_file_df, new_col, source, function, config):

        # Handle 'CurrentDateTime' function separately
        if function == "CurrentDateTime":
            format = "%Y-%m-%dT%H:%M:%S.%fZ"
            if config.get("Format", ""):
                format = config.get("Format", "")
            input_file_df[new_col] = self.get_current_datetime(format)
        else:
            input_file_df[new_col] = input_file_df.apply(
                lambda row: self.handle_other_functions(row, source, function, config),
                axis=1,
            )

    def handle_other_functions(self, row, path, function, config):

        if function == "Length":
            source_list = self.get_updated_value(
                row, self.modify_string(path, ["inputfile1.", "InputFile1."])
            )
            if isinstance(source_list, list):
                return len(source_list)
        elif function == "SplitByDelimiter":
            delimiter = config.get("Delimiter", "")
            index = config.get("Index", "")
            return self.get_split_value(row, path, index, delimiter)
        return "N/A"

    def get_split_value(self, row, path, index, delimiter):
        path_value = self.get_updated_value(
            row, self.modify_string(path, ["inputfile1.", "InputFile1."])
        )
        if isinstance(path_value, str):
            return path_value.split(delimiter)[index]
        return "N/A"

    def get_current_datetime(self, format):
        current_time = datetime.now(timezone.utc)
        formatted_time = current_time.strftime(format)
        return formatted_time

    def add_column_in_df_by_mapping(
        self, row, target_data_df, new_column, source_column, target_column, map_column, is_case_sensitive
    ):

        if not target_data_df.empty:

            # Extract the source column value from the row
            source_column_value = self.get_updated_value(row, f"<<{source_column}>>")

            if not target_column in target_data_df.columns:
                self.err_msg = self.err_msg = f"Invalid column - '{target_column}'"
                raise ValueError

            # Find the row in the target dataframe where the target column matches the source column value
            target_row = pd.DataFrame()
            if is_case_sensitive:
                target_row = target_data_df[
                    target_data_df[target_column] == source_column_value
                ]
            else:
                target_row = target_data_df[
                    target_data_df[target_column].astype(str) == str(source_column_value or "")
                ]

            if not target_row.empty:
                # Retrieve the value from the map column
                if not map_column in target_row.columns:
                    self.err_msg = self.err_msg = f"Invalid column - '{map_column}'"
                    raise ValueError
                manager_value = target_row[map_column].values[0]
                row[new_column] = manager_value
            else:
                # Handle cases where there is no match (optional)
                row[new_column] = None

        return row  # Ensure the updated row is returned

    def split_df_based_on_condition(self, df, condition):

        matched_df = pd.DataFrame()
        un_matched_df = pd.DataFrame()

        try:
            if condition:

                condition = (
                    condition.replace("<<", "")
                    .replace(">>", "")
                    .replace("inputfile1.", "")
                )

                matched_df = df.query(condition)

                # If there are no matches, 'un_matched_df' will contain all rows
                if matched_df.empty:
                    un_matched_df = df
                else:
                    un_matched_df = df[
                        ~df.index.isin(matched_df.index)
                    ]  # Get the rows that didn't match

            return matched_df, un_matched_df, ""

        except pd.errors.UndefinedVariableError as e:
            try:
                match = re.search(r"'([^']*)'", str(e))
                if match:
                    return (
                        matched_df,
                        un_matched_df,
                        f"Invalid column - '{match.group(1)}'",
                    )
                return matched_df, un_matched_df, str(e)
            except Exception as e:
                return matched_df, un_matched_df, str(e)
        except Exception as e:
            return matched_df, un_matched_df, str(e)

    def modify_string(self, key, regex_list):
        # Combine all regex patterns into one using a non-capturing group
        combined_regex = "|".join(f"({regex})" for regex in regex_list)

        # Precompile the combined regular expression
        pattern = re.compile(combined_regex)

        # Replace all matching patterns in the string
        return pattern.sub("", key)

    def get_index_element(self, list_data, index):
        if isinstance(list_data, list):
            return list_data[index]
        # By default returing 0th index
        return list_data[0]

    def get_updated_value(self, row, path):

        # Check for the pattern "<<...>>" in path
        matches = re.findall(r"<<([^>]*)>>", path)
        # If there are no matches, return the original path
        if not matches:
            return ""
        # If there's only one match and it fully matches the path (ignoring the '<<' and '>>')
        if len(matches) == 1 and len(matches[0]) == len(path.strip("<<>>")):
            return self.extract_value_from_data(row, path)
        # Replace each match with its corresponding value from the data
        for match in matches:
            value = self.extract_value_from_data(row, match)
            path = path.replace(f"<<{match}>>", str(value))
        return path

    def extract_value_from_data(self, row, path):

        path = path.strip("<<>>")
        keys = path.split(".")
        value = row
        for key in keys:
            value = value.get(key, "<<col_not_exist>>")
            if self.is_nan(value) or value is None:
                break
        if value == "<<col_not_exist>>":
            self.err_msg = f"Invalid column - '{path}'"
            raise ValueError
        return value

    def is_nan(self, value):
        # If the value is a float (including numpy float), we can check for NaN
        if isinstance(value, (float, np.float32, np.float64)):
            return math.isnan(value)  # Or use np.isnan(value) if you prefer numpy
        # If the value is None, we can treat it as not NaN
        elif value is None:
            return False
        # For other types (list, dict, string), we can't have NaN, so return False
        else:
            return False

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

    def is_valid_url(self, url):
        try:
            result = urllib.parse.urlparse(url)
            if not all([result.scheme, result.netloc]):
                return False
            return True
        except ValueError as e:
            return False

    def get_extension(self, file_path):
        try:
            file_extension = os.path.splitext(file_path)[1]
            return file_extension
        except IndexError:
            return ""

    def validate(self):

        task_inputs = self.task_inputs
        if not task_inputs:
            return [{"Error": "Task input is missing"}]

        error_list = []
        empty_attrs = []
        unsupported_str_fields = []
        invalid_file_paths = []

        # Validate InputFile
        data_file_path = task_inputs.user_inputs.get("InputFile1")
        if not data_file_path:
            empty_attrs.append("InputFile1")
        elif not isinstance(data_file_path, str):
            unsupported_str_fields.append("InputFile1")
        else:
            if not self.is_valid_url(data_file_path):
                invalid_file_paths.append("InputFile1")
            else:
                extension = self.get_extension(data_file_path)
                if extension != ".json":

                    error_list.append(
                        {
                            "Error": f"'InputFile1' extension - '{extension}' is not supported. Please upload a file with the '.json' extension."
                        }
                    )

        # Validate TransformConfigFile
        toml_file_path = task_inputs.user_inputs.get("TransformConfigFile")
        if not toml_file_path:
            empty_attrs.append("TransformConfigFile")
        elif not isinstance(toml_file_path, str):
            unsupported_str_fields.append("TransformConfigFile")
        else:
            if not self.is_valid_url(toml_file_path):
                invalid_file_paths.append("TransformConfigFile")
            else:
                extension = self.get_extension(toml_file_path)
                if extension != ".toml":
                    error_list.append(
                        {
                            "Error": f"'TransformConfigFile' extension - '{extension}' is not supported. Please upload a file with the '.toml' extension."
                        }
                    )

        if empty_attrs:
            error_list.append({"Error": f"Empty input(s): {', '.join(empty_attrs)}"})
        if unsupported_str_fields:
            error_list.append(
                {
                    "Error": f"Unsupported user input(s): {', '.join(unsupported_str_fields)}. Supported type: String"
                }
            )
        if invalid_file_paths:
            error_list.append(
                {
                    "Error": f"Invalid file path(s): {', '.join(invalid_file_paths)}. Valid file path: http://host:port/folder_name/file_name_with_extension"
                }
            )

        return error_list
