from compliancecowcards.structs import cards
import uuid
import pandas as pd
from typing import Tuple, Optional, List, Dict, Any
from pathlib import Path
from compliancecowcards.utils import cowutils

logger = cards.Logger()

MINIO_PLACEHOLDER = "<<MINIO_FILE_PATH>>"


class MergeData():

    MERGE_TYPES = {
        "CONCAT": {"concatenate", "concat"},
        "APPEND": {"append", ""}
    }

    def __init__(self, merge_type: str, df1: pd.DataFrame, df2: pd.DataFrame):
        """Initializes the MergeData class with the merge type and DataFrames."""
        self.merge_type = (merge_type or "").lower().strip()
        self.df1 = df1
        self.df2 = df2

    def merge(self) -> Tuple[Optional[pd.DataFrame], Optional[str], Optional[Dict[str, Any]]]:
        """Merges the two DataFrames based on the specified merge type."""
        if self.merge_type in self.MERGE_TYPES["CONCAT"]:
            return self._concat_merge()
        elif self.merge_type in self.MERGE_TYPES["APPEND"]:
            return self._append_merge()
        else:
            return None, "MergeData.Validation.MergeType.invalid", {"merge_type": f"{self.merge_type}"}

    def _concat_merge(self) -> Tuple[pd.DataFrame, None, None]:
        """Performs a concatenation merge by combining the first non-null values from both DataFrames."""
        max_len = max(len(self.df1), len(self.df2))
        df1 = self.df1.reindex(range(max_len))
        df2 = self.df2.reindex(range(max_len))
        merged_df = df2.combine_first(df1)

        return merged_df, None, None

    def _append_merge(self) -> Tuple[Optional[pd.DataFrame], Optional[str], Optional[Dict[str, Any]]]:
        """Enhanced append merge that preserves complex data types like PRReviews"""
        missing_cols = set(self.df1.columns) - set(self.df2.columns)
        if missing_cols:
            return None, "MergeData.Validation.InputFile2.missing_columns", {"missing_columns": ", ".join(missing_cols)}

        # Ensure both DataFrames have object dtype for complex columns
        df1_copy = self.df1.copy()
        df2_copy = self.df2.copy()

        # Fix dtype issues for complex columns like PRReviews
        for col in df1_copy.columns:
            if col in df2_copy.columns:
                # If either DataFrame has object dtype, ensure both do
                if df1_copy[col].dtype == 'object' or df2_copy[col].dtype == 'object':
                    df1_copy[col] = df1_copy[col].astype('object')
                    df2_copy[col] = df2_copy[col].astype('object')

        # Perform append with explicit settings to preserve complex types
        merged_df = pd.concat([df1_copy, df2_copy],
                              ignore_index=True,
                              sort=False,
                              copy=False)

        return merged_df, None, None


class Task(cards.AbstractTask):

    def __init__(self) -> None:
        """Initialize the Task with empty log data."""
        super().__init__()
        self.prev_log_data: List[Dict[str, Any]] = []

    def execute(self) -> Dict[str, Any]:
        """Execute the task to merge files."""
        response = {}
        user_inputs = self.task_inputs.user_inputs or {}

        log_file_url = user_inputs.get("LogFile", "") if user_inputs.get(
            "LogFile", "") != MINIO_PLACEHOLDER else ""

        
        self.proceed_if_log_exists  = cowutils.str_to_bool(value=user_inputs.get("ProceedIfLogExists"),default_val=True)
        self.proceed_if_error_exists = cowutils.str_to_bool(value=user_inputs.get("ProceedIfErrorExists"),default_val=True)
        
        self.set_log_file_name(
            "LogFile" if self.proceed_if_error_exists else "Errors")

        output_file_format = (
            user_inputs.get("OutputFileFormat", "PARQUET")
            or "PARQUET"
        ).upper().strip() or "PARQUET"

        default_log_config_filepath = str(
            Path(__file__).parent.joinpath("LogConfig_default.toml").resolve())
        custom_log_config_url = user_inputs.get(
            "LogConfigFile")

        log_manager, error = cards.LogConfigManager.from_minio_file_url(
            custom_log_config_url if custom_log_config_url and custom_log_config_url != "<<MINIO_FILE_PATH>>" else "",
            self.download_toml_file_from_minio_as_dict,
            default_log_config_filepath,
            default_context_data={
                'fromdate': self.task_inputs.from_date.strftime('%d/%m/%Y %H:%M'),
                'todate': self.task_inputs.to_date.strftime('%d/%m/%Y %H:%M')
            }
        )
        if error:
            return {'Error': error}

        self.prev_log_data, error_info = self.download_log_file(
            log_file_url)
        if error_info:
            return self.upload_log_file_panic(error_data=log_manager.get_error_message(
                "MergeData.Validation.LogFile.download_failed", error_info))
        elif not self.proceed_if_log_exists and log_file_url:
            return {"LogFile": log_file_url}

        input_file1_minio_url = user_inputs.get("InputFile1", "")
        input_file2_minio_url = user_inputs.get("InputFile2", "")

        pre_merged_file, error_info = self.validate_inputs(
            input_file1_minio_url, input_file2_minio_url)
        if error_info:
            return self.upload_log_file_panic(error_data=log_manager.get_error_message(
                "MergeData.Validation.InputFiles.empty"))
        elif pre_merged_file:
            return pre_merged_file

        df1, error_info = self.download_input_file(input_file1_minio_url)
        if error_info:
            return self.upload_log_file_panic(error_data=log_manager.get_error_message(
                "MergeData.Exception.InputFile1.download_failed", error_info))

        df2, error_info = self.download_input_file(input_file2_minio_url)
        if error_info:
            return self.upload_log_file_panic(error_data=log_manager.get_error_message(
                "MergeData.Exception.InputFile2.download_failed", error_info))

        merge_type = user_inputs.get("MergeType", "append")
        merged_df, error_type, error_info = MergeData(
            merge_type, df1, df2).merge()
        if error_info:
            return self.upload_log_file_panic(error_data=log_manager.get_error_message(
                error_type, error_info))

        output_file_name = "MergedData"
        if self.task_inputs.user_inputs.get("OutputFileName", ""):
            output_file_name = self.task_inputs.user_inputs.get("OutputFileName", "")
        if output_file_format.upper() == "CSV":
            file_path, error_info = self.upload_df_as_csv_file_to_minio(
                df=merged_df, file_name=output_file_name
            )
        elif output_file_format.upper() == "JSON":
            file_path, error_info = self.upload_df_as_json_file_to_minio(
                df=merged_df, file_name=output_file_name
            )
        elif output_file_format.upper() == "PARQUET":
            file_path, error_info = self.upload_df_as_parquet_file_to_minio(
                df=merged_df, file_name=output_file_name
            )
        else:
            return self.upload_log_file_panic(error_data=log_manager.get_error_message(
                "MergeData.Validation.OutputFileFormat.invalid", {"output_file_format": output_file_format}))
        
        if error_info:
            return self.upload_log_file_panic(error_data=log_manager.get_error_message(
                "MergeData.Exception.OutputFile.upload_failed", {"error": error_info.get("error")}))

        if log_file_url:
            response["LogFile"] = log_file_url
        response["MergedData"] = file_path

        return response

    def download_log_file(self, path: str) -> Tuple[Optional[List[Dict[str, Any]]], Dict[str, Any]]:
        """Validates the given path and downloads the corresponding log file from MinIO"""
        if not path:
            return [], None
        content, error = self.download_json_file_from_minio_as_iterable(path)
        return (content, None) if not error else ([], {"error": error.get("error")})

    def validate_inputs(self, url1: str, url2: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        """Validates the input file URLs to ensure that they are not empty."""
        if url1 == MINIO_PLACEHOLDER:
            url1 = ""
        if url2 == MINIO_PLACEHOLDER:
            url2 = ""

        if not url1 and not url2:
            return None, {"error": "Both InputFile1 and InputFile2 are missing or invalid."}
        if not url1:
            return {"MergedData": url2}, None
        if not url2:
            return {"MergedData": url1}, None
        return None, None

    def download_input_file(self, input_file_minio_url: str) -> Tuple[Optional[pd.DataFrame], Optional[Dict[str, Any]]]:
        """Downloads an input file from MinIO and returns it as a pandas DataFrame."""
        df, error = self.download_file_from_minio_as_df(
            input_file_minio_url)
        if error:
            return None, {"error": error.get("error")}
        return df, None
