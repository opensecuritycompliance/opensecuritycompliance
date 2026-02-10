from typing import Dict, List, Optional, Union, Tuple
from compliancecowcards.structs import cards
from compliancecowcards.utils import cowdictutils, cowutils
from datetime import datetime
import json
import sqlite3
import pandas as pd
import os
import urllib.parse
import uuid
import pyarrow as pa
import pyarrow.parquet as pq
import io
import pathlib
import re

logger = cards.Logger()

CONTENT_TYPE_PARQUET = "application/parquet"
MINIO_PLACEHOLDER = "<<MINIO_FILE_PATH>>"


class Task(cards.AbstractTask):
    """Task to execute an SQL query on input files and return the result."""

    def execute(self) -> Dict[str, str]:
        """Execute the SQL query task on input files.

        Returns:
            Dict with 'OutputFile' and optionally 'LogFile' on success, or 'LogFile'/'error' on failure.
        """

        self.prev_task_log_data: List = []
        self.proceed_if_log_exists: bool = True
        self.proceed_if_error_exists: bool = True

        user_inputs = self.task_inputs.user_inputs if self.task_inputs else {}
        prev_log_file = user_inputs.get("LogFile", "")
        file1_url = user_inputs.get("InputFile1", "")
        file2_url = user_inputs.get("InputFile2", "")
        output_file_format = user_inputs.get("OutputFileFormat") or "PARQUET"

        default_log_config_filepath = str(
            pathlib.Path(__file__).parent.joinpath("LogConfig_default.toml").resolve()
        )
        custom_log_config_url = self.task_inputs.user_inputs.get("LogConfigFile")

        self.proceed_if_log_exists = user_inputs.get("ProceedIfLogExists")
        self.proceed_if_log_exists = (
            self.proceed_if_log_exists
            if self.proceed_if_log_exists is not None
            else True
        )

        self.proceed_if_error_exists = user_inputs.get("ProceedIfErrorExists")
        self.proceed_if_error_exists = (
            self.proceed_if_error_exists
            if self.proceed_if_error_exists is not None
            else True
        )

        log_config_manager, error = cards.LogConfigManager.from_minio_file_url(
            (
                custom_log_config_url
                if custom_log_config_url
                and custom_log_config_url != "<<MINIO_FILE_PATH>>"
                else ""
            ),
            self.download_toml_file_from_minio_as_dict,
            default_log_config_filepath,
            default_context_data={
                "fromdate": self.task_inputs.from_date.strftime("%d/%m/%Y %H:%M"),
                "todate": self.task_inputs.to_date.strftime("%d/%m/%Y %H:%M"),
            },
        )
        if error:
            return self.upload_log_file({"Error": error})

        log_data, self.prev_task_log_data, error = self.validate_log(prev_log_file)
        if log_data:
            return log_data
        elif error:
            error_info = log_config_manager.get_error_message(
                "ExcecuteSQLQuery.Validation.LogFile.download_failed", {"error": error}
            )
            return self.upload_log_file({"Error": error_info})

        validate_flow = cowutils.str_to_bool(user_inputs.get("ValidateFlow", False))

        error = self.validate_inputs()
        if error:
            error_info = log_config_manager.get_error_message(
                "ExcecuteSQLQuery.Validation.Inputs.empty_or_invalid",
                {"error": error["Error"]},
            )
            return self.upload_log_file({"Error": error_info})

        sql_config_file = user_inputs.get("SQLConfig", "")
        sql_query = user_inputs.get("SQLQuery", "")

        # If both SQLConfig and SQLQuery are provided, SQLConfig takes precedence
        if sql_config_file != MINIO_PLACEHOLDER and sql_config_file:
            config, error = self.download_toml_file_from_minio_as_dict(sql_config_file)
            if error:
                error_info = log_config_manager.get_error_message(
                    "ExcecuteSQLQuery.Validation.SQLConfig.download_failed",
                    {"error": error},
                )
                return self.upload_log_file({"Error": error_info})
        elif sql_query:
            config = {"SQLQuery": sql_query}

        sql_config_errors = self.validate_sql_config(config)
        if sql_config_errors:
            error_info = log_config_manager.get_error_message(
                "ExcecuteSQLQuery.Validation.SQLConfig.validation_failed",
                {"error": sql_config_errors[0]["Error"]},
            )
            return self.upload_log_file({"Error": error_info})

        sql_query = config["SQLQuery"]

        # Validate SQL query to mitigate injection
        if not self.is_safe_sql_query(sql_query):
            error_info = log_config_manager.get_error_message(
                "ExcecuteSQLQuery.Validation.SQLConfig.unsafe_query_detected"
            )
            return self.upload_log_file({"Error": error_info})

        if validate_flow:
            return {"ValidationStatus": "Input data validated successfully"}

        file1_df, error = self.load_file(file1_url)
        if error:
            error_info = log_config_manager.get_error_message(
                "ExcecuteSQLQuery.Validation.InputFile1.load_failed", {"error": error}
            )
            return self.upload_log_file({"Error": error_info})

        file1_df = file1_df.map(self.stringify_complex_types)
        file2_df = pd.DataFrame()
        if file2_url:
            file2_df, error = self.load_file(file2_url)
            if error:
                error_info = log_config_manager.get_error_message(
                    "ExcecuteSQLQuery.Validation.InputFile2.load_failed",
                    {"error": error},
                )
                return self.upload_log_file({"Error": error_info})
            file2_df = file2_df.map(self.stringify_complex_types)

        try:
            with sqlite3.connect(":memory:") as conn:
                file1_df.to_sql("inputfile1", conn, if_exists="replace", index=False)
                if not file2_df.empty:
                    file2_df.to_sql(
                        "inputfile2", conn, if_exists="replace", index=False
                    )
                result_df = pd.read_sql_query(sql_query, conn)
        except (sqlite3.Error, pd.errors.DatabaseError) as e:
            error_info = log_config_manager.get_error_message(
                "ExcecuteSQLQuery.Validation.SQLConfig.query_execution_failed",
                {"error": str(e)},
            )
            return self.upload_log_file({"Error": error_info})

        result_df = result_df.map(self.parse_json_string)
        result = self.handle_output_file_upload(
            result_df, output_file_format, log_config_manager
        )
        return result

    def validate_sql_config(self, config: dict) -> list[dict]:
        errors = []

        required_fields = ["SQLQuery"]
        for field in required_fields:
            if not config.get(field):
                errors.append({"Error": f"{field} missing in SQLConfig File."})

        return errors

    def validate_inputs(self) -> Dict[str, str]:
        """Validate required task inputs."""
        if not self.task_inputs:
            return {"Error": "Task inputs are missing"}
        if not self.task_inputs.user_inputs:
            return {"Error": "User inputs are missing"}
        user_obj = self.task_inputs.user_object
        if (
            not user_obj
            or not user_obj.app
            or not user_obj.app.application_url
            or not user_obj.app.user_defined_credentials
        ):
            return {"Error": "User credentials are missing"}

        errors = []
        if not cowdictutils.is_valid_key(self.task_inputs.user_inputs, "InputFile1"):
            errors.append("InputFile1")

        if not cowdictutils.is_valid_key(self.task_inputs.user_inputs, "SQLConfig"):
            if not cowdictutils.is_valid_key(self.task_inputs.user_inputs, "SQLQuery"):
                errors.append("SQLConfig or SQLQuery")
        return (
            {"Error": "The following input(s): " + ", ".join(errors) + " is/are empty"}
            if errors
            else {}
        )

    def load_prior_errors(self, log_file: str) -> List[Dict[str, str]]:
        """Load prior errors from a log file."""
        log_data, error = self.download_json_file_from_minio_as_iterable(log_file)
        return (
            log_data
            if not error
            else [{"Error": f"Failed to download LogFile: {error}"}]
        )

    def load_file(self, file_path: str) -> Tuple[pd.DataFrame, Optional[str]]:
        """Load a JSON file into a DataFrame."""
        if not self.is_valid_url(file_path):
            return pd.DataFrame(), "Invalid URL"
        if not file_path.endswith(".json"):
            return (
                pd.DataFrame(),
                f"Expected JSON, got {os.path.splitext(file_path)[1]}",
            )
        data, error = self.download_json_file_from_minio_as_iterable(file_path)
        if error:
            return pd.DataFrame(), error
        return pd.json_normalize(data), None

    def is_safe_sql_query(self, query: str) -> bool:
        """Basic validation to prevent SQL injection."""
        # Disallow dangerous keywords (case-insensitive)
        dangerous_keywords = {
            "drop",
            "delete",
            "truncate",
            "update",
            "insert",
            "alter",
            ";--",
            "/*",
            "*/",
        }
        query_lower = query.lower()
        return not any(
            re.search(rf"\b{re.escape(kw)}\b", query_lower, re.IGNORECASE)
            for kw in dangerous_keywords
        )

    def stringify_complex_types(self, value: any) -> Union[str, any]:
        """Convert complex types to JSON strings for SQLite compatibility."""
        if isinstance(
            value, (int, float, str, bool, datetime, pd.Timedelta, bytes, complex)
        ):
            return value
        try:
            return json.dumps(value)
        except Exception:
            return str(value)

    def parse_json_string(self, value: str) -> any:
        """Convert JSON strings back to objects."""
        if not isinstance(value, str):
            return value
        try:
            return json.loads(value)
        except Exception:
            return value

    def upload_df_as_parquet(
        self, output_df: pd.DataFrame, name: str
    ) -> Tuple[str, Optional[str]]:
        """Upload a DataFrame as a Parquet file."""
        return self.upload_df_as_parquet_file_to_minio(
            df=output_df, file_name=f"{name}.parquet"
        )

    def handle_output_file_upload(
        self, result_df: pd.DataFrame, output_file_format: str, log_config_manager
    ) -> Dict:
        """
        Handle uploading result DataFrame in the specified format (JSON, CSV, or PARQUET).

        Args:
            result_df: The DataFrame to upload
            output_file_format: The format to save the file in (JSON, CSV, or PARQUET)
            log_config_manager: The log configuration manager for error messages

        Returns:
            Dict with 'OutputFile' key on success, or error information on failure
        """
        response = {}

        if not result_df.empty:

            if output_file_format.upper() == "JSON":
                # Convert DataFrame to JSON string
                result_json = result_df.to_json(orient="records")
                file_path, error = self.upload_iterable_as_json_file_to_minio(
                    json.loads(result_json), "OutputFile"
                )

            elif output_file_format.upper() == "CSV":
                file_name = f"OutputFile-{uuid.uuid4()}"
                # Convert DataFrame to CSV and upload
                csv_buffer = io.StringIO()
                result_df.to_csv(csv_buffer, index=False)
                csv_content = csv_buffer.getvalue().encode("utf-8")

                file_path, error = self.upload_file_to_minio(
                    file_name=f"{file_name}.csv",
                    file_content=csv_content,
                    content_type="text/csv",
                )

            else:
                # Default to PARQUET if format not recognized
                file_path, error = self.upload_df_as_parquet(result_df, "OutputFile")

            if error:
                error_info = log_config_manager.get_error_message(
                    "ExcecuteSQLQuery.Validation.OutputFile.upload_failed",
                    {"error": error},
                )
                return self.upload_log_file({"Error": error_info})

            if file_path:
                response["OutputFile"] = file_path

        else:
            # Handle empty result
            output_path, error = self.upload_empty_output_by_format(output_file_format)
            if error:
                error_info = log_config_manager.get_error_message(
                    "ExcecuteSQLQuery.Validation.OutputFile.upload_failed",
                    {"error": error},
                )
                return self.upload_log_file({"Error": error_info})

            if output_path:
                response["OutputFile"] = output_path

            log_data = {
                "Error": log_config_manager.get_error_message(
                    "ExcecuteSQLQuery.Validation.SQLConfig.query_no_output"
                )
            }
            log_path = self.upload_log_file(log_data)

            if "LogFile" in log_path:
                response["LogFile"] = log_path.get("LogFile")
            else:
                response["Error"] = log_path.get("Error", "")

        return response

    def upload_empty_output_by_format(
        self, output_file_format: str
    ) -> Tuple[str, Optional[str]]:
        """
        Upload an empty file in the specified format.

        Args:
            output_file_format: The format to save the empty file (JSON, CSV, or PARQUET)

        Returns:
            Tuple of (file_path, error)
        """
        file_name = f"OutputFile-{uuid.uuid4()}"

        if output_file_format.upper() == "JSON":
            # Empty JSON array
            empty_json = []
            return self.upload_iterable_as_json_file_to_minio(
                empty_json, file_name="OutputFile"
            )

        elif output_file_format.upper() == "CSV":
            empty_csv = "\n".encode("utf-8")
            return self.upload_file_to_minio(
                file_name=f"{file_name}.csv",
                file_content=empty_csv,
                content_type="text/csv",
            )

        else:  # Default to PARQUET
            schema = pa.schema([])
            empty_table = pa.Table.from_batches([], schema=schema)

            buffer = io.BytesIO()
            pq.write_table(empty_table, buffer)
            buffer.seek(0)

            return self.upload_file_to_minio(
                file_name=f"{file_name}.parquet",
                file_content=buffer.read(),
                content_type="application/parquet",
            )

    def validate_log(
        self, path: str
    ) -> Tuple[Optional[Dict], Optional[List[Dict]], Optional[Dict]]:
        if not path or path == MINIO_PLACEHOLDER:
            return None, None, None

        if not self.proceed_if_log_exists:
            return {"LogFile": path}, None, None

        content, error = self.download_json_file_from_minio_as_iterable(path)

        return (
            (None, content, None)
            if not error
            else (None, None, {"error": error.get("error")})
        )

    def upload_log_file(self, error_data: list | dict | str) -> Dict:
        """Upload error messages to a log file."""
        if isinstance(error_data, dict):
            error_data = [error_data]
        elif isinstance(error_data, str):
            error_data = [{"Error": error_data}]

        if self.prev_task_log_data:
            error_data.extend(self.prev_task_log_data)

        if self.proceed_if_error_exists:
            file_path, error_info = self.upload_log_file_to_minio(error_data=error_data)
            if error_info:
                logger.log_data(
                    {
                        "Error": f"Unable to upload the log file to MinIO. Please find more details: {error_info.get('error')}"
                    }
                )
            else:
                return {"LogFile": file_path}

        return {"Errors": error_data}

    def is_valid_url(self, url: str) -> bool:
        """Check if a URL is valid."""
        try:
            result = urllib.parse.urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
