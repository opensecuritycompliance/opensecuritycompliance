from typing import Dict, List, Literal, Optional, Union, Tuple
from compliancecowcards.structs import cards
from compliancecowcards.utils import cowdictutils, cowutils
from datetime import datetime
from compliancecowcards.utils import cowbqschema_generator
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
import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError
import sqlalchemy
from sqlalchemy.types import JSON
from sqlalchemy.exc import SQLAlchemyError
import duckdb

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

        self.proceed_if_log_exists  = cowutils.str_to_bool(value=user_inputs.get("ProceedIfLogExists"),default_val=True)
        self.proceed_if_error_exists = cowutils.str_to_bool(value=user_inputs.get("ProceedIfErrorExists"),default_val=True)

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

        file1_list, error = self.load_file(file1_url)
        if error:
            error_info = log_config_manager.get_error_message(
                "ExcecuteSQLQuery.Validation.InputFile1.load_failed", {"error": error}
            )
            return self.upload_log_file({"Error": error_info})

        file2_list = []
        if file2_url:
            file2_list, error = self.load_file(file2_url)
            if error:
                error_info = log_config_manager.get_error_message(
                    "ExcecuteSQLQuery.Validation.InputFile2.load_failed",
                    {"error": error},
                )
                return self.upload_log_file({"Error": error_info})
                
        result_df, error = self.run_duckdb(file1_list, file2_list, sql_query)
        if error:
            result_df, error = self.run_sqlite(file1_list, file2_list, sql_query, log_config_manager)
            if error:
                return self.upload_log_file({"Error": error})
            
        result = self.handle_output_file_upload(
            result_df, output_file_format, log_config_manager
        )
        if prev_log_file and not result.get("LogFile"):
            result["LogFile"] = prev_log_file
        return result
        
    def run_duckdb(
        self,
        file1_list: list[dict],
        file2_list: list[dict],
        sql_query: str
    ) -> tuple[pd.DataFrame, str]:
        file1_df = pd.DataFrame(file1_list)
        try:
            with sqlalchemy.create_engine("duckdb:///:memory:").begin() as conn:
                self.df_to_sql_with_schema(file1_df, conn, "inputfile1")
                if file2_list:
                    file2_df = pd.DataFrame(file2_list)
                    self.df_to_sql_with_schema(file2_df, conn, "inputfile2")
                    
                result_df = pd.read_sql_query(sql_query, conn)
                return result_df, ""
        except (duckdb.Error, SQLAlchemyError) as e:
            logger.log_data({
                "warning": f"Unable to run SQL query using DuckDB, falling back to SQLite",
                "details": str(e)
            })
            
            return pd.DataFrame(), str(e)
        
    def run_sqlite(
        self,
        file1_list: list[dict],
        file2_list: list[dict],
        sql_query: str,
        log_config_manager: cards.LogConfigManager
    ) -> tuple[pd.DataFrame, str]:
        file1_df = pd.json_normalize(file1_list).map(self.stringify_complex_types)
        file2_df = pd.json_normalize(file2_list if file2_list else []).map(self.stringify_complex_types)

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
            return pd.DataFrame(), error_info

        result_df = result_df.map(self.parse_json_string)
        return result_df, ""

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

    def load_file(self, file_path: str) -> Tuple[list[dict], Optional[str]]:
        """Load a JSON file into a DataFrame."""
        if not self.is_valid_url(file_path):
            return [], "Invalid URL"
        if not file_path.endswith(".json"):
            return (
                [],
                f"Expected JSON, got {os.path.splitext(file_path)[1]}",
            )
        data, error = self.download_json_file_from_minio_as_iterable(file_path)
        if error:
            return [], error
        return data if isinstance(data, list) else [data], None

    def is_safe_sql_query(self, query: str) -> bool:
        """Allow only non-mutating statements and reject explicit SQL comments."""
    
        if "/*" in query or "*/" in query or ";--" in query:
            return False
    
        try:
            statements = list(sqlglot.parse(query))
        except ParseError:
            return False
    
        if not statements:
            return False
    
        for statement in statements:
            if isinstance(
                statement,
                (exp.Delete, exp.Drop, exp.Insert, exp.Update, exp.Alter),
            ):
                return False
    
        return True

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

        output_file_name = "OutputFile"
        if self.task_inputs.user_inputs.get("OutputFileName", ""):
            output_file_name = self.task_inputs.user_inputs.get("OutputFileName", "")

        if not result_df.empty:

            if output_file_format.upper() == "JSON":
                # Convert DataFrame to JSON string
                result_json = result_df.to_json(orient="records")
                file_path, error = self.upload_iterable_as_json_file_to_minio(
                    json.loads(result_json), output_file_name
                )

            elif output_file_format.upper() == "CSV":
                file_name = f"{output_file_name}-{uuid.uuid4()}"
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
            
    def df_to_sql_with_schema(
        self,
        df: pd.DataFrame,
        connector_engine,
        table_name: str,
        index = False,
        if_exists: Literal["fail", "replace", "append"] = "replace",
    ):
        field_info_list = self.generate_schema(df, table_name)
        
        if field_info_list:
            field_info = dict()
            for val in field_info_list:
                if cowdictutils.is_valid_key(val, "type"):
                    if val["type"] == "RECORD" or val["mode"] == "REPEATED":
                        field_info[val["name"]] = JSON

            if bool(field_info):
                df.to_sql(
                    table_name,
                    connector_engine,
                    dtype=field_info,
                    index=index,
                    if_exists=if_exists,
                )
            else:
                df.to_sql(
                    table_name, connector_engine, index=index, if_exists=if_exists
                )
                
    def generate_schema(self, df: pd.DataFrame, table_name: str):
        schema = None
        jsonData = df.to_dict(orient='records')
        
        generator = cowbqschema_generator.SchemaGenerator(
            input_format='dict',
            keep_nulls=True,
            quoted_values_are_strings=True
        )

        schema_map, error_logs = generator.deduce_schema(jsonData)
        if error_logs:
            logger.log_data({
                "warning": f"There were type mismatch errors while trying to generate schema for '{table_name}'",
                "details": error_logs,
            })
        
        schema = generator.flatten_schema(schema_map)
        schema = json.loads(json.dumps(schema))
        
        return schema
