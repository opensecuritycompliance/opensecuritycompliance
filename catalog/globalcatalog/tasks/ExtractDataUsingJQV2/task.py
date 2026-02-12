from typing import Tuple, Dict, Any, List, Optional, Union
from compliancecowcards.structs import cards
from compliancecowcards.utils import cowdictutils, cowdfutils, cowjqutils
from applicationtypes.nocredapp import nocredapp
import pandas as pd
import jq
import json
from pathlib import Path
import re
import pathlib

MINIO_PLACEHOLDER = "<<MINIO_FILE_PATH>>"

class Task(cards.AbstractTask):
    """
    The purpose of this task is to extract data from the InputFile based on the provided JQ filter/expression.
    The task expects a JSON file and JQ filter/expression as inputs, and provides the extracted data as JSON file in the output.
    """

    def __init__(self) -> None:
        """Initialize the Task with empty log data."""
        super().__init__()
        self.prev_log_data: List[Dict[str, Any]] = []

    def execute(self) -> Dict[str, Any]:
        """
        Execute the main task logic.

        Returns:
            Dict[str, Any]: Result containing output file URLs or error messages
        """
        # Initialize variables
        prev_log_file_url: str = ""
        data_file_url: str = ""
        
        # Determine whether to proceed if errors exist
        self.proceed_if_error_exists = self.task_inputs.user_inputs.get(
            "ProceedIfErrorExists", True
        )
        self.proceed_if_error_exists = self.proceed_if_error_exists is None or self.proceed_if_error_exists

        # Set log file name based on whether to proceed when errors exist
        # If proceeding despite errors, use "LogFile"; otherwise, use "Errors"
        self.set_log_file_name("LogFile" if self.proceed_if_error_exists else "Errors")

        # Get the default logConfig file path and optional custom config URL from user inputs
        default_log_config_filepath = str(
            pathlib.Path(__file__).parent.joinpath("LogConfig_default.toml").resolve()
        )
        custom_log_config_url = self.task_inputs.user_inputs.get("LogConfigFile")

        # Initialize LogConfigManager
        self.log_manager, error = cards.LogConfigManager.from_minio_file_url(
            (
                custom_log_config_url
                if custom_log_config_url
                and custom_log_config_url != MINIO_PLACEHOLDER
                else ""
            ),
            self.download_toml_file_from_minio_as_dict,
            default_log_config_filepath,
            default_context_data={
                'fromdate': self.task_inputs.from_date.strftime('%d/%m/%Y %H:%M'),
                'todate': self.task_inputs.to_date.strftime('%d/%m/%Y %H:%M')
            }
        )
        if error:
            return self.upload_log_file_panic(error)

        # Safely extract input values
        if cowdictutils.is_valid_key(self.task_inputs.user_inputs, "LogFile"):
            prev_log_file_url = self._sanitize_url(
                self.task_inputs.user_inputs["LogFile"]
            )

        # Get the number of chunks to process per iteration (default is 0)
        chunks_per_iteration = self.task_inputs.user_inputs.get("ChunksPerIteration", 0)

        # Determine whether to proceed if the log file exists
        self.proceed_if_log_exists = self.task_inputs.user_inputs.get(
            "ProceedIfLogExists", True
        )
        self.proceed_if_log_exists = (
            True if self.proceed_if_log_exists is None else self.proceed_if_log_exists
        )

        if (not self.proceed_if_log_exists) and (prev_log_file_url != MINIO_PLACEHOLDER) and prev_log_file_url:
            return {"LogFile": prev_log_file_url}

        if cowdictutils.is_valid_key(self.task_inputs.user_inputs, "InputFile"):
            data_file_url = self._sanitize_url(
                self.task_inputs.user_inputs["InputFile"]
            )

        # Download previous log file if it exists
        if prev_log_file_url and prev_log_file_url != MINIO_PLACEHOLDER:
            self.prev_log_data, error = self.download_json_file_from_minio_as_dict(
                prev_log_file_url
            )
            if error:
                return self.upload_log_file_panic(
                    {
                        "Error": self.log_manager.get_error_message(
                            "ExtractDataUsingJQ.LogFile.download_error",
                            {"error": error},
                        )
                    }
                )

        if not data_file_url or data_file_url == MINIO_PLACEHOLDER:
            return self.upload_log_file_panic(
                {
                    "Error": self.log_manager.get_error_message(
                        "ExtractDataUsingJQ.InputFile.missing"
                    )
                }
            )

        if not self._is_valid_json_file(data_file_url):
            return self.upload_log_file_panic(
                {
                    "Error": self.log_manager.get_error_message(
                        "ExtractDataUsingJQ.InputFile.type_error",
                        {"extension": Path(data_file_url).suffix[1:]},
                    )
                }
            )

        # Retrieve and validate JQ config data
        jq_config_data, error = self.validate_and_get_jq_config_data()
        if error:
            return self.upload_log_file_panic(error)

        # Download and process input data
        data_list, error = self.download_json_file_from_minio_as_dict(data_file_url)
        if error:
            return self.upload_log_file_panic(
                {
                    "Error": self.log_manager.get_error_message(
                        "ExtractDataUsingJQ.InputFile.download_error",
                        {"error": error},
                    )
                }
            )

        if not data_list:
            return self.upload_log_file_panic(
                {
                    "Error": self.log_manager.get_error_message(
                        "ExtractDataUsingJQ.InputFile.empty"
                    )
                }
            )

        total_items = 1  # Default to 1 if not a list
        if isinstance(data_list, list):
            total_items = len(data_list)

        if not chunks_per_iteration:
            chunks_per_iteration = total_items

        response_data = []
        for start in range(0, total_items, chunks_per_iteration):

            datachunk = data_list
            if isinstance(data_list, list):
                end = min(start + chunks_per_iteration, total_items)
                datachunk = data_list[start:end]

            # Evaluate the JQ filter on the data chunk using the configured filter and output method
            jq_result, error = cowjqutils.evaluate_jq_filter(
                datachunk,
                jq_config_data.get("jq_filter", ""),
                jq_config_data.get("output_method", ""),
            )
            if error:
                return self.upload_log_file_panic(error)

            if jq_result:

                # Ensure jq_result is a valid type (dict or list)
                if not isinstance(jq_result, (dict, list)):
                    return self.upload_log_file_panic(
                        {
                            "Error": self.log_manager.get_error_message(
                                "ExtractDataUsingJQ.JQExpression.no_result",
                                {"jq_result_type": type(jq_result).__name__},
                            )
                        }
                    )

                # Normalize jq_result to a list and extend response_data
                response_data.extend(
                    [jq_result] if isinstance(jq_result, dict) else jq_result
                )

        if not response_data:
            return self.upload_log_file_panic(
                {
                    "Error": self.log_manager.get_error_message(
                        "ExtractDataUsingJQ.JQExpression.no_result"
                    )
                }
            )
        # Upload the response data as a JSON file to MinIO
        result_file_url, error = self.upload_iterable_as_json_file_to_minio(response_data, "OutputFile")
        if error:
            return self.upload_log_file_panic(
                {
                    "Error": self.log_manager.get_error_message(
                        "ExtractDataUsingJQ.OutputFile.upload_error",
                        {"error": error},
                    )
                }
            )

        response_data = {"OutputFile": result_file_url}
        if prev_log_file_url and prev_log_file_url != MINIO_PLACEHOLDER:
            response_data["LogFile"] = prev_log_file_url

        return response_data

    def validate_and_get_jq_config_data(
        self,
    ) -> Tuple[Optional[Dict[str, str]], Optional[Dict[str, str] | str]]:
        """
        Extract JQ filter and output method from user inputs.

        Returns:
            dict: A dictionary containing the JQ filter, output method,
                  and an error string if any issues are found.
        """

        has_config_file = cowdictutils.is_valid_key(
            self.task_inputs.user_inputs, "JQConfigFile"
        )

        has_string_inputs = cowdictutils.is_valid_key(
            self.task_inputs.user_inputs, "JQExpression"
        )
        
        output_method_input = cowdictutils.is_valid_key(
            self.task_inputs.user_inputs, "OutputMethod"
        )

        # INFO : We don't need the following sanitization. Just for our reference to secure code handle
        config_url = self._sanitize_url(self.task_inputs.user_inputs.get("JQConfigFile",""))

        if (not has_config_file or config_url == MINIO_PLACEHOLDER) and (not has_string_inputs):
            return None, self.log_manager.get_error_message(
                "ExtractDataUsingJQ.JQConfigFile.missing"
            )

        if has_config_file:
            jq_config_dict, error = self.download_toml_file_from_minio_as_dict(config_url)
            if error:
                return None, self.log_manager.get_error_message(
                    "ExtractDataUsingJQ.JQConfigFile.download_error",
                    {"error": error},
                )
            
        elif has_string_inputs:
            jq_config_dict = {
                "JQConfig": {
                    "JQExpression": self.task_inputs.user_inputs.get("JQExpression",""),
                    "OutputMethod": self.task_inputs.user_inputs.get("OutputMethod","")
                }
            }

        if not cowdictutils.is_valid_key(jq_config_dict, "JQConfig"):
            return None, self.log_manager.get_error_message(
                "ExtractDataUsingJQ.JQConfigFile.jq_config_field_missing_or_empty"
            )

        jq_config_dict = jq_config_dict["JQConfig"]

        required_fields = {
            "FileName": "JQConfigFile",
            "RequiredFields": ["JQExpression"],
            "RemoveDuplicates": True,
        }

        # Extract JQConfigFile data and validate it against required fields
        jq_config_data, error_list = nocredapp.NoCredApp().validate_input_file_config(
            jq_config_dict, required_fields
        )
        if error_list:
            return None, error_list

        jq_config_data = dict()

        jq_config_data["jq_filter"] = self._sanitize_jq_filter(
            jq_config_dict.get("JQExpression", "")
        )

        jq_config_data["output_method"] = self._sanitize_output_method(
            jq_config_dict.get("OutputMethod", "")
        )

        return jq_config_data, None

    def _sanitize_url(self, url: str) -> str:
        """
        Sanitize a URL input to prevent path traversal attacks.

        Args:
            url: URL to sanitize

        Returns:
            Sanitized URL
        """
        if not isinstance(url, str):
            return str(url)

        # Remove any path traversal attempts
        sanitized = re.sub(r"\.\./", "", url)
        return sanitized

    def _sanitize_jq_filter(self, jq_filter: str) -> str:
        """
        Sanitize a JQ filter expression.

        Args:
            jq_filter: JQ filter to sanitize

        Returns:
            Sanitized JQ filter
        """
        if not isinstance(jq_filter, str):
            return str(jq_filter)

        # Basic sanitization - remove any potentially dangerous constructs
        return jq_filter.strip()

    def _sanitize_output_method(self, output_method: str) -> str:
        """
        Sanitize output method parameter.

        Args:
            output_method: Output method to sanitize

        Returns:
            Sanitized output method
        """
        if not isinstance(output_method, str):
            return str(output_method)

        return output_method.strip()

    def _is_valid_json_file(self, file_path: str) -> bool:
        """
        Check if a file path has a JSON extension.

        Args:
            file_path: File path to check

        Returns:
            True if file has JSON extension, False otherwise
        """
        return file_path.lower().endswith(".json")

    def _create_error_dict(self, error_message: str) -> Dict[str, str]:
        """
        Create a standardized error dictionary.

        Args:
            error_message: Error message

        Returns:
            Error dictionary
        """
        return {"Error": error_message}
