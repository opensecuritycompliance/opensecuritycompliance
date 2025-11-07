import pathlib
import re
from pathlib import Path
from typing import Any, List

import pandas as pd

from compliancecowcards.structs import cards
from compliancecowcards.utils import cowdfutils, cowdictutils, cowjqutils

MINIO_PLACEHOLDER = "<<MINIO_FILE_PATH>>"
logger = cards.Logger()

class Task(cards.AbstractTask):

    def __init__(self) -> None:
        """Initialize the Task with empty log data."""
        super().__init__()
        self.prev_log_data: List[dict[str, Any]] = []

    def execute(self) -> dict:
        user_inputs = self.task_inputs.user_inputs

        # Get required inputs
        output_method: str = user_inputs.get("OutputMethod")
        prev_log_file_url: str = ""
        input_file_url: str | None = user_inputs.get("InputFile")
        jq_filter: str | None = user_inputs.get("JQFilter")

        validate_flow: bool = user_inputs.get("ValidateFlow", False)
        jq_description: str | None = user_inputs.get("JQDescription")

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

        # Check for previous log file if specified
        if cowdictutils.is_valid_key(self.task_inputs.user_inputs, "LogFile"):
            prev_log_file_url = self._sanitize_url(
                self.task_inputs.user_inputs["LogFile"]
            )

        # Determine whether to proceed if the log file exists
        self.proceed_if_log_exists = self.task_inputs.user_inputs.get(
            "ProceedIfLogExists", True
        )
        self.proceed_if_log_exists = self.proceed_if_log_exists is None or self.proceed_if_log_exists

        if (not self.proceed_if_log_exists) and (prev_log_file_url != MINIO_PLACEHOLDER) and prev_log_file_url:
            return {"LogFile": prev_log_file_url}
        
        # Download previous log file if it exists
        if prev_log_file_url and prev_log_file_url != MINIO_PLACEHOLDER:
            self.prev_log_data, error = self.download_json_file_from_minio_as_dict(
                prev_log_file_url
            )
            if error:
                return self.upload_log_file_panic(
                    {
                        "Error": self.log_manager.get_error_message(
                            "FilterDataWithJQ.LogFile.download_error",
                            {"error": error},
                        )
                    }
                )

        # Validate required inputs
        if not self._is_valid_file_input(input_file_url):
            return self.upload_log_file_panic(
                {
                    "Error": self.log_manager.get_error_message(
                        "FilterDataWithJQ.InputFile.missing"
                    )
                }
            )

        if not self._is_valid_json_file(input_file_url):
            return self.upload_log_file_panic(
                {
                    "Error": self.log_manager.get_error_message(
                        "FilterDataWithJQ.InputFile.type_error",
                        {"extension": Path(input_file_url).suffix[1:]},
                    )
                }
            )

        if not jq_filter or not isinstance(jq_filter, str):
            return self.upload_log_file_panic(self.log_manager.get_error_message(
                "FilterDataWithJQ.JQConfig.missing"
                )
            )

        if output_method not in ["ALL", "FIRST", "all", "first"]:
            return self.upload_log_file_panic(
                {
                    "Error": self.log_manager.get_error_message(
                        "FilterDataWithJQ.OutputMethod.invalid",
                        {"output_method": output_method},
                    )
                }
            )

        # JQDescription is optional, but we can log it for debugging/documentation purposes
        if jq_description:
            self._log_jq_description(jq_description)

        # Download and parse input file
        input_data, error = self._download_json(str(input_file_url))
        if error:
            return self.upload_log_file_panic(
                {
                    "Error": self.log_manager.get_error_message(
                        "FilterDataWithJQ.InputFile.download_error",
                        {"error": error},
                    )
                }
            )

        if not input_data:
            return self.upload_log_file_panic(
                {
                    "Error": self.log_manager.get_error_message(
                        "FilterDataWithJQ.InputFile.empty"
                    )
                }
            )

        # Validate JQ filter syntax
        validation_error = self._validate_jq_filter(jq_filter, input_data)
        if validation_error:
            return {"Error": validation_error}

        if validate_flow:
            return {"ValidationStatus": "Input data validated successfully"}

        # Apply JQ filter to entire dataset
        try:
            # Use JQ to filter the data directly
            filtered_data, error = cowjqutils.evaluate_jq_filter(input_data, f"{jq_filter}", output_method)
            if error:
                return self.upload_log_file_panic(error)

            # # Get unfiltered data (records that don't match the filter)
            # unfiltered_data, error = cowjqutils.evaluate_jq_filter(input_data, f"{jq_filter} | not)")
            # if error:
            #     return {'Error': f'Error evaluating JQ filter for unmatched records: {error}'}

        except Exception as e:
            return {"Error": f"JQ filter processing error: {str(e)}"}

        # Prepare response
        response = {
            "FilteredFile": "",
            "ComplianceStatus_": "",
            "CompliancePCT_": 0,
        }

        # Upload filtered data if any
        response_data = []
        if filtered_data:
            if not isinstance(filtered_data, (dict, list)):
                    return self.upload_log_file_panic(
                        {
                            "Error": self.log_manager.get_error_message(
                                "FilterDataWithJQ.JQExpression.no_result",
                                {"jq_result_type": type(filtered_data).__name__},
                            )
                        }
                    )
            response_data.extend(
                    [filtered_data] if isinstance(filtered_data, dict) else filtered_data
                )

            filtered_file_url, error = self.upload_iterable_as_json_file_to_minio(
                data=response_data, file_name="FilteredFile"
            )

            if error:
                return self.upload_log_file_panic(
                    {
                        "Error": self.log_manager.get_error_message(
                            "FilterDataWithJQ.OutputFile.upload_error",
                            {"error": error},
                        )
                    }
                )

            response = {
                "FilteredFile": filtered_file_url,
                "ComplianceStatus_": "COMPLIANT",
                "CompliancePCT_": 100,
            }

        else:
            return self.upload_log_file_panic(
                {
                    "Error": self.log_manager.get_error_message(
                        "FilterDataWithJQ.JQExpression.no_result"
                    )
                }
            )

        # Upload unfiltered data if any
        # if unfiltered_data:
        #     unfiltered_file_url, error = self.upload_df_as_parquet_file_to_minio(
        #         df=pd.DataFrame(unfiltered_data),
        #         file_name='UnfilteredFile'
        #     )
        #     if error:
        #         return error

        #     response['UnfilteredFile'] = unfiltered_file_url

        return response

    def _validate_jq_filter(
        self, jq_filter: str, input_data: List[dict] | dict
    ) -> str | None:
        """Validate JQ filter syntax by testing with sample data"""
        try:
            # Test with sample data to validate syntax
            result, error = cowjqutils.evaluate_jq_filter(
                input_data, f"{jq_filter}")
            if error:
                return f"JQ filter syntax error: {error}"

            if result is None:
                return "JQ filter did not match any records"
            return None
        except Exception as e:
            return f"JQ filter validation error: {str(e)}"

    def _is_valid_file_input(self, input_url: str | Any = "") -> bool:
        """Check if file input URL is valid"""
        return bool(input_url and input_url != MINIO_PLACEHOLDER)

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

    def _is_valid_json_file(self, file_path: str) -> bool:
        """
        Check if a file path has a JSON extension.

        Args:
            file_path: File path to check

        Returns:
            True if file has JSON extension, False otherwise
        """
        return file_path.lower().endswith(".json")

    def _log_jq_description(self, description: str) -> None:
        """Log the JQ query description for documentation purposes"""
        logger.log_data({'JQ_Description': description})

    def _download_json(self, file_url: str):
        """Download JSON file from MinIO"""
        return self.download_json_file_from_minio_as_iterable(file_url)
