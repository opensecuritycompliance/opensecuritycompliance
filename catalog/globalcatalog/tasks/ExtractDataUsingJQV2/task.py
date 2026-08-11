from typing import Tuple, Dict, Any, List, Optional, Union
from compliancecowcards.structs import cards
from compliancecowcards.utils import cowdictutils, cowdfutils, cowjqutils, cowutils, cowplaceholderutils
from applicationtypes.nocredapp import nocredapp
import pandas as pd
import ijson
import json
import os
from pathlib import Path
import re
import pathlib

MINIO_PLACEHOLDER = "<<MINIO_FILE_PATH>>"
logger = cards.Logger()

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
        self.proceed_if_error_exists =  cowutils.str_to_bool(value=self.task_inputs.user_inputs.get("ProceedIfErrorExists"),default_val=True)
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
                if custom_log_config_url and custom_log_config_url != MINIO_PLACEHOLDER
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
            return self.upload_log_file_panic({
                "Error": error
            })

        # Safely extract input values
        if cowdictutils.is_valid_key(self.task_inputs.user_inputs, "LogFile"):
            prev_log_file_url = self._sanitize_url(
                self.task_inputs.user_inputs["LogFile"]
            )

        # Get the number of chunks to process per iteration (default is 0)
        chunks_per_iteration = self.task_inputs.user_inputs.get("ChunksPerIteration", 0)

        # Determine whether to proceed if the log file exists
        
        self.proceed_if_log_exists  =  cowutils.str_to_bool(value=self.task_inputs.user_inputs.get("ProceedIfLogExists"),default_val=True)

        if (
            (not self.proceed_if_log_exists)
            and (prev_log_file_url != MINIO_PLACEHOLDER)
            and prev_log_file_url
        ):
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
            return self.upload_log_file_panic({
                "Error": error
            })
        
        # Detect whether streaming should be used
        use_streaming, error = self.should_use_streaming(data_file_url, jq_config_data)
        if error:
            return self.upload_log_file_panic({
                "Error": error
            })
        
        # Process with streaming
        if use_streaming:
            response_data, error = self.process_with_streaming(
                data_file_url, 
                jq_config_data
            )
            if error:
                return self.upload_log_file_panic({
                "Error": error
            })
            
        # Normal method (Non-Streaming)
        else:
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
                    return self.upload_log_file_panic({
                        "Error": error
                    })

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

        output_file_name = "OutputFile"
        if self.task_inputs.user_inputs.get("OutputFileName", ""):
            output_file_name = self.task_inputs.user_inputs.get("OutputFileName", "")
        # Upload the response data as a JSON file to MinIO
        result_file_url, error = self.upload_iterable_as_json_file_to_minio(
            response_data, output_file_name
        )
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
        Also extracts streaming configuration if present.

        Returns:
            dict: A dictionary containing the JQ filter, output method,
                  streaming settings, and an error string if any issues are found.
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
        config_url = self._sanitize_url(
            self.task_inputs.user_inputs.get("JQConfigFile", "")
        )

        if (not has_config_file or config_url == MINIO_PLACEHOLDER) and (
            not has_string_inputs
        ):
            return None, self.log_manager.get_error_message(
                "ExtractDataUsingJQ.JQConfigFile.missing"
            )

        if has_config_file:
            jq_config_dict, error = self.download_toml_file_from_minio_as_dict(
                config_url
            )
            if error:
                return None, self.log_manager.get_error_message(
                    "ExtractDataUsingJQ.JQConfigFile.download_error",
                    {"error": error},
                )

        elif has_string_inputs:
            jq_config_dict = {
                "JQConfig": {
                    "JQExpression": self.task_inputs.user_inputs.get(
                        "JQExpression", ""
                    ),
                    "OutputMethod": self.task_inputs.user_inputs.get(
                        "OutputMethod", ""
                    ),
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

        date_dict = {
            "fromdate": self.task_inputs.from_date.strftime("%d/%m/%Y %H:%M"),
            "todate": self.task_inputs.to_date.strftime("%d/%m/%Y %H:%M"),
        }

        jq_expression = jq_config_dict.get("JQExpression", "")
        jq_expression, _, error = cowplaceholderutils.replace_placeholders_using_jmespath(template=jq_expression,data=date_dict,placeholders=["fromdate","todate"])
        
        if error:
            return None, {"error": error}

        jq_config_dict["JQExpression"]=jq_expression

        jq_config_data["jq_filter"] = self._sanitize_jq_filter(
            jq_config_dict.get("JQExpression", "")
        )

        jq_config_data["output_method"] = self._sanitize_output_method(
            jq_config_dict.get("OutputMethod", "")
        )
        
        # Extract streaming configuration
        jq_config_data["enable_streaming"] = jq_config_dict.get("EnableStreaming", False)
        jq_config_data["streaming_threshold_mb"] = jq_config_dict.get("StreamingThresholdMB", 50)
        jq_config_data["streaming_jq_expression"] = jq_config_dict.get("StreamingJQExpression", "")

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
    
    def should_use_streaming(
        self, 
        file_url: str, 
        jq_config_data: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        """
        Determine if streaming should be used based on file size and configuration.
        
        Args:
            file_url: URL of the file to check
            jq_config_data: JQ configuration dictionary
            
        Returns:
            Tuple of (should_stream boolean, error message if any)
        """
        # Check if streaming is enabled in config
        enable_streaming = jq_config_data.get("enable_streaming", False)
        
        if not enable_streaming:
            return False, None
        
        # Check if streaming threshold is set
        threshold_mb = jq_config_data.get("streaming_threshold_mb", 50)
        
        # Check if streaming JQ expression is provided
        streaming_jq_expr = jq_config_data.get("streaming_jq_expression", "")
        if not streaming_jq_expr:
            return False, self.log_manager.get_error_message(
                "Streaming.missing_expression"
            )
        
        file_size_mb, error = self.get_minio_file_size_mb(file_url)
        
        if error:
            # If we can't get file size, fall back to non-streaming
            # Log warning but don't fail
            logger.log_data({"Info":"Warning: Could not determine file size, using non-streaming mode. Error: {error}"})
            return False, error
        
        # Use streaming if file exceeds threshold
        should_stream = file_size_mb > threshold_mb
        
        if should_stream:
            logger.log_data({"Info":"File size ({file_size_mb:.2f} MB) exceeds threshold ({threshold_mb} MB). Using streaming mode."})
        
        return should_stream, None

    def process_with_streaming(
        self,
        data_file_url: str,
        jq_config_data: Dict[str, Any],
    ) -> Tuple[Optional[List[Dict[str, Any]]], Optional[Dict[str, str]]]:
        """
        Process JSON file using streaming to handle large files efficiently.
        
        Args:  
            data_file_url: URL of the JSON file
            jq_config_data: JQ configuration with streaming settings
            
        Returns:
            Tuple of (processed data list, error dict if any)
        """
        try:
            # Download file as stream
            file_stream, error = self.download_file_from_minio_as_stream(data_file_url)
            if error:
                return None, {
                    "Error": self.log_manager.get_error_message(
                        "ExtractDataUsingJQ.InputFile.download_error",
                        {"error": error},
                    )
                }

            response_data = []
            streaming_jq_filter = jq_config_data.get("streaming_jq_expression", "")
            output_method = jq_config_data.get("output_method", "")

            parser = ijson.items(file_stream, "item")

            for item in parser:
                jq_result, error = cowjqutils.evaluate_jq_streaming_filter(
                    item,
                    streaming_jq_filter,
                    output_method
                )

                if error:
                    if not self.proceed_if_error_exists:
                        return None, error
                    continue

                if jq_result:
                    print(jq_result)
                    if isinstance(jq_result, dict):
                        response_data.append(jq_result)
                    elif isinstance(jq_result, list):
                        response_data.extend(jq_result)

                    if output_method == "FIRST":
                        break

            return response_data, None

        except (IOError, OSError, ConnectionError) as e:
            return None, {"error": f"I/O error while reading the file stream: {str(e)}"}

        except ijson.JSONError as e:
            return None, {"error": f"Invalid or malformed JSON in input file: {str(e)}"}

        except (ValueError, RuntimeError) as e:
            return None, {"error": f"Error while applying JQ filter: {str(e)}"}

        except Exception as e:
            return None, {"error": f"Unexpected error during streaming processing: {str(e)}"}

        finally:
            if "file_stream" in locals() and hasattr(file_stream, "close"):
                file_stream.close()