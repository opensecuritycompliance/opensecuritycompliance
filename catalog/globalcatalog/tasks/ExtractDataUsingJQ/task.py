from typing import Tuple, Dict, Any, List, Optional, Union
from compliancecowcards.structs import cards
from compliancecowcards.utils import cowdictutils, cowdfutils
import pandas as pd
import jq
import json
from pathlib import Path
import re

# Initialize a Logger instance to log data
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
        prev_log_file_url: str = ''
        data_file_url: str = ''
        
        # Safely extract input values
        if cowdictutils.is_valid_key(self.task_inputs.user_inputs, 'LogFile'):
            prev_log_file_url = self._sanitize_url(self.task_inputs.user_inputs['LogFile'])
        
        if cowdictutils.is_valid_key(self.task_inputs.user_inputs, 'InputFile'):
            data_file_url = self._sanitize_url(self.task_inputs.user_inputs['InputFile'])

        # Handle cases where files are missing or only log file is provided
        if prev_log_file_url and not data_file_url:
            return {'LogFile': prev_log_file_url}

        # Download previous log file if it exists
        if prev_log_file_url and data_file_url:
            self.prev_log_data, error = self.download_json_file_from_minio_as_dict(prev_log_file_url)
            if error:
                return self._create_error_dict(f"Error downloading log file: {error}")

        # Validate input file
            
        chunks_per_iteration = self.task_inputs.user_inputs.get('ChunksPerIteration', 0)

        if not data_file_url:
            return self.upload_log_file_panic('InputFile is missing in user inputs.')
        
        if not self._is_valid_json_file(data_file_url):
            return self.upload_log_file_panic(
                f"InputFile must be a JSON file, got file with '{Path(data_file_url).suffix[1:]}' extension instead"
            )

        # Get JQ filter and output method
        jq_filter, output_method, error = self.get_jq_filter_and_output_method()
        if error:
            return self.upload_log_file_panic(error)

        # Download and process input data
        data_list, error = self.download_json_file_from_minio_as_dict(data_file_url)
        if error:
            return self.upload_log_file_panic(f'Error while downloading InputFile :: {error}')

        if not data_list:
            return self.upload_log_file_panic('InputFile is empty, please check.')

        total_items = 1 # Default to 1 if not a list
        if isinstance(data_list, list):
            total_items = len(data_list)

        if not chunks_per_iteration:
            chunks_per_iteration = total_items
            
        response_data = []
        for start in range(0, total_items, chunks_per_iteration):
            
            datachunk = data_list
            if  isinstance(data_list, list):
                end = min(start + chunks_per_iteration, total_items)
                datachunk = data_list[start:end] 
            
            jq_result, error = self.evaluate_jq_filter(datachunk, jq_filter, output_method)
            if error:
                return self.upload_log_file_panic(error)

            if not jq_result:
                return self.upload_log_file_panic('JQExpression returned no results.')

        # Validate result type
            if not isinstance(jq_result, (dict, list)):
                return self.upload_log_file_panic(f"JQExpression must return an object or an array, got '{type(jq_result).__name__}' instead")
                        
            if isinstance(jq_result, dict):
                response_data.extend([jq_result])
            elif isinstance(jq_result, list):
                response_data.extend(jq_result)
                
        result_file_url, error = self.upload_df_as_json_file_to_minio(
            df = pd.DataFrame(response_data),
            file_name = 'OutputFile'
        )
        if error:
            return self._create_error_dict(f"Error uploading result: {error}")

        return {
            "OutputFile": result_file_url,
            "LogFile": prev_log_file_url
        }

    def upload_log_file(self, error_data: Union[Dict[str, Any], List[Dict[str, Any]]]) -> Tuple[Optional[str], Optional[Dict[str, str]]]:
        """
        Upload error data to a log file.
        
        Args:
            error_data: Dictionary or list of dictionaries containing error information
            
        Returns:
            Tuple containing the file URL or None, and an error dictionary or None
        """
        # Normalize error_data to list
        if not isinstance(error_data, list):
            error_data = [error_data]

        # Add new error data to existing log data
        self.prev_log_data.extend(error_data)

        # Upload log file
        file_url, error = self.upload_df_as_json_file_to_minio(
            df=pd.DataFrame(self.prev_log_data),
            file_name='LogFile'
        )
        if error:
            return None, {'error': f"Error while uploading LogFile :: {error}"}
        
        return file_url, None

    def upload_log_file_panic(self, error_data: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Upload error data and return a response for error cases.
        
        Args:
            error_data: Error message or dictionary
            
        Returns:
            Dictionary with LogFile URL or error information
        """
        # Convert string errors to dictionary
        if isinstance(error_data, str):
            error_data = {'Error': error_data}
            
        # Upload error to log file
        file_url, error = self.upload_log_file(error_data)
        if error:
            return error
            
        return {'LogFile': file_url}

    def get_jq_filter_and_output_method(self) -> Tuple[str, str, str]:
        """
        Extract JQ filter and output method from user inputs.
        
        Returns:
            Tuple containing JQ filter, output method, and error string (if any)
        """
        has_config_file = cowdictutils.is_valid_key(self.task_inputs.user_inputs, 'JQConfig')
        has_string_inputs = cowdictutils.is_valid_key(self.task_inputs.user_inputs, 'JQExpression')
        
        # Validate inputs - can't have both config file and direct expression
        if has_config_file and has_string_inputs:
            return '', '', "Found values for both 'JQConfig' and 'JQExpression'. You must give values to either of these inputs only. Please check the 'ExtractDataUsingJQ' task readme for more info."

        # Handle config file case
        if has_config_file:
            # INFO : We don't need the following sanitization. Just for our reference to secure code handle
            config_url = self._sanitize_url(self.task_inputs.user_inputs['JQConfig'])
            jq_config_dict, error = self.download_toml_file_from_minio_as_dict(config_url)
            if error:
                return '', '', f"Error occurred while downloading JQConfig file :: {error}"

            if not cowdictutils.is_valid_key(jq_config_dict, 'JQConfig'):
                return '', '', "'JQConfig' table is missing in the provided JQConfig file. Please refer to the JQConfig-sample.toml file."

            jq_config_dict = jq_config_dict['JQConfig']
            if not cowdictutils.is_valid_key(jq_config_dict, 'JQExpression'):
                return '', '', "'JQExpression' field is missing in the provided JQConfig file. Please refer to the JQConfig-sample.toml file."

            jq_filter = self._sanitize_jq_filter(jq_config_dict['JQExpression'])
            output_method = self._sanitize_output_method(jq_config_dict.get('OutputMethod', ''))

            return jq_filter, output_method, ''

        # Handle direct expression input
        if has_string_inputs:
            jq_filter = self._sanitize_jq_filter(self.task_inputs.user_inputs['JQExpression'])
            output_method = self._sanitize_output_method(self.task_inputs.user_inputs.get('OutputMethod', ''))


            return jq_filter, output_method, ''

        # No valid inputs found
        return '', '', "The following user inputs are missing: 'JQConfig', 'JQExpression'. You must give at least one of these inputs. Please check the 'ExtractDataUsingJQ' task readme for more info."

    def evaluate_jq_filter(self, input_data: Any, jq_filter: str, output_method: str = "FIRST") -> Tuple[Any, str]:
        """
        Apply JQ filter to input data.
        
        Args:
            input_data: Input data to process
            jq_filter: JQ filter expression
            output_method: Method to determine output (ALL or FIRST)
            
        Returns:
            Tuple containing result and error string (if any)
        """
        try:
            # Validate filter before execution
            try:
                self._validate_jq_filter(jq_filter)
            except ValueError as e:
                return None, str(e)
            
            # Compile and apply filter
            compiled_filter = jq.compile(jq_filter).input(input_data)
            output_method = output_method.lower()

            # Validate output method
            valid_methods = ['all', 'first', '']
            if output_method not in valid_methods:
                return None, f"The provided OutputMethod: '{output_method}' is invalid. Expected one of: {', '.join(valid_methods)}"

            # Get results based on output method
            jq_result = compiled_filter.all() if output_method == 'all' else compiled_filter.first()

            return jq_result, ''
        except ValueError as e:
            # Log detailed error information
            error_message = f'Error while executing JQExpression :: {str(e)}'
            logger.log_data({'Error': error_message})
            return None, 'Got an error while executing JQExpression, ensure whether the JQExpression that you entered is correct. Please check the RuleLogs for more information.'
        except Exception as e:
            # Catch broader exceptions for more robust error handling
            error_message = f'Unexpected error while executing JQExpression :: {str(e)}'
            logger.log_data({'Error': error_message})
            return None, 'An unexpected error occurred while executing JQExpression. Please check the RuleLogs for more information.'

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
        sanitized = re.sub(r'\.\./', '', url)
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

    def _validate_jq_filter(self, jq_filter: str) -> None:
        """
        Validate a JQ filter for security concerns.
        
        Args:
            jq_filter: JQ filter to validate
            
        Raises:
            ValueError: If filter contains potentially dangerous patterns
        """
        # Validate filter to catch potential security issues
        # This is a basic check - more comprehensive validation might be needed
        dangerous_patterns = [
            r'`.*`',  # Backtick execution
            r'system\(',  # System calls
            r'exec\(',  # Exec calls
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, jq_filter):
                raise ValueError(f"JQ filter contains potentially dangerous pattern: {pattern}")

    def _is_valid_json_file(self, file_path: str) -> bool:
        """
        Check if a file path has a JSON extension.
        
        Args:
            file_path: File path to check
            
        Returns:
            True if file has JSON extension, False otherwise
        """
        return file_path.lower().endswith('.json')

    def _create_error_dict(self, error_message: str) -> Dict[str, str]:
        """
        Create a standardized error dictionary.
        
        Args:
            error_message: Error message
            
        Returns:
            Error dictionary
        """
        return {'Error': error_message}