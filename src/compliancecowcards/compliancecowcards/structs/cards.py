from datetime import datetime
from typing import Optional, Tuple, List, Any, Callable
from abc import abstractmethod
from compliancecowcards.utils import cowfilestoreutils, cowstorageserviceutils, cowdfutils, cowdictutils
from compliancecowcards.structs import cowvo, cowsynthesizerservice_pb2
import pandas as pd
import uuid
import os
import minio
import json
import tomli
import tomli_w
import re
import pathlib
from posixpath import join as urljoin
from typing_extensions import deprecated
import io
import pyarrow
import jmespath

# We'll give the compliancecow data library to user to connect with the endpoints in
# compliancecow and continube(Need to discuss)


class AbstractTask(object):
    """ 
        This class should be extend by the user to implement the task
        No Need to implement the common methods which is required by task like getappgroup based on tag.
        They can get it from our common library
    """
    task_inputs: cowvo.TaskInputs  # TaskInputs -  It'll contains all the inputs for task like Go
    minio_client: minio.Minio
    _log_file_name: str
    prev_log_data: List[dict[str, Any]]

    def __init__(self, task_inputs: cowvo.TaskInputs = None, minio_client: minio.Minio = None) -> None:
        self.task_inputs = task_inputs
        self.minio_client = minio_client
        self._log_file_name = 'LogFile'
        self.prev_log_data = []
        pass

    def upload_file_to_minio(self, file_content=None, file_name: str = None, content_type: str = None) -> Tuple[str, dict]:
        """
        Uploads a file to a MinIO object storage server.

        :param file_content: (bytes|pd.DataFrame()|dict) The content of the file to be uploaded.
        :param file_name: (str) The name of the file in MinIO (including path if needed).
        :param content_type: (str) The MIME type of the file content (e.g., 'application/pdf').

        :return: A string and a dictionary. The string is a URL or an identifier of the uploaded file.
                The dictionary contains additional information about the uploaded file.
        """

        minio_client = self.minio_client
        if minio_client is None:
            minio_client, error = cowfilestoreutils.get_minio_client_with_inputs(
                self.task_inputs)
            if error and bool(error):
                return None, error
            # need to create minio client with minio credentials with app config - default "minio" tag

        object_name = file_name

        file_name = cowfilestoreutils.add_extension_if_missing(
            file_name, content_type)

        _, absolute_file_path, error = cowfilestoreutils.upload_file(
            self.task_inputs, minio_client=minio_client, object_name=object_name,
            file_name=file_name, file_content=file_content, content_type=content_type)

        return absolute_file_path, error
    
    def convert_and_upload_df_to_minio(
            self, 
            df: pd.DataFrame = None,
            convertion_func = None,
            file_name: str = None,
            extension: str = None,
            content_type: str = None
        ) -> Tuple[str, dict]:

        """
        Uploads the result after applying the convertion_func function on a DataFrame to MinIO.
        
        ### Parameters:
        - df (pd.DataFrame): The DataFrame to upload.
        - convertion_func (function): A function that takes pd.DataFrame as argument, and returns file_content and error information if any, as a tuple.
                                      This function will be applied to the 'df'.
        - file_name (str): The name of the file to be uploaded.
        - extension (str): The extension of the file to be uploaded.
        - content_type (str): The MIME type of the file content (e.g., 'application/pdf').

        ### Returns:
        - str: The absolute file path of the uploaded file.
        - dict: Dictionary containing error information if any, otherwise None.
        """

        if not file_name:
            return None, {"error": "File name cannot be empty. Please provide a valid file name for uploading."}
            
        if cowdfutils.is_df_empty(df):
            return None, {"error": "DataFrame is empty. Please ensure the DataFrame contains data before uploading."}
        
        file_name, _ = os.path.splitext(file_name)
        
        try:
            file_content, error = convertion_func(df)
            if error: return None, error
        except (ValueError, TypeError) as e:
            return None, {"error": str(e)}

        return self.upload_file_to_minio(
            file_name=f'{file_name}-{str(uuid.uuid4())}.{extension}',
            file_content=file_content,
            content_type=content_type)
    
    def upload_df_as_parquet_file_to_minio(self, df: pd.DataFrame = None, file_name: str = None) -> Tuple[str, dict]:
        
        """
        Uploads a DataFrame as a Parquet file to MinIO.
        ### Parameters:
        - df (pd.DataFrame): The DataFrame to upload.
        - file_name (str): The name of the file to be uploaded.
        ### Returns:
        - str: The absolute file path of the uploaded file.
        - dict: Dictionary containing error information if any, otherwise None.
        """
        
        return self.convert_and_upload_df_to_minio(
            df=df,
            convertion_func=cowdfutils.df_to_parquet,
            file_name=file_name,
            extension="parquet",
            content_type="application/parquet"
        )
    
    def upload_df_as_json_file_to_minio(self, df: pd.DataFrame = None, file_name: str = None) -> Tuple[str, dict]:
        
        """
        Uploads a DataFrame as a JSON file to MinIO.
        ### Parameters:
        - df (pd.DataFrame): The DataFrame to upload.
        - file_name (str): The name of the file to be uploaded.
        ### Returns:
        - str: The absolute file path of the uploaded file.
        - dict: Dictionary containing error information if any, otherwise None.
        """

        return self.convert_and_upload_df_to_minio(
            df=df,
            convertion_func=cowdfutils.df_to_json,
            file_name=file_name,
            extension="json",
            content_type="application/json"
        )
    
    def upload_df_as_csv_file_to_minio(self, df: pd.DataFrame = None, file_name: str = None) -> Tuple[str, dict]:
        
        """
        Uploads a DataFrame as a CSV file to MinIO.
        ### Parameters:
        - df (pd.DataFrame): The DataFrame to upload.
        - file_name (str): The name of the file to be uploaded.
        ### Returns:
        - str: The absolute file path of the uploaded file.
        - dict: Dictionary containing error information if any, otherwise None.
        """

        return self.convert_and_upload_df_to_minio(
            df=df,
            convertion_func=cowdfutils.df_to_csv,
            file_name=file_name,
            extension="csv",
            content_type="application/csv"
        )
    
    def upload_df_as_ndjson_file_to_minio(self, df: pd.DataFrame = None, file_name: str = None) -> Tuple[str, dict]:
        
        """
        Uploads a DataFrame as a NDJSON file to MinIO.
        ### Parameters:
        - df (pd.DataFrame): The DataFrame to upload.
        - file_name (str): The name of the file to be uploaded.
        ### Returns:
        - str: The absolute file path of the uploaded file.
        - dict: Dictionary containing error information if any, otherwise None.
        """

        return self.convert_and_upload_df_to_minio(
            df=df,
            convertion_func=cowdfutils.df_to_ndjson,
            file_name=file_name,
            extension="ndjson",
            content_type="application/ndjson"
        )

    def upload_iterable_as_json_file_to_minio(
            self, 
            data: List[dict] | dict = None,
            file_name: str = None
        ) -> Tuple[str, dict]:

        """
        Uploads a Dict or a List[dict] as a JSON file to MinIO.
        ### Parameters:
        - data (Dict or List[dict]): The dictionary or list to upload.
        - file_name (str): The name of the file to be uploaded.
        ### Returns:
        - str: The absolute file path of the uploaded file.
        - dict: Dictionary containing error information if any, otherwise None.
        """

        if not file_name:
            return None, {"error": "File name cannot be empty. Please provide a valid file name for uploading."}
        
        if not isinstance(data, (list, dict)):
            return None, {'error': f"Data must be a dictionary or list of dictionaries, got '{type(data).__name__}' instead"}
        
        file_name, _ = os.path.splitext(file_name)
        
        try:
            file_content = json.dumps(data)
        except TypeError as e:
            return None, {'error': f'Please check the data, and ensure that all fields are serializable :: {str(e)}'}

        return self.upload_file_to_minio(
            file_name=f'{file_name}-{str(uuid.uuid4())}.json',
            file_content=file_content,
            content_type="application/json")
    
    def upload_dict_as_toml_file_to_minio(
            self, 
            data: dict = None,
            file_name: str = None
        ) -> Tuple[str, dict]:

        """
        Uploads a dict as a TOML file to MinIO.
        ### Parameters:
        - data (dict): The dictionary to upload.
        - file_name (str): The name of the file to be uploaded.
        ### Returns:
        - str: The absolute file path of the uploaded file.
        - dict: Dictionary containing error information if any, otherwise None.
        """

        if not file_name:
            return None, {"error": "File name cannot be empty. Please provide a valid file name for uploading."}
        
        if not isinstance(data, dict):
            return None, {'error': f"Data must be a dictionary, got '{type(data).__name__}' instead"}
        
        file_name, _ = os.path.splitext(file_name)
        
        try:
            file_content = tomli_w.dumps(data)
        except TypeError as e:
            return None, {'error': f'Please check the data, and ensure that all fields are serializable :: {str(e)}'}

        return self.upload_file_to_minio(
            file_name=f'{file_name}-{str(uuid.uuid4())}.toml',
            file_content=file_content,
            content_type="application/toml")
        
    def set_log_file_name(self, log_file_name: str) -> None:
        
        """
        Sets default value for the `log_file_name` parameter of `upload_log_file_to_minio` and `upload_log_file_panic` methods. The value: 'LogFile' is set to this variable while initialization. Do NOT modify this variable, unless you explicitly want to change LogFile's name, such as in an action/workflow task.
        ### Parameters:
        - log_file_name (str): The name of the log file to be uploaded, when calling any one of `upload_log_file_to_minio` or `upload_log_file_panic` methods
        ### Returns:
        - None
        
        #### Note for `upload_log_file_to_minio` and `upload_log_file_panic` methods:
        - When `log_file_name` is "Error":
            - The function will stop execution and return an error
            - The return type will be `dict[str, str]`
            - Any value in `self.prev_log_data` will be ignored completely
            - Example return might look like: `{"Error": "stringified value of `error_data`"}`
        - When `log_file_name` is "Errors":
            - The function will also stop execution and return an error
            - The return type will be `dict[str, list[dict]]`
            - Example return might look like: `{"Errors": [<value of 'error_data', appended to 'self.prev_log_data'>]}`
        - You can use any of the above methods to stop task/rule execution.
        """
        
        if log_file_name:
            self._log_file_name = log_file_name
            
    def set_prev_log_data(self, existing_log_data: list[dict[str, Any]]):
        """
        Sets default value for existing error data. In `upload_log_file_to_minio` and `upload_log_file_panic` methods, `error_data`will be appended to `prev_log_data` parameter value before uploading to MinIO.
        ### Parameters:
        - prev_error_data (List[dict]): Existing error data from previous task.
        ### Returns:
        - None
        """
        
        self.prev_log_data = existing_log_data

    def upload_log_file_to_minio(
        self,
        error_data: List[dict] | dict,
        logger: Optional['Logger'] = None,
        log_file_name: Optional[str] = ''
    ) -> tuple[str, dict | None]:

        """
        Uploads Dict or a List[dict] as LogFile to MinIO.
        ### Parameters:
        - error_data (List[dict] | dict): The dictionary or list containing error data.
        - logger (Logger): Logger instance for logging errors (Default: `None`)
        - log_file_name (str): The name of the file to be uploaded (Default: `'LogFile'`). Do NOT assign this parameter, unless you explicitly want to change LogFile's name, such as in an action/workflow task.
        ### Returns:
        - str: The absolute file path of the uploaded LogFile.
        - dict: Dictionary containing error information if any, otherwise None.
        
        ### Note:
        - When `log_file_name` is "Error":
            - The function will stop execution and return an error
            - The return type will be `dict[str, str]`
            - Any value in `self.prev_log_data` will be ignored completely
            - Example return might look like: `{"Error": "stringified value of `error_data`"}`
        - When `log_file_name` is "Errors":
            - The function will also stop execution and return an error
            - The return type will be `dict[str, list[dict]]`
            - Example return might look like: `{"Errors": [<value of 'error_data', appended to 'self.prev_log_data'>]}`
        - You can use any of the above methods to stop task/rule execution.
        """
        
        if not log_file_name:
            log_file_name = self._log_file_name
        
        if log_file_name == 'Error':
            return '', {'Error': str(error_data)}
            
        if not isinstance(error_data, list):
            error_data = [error_data]
            
        self.prev_log_data.extend(error_data)
            
        if log_file_name == 'Errors':
            return '', {'Errors': self.prev_log_data}

        file_url, error = self.upload_iterable_as_json_file_to_minio(
            data=self.prev_log_data,
            file_name=log_file_name
        )
        if error:
            return '', {'error': f"Error while uploading {log_file_name} :: {error}"}
            
        if logger:
            logger.log_data({"event": "errors_logged", "errors": json.dumps(error_data)})  # Optional logging
        
        return file_url, None
    
    def upload_log_file_panic(
        self,
        error_data: List[dict] | dict | str,
        logger: Optional['Logger'] = None,
        log_file_name: Optional[str] = ''
    ) -> dict:

        """
        Uploads Dict or a List[dict] as LogFile to MinIO.
        ### Parameters:
        - error_data (List[dict] | dict | str): The dictionary, list or string containing error data.
        - logger (Logger): Logger instance for logging errors (Default: `None`)
        - log_file_name (str): The name of the file to be uploaded (Default: `'LogFile'`). Do NOT assign this parameter, unless you explicitly want to change LogFile's name, such as in an action/workflow task.
        ### Returns:
        - dict: Dictionary containing the uploaded LogFile's URL, in a ready to exit task format.
        
        ### Note:
        - When `log_file_name` is "Error":
            - The function will stop execution and return an error
            - The return type will be `dict[str, str]`
            - Any value in `self.prev_log_data` will be ignored completely
            - Example return might look like: `{"Error": "stringified value of `error_data`"}`
        - When `log_file_name` is "Errors":
            - The function will also stop execution and return an error
            - The return type will be `dict[str, list[dict]]`
            - Example return might look like: `{"Errors": [<value of 'error_data', appended to 'self.prev_log_data'>]}`
        - You can use any of the above methods to stop task/rule execution.

        ### Sample Usage:
        ```python
        class Task(cards.AbstractTask):

            def execute(self) -> dict:

                error = self.check_inputs(["InputField1", "InputField2"])
                if error:
                    return self.upload_log_file_panic(error)

                # Other task code
        ```
        """
        
        log_file_name = log_file_name if log_file_name else self._log_file_name
        
        if log_file_name == 'Error':
            return {'Error': str(error_data)}

        if isinstance(error_data, str):
            error_data = [{'Error': error_data}]
            
        file_url, error = self.upload_log_file_to_minio(error_data, logger, log_file_name)
        if error:
            return error
        return { log_file_name: file_url }
        
    def download_parquet_file_from_minio_as_df(self, file_url=None) -> Tuple[pd.DataFrame, dict]:
        
        """
        Downloads a Parquet file from MinIO as a DataFrame.
        ### Parameters:
        - file_url (str): The URL of the Parquet file in MinIO.
        ### Returns:
        - pd.DataFrame: The DataFrame created from the downloaded Parquet file.
        - dict: Dictionary containing error information if any, otherwise None.
        """

        parquet_bytes, error = self.download_file_from_minio(
            file_url=file_url)
        if error:
            return None, error
        
        try:
            buffer = io.BytesIO(parquet_bytes)
            df = pd.read_parquet(buffer, engine='fastparquet')
        except TypeError:
            buffer = io.BytesIO(parquet_bytes)
            df = pd.read_parquet(buffer)
        except (pyarrow.ArrowInvalid, OSError):
            return None, { "error": "Invalid file format: The provided file does not adhere to any recognized format." }
        
        return df, None
    
    def download_json_file_from_minio_as_dict(self, file_url=None) -> Tuple[dict, dict]:
        
        """
        Downloads a JSON file from MinIO as a Python Dictionary.
        ### Parameters:
        - file_url (str): The URL of the JSON file in MinIO.
        ### Returns:
        - dict: Dictionary containing JSON file content.
        - dict: Dictionary containing error information if any, otherwise None.
        """

        json_bytes, error = self.download_file_from_minio(
            file_url=file_url)
        if error:
            return None, error
        
        try:
            json_string = json_bytes.decode("utf-8")
            json_data = json.loads(json_string)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None, { "error": "Invalid file format: The provided file does not adhere to any recognized format." }
        
        return json_data, None
    
    def download_json_file_from_minio_as_iterable(self, file_url=None) -> Tuple[List[dict] | dict, dict]:
        """
        Downloads a JSON file from MinIO as a Python Iterable.
        ### Parameters:
        - file_url (str): The URL of the JSON file in MinIO.
        ### Returns:
        - List[dict] | dict: List or Dictionary containing the JSON file content.
        - dict             : Dictionary containing error information if any, otherwise None.
        """

        return self.download_json_file_from_minio_as_dict(file_url)
    
    def download_toml_file_from_minio_as_dict(self, file_url=None) -> Tuple[dict, dict]:
        
        """
        Downloads a TOML file from MinIO as a Python Dictionary.
        ### Parameters:
        - file_url (str): The URL of the TOML file in MinIO.
        ### Returns:
        - dict: Dictionary containing JSON file content.
        - dict: Dictionary containing error information if any, otherwise None.
        """

        toml_bytes, error = self.download_file_from_minio(
            file_url=file_url)
        if error:
            return None, error
        
        try:
            toml_string = toml_bytes.decode("utf-8")
            toml_data = tomli.loads(toml_string)
        except (UnicodeDecodeError, tomli.TOMLDecodeError):
            return None, { "error": "Invalid file format: The provided file does not adhere to any recognized format." }
        
        return toml_data, None
    
    def download_json_file_from_minio_as_df(self, file_url=None) -> Tuple[pd.DataFrame, dict]:

        """
        Downloads a JSON file from MinIO as a DataFrame.
        ### Parameters:
        - file_url (str): The URL of the JSON file in MinIO.
        ### Returns:
        - pd.DataFrame: The DataFrame created from the downloaded JSON file.
        - dict: Dictionary containing error information if any, otherwise None.
        """

        json_dict, error = self.download_json_file_from_minio_as_dict(file_url)
        if error:
            return None, error
        
        if isinstance(json_dict, dict):
            json_dict = [json_dict]
        
        try:
            df = pd.DataFrame(json_dict)
        except AttributeError:
            return pd.DataFrame(), {'error': 'Invalid data structure. Ensure the input is a properly formatted list of objects.'}

        return df, None

    def download_ndjson_file_from_minio_as_df(self, file_url=None) -> Tuple[pd.DataFrame, dict]:

        """
        Downloads a NDJSON file from MinIO as a DataFrame.
        ### Parameters:
        - file_url (str): The URL of the NDJSON file in MinIO.
        ### Returns:
        - pd.DataFrame: The DataFrame created from the downloaded NDJSON file.
        - dict: Dictionary containing error information if any, otherwise None.
        """

        file_bytes, error = self.download_file_from_minio(file_url)
        if error:
            return None, error
        
        try:
            data = io.StringIO(file_bytes.decode('utf-8'))
            df = pd.read_json(
                data,
                lines=True,
                keep_default_dates=False,
                dtype=False
            )
        except ValueError:
            return None, { "error": "Invalid file format: The provided file does not adhere to any recognized format." }
        
        return df, None
    
    def download_csv_file_from_minio_as_df(self, file_url=None) -> Tuple[pd.DataFrame, dict]:

        """
        Downloads a CSV file from MinIO as a DataFrame.
        ### Parameters:
        - file_url (str): The URL of the CSV file in MinIO.
        ### Returns:
        - pd.DataFrame: The DataFrame created from the downloaded CSV file.
        - dict: Dictionary containing error information if any, otherwise None.
        """

        file_bytes, error = self.download_file_from_minio(file_url)
        if error:
            return None, error
        
        try:
            data = io.StringIO(file_bytes.decode('utf-8'))
            df = pd.read_csv(data)
        except (pd.errors.ParserError, UnicodeDecodeError):
            return None, { "error": "Invalid file format: The provided file does not adhere to any recognized format." }
        
        return df, None

    def download_file_from_minio_as_df(self, file_url: str) -> tuple[pd.DataFrame, dict | None]:
        """
        Downloads a file from MinIO as a DataFrame. Supported file formats: JSON, NDJSON, CSV, PARQUET
        ### Parameters:
        - file_url (str): The URL of the file in MinIO.
        ### Returns:
        - pd.DataFrame: The DataFrame created from the downloaded file.
        - dict: Dictionary containing error information if any, otherwise None.
        """

        file_download_func = {
            'json': self.download_json_file_from_minio_as_df,
            'ndjson': self.download_ndjson_file_from_minio_as_df,
            'csv': self.download_csv_file_from_minio_as_df,
            'parquet': self.download_parquet_file_from_minio_as_df
        }

        file_df = pd.DataFrame()

        file_extension = (pathlib.Path(file_url).suffix).lstrip('.')
        if file_extension not in file_download_func:
            return file_df, {"error": f"The provided file is of an unsupported file type :: Expected a file with one of '{', '.join(file_download_func.keys())}' extensions, got '{file_extension}' instead."}

        file_df, error = file_download_func[file_extension](file_url)
        if error:
            return file_df, error
        if file_df.empty:
            return file_df, {"error": f"Provided file has no content, please check."}

        return file_df, None

    def download_file_from_minio(self, file_url=None) -> Tuple[bytes, dict]:

        if file_url.startswith("file://"):
            file_name = os.path.basename(file_url)
            userdata_file_path = os.path.join(os.getenv("LOCAL_FOLDER"), file_name)
            if os.path.exists(userdata_file_path):
                with open(userdata_file_path, 'rb') as file:
                    file_content = file.read()
                    return file_content, None
            else:
                return None, {"error": "cannot download the file"}
            
        """
        Downloads a file from a MinIO object storage server.

        :param file_url: (str) The URL or identifier of the file to be downloaded from MinIO.

        :return: A bytes object and a dictionary. The bytes object contains the content of the downloaded file.
                The dictionary provides additional information about the downloaded file.
        """

        _, resp_file_bytes, error = cowfilestoreutils.download_file(task_inputs=self.task_inputs,
                                                                    object_name=file_url)
        return resp_file_bytes, error

    @deprecated("use upload_file_to_minio")
    def upload_file(self, file_name=None, file_content=None, minio_client=None, object_name=None, bucket_name=None, content_type=None):
        """
        Attributes
        ----------
        file_name : str
            name of the file name to be upload
        file_content : bytes
            file content
        minio_client : minio.Minio
            you can pass minio client(based on the persistence u chose).
        bucket_name : str

        """
        if minio_client is None:
            minio_client = self.minio_client
            if minio_client is None:
                minio_client, error = cowfilestoreutils.get_minio_client_with_inputs(
                    self.task_inputs)
                if error and bool(error):
                    return None, None, error
            # need to create minio client with minio credentials with app config - default "minio" tag

        if object_name is None:
            object_name = file_name
        object_name = object_name

        return cowfilestoreutils.upload_file(
            self.task_inputs, minio_client=minio_client, bucket_name=bucket_name, object_name=object_name,
            file_name=file_name, file_content=file_content, content_type=content_type)

    @deprecated("use download_file_from_minio")
    def download_file(self, minio_client=None, bucket_name=None, file_name=None):
        if minio_client is None:
            pass

        return cowfilestoreutils.download_file(
            self.task_inputs, minio_client, bucket_name, file_name)

    @abstractmethod
    def execute() -> dict:
        """
            This method need to be override by the user. Here it'll have task_inputs.
            The python tasks won't be having task specific file names. 
            And we'll have some common utilities in the library which can be used by 
            both clients and our developers. It'll return a dictionary(like golang task)

        """
        pass

    def check_inputs(self, required_user_inputs: List[str]) -> str:

        """
        Checks whether the provided string fields are available in the task inputs
        ### Parameters:
        - required_user_inputs (List[str]): The list of required user input field names that have to be validated.
        ### Returns:
        - str: String containing the missing inputs data, if any.
        """

        if self.task_inputs is None:
            return 'Task inputs are missing'
        user_object = self.task_inputs.user_object
        if (
            user_object is None
            or user_object.app is None
            or user_object.app.application_url is None
            or user_object.app.user_defined_credentials is None
        ):
            return 'User defined credentials are missing"'
        
        if self.task_inputs.user_inputs is None:
            return 'User inputs are missing'
        
        missing_inputs = []
        for input in required_user_inputs:
            if not cowdictutils.is_valid_key(self.task_inputs.user_inputs, input) or self.task_inputs.user_inputs[input] == '<<MINIO_FILE_PATH>>':
                missing_inputs.append(input)

        return "The following inputs: " + ", ".join(missing_inputs) + " is/are empty" if missing_inputs else ""

class AbstractSynthesizer(object):
    """ 
        The user should extend their class from this, to implement the synthesizer.
        They'll get the inputs specific to synthesizer cards.
        We'll have common libraries to use within synthesizers
    """

    synthesizer_inputs: cowsynthesizerservice_pb2.SynthesizerV2

    file_outputs: list
    auth_token: str
    header: dict

    def __init__(self, synthesizer_inputs=None, file_outputs=None, auth_token=None, header=None) -> None:
        self.synthesizer_inputs = synthesizer_inputs
        self.auth_token = auth_token
        self.header = header
        if self.auth_token is None and self.synthesizer_inputs and self.synthesizer_inputs.auth_token:
            self.auth_token = self.synthesizer_inputs.auth_token
        if self.header is None:
            self.header = {'Authorization': self.auth_token}
        if file_outputs is None:
            file_outputs = list()
        self.file_outputs = file_outputs

    def compliance_pct(self, output_files: list = None) -> dict:
        return None

    def compliance_status(self, output_files: list = None) -> dict:
        return None

    def get_compliance_info(self, output_files: list = None) -> dict:
        return None

    def upload_file(self, bucket_name=None, file_name=None, file_df: pd.DataFrame = pd.DataFrame(), meta_df: pd.DataFrame = pd.DataFrame(), fields_meta: dict = None, compliance_status=None, compliance_pct=0, compliance_weight=0):
        """

        we need to take care of file uploading, and we need to return the handle as an object like what we handle it in synthesizers
        data_frame | file_byts, meta_data, field_meta

        """

        if not bucket_name:
            bucket_name = "demo"

        # filepath = domain + os.sep + plan_guid + os.sep + \
        #     control_guid + os.sep + plan_exec_guid + \
        #     os.sep + template_type + os.sep + evidence_id

        domain_id, assessment_id, assessment_run_id, assessment_control_id, evidence_id = None, self.synthesizer_inputs.assessment_run_id, self.synthesizer_inputs.assessment_run_control_id, self.synthesizer_inputs.assessment_id, self.synthesizer_inputs.evidence_id

        if not assessment_id:
            assessment_id = str(uuid.uuid4())

        if not assessment_run_id:
            assessment_run_id = str(uuid.uuid4())

        if not assessment_control_id:
            assessment_control_id = str(uuid.uuid4())

        if not domain_id:
            domain_id = str(uuid.uuid4())

        if not evidence_id:
            evidence_id = str(uuid.uuid4())

        regexp = re.compile(r'^.[A-Za-z]+$')
        file_path_lib_obj = pathlib.Path(file_name)
        extension = file_path_lib_obj.suffix
        filename = file_name
        if regexp.search(extension):
            filename = file_path_lib_obj.stem

        # filename, file_extension = os.path.splitext(
        #     os.path.basename(file_name))

        file_name = domain_id+"/"+assessment_id+"/"+assessment_control_id + \
            "/"+assessment_run_id+"/evidence/"+evidence_id+"/"+filename

        file_name_parquet = file_name+".parquet"
        meta_file_name_parquet = file_name+"_meta__.parquet"
        fields_meta_file_name = file_name+"_fields_meta__.json"

        responsedata = cowsynthesizerservice_pb2.FileOutput(
            compliance_pct__=compliance_pct, compliance_status__=compliance_status, compliance_weight__=compliance_weight)

        # responsedata = {
        #     "dataFileHash": "",
        #     "metaDataFileHash": "",
        #     "metaFieldFileHash": "",
        #     "compliancePCT__": compliance_pct,
        #     "complianceStatus__": compliance_status,
        #     "complianceWeight__": compliance_weight,
        # }

        file_hash, file_path = None, None

        if not file_df.empty:
            file_byts = cowstorageserviceutils.df_to_parquet_bytes(file_df)
            file_hash, file_path, error = cowfilestoreutils.upload_file(
                bucket_name=bucket_name, file_name=file_name_parquet, file_content=file_byts)
            if error:
                responsedata.errors.append(cowsynthesizerservice_pb2.ErrorMessage(details=json.dumps(
                    error), error="cannot upload the src file", error_code=500, error_type=cowsynthesizerservice_pb2.SYSTEM_DEFINED_ERROR, status="error"))
                return error

        responsedata.data_file_hash = file_hash
        responsedata.data_file_path = file_path
        responsedata.file_name = filename

        # responsedata["dataFileHash"] = file_hash
        # responsedata["dataFilePath"] = file_path
        # responsedata["fileName"] = filename
        # responsedata["file_name"] = filename

        if not meta_df.empty:

            meta_file_byts = cowstorageserviceutils.df_to_parquet_bytes(
                meta_df)

            meta_file_hash, meta_file_path, error = cowfilestoreutils.upload_file(
                bucket_name=bucket_name, file_name=meta_file_name_parquet, file_content=meta_file_byts)

            if not error:
                responsedata.meta_data_file_hash = meta_file_hash
                responsedata.meta_data_file_path = meta_file_path
                # responsedata["metaDataFileHash"] = meta_file_hash
                # responsedata["metaDataFilePath"] = meta_file_path

        # TODO: As of now we're not allowing the user to define the column details. Need to evaluate to enable this

        # if fields_meta and isinstance(fields_meta, dict) and bool(fields_meta):
        #     fields_meta_byts = cowstorageserviceutils.dict_to_json_bytes(
        #         fields_meta)

        #     fields_meta_file_hash, fields_meta_meta_file_path, error = cowfilestoreutils.upload_file(
        #         bucket_name=bucket_name, file_name=fields_meta_file_name, file_content=fields_meta_byts)

        #     if not error:
        #         responsedata.meta_field_file_hash = fields_meta_file_hash
        #         responsedata.meta_field_file_path = fields_meta_meta_file_path
                # responsedata["metaFieldFileHash"] = fields_meta_file_hash
                # responsedata["metaFieldFilePath"] = fields_meta_meta_file_path

        if error is None:
            is_data_already_available = False
            if self.file_outputs:
                for idx, file_output in enumerate(self.file_outputs):
                    if file_output.file_name == file_name:
                        is_data_already_available = True
                        responsedata.errors = file_output.errors
                        self.file_outputs[idx] = responsedata
                        break

            if not is_data_already_available:
                self.file_outputs.append(responsedata)

        return error

    def append_errors(self, file_name: str, error_msg: str, error_code: int = 400, error: str = None, error_data_as_df: pd.DataFrame = pd.DataFrame()) -> dict:
        file_hash, file_path = None, None

        if not error_data_as_df.empty:
            file_byts = cowstorageserviceutils.df_to_parquet_bytes(
                error_data_as_df)
            file_hash, file_path, error = cowfilestoreutils.upload_file(
                file_name=file_name+"_error.parquet", file_content=file_byts, bucket_name="demo")
            if error:
                return error
        error_obj = cowsynthesizerservice_pb2.ErrorMessage(
            details=error_msg, error=error, status="error", error_code=error_code, error_type=cowsynthesizerservice_pb2.USER_DEFINED_ERROR, file_hash=file_hash)

        is_value_already_present = False

        if self.file_outputs:
            for idx, file_output in enumerate(self.file_outputs):
                if file_output.file_name == file_name:
                    file_output.errors.append(error_obj)
                    self.file_outputs[idx] = file_output
                    is_value_already_present = True
                    break

        # if is_proper_response_already_present:
        #     return {'error': 'proper response already presented in the outputs'}

        if not self.file_outputs:
            self.file_outputs = []

        if not is_value_already_present:
            responsedata = cowsynthesizerservice_pb2.FileOutput(
                file_name=file_name, errors=[error_obj])

            self.file_outputs.append(responsedata)

        return None

    def download_file(self, hash=None, header=None):
        return cowfilestoreutils.download_file(hash=hash, header=header)

    @abstractmethod
    def execute(self, synthesizer_inputs: dict):
        """
            please use upload_file method from the class
        """

        pass

    def add_signal(self, df: pd.DataFrame = pd.DataFrame(), condition=None, values=None, actions=None):
        """
            Needs to discuss about the structure
        """

        if not df.empty:
            pass

class Logger(object):
    def __init__(self, log_file="TaskLogs.ndjson"):
        self.log_file = log_file

    def log_data(self, data):        
        if not isinstance(data, dict):
            raise TypeError("Expected data to be a dictionary")

        log_entry = {
            "createdTime": datetime.now().isoformat(),
            "payload": data
        }

        with open(self.log_file, 'a') as file:
            file.write(json.dumps(log_entry) + '\n')
            
class LogConfigManager:
    """
    This class is used to manage custom log messages for each error that is returned from the task, so that it can easily be configured by the end user.
    """

    def __init__(self, log_config: Optional[dict] = None, default_log_config: Optional[dict] = None, default_context_data: Optional[dict] = None) -> None:
        """
        This class is used to manage custom log messages for each error that is returned from the task, so that it can easily be configured by the end user.
        ### Parameters:
        - log_config (Optional[dict]): Dictionary object containing the error messages for some or all error types
        - default_log_config (Optional[dict]): Dictionary object containing the error messages for all error types. This will be used as a fallback if an error type is not available in log_config
        - default_context_data (Optional[dict]): Dictionary containing default placeholder data that has to be replaced whiel fetching error message
        """
        self.log_config = log_config
        self.default_log_config = default_log_config
        self.default_context_data = default_context_data

    @staticmethod
    def from_minio_file_url(
        log_config_url: str|None = None,
        toml_download_func: Callable[[str], Tuple[Optional[dict], Optional[dict]]] | None = None,
        default_log_config_filepath: str | None = None,
        default_context_data: dict | None = None
    ) -> tuple['LogConfigManager', str|dict]:
        """
        Creates an instance of `LogConfigManager` using MinIO file URL for log_config, and absolute filepath of default_log_config
        ### Parameters:
        -  log_config_url (str | None): MinIO URL of the TOML file containing the error messages for some or all error types
        -  toml_download_func (Function | None): Function that has to be called, to download TOML file from MinIO. This can be set to `self.download_toml_file_from_minio_as_dict` function inside the task
        -  default_log_config_filepath (str | None): Absolute filepath of the TOML file containing the error messages for all error types. This will be used as a fallback if an error type is not available in log_config
        -  default_context_data (Optional[dict]): Dictionary containing default placeholder data that has to be replaced whiel fetching error message
        ### Returns:
        - LogConfigManager : Instance of LogConfigManager class
        - str : String containing error information if any, otherwise None.
        
        ### Sample Usage:
        ```python
        class Task(cards.AbstractTask):

            def execute(self) -> dict:
                
                # It's important to get the filepath exactly in this way in your task.py file
                default_log_config_filepath = str(pathlib.Path(__file__).parent.joinpath('LogConfig_default.toml').resolve())
                
                custom_log_config_url = self.task_inputs.user_inputs.get('LogConfig')
                
                log_manager, error = LogConfigManager.from_minio_file_url(
                    log_config_url=custom_log_config_url,
                    toml_download_func=self.download_toml_file_from_minio_as_dict,
                    default_log_config_filepath=default_log_config_filepath
                )
                if error:
                    return {'Error': error}

                # Other task code
        ```
        """

        log_manager = LogConfigManager(default_context_data=default_context_data)
        
        if log_config_url and not toml_download_func:
            return log_manager, 'LogConfig file URL is provided, but toml_download_func is not provided.'        
        
        if log_config_url and toml_download_func:
            log_manager.log_config, error = toml_download_func(log_config_url)
            if error:
                return log_manager, error

        if default_log_config_filepath:
            error = log_manager.set_default_log_config_from_filepath(default_log_config_filepath)
            if error:
                return log_manager, error

        if not log_manager.log_config and not log_manager.default_log_config:
            return log_manager, 'Both LogConfig and DefaultLogConfig are empty'

        return log_manager, ''

    @staticmethod
    def from_absolute_filepath(
        log_config_filepath: str = '',
        default_log_config_filepath: str = '',
        default_context_data: dict | None = None
    ) -> tuple['LogConfigManager', str]:
        """
        Creates an instance of `LogConfigManager` using absolute filepaths for both log_config and default_log_config files.
        This method must only be used for testing. For production, please use the `LogConfigManager.from_minio_file_url` method
        ### Parameters:
        - log_config_filepath (str | None): Absolute filepath of the TOML file containing the error messages for all error types
        - default_log_config_filepath (str | None): Absolute filepath of the TOML file containing the error messages for all error types. This will be used as a fallback if an error type is not available in log_config
        - default_context_data (Optional[dict]): Dictionary containing default placeholder data that has to be replaced whiel fetching error message
        ### Returns:
        - LogConfigManager : Instance of LogConfigManager class
        - str : String containing error information if any, otherwise None.
        
        ### Sample Usage:
        ```python
        class Task(cards.AbstractTask):

            def execute(self) -> dict:
                
                # It's important to get the filepath exactly in this way in your task.py file
                default_log_config_filepath = str(pathlib.Path(__file__).parent.joinpath('LogConfig_default.toml').resolve())
                custom_log_config_filepath = str(pathlib.Path(__file__).parent.joinpath('LogConfig_custom.toml').resolve())
                
                log_manager, error = LogConfigManager.from_absolute_filepath(
                    log_config_filepath=custom_log_config_filepath,
                    default_log_config_filepath=default_log_config_filepath
                )
                if error:
                    return {'Error': error}

                # Other task code
        ```
        """
    
        log_manager = LogConfigManager(default_context_data=default_context_data)
        
        if log_config_filepath:
            log_manager.log_config, error = LogConfigManager.__load_toml_file(log_config_filepath)
            if error:
                return log_manager, error

        if default_log_config_filepath:
            error = log_manager.set_default_log_config_from_filepath(default_log_config_filepath)
            if error:
                return log_manager, error
                
        if not log_manager.log_config and not log_manager.default_log_config:
            return log_manager, 'Both LogConfig and DefaultLogConfig are empty'

        return log_manager, ''
        
    def get_error_message(self, error_type: str, context_data: Optional[dict] = None, strict = True) -> str:
        """
        Get error message from log_config for the given error_type.
        If an error message for the given error_type is not found in log_config, then default_log_config will be used as a fallback.
        ### Parameters:
        - error_type (str): Type of error that has to be fetched from the log_config or default_log_config dictionaries
        - context_data (dict | None): Dictionary containing placeholder data that has to be replaced in the fetched error message
        - strict (bool): Specifies whether the placeholders must be validated or not. Default: True
        ### Returns:
        - str : String containing the error message or error information
        
        ### Sample Usage:
        ```python
        class Task(cards.AbstractTask):

            def execute(self) -> dict:
                
                # It's important to get the filepath exactly in this way in your task.py file
                default_log_config_filepath = str(pathlib.Path(__file__).parent.joinpath('LogConfig_default.toml').resolve())
                
                custom_log_config_url = self.task_inputs.user_inputs.get('LogConfig')
                
                log_manager, error = LogConfigManager.from_minio_file_url(
                    log_config_url=custom_log_config_url,
                    toml_download_func=self.download_toml_file_from_minio_as_dict,
                    default_log_config_filepath=default_log_config_filepath
                )
                if error:
                    return {'Error': error}
                    
                str_input = self.task_inputs.user_inputs.get('StringInput')
                if not str_input or not isinstance(str_input, str):
                    return self.upload_log_file_panic({'Error': log_manager.get_error_message('UserInputs.StringInput.invalid')})

                # Example with placeholders:
                data, error = some_api_call_function()
                if error:
                    # Error message for `API.Response.error` in LogConfig: "An error occurred while fetching API response :: {error_data}"
                    return self.upload_log_file_panic({
                        'Error': log_manager.get_error_message(
                            error_type='API.Response.error',
                            context_data={ 
                                'error_data': str(error) # replaces '{error_data}' placeholder in error message with value of `error`
                            }
                        )
                    })
        ```
        """
        
        error_message = jmespath.search(f'custom.{error_type} || default.{error_type}', {
            'custom': self.log_config,
            'default': self.default_log_config
        })
        if not error_message:
            return f"Error message is missing in LogConfig file for the ErrorType: '{error_type}'"

        return self._parse_error_message(error_message, error_type, context_data, strict)

    def set_default_log_config_from_filepath(self, abs_filepath: str) -> str | None:
        """
        Set the default_log_config value of a LogConfigManager instance from a given filepath
        ### Parameters:
        - abs_filepath (str | None): Absolute filepath of the TOML file containing the error messages for some or all error types
        ### Returns:
        - str : String containing error information if any, otherwise None.
        """
        toml_data, error = self.__load_toml_file(abs_filepath)
        if error:
            return error

        self.default_log_config = toml_data
        
    def _parse_error_message(self, error_message: str, error_type: str, context_data: Optional[dict] = None, strict = True) -> str:
        """
        Parses error message by validating and replacing the placeholders.
        ### Parameters:
        - error_message (str): Error message content that has to be parsed
        - error_type (str): Type of error that has to be fetched from the log_config or default_log_config dictionaries
        - context_data (dict | None): Dictionary containing placeholder data that has to be replaced in the fetched error message
        - strict (bool): Specifies whether the placeholders must be validated or not. Default: True
        ### Returns:
        - str : String containing the parsed error message or error information
        """
        
        # Find placeholders and return error if there is no context_data
        if re.match(r'{.+?}', error_message) and not context_data and not self.default_context_data and strict:
            return f"The ErrorType: '{error_type}' provides no placeholder data, but placeholders are found in the error message."
        
        full_context_data = context_data
        if self.default_context_data:
            full_context_data = self.default_context_data.copy()
            if context_data:
                full_context_data.update(context_data)
            
        if full_context_data:
            try:
                error_message = str(error_message).format(**full_context_data)
            except KeyError as e:
                return f"Found invalid placeholder in error message for following ErrorType: '{error_type}' in LogConfig file :: {e}"
                
        return error_message

    @staticmethod
    def __load_toml_file(abs_filepath: str) -> tuple[dict[Any, Any], str]:
        """
        Load TOML file data from a given filepath
        ### Parameters:
        - abs_filepath (str | None): Absolute filepath of the TOML file to load
        ### Returns:
        - dict : Dictionary containing data from the TOML file
        - str : String containing error information if any, otherwise None.
        """
        if pathlib.Path(abs_filepath).exists():
            with open(abs_filepath, 'rb') as f:
                try:
                    toml_data = tomli.load(f)
                except (UnicodeDecodeError, tomli.TOMLDecodeError):
                    return {}, "Provided TOML file is in an invalid format"
                return toml_data, ''
        else:
            return {}, f"The provided filepath: '{abs_filepath}' does not exist"
