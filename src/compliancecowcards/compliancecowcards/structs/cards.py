from datetime import datetime
from typing import Tuple
from abc import abstractmethod
from compliancecowcards.utils import cowfilestoreutils, cowstorageserviceutils, cowdfutils
from compliancecowcards.structs import cowvo
import pandas as pd
import uuid
import os
import minio
import json
import re
import pathlib
from posixpath import join as urljoin
from typing_extensions import deprecated
import io
import pyarrow

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

    def __init__(self, task_inputs: cowvo.TaskInputs = None, minio_client: minio.Minio = None) -> None:
        self.task_inputs = task_inputs
        self.minio_client = minio_client
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
        Parameters:
        - df (pd.DataFrame): The DataFrame to upload.
        - convertion_func (function): A function that takes pd.DataFrame as argument, and returns file_content and error information if any, as a tuple.
                                      This function will be applied to the 'df'.
        - file_name (str): The name of the file to be uploaded.
        - extension (str): The extension of the file to be uploaded.
        - content_type (str): The MIME type of the file content (e.g., 'application/pdf').
        Returns:
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
        except ValueError as e:
            return None, {"error": str(e)}

        return self.upload_file_to_minio(
            file_name=f'{file_name}-{str(uuid.uuid4())}.{extension}',
            file_content=file_content,
            content_type=content_type)
    
    def upload_df_as_parquet_file_to_minio(self, df: pd.DataFrame = None, file_name: str = None) -> Tuple[str, dict]:
        
        """
        Uploads a DataFrame as a Parquet file to MinIO.
        Parameters:
        - df (pd.DataFrame): The DataFrame to upload.
        - file_name (str): The name of the file to be uploaded.
        Returns:
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
        Parameters:
        - df (pd.DataFrame): The DataFrame to upload.
        - file_name (str): The name of the file to be uploaded.
        Returns:
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
        Parameters:
        - df (pd.DataFrame): The DataFrame to upload.
        - file_name (str): The name of the file to be uploaded.
        Returns:
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
        Parameters:
        - df (pd.DataFrame): The DataFrame to upload.
        - file_name (str): The name of the file to be uploaded.
        Returns:
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
        
    def download_parquet_file_from_minio_as_df(self, file_url=None) -> Tuple[pd.DataFrame, dict]:
        
        """
        Downloads a Parquet file from MinIO as a DataFrame.
        Parameters:
        - file_url (str): The URL of the Parquet file in MinIO.
        Returns:
        - pd.DataFrame: The DataFrame created from the downloaded Parquet file.
        - dict: Dictionary containing error information if any, otherwise None.
        """

        parquet_bytes, error = self.download_file_from_minio(
            file_url=file_url)
        if error:
            return None, error
        
        try:
            buffer = io.BytesIO(parquet_bytes)
            df = pd.read_parquet(buffer)
        except (pyarrow.ArrowInvalid, OSError):
            return None, { "error": "Invalid file format: The provided file does not adhere to any recognized format." }
        
        return df, None
    
    def download_json_file_from_minio_as_dict(self, file_url=None) -> Tuple[dict, dict]:
        
        """
        Downloads a JSON file from MinIO as a Python Dictionary.
        Parameters:
        - file_url (str): The URL of the JSON file in MinIO.
        Returns:
        - dict: Dictionary containing JSON file content.
        - dict: Dictionary containing error information if any, otherwise None.
        """

        json_bytes, error = self.download_file_from_minio(
            file_url=file_url)
        if error:
            return None, error
        
        try:
            file_content = json_bytes.decode("utf-8")
            file_content = json.loads(file_content)
        except json.JSONDecodeError:
            return None, { "error": "Invalid file format: The provided file does not adhere to any recognized format." }
        
        return file_content, None
    
    
    def download_json_file_from_minio_as_df(self, file_url=None) -> Tuple[pd.DataFrame, dict]:

        """
        Downloads a JSON file from MinIO as a DataFrame.
        Parameters:
        - file_url (str): The URL of the JSON file in MinIO.
        Returns:
        - pd.DataFrame: The DataFrame created from the downloaded JSON file.
        - dict: Dictionary containing error information if any, otherwise None.
        """

        json_dict, error = self.download_json_file_from_minio_as_dict(file_url)
        if error:
            return None, error
        
        if isinstance(json_dict, dict):
            json_dict = [json_dict]
        
        df = pd.DataFrame(json_dict)

        return df, None

    def download_ndjson_file_from_minio_as_df(self, file_url=None) -> Tuple[pd.DataFrame, dict]:

        """
        Downloads a NDJSON file from MinIO as a DataFrame.
        Parameters:
        - file_url (str): The URL of the NDJSON file in MinIO.
        Returns:
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
        Parameters:
        - file_url (str): The URL of the CSV file in MinIO.
        Returns:
        - pd.DataFrame: The DataFrame created from the downloaded CSV file.
        - dict: Dictionary containing error information if any, otherwise None.
        """

        file_bytes, error = self.download_file_from_minio(file_url)
        if error:
            return None, error
        
        try:
            data = io.StringIO(file_bytes.decode('utf-8'))
            df = pd.read_csv(data)
        except pd.errors.ParserError:
            return None, { "error": "Invalid file format: The provided file does not adhere to any recognized format." }
        
        return df, None

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
    def execute():
        """
            This method need to be override by the user. Here it'll have task_inputs.
            The python tasks won't be having task specific file names. 
            And we'll have some common utilities in the library which can be used by 
            both clients and our developers. It'll return a dictionary(like golang task)

        """
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