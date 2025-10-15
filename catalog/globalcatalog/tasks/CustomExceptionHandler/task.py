from typing import overload, Optional, Dict, Tuple
from compliancecowcards.structs import cards
from compliancecowcards.utils import cowdictutils
import pandas as pd
import uuid

logger = cards.Logger() # Initializes a Logger instance to log data, use logger.log_data(dict) to log a data

class Task(cards.AbstractTask):

    def execute(self) -> dict:

        response = {}
        prev_log_file_url = ''
        error_config_file_url = ''
        output_file_url_1 = ''
        output_file_url_2 = ''
        log_data = ''
        error_config_data = ''
        current_log_file_url = ''

        error = self.check_inputs()
        if error:
            current_log_file_url, error = self.upload_log_file({"Error": error})
            if error:
                self.handle_file_upload_error("LogFile", error)

        user_inputs = self.task_inputs.user_inputs

        if not current_log_file_url:
            prev_log_file_url = user_inputs['LogFile'] if user_inputs['LogFile']!='<<MINIO_FILE_PATH>>' else ''
            error_config_file_url = user_inputs['CustomExceptionConfigFile'] if user_inputs['CustomExceptionConfigFile']!='<<MINIO_FILE_PATH>>' else ''
        if cowdictutils.is_valid_key(user_inputs, 'InputFile1') and user_inputs['InputFile1'] != '<<MINIO_FILE_PATH>>':
            output_file_url_1 = user_inputs['InputFile1']
        if cowdictutils.is_valid_key(user_inputs, 'InputFile2') and user_inputs['InputFile2'] != '<<MINIO_FILE_PATH>>':
            output_file_url_2 = user_inputs['InputFile2']

        if output_file_url_1:
            response["OutputFile1"] = output_file_url_1
        if output_file_url_2:
            response["OutputFile2"] = output_file_url_2

        if prev_log_file_url and error_config_file_url:
            log_data, error = self.download_json_file_from_minio_as_dict(prev_log_file_url)
            if error:
                current_log_file_url, error = self.upload_log_file({"Error": f'Error while downloading "InputLogFile" :: {error}'})
                if error:
                    self.handle_file_upload_error("LogFile", error)
            error_config_data, error = self.download_json_file_from_minio_as_dict(error_config_file_url)
            if error:
                current_log_file_url, error = self.upload_log_file({"Error": f'Error while downloading "CustomErrorConfigFile" :: {error}'})
                if error:
                    self.handle_file_upload_error("LogFile", error)

        if not (output_file_url_1 or output_file_url_2) and not prev_log_file_url and not current_log_file_url:
            current_log_file_url, error = self.upload_log_file({"Error": f'Either InputFile or LogFile should be mapped or present.'})
            if error:
                self.handle_file_upload_error("LogFile", error)

        if not error_config_file_url and not current_log_file_url and prev_log_file_url:
            response['LogFile'] = prev_log_file_url
        elif not current_log_file_url and prev_log_file_url:
            updated_log_data_df, error = self.update_log_from_config(log_data, error_config_data)
            if error:
                current_log_file_url, error = self.upload_log_file(error)
                if error:
                    self.handle_file_upload_error("LogFile", error)
            if updated_log_data_df.empty:
                current_log_file_url, error = self.upload_log_file({"Error": 'Log data is empty.'})
                if error:
                    self.handle_file_upload_error("LogFile", error)

            if updated_log_data_df is not None and not current_log_file_url:
                file_name = 'LogFile'
                log_output_file_url, error = self.upload_df_as_json_file_to_minio(
                    df=updated_log_data_df,
                    file_name=file_name
                )
                if error:
                    self.handle_file_upload_error(file_name, error)
                response["LogFile"] = log_output_file_url
        
        if current_log_file_url:
            response["LogFile"] = current_log_file_url

        return response
    
    def update_log_from_config(self, log_data: list, error_config_data: dict) -> Tuple[Optional[pd.DataFrame], Optional[Dict[str, str]]]:
        updated_log_data = []
        try:
            error_config_dict = {}

            for config in error_config_data:
                error_config_dict.update(config)

            for log_entry in log_data:
                error_message = log_entry.get("Error")
                
                if error_message and error_message in error_config_dict:
                    updated_log_data.append({"Error": error_config_dict[error_message]})
                else:
                    updated_log_data.append(log_entry)

            return pd.DataFrame(updated_log_data), None
        
        except KeyError as e:
            return None, {"Error" :f"KeyError: {e} - 'Error' key not found in log entry"}
        
    def handle_file_upload_error(self, file_type: str, error_message: str) -> Optional[Dict[str, str]]:
        if error_message:
            return { "Error": f"Error while uploading {file_type} :: {error_message}" }
        return None

    def upload_log_file(self, error_data: list | dict) -> Tuple[Optional[str], Optional[str]]:
        if not isinstance(error_data, list):
            error_data = [error_data]
        
        file_name = f"LogFile-{str(uuid.uuid4())}.json"
        file_url, error = self.upload_df_as_json_file_to_minio(
            df=pd.DataFrame(error_data),
            file_name=file_name
        )
        if error:
            return None, f"Error while uploading LogFile:: {error}"
        return file_url, None

    def check_inputs(self) -> Optional[str]:
        if not self.task_inputs:
            return 'Task inputs are missing'
        user_object = self.task_inputs.user_object
        if (
            user_object is None
            or user_object.app is None
            or user_object.app.application_url is None
            or user_object.app.user_defined_credentials is None
        ):
            return 'User defined credentials are missing'

        user_inputs = self.task_inputs.user_inputs
        if user_inputs is None:
            return 'User inputs are missing'
        
        empty_attrs = []
        required_files = ['CustomExceptionConfigFile']

        for file in required_files:
            if not cowdictutils.is_valid_key(user_inputs, file):
                empty_attrs.append(f'"{file}" is missing in user inputs')

        return "The following inputs: " + ", ".join(
            empty_attrs) if empty_attrs else ""