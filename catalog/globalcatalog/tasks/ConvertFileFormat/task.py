import io
import json
from typing import overload
import uuid
from compliancecowcards.structs import cards
#As per the selected app, we're importing the app package 
from applicationtypes.nocredapp import nocredapp
import numpy as np
import pandas as pd
import toml
import yaml
import xmltodict
import base64
from compliancecowcards.utils import cowdictutils
import os
from io import BytesIO
import openpyxl

class Task(cards.AbstractTask):

    JSON = 'json'
    YAML = 'yaml'
    TOML = 'toml'
    CSV = 'csv'
    PARQUET = 'parquet'
    XML = 'xml'
    XLSX = 'xlsx'

    content_type = {
        JSON : 'application/json',
        YAML : 'application/x-yaml',
        TOML :'application/toml',
        CSV  : 'text/csv',
        PARQUET : 'application/parquet' 
    }

    prev_log_data: list = []

    def execute(self) -> dict:
        
        input_log_file_url = ''
        input_file_url = ''
        if self.task_inputs.user_inputs:
            if cowdictutils.is_valid_key(self.task_inputs.user_inputs, 'LogFile'):
                input_log_file_url = self.task_inputs.user_inputs['LogFile']

            if cowdictutils.is_valid_key(self.task_inputs.user_inputs, 'InputFile'):
                input_file_url = self.task_inputs.user_inputs['InputFile']

        if input_log_file_url and not input_file_url:
            return { "LogFile": input_log_file_url }
        
        if input_log_file_url and input_file_url:
            self.prev_log_data, error = self.download_json_file_from_minio_as_dict(input_log_file_url)
            if error:
                return error
            
        error = self.check_inputs()
        if error:
            log_file_url, error = self.upload_log_file([{ 'Error': error }])
            if error:
                    return { 'Error': error }
            return { "LogFile": log_file_url }
        input_file = self.task_inputs.user_inputs.get("InputFile")
        output_file_format = self.task_inputs.user_inputs.get("OutputFileFormat").lower()
        
        file_bytes, error = self.download_file_from_minio(input_file)

        if error:
            log_file_url, error = self.upload_log_file([{ 'Error': f"Error while downloading InputFile :: {error}" }])
            if error:
                return { 'Error': error }
            return { "LogFile": log_file_url }
        
        if input_file.startswith("file://") or input_file.startswith("http"):
            input_file_format = self.detect_input_format(input_file)
        else:
            input_file_format = self.detect_file_format_from_bytes(file_bytes)

        if input_file_format is None:
            log_file_url, error = self.upload_log_file([{ 'Error': "Provided file extension is not supported" }])
            if error:
                return { 'Error': error }
            return { "LogFile": log_file_url }

        data, error = self.parse_input_content(file_bytes, input_file_format)
        if error:
            log_file_url, error = self.upload_log_file([{ 'Error': f"Error parsing input file :: {error}" }])
            if error: 
                return { 'Error': error}
            return { "LogFile": log_file_url }

        output_data, error = self.convert_to_format(data, output_file_format)
        if error:
            log_file_url, error = self.upload_log_file([{ 'Error': f"Error while converting format :: {error}" }])
            if error: 
                return { 'Error': error}
            return { "LogFile": log_file_url }
        
        response = {}
        if input_log_file_url:
            response['LogFile'] = input_log_file_url
 
        output_file_name=f'OutputFile-{str(uuid.uuid4())}'  
        if self.task_inputs.user_inputs.get("OutputFileName",""):
            output_file_name = self.task_inputs.user_inputs.get("OutputFileName","")

        output_file_url, error = self.upload_output_file(output_file_name, output_data, output_file_format)
        if error:
            return { 'Error': error } 
        
        response['OutputFile'] = output_file_url      

        return response
    
    def check_inputs(self):
        if self.task_inputs is None:
            return 'Task inputs are missing'
        user_object = self.task_inputs.user_object
        if (
            user_object is None
            or user_object.app is None
            or user_object.app.application_url is None
            or user_object.app.user_defined_credentials is None
        ):
            return 'User defined credentials are missing'
        
        emptyAttrs = []
        if self.task_inputs.user_inputs is None:
            emptyAttrs.append("User inputs")
        if not self.task_inputs.user_inputs.get("InputFile"):
            emptyAttrs.append("InputFile")
        if not self.task_inputs.user_inputs.get("OutputFileFormat"):
            emptyAttrs.append("OutputFileFormat")

        return "The following inputs: " + ", ".join(
            emptyAttrs) + " is/are empty" if emptyAttrs else ""

    
    def upload_log_file(self, error_data):
        if not isinstance(error_data, list):
            error_data = [error_data]

        error_data = self.prev_log_data + error_data 

        file_url, error = self.upload_file_to_minio(
            file_content=error_data,
            file_name=f"LogFile-{str(uuid.uuid4())}.json",
            content_type="application/json"
        )
        if error:
            return None, {'Error': f"Error while uploading LogFile :: {error}"}
        return file_url, None
    
    def upload_output_file(self, file_name, data, format_to_convert):
        file_name = f'{file_name}.{format_to_convert}'
        content_type = self.get_content_type(format_to_convert)
        absolute_file_path, error = self.upload_file_to_minio(
            file_name=file_name,
            file_content=data,
            content_type=content_type,
        )
        if error:
            return '', error

        return absolute_file_path, None
    
    def detect_input_format(self, file_name):
        if file_name.endswith('.json'):
            return self.JSON
        elif file_name.endswith('.yaml'):
            return self.YAML
        elif file_name.endswith('.toml'):
            return self.TOML
        elif file_name.endswith('.csv'):
            return self.CSV
        elif file_name.endswith('.parquet'):
            return self.PARQUET
        elif file_name.endswith('.xml'):
            return self.XML
        elif file_name.endswith('.xlsx'):
            return self.XLSX
        return None
    
    def detect_file_format_from_bytes(self, file_bytes):
        try:
            json.loads(file_bytes.decode('utf-8'))
            return self.JSON
        except Exception:
            pass
        try:
            yaml.safe_load(file_bytes.decode('utf-8'))
            return self.YAML
        except Exception:
            pass
        try:
            toml.loads(file_bytes.decode('utf-8'))
            return self.TOML
        except Exception:
            pass
        try:
            pd.read_csv(io.BytesIO(file_bytes))
            return self.CSV
        except Exception:
            pass
        try:
            pd.read_parquet(io.BytesIO(file_bytes))
            return self.PARQUET
        except Exception:
            pass
        try:
            xmltodict.parse(file_bytes.decode())
            return self.XML
        except Exception:
            pass
        try:
            pd.read_excel(io.BytesIO(file_bytes))
            return self.XLSX
        except Exception:
            pass
        return None


    def parse_input_content(self, file_bytes, input_format):
        try:
            match input_format:
                case self.JSON:
                    return json.loads(file_bytes), None
                case self.YAML:
                    return yaml.safe_load(file_bytes), None
                case self.TOML:
                    return toml.loads(file_bytes.decode('utf-8')), None
                case self.XML:
                    return xmltodict.parse(file_bytes.decode('utf-8')), None
                case self.CSV:
                    df = pd.read_csv(io.BytesIO(file_bytes)).to_dict(orient='records')
                    return self.convertpandasdicttodictionary(df), None
                case self.PARQUET:
                    df = pd.read_parquet(io.BytesIO(file_bytes)).to_dict(orient='records')
                    return self.convertpandasdicttodictionary(df), None
                case self.XLSX:
                    excel_file = io.BytesIO(file_bytes)
                    df = pd.read_excel(excel_file)
                    return df.to_dict(orient='records'), None
                case _:
                    return None, f"Unsupported format: {input_format}"

        except json.JSONDecodeError as e:
            return None, f"JSON parsing error: {str(e)}"
        except yaml.YAMLError as e:
            return None, f"YAML parsing error: {str(e)}"
        except toml.TomlDecodeError as e:
            return None, f"TOML parsing error: {str(e)}"
        except pd.errors.ParserError as e:
            return None, f"CSV parsing error: {str(e)}"
        except OSError as e:
            return None, f"Parquet file error: {str(e)}"
        except Exception as e:
            return None, f"Unknown error: {str(e)}"

    def convert_to_format(self, data, format_to_convert):
        try:
            match format_to_convert:
               
                case self.JSON:
                    return json.dumps(data, indent=4).encode('utf-8'), None
                case self.YAML:
                    return yaml.dump(data).encode('utf-8'), None
                case self.TOML:
                    if isinstance(data, dict):
                        return toml.dumps(data).encode('utf-8'), None
                    elif isinstance(data, list) and all(isinstance(item, dict) for item in data):
                        return toml.dumps({"data": data}).encode('utf-8'), None
                    else:
                        return None, 'Invalid data format for TOML conversion'

                case self.CSV | self.PARQUET:
                    if isinstance(data, dict):
                        data = [data] 
                    df = pd.DataFrame(data)
                    
                    match format_to_convert:
                        case self.CSV:
                            output = io.BytesIO() 
                            df.to_csv(output, index=False)
                            return output.getvalue(), None
                
                        case self.PARQUET:                        
                            return df.to_parquet(), None
                
                case self.XLSX:
                    df = pd.DataFrame(data)  
                    output = BytesIO()       
                    df.to_excel(output, index=False, engine='openpyxl')  
                    output.seek(0)  
                    excel_data = output.getvalue()  
                    output.close()  
                    return excel_data, None  

                case _:
                    return None, f"Unsupported format: {format_to_convert}"
            
        except Exception as e:
            return None, str(e)
        
    def get_content_type(self, format_to_convert):
        if format_to_convert in self.content_type:
            return self.content_type[format_to_convert]
        return 'text/plain'
        
    def dataframetodictionarserializer(self, obj):
        if isinstance(obj, np.ndarray):
            return obj.tolist()

    def convertpandasdicttodictionary(self, obj):
        if obj and bool(obj):
            obj = json.dumps(obj, default=self.dataframetodictionarserializer)
            obj = json.loads(obj)
        return obj
