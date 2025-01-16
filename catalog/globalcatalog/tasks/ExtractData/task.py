
from typing import List
from compliancecowcards.structs import cards
#As per the selected app, we're importing the app package 
from appconnections.nocredapp import nocredapp
import uuid
import json
import os
import pandas as pd



class Task(cards.AbstractTask):

    def execute(self) -> dict:
        log_file_url = self.task_inputs.user_inputs.get('LogFile')
        if log_file_url and not self.task_inputs.user_inputs.get("DataFile"):
            return {'LogFile' : log_file_url}
        
        data_file_url:str= self.task_inputs.user_inputs.get("DataFile", "")
        extract_data_path:str = self.task_inputs.user_inputs.get("ExtractPath", "")
        error_details:list = []
        
        error_details = self.check_inputs(data_file_url,extract_data_path,error_details)
        if len(error_details)>0:
            return self.upload_log_file(error_details,log_file_url)
        data_file_bytes, error = self.download_file_from_minio(file_url=data_file_url)
        if error:
            error_details.append( {"Error" : f'Error while downloading data file from minio: {error}'})
            return self.upload_log_file(error_details,log_file_url)
        
        try:
             data_json_format = json.loads(data_file_bytes)
        except  json.JSONDecodeError as e:
             error_details.append( {"Error" : f'Error while parsing json file: {e}'})
             return self.upload_log_file(error_details,log_file_url)
       
        
        path_steps = extract_data_path.split('.')
        output = self.get_value_by_path(data_json_format,path_steps)
        if output is None:
            error_details.append({"Error":"ExtractPath is invalid"})
            return self.upload_log_file(error_details,log_file_url)
        
        if not isinstance(output, (dict, list)):
            return self.upload_log_file([{"Error":f"The expression must return an object or an array, got '{type(output)}' instead"}])
        
        response_data = json.dumps(output).encode('utf-8')
        return self.upload_output_file(response_data ,os.path.basename(data_file_url),log_file_url)
  
    def load_json_file(self,file_bytes):
        try:
            data = json.loads(file_bytes.decode('utf-8'))
            return data,None
        except  json.JSONDecodeError as e:
            err = [{"Error" : f'Error while parsing json file: {e}'}]
            return None,err
        
    def upload_log_file(self, error_msg,log_file=None)->dict:
            log_file_err_msg:list = error_msg
            if (log_file):
                prev_log_file_bytes, error = self.download_file_from_minio(file_url=log_file)
                if error:
                    return self.upload_log_file([error])
                prev_task_log_data,err = self.load_json_file(prev_log_file_bytes)
                if err:
                    return self.upload_log_file([err])
                
                if isinstance(prev_task_log_data,dict):
                    log_file_err_msg.append(prev_task_log_data)
                if isinstance(prev_task_log_data,list):
                    log_file_err_msg=log_file_err_msg+prev_task_log_data
             
            absolute_file_path, error = self.upload_file_to_minio(
                file_name=f'LogFile-{str(uuid.uuid4())}.json',
                file_content=json.dumps(log_file_err_msg).encode(),
                content_type='application/json',
            )
            if error:
                return {'Error': error}
            return {'LogFile': absolute_file_path}

    def get_value_by_path(self,data, path_components):
       
        for component in path_components:
            if isinstance(data, list): # handling arr values
                index = int(component)
                if 0 <= index < len(data): # checking arr index to be extracted is in range
                    data = data[index]
                else:
                    return None
            else:
                data = data.get(component, None)
            if data is None:
                return None  
        return data
    def upload_output_file(self, output ,file_name,log_file_url=None)->dict:
        response={}
        absolute_file_path, error = self.upload_file_to_minio(
             output,
             file_name=file_name,
            content_type="application/json"
        )
        if error:
            return {'Error': error}
        response['DataFile'] = absolute_file_path
        if(log_file_url):
            response["LogFile"] = log_file_url
        return response
    
    def check_inputs(self,data_file_url:str,extract_data_path:str,error_details:list)-> list:
         if not data_file_url :
            error_details.append( {"Error" : 'Data file canot be empty.'})
            return error_details
         if not extract_data_path:
             error_details.append( {"Error" : 'ExtractPath canot be empty.'})
             return error_details
         if not data_file_url.endswith(".json"):
              error_details.append( {"Error" : 'Data file is not a json.'})
              return error_details
         return error_details
    

