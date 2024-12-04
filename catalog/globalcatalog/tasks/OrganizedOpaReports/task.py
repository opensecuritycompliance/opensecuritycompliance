
from compliancecowcards.structs import cards
import json
import os
import pandas as pd
import uuid
from compliancecowcards.utils import cowdictutils

class Task(cards.AbstractTask):

    def execute(self) -> dict:

        data_file_url = self.task_inputs.user_inputs.get("DataFile", "")
        log_file_url = self.task_inputs.user_inputs.get("LogFile" , "")
        error_details = []
        
        if log_file_url != "":
            if data_file_url == "" and log_file_url != "" :
                response = {
                    "LogFile" :log_file_url
                }
                return response
            else:
                log_file_bytes, error = self.download_file_from_minio(file_url=log_file_url)
                if error != None :
                    return self.upload_log_file([ {"Error" : 'Data file canot be empty.'}])
                
                log_file_str = log_file_bytes.decode('utf-8')

                try:
                    log_data = json.loads(log_file_str)
                    error_details = log_data
                except json.JSONDecodeError as e:
                    error_details.append( {"Error" : 'Error while reading log file.'})
                    return self.upload_log_file(error_details)

        if data_file_url == "" :
            error_details.append( {"Error" : 'Data file canot be empty.'})
            return self.upload_log_file(error_details)
        
        data_file_bytes, error = self.download_file_from_minio(file_url=data_file_url)
        if error != None :
            error_details.append( {"Error" : f'Error while downloading data file from minio: {error}'})
            return self.upload_log_file(error_details)

        data_file_json_formate = json.loads(data_file_bytes)

        report_data_dict = pd.DataFrame(data_file_json_formate)
        
        if 'items' not in report_data_dict.columns:
            error_details.append( {"Error" : "Excepted field Items is mising in resource data."})
            return self.upload_log_file(error_details)

        report_data_dict_list = report_data_dict.explode("items")["items"].tolist()

        cleaned_data = list(map(lambda d: d if isinstance(d, dict) else {}, report_data_dict_list))
        resource_data_df = pd.DataFrame.from_dict(cleaned_data)
        known_columns = [] 


        if 'metadata' in resource_data_df.columns:
            resource_data_df['Name']=resource_data_df['metadata'].apply(lambda x: x["name"] if isinstance(x,dict) else x)

            known_columns = ["ApiVersion","Kind","Name","Metadata","Spec","Status"] 
        else :
            resource_type = ""
            if "resourceType" in report_data_dict.columns:
                resource_type = report_data_dict["resourceType"]
            if resource_type is not None and len(resource_type) > 0:
                resource_data_df["ResourceType"] = resource_type[0]
            known_columns = ["AccountID","Region","ResourceType","ResourceID","ResourceName"] 



        dict_cols = resource_data_df.select_dtypes(include=[object]).columns

        for col in dict_cols:
            resource_data_df[col] = resource_data_df[col].apply(lambda x: str(x) if isinstance(x, (dict, list)) else x)
            
        resource_data_df.columns = [col[0].upper() + col[1:] for col in resource_data_df.columns]

        known_columns = [col for col in known_columns if col in resource_data_df.columns]

        remaining_columns = [col for col in resource_data_df.columns if col not in known_columns]

        new_order = known_columns + remaining_columns

        resource_data_df = resource_data_df[new_order]
        
        response = self.upload_output_file(resource_data_df ,os.path.basename(data_file_url))
        if len(error_details) > 0:
            log_file_response = self.upload_log_file(error_details)
            if cowdictutils.is_valid_key(log_file_response, 'LogFile'):
                response['LogFile'] = log_file_response["LogFile"]
            elif cowdictutils.is_valid_key(log_file_response, 'error'):
                return log_file_response
            
        return response
    
    def upload_output_file(self, output , file_name):
        
        absolute_file_path, error = self.upload_file_to_minio(
            file_content=(output).to_json(orient='records').encode('utf-8'),
             file_name=file_name,
            content_type="application/json"
        )
        if error:
            return {'error': error}
        return {'DataFile': absolute_file_path}
    
    def upload_log_file(self, error_msg):
        absolute_file_path, error = self.upload_file_to_minio(
            file_name=f'LogFile-{str(uuid.uuid4())}.json',
            file_content=json.dumps(error_msg).encode(),
            content_type='application/json',
        )
        if error:
            return {'error': error}
        return {'LogFile': absolute_file_path}



