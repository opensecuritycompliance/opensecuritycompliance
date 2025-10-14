from compliancecowcards.structs import cards
import json
import uuid
import pandas as pd

logger = cards.Logger()

class Task(cards.AbstractTask):

    def execute(self) -> dict:
        log_file_url = self.task_inputs.user_inputs.get('LogFile')
        if log_file_url and (not self.task_inputs.user_inputs.get("InputFile1") or not self.task_inputs.user_inputs.get("InputFile2")):
            return {'LogFile' : log_file_url}
        
        error_details=[]
        
        input1_file_url: str = self.task_inputs.user_inputs.get('InputFile1')
        input2_file_url: str = self.task_inputs.user_inputs.get('InputFile2')

        if input1_file_url == '<<MINIO_FILE_PATH>>':
            input1_file_url = ''
        if input2_file_url == '<<MINIO_FILE_PATH>>':
            input2_file_url = ''

        if not input1_file_url and not input2_file_url:
            error_details.append({'Error': "Both 'InputFile1' and 'InputFile2' are empty"})
            return self.upload_log_file(error_details, log_file_url)
        
        if not input1_file_url:
            return {'MergedData': input2_file_url}
        if not input2_file_url:
            return {'MergedData': input1_file_url}
        
        file_download_func = {
            'json': self.download_json_file_from_minio_as_df,
            'ndjson': self.download_ndjson_file_from_minio_as_df,
            'csv': self.download_csv_file_from_minio_as_df,
            'parquet': self.download_parquet_file_from_minio_as_df
        }

        input1_file_extension = input1_file_url.split('.')[-1]
        if input1_file_extension not in file_download_func:
            error_details.append({
                "Error": f"The provided InputFile1 is of an unsupported file type :: Expected a file with one of '{', '.join(file_download_func.keys())}' extensions, got '{input1_file_extension}' instead."
            })
            return self.upload_log_file(error_details, log_file_url)
        input1_df, error = file_download_func[input1_file_extension](input1_file_url)
        if error:
            error_details.append({"Error" :f"Error occurred while downloading InputFile1 :: {error}"})
            return self.upload_log_file(error_details, log_file_url)
        if input1_df.empty:
            error_details.append({"Error" :f"Provided InputFile1 has no content, please check."})
            return self.upload_log_file(error_details, log_file_url)
        
        input2_file_extension = input2_file_url.split('.')[-1]
        if input2_file_extension not in file_download_func:
            error_details.append({
                "Error": f"The provided InputFile2 is of an unsupported file type :: Expected a file with one of '{', '.join(file_download_func.keys())}' extensions, got '{input2_file_extension}' instead."
            })
            return self.upload_log_file(error_details, log_file_url)
        input2_df, error = file_download_func[input2_file_extension](input2_file_url)
        if error:
            error_details.append({"Error" :f"Error occurred while downloading InputFile2 :: {error}"})
            return self.upload_log_file(error_details, log_file_url)
        if input2_df.empty:
            error_details.append({"Error" :f"Provided InputFile2 has no content, please check."})
            return self.upload_log_file(error_details, log_file_url)
        
        input1_dict = input1_df.to_dict(orient='records')
        input2_dict = input2_df.to_dict(orient='records')

        merged_data = []
        merge_type = self.task_inputs.user_inputs.get('MergeType')
        
        if isinstance(merge_type, str):
            merge_type = merge_type.lower().strip()

        if merge_type in ['concatenate', 'concat']:
            # Swap the data, to prioritize the file which has the most records
            if len(input2_dict) > len(input1_dict):
                input1_dict, input2_dict = input2_dict, input1_dict
            
            for idx in range(len(input1_dict)):
                if idx < len(input2_dict):
                    merged_data.append({
                        **input1_dict[idx],
                        **input2_dict[idx]
                    })
                else:
                    merged_data.append(input1_dict[idx])
        elif merge_type in ['append', ''] or bool(pd.isna(merge_type)):
            # validate InputFile2 - check whether InputFile2 has all fields that are in InputFile1
            required_input1_columns = set(input1_df.columns)
            missing_input1_columns = required_input1_columns.difference(input2_df.columns)
            if missing_input1_columns:
                error_details.append({"Error" :f"The following columns that are in InputFile1 are not in InputFile2: {', '.join(missing_input1_columns)}. InputFile1 and InputFile2 must have the same structure to be merged."})
                return self.upload_log_file(error_details, log_file_url)
            
            merged_data = input1_dict + input2_dict
        else:
            error_details.append({'Error': f"Provided MergeType: '{merge_type}' is invalid, please check"})
            return self.upload_log_file(error_details, log_file_url)

        return self.upload_output_file(merged_data,f"Merged_data-{str(uuid.uuid4())}.json","application/json",log_file_url)
    
    def upload_output_file(self, output , file_name,content_type,log_file_url):
        response={}
        absolute_file_path, error = self.upload_file_to_minio(
            file_content=output,
             file_name=file_name,
            content_type=content_type
        )
        if error:
            return {'error': error}
        response["MergedData"] = absolute_file_path
        if (log_file_url):
             response["LogFile"] = log_file_url

        return response
    
    def upload_log_file(self, error_msg,log_file_url=None):
        log_file_err_msg:list = error_msg
        if (log_file_url):
                prev_task_log_data,err = self.download_json_file_from_minio_as_iterable(log_file_url)
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
        
            
            


