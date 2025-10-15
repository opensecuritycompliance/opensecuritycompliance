from typing import overload
from compliancecowcards.structs import cards
import json
import uuid
import toml
import re
import math
import numpy as np


logger = cards.Logger() # Initializes a Logger instance to log data, use logger.log_data(dict) to log a data

class Task(cards.AbstractTask):

    def execute(self) -> dict:  
        
        self.prev_log_data = []
        err_msg = ''
        log_file = ""

        try:

            log_file = self.task_inputs.user_inputs.get('LogFile') 
            output_type = self.task_inputs.user_inputs.get('Type')
            config_file = self.task_inputs.user_inputs.get('ConfigFile') 
            input_file = self.task_inputs.user_inputs.get('InputFile') 
            hierarchy_file = self.task_inputs.user_inputs.get('HierarchyFile')  
            
            if log_file and not input_file:
                return {'LogFile' : self.task_inputs.user_inputs.get('LogFile')}
            
            if log_file and input_file:
                self.prev_log_data, error = self.download_json_file_from_minio_as_iterable(log_file)
                if error:
                    return error
            
            err_list = []
            
            err_list = self.validate_inputs()
            if err_list:
                return self.upload_log_file(err_list)

            toml_bytes, error = self.download_file_from_minio(config_file)
            if error:
                return self.upload_log_file([{"Error": f"Error while downloading 'TransformConfigFile'. {error}"}])
            if not toml_bytes:
                return self.upload_log_file([{"Error": "Empty file - 'TransformConfigFile'"}])

            input_file_df, error = self.download_json_file_from_minio_as_df(input_file)
            if error:
                return self.upload_log_file([{"Error": f"Error while downloading 'InputFile'. {error}"}])
            if input_file_df.empty:
                return self.upload_log_file([{"Error": "Empty file - 'InputFile'"}])
            
            hierarchy_file_df, error = self.download_csv_file_from_minio_as_df(hierarchy_file)
            if error:
                return self.upload_log_file([{"Error": f"Error while downloading 'HierarchyFile'. {error}"}])
            if hierarchy_file_df.empty:
                return self.upload_log_file([{"Error": "Empty file - 'HierarchyFile'"}])
            
            toml_data = {}
            try:
                toml_data = toml.loads(toml_bytes.decode('utf-8'))
            except (UnicodeDecodeError, toml.TomlDecodeError) as e:
                return self.upload_log_file([{"Error" : f"Error while parsing 'TransformConfigFile' data. {str(e)}"}])
            
            new_col, source_col, target_col, map_col, err = self.handle_toml_data(toml_data)
            if err:
                return self.upload_log_file([{"Error" : err}])
            
            if output_type == 'Manager':
                input_file_df = input_file_df.apply(
                    lambda row: self.add_column_in_df_by_mapping(row, hierarchy_file_df, new_col, source_col, target_col, map_col),
                    axis=1
                )
            
            if output_type == 'Hierarchy':
                input_file_df = input_file_df.apply(
                    lambda row: self.add_column_in_df_by_mapping_v1(row, hierarchy_file_df, new_col, source_col, target_col, map_col),
                    axis=1
                )

            response = {}

            response["OutputFile"] = self.upload_output_file(input_file_df, "OutputFile")

            if log_file:
                response["LogFile"] = log_file
                    
            return response

        except ValueError as e:
            if self.err_msg:
                return self.upload_log_file([{"Error" : self.err_msg}])
            return self.upload_log_file([{"Error" : f"ValueError occured. {str(e)}"}])

    def upload_output_file(self, input_df , file_name):
        
        absolute_file_path, error = self.upload_file_to_minio(
            file_content=(input_df).to_json(orient='records').encode('utf-8'),
             file_name=f'{file_name}-{str(uuid.uuid4())}.json',
            content_type="application/json"
        )
        
        if error:
            return {"Error": error}
        return absolute_file_path

    def handle_toml_data(self, toml_data:dict):

        input_file_dict = toml_data.get("InputFile", "")
        hierarchy_file_dict = toml_data.get("HierarchyFile", "")

        emp_val = []

        if not input_file_dict:
            emp_val.append("InputFile")
        if not hierarchy_file_dict:
            emp_val.append("HierarchyFile")

        input_file_user_name = input_file_dict.get("UserColumn", "")
        input_file_col_name = input_file_dict.get("NewColumn", "")
        hierarchy_file_user_name = hierarchy_file_dict.get("UserColumn", "")
        hierarchy_file_manager = hierarchy_file_dict.get("ManagerColumn", "")
        

        if not input_file_user_name:
            emp_val.append("InputFile - UserColumn")
        if not input_file_col_name:
            emp_val.append("InputFile - NewColumn")
        if not hierarchy_file_user_name:
            emp_val.append("HierarchyFile - UserColumn")
        if not hierarchy_file_manager:
            emp_val.append("HierarchyFile - ManagerColumn")
        
        if emp_val:
            return "", "", "", "", f"Missing data in config - {', '.join(emp_val)}"
        
        return input_file_col_name, input_file_user_name, hierarchy_file_user_name, hierarchy_file_manager, ''

    def add_column_in_df_by_mapping_v1(self, row, target_data_df, new_column, source_column, target_column, map_column):
        
        if not target_data_df.empty:

            is_list_completed = False
            req_list = []

            # Extract the source column value from the row
            source_column_value = self.get_path_value(row, source_column)
            
            while not is_list_completed:

                # Find the row in the target dataframe where the target column matches the source column value
                target_row = target_data_df[target_data_df[target_column] == source_column_value]
                
                if not target_row.empty:
                    # Retrieve the value from the map column
                    manager_value = target_row[map_column].values[0]
                    req_list.append(manager_value)

                    source_column_value = manager_value
                else:
                    is_list_completed = True
                    
        row[new_column] = req_list  
        return row  # Ensure the updated row is returned   

    def add_column_in_df_by_mapping(self, row, target_data_df, new_column, source_column, target_column, map_column):
        
        if not target_data_df.empty:

            # Extract the source column value from the row
            source_column_value = self.get_path_value(row, source_column)

            if not target_column in target_data_df.columns:
                self.err_msg = self.err_msg =  f"Invalid column - '{target_column}'"
                raise ValueError

            # Find the row in the target dataframe where the target column matches the source column value
            target_row = target_data_df[target_data_df[target_column] == source_column_value]
            
            if not target_row.empty:
                # Retrieve the value from the map column
                if not map_column in target_row.columns:
                    self.err_msg = self.err_msg =  f"Invalid column - '{map_column}'"
                    raise ValueError
                manager_value = target_row[map_column].values[0]
                row[new_column] = manager_value
            else:
                # Handle cases where there is no match (optional)
                row[new_column] = None  
                
        return row  # Ensure the updated row is returned
    
    def get_path_value(self, row, path):
    
        keys = path.split(".")
        value = row
        for key in keys:
            value = value.get(key, None)
            if self.is_nan(value):
                value = None
                break
            if value is None:
                break
        if value is None:
            self.err_msg =  f"Invalid column - '{path}'"
            raise ValueError
        return value
    
    def is_nan(self, value):
        # If the value is a float (including numpy float), we can check for NaN
        if isinstance(value, (float, np.float32, np.float64)):
            return math.isnan(value)  # Or use np.isnan(value) if you prefer numpy
        # If the value is None, we can treat it as not NaN
        elif value is None:
            return False
        # For other types (list, dict, string), we can't have NaN, so return False
        else:
            return False
    
    def validate_inputs(self):

        task_inputs = self.task_inputs
        if not task_inputs:
            return [{"Error" : "Task input is missing"}]

        output_type = self.task_inputs.user_inputs.get('Type')
        config_file = self.task_inputs.user_inputs.get('ConfigFile') 
        input_file = self.task_inputs.user_inputs.get('InputFile') 
        hierarchy_file = self.task_inputs.user_inputs.get('HierarchyFile') 

        err_list = []
        invalid_type_inputs = []
        empty_inputs = []

        if not output_type:
            empty_inputs.append('Type')
        if not config_file:
            empty_inputs.append('ConfigFile')
        if not input_file:
            empty_inputs.append('InputFile')
        if not hierarchy_file:
            empty_inputs.append('HierarchyFile')


        if not isinstance(output_type, str):
            invalid_type_inputs.append('Type')
        if not isinstance(config_file, str):
            invalid_type_inputs.append('ConfigFile')
        if not isinstance(input_file, str):
            invalid_type_inputs.append('InputFile')
        if not isinstance(input_file, str):
            invalid_type_inputs.append('HierarchyFile')
        
        if isinstance(output_type, str) and output_type != 'Manager' and output_type != 'Hierarchy':
            err_list.append({"Error" : f"Invalid Type - '{output_type}'. Supported values - 'Manager', 'Hierarchy'"})
        
        if empty_inputs:
            err_list.append({"Error" : f"Empty input(s) -  {', '.join(empty_inputs)}"})
        if invalid_type_inputs:
            err_list.append({"Error" : f"Invalid Type -  {', '.join(invalid_type_inputs)}. Supported Type - 'String'"})
        
        return err_list
    
    def upload_log_file(self, errors_list):
        if not isinstance(errors_list, list):
            errors_list = [errors_list]

        self.prev_log_data.extend(errors_list)

        log_file_path, error = self.upload_file_to_minio(file_content=json.dumps(self.prev_log_data).encode('utf-8'), 
                                                         file_name=f'LogFile-{str(uuid.uuid4())}.json', content_type='application/json')
        if error:
            return {'Error': f"Error while uploading 'LogFile': {error}"}
        return {'LogFile': log_file_path}       