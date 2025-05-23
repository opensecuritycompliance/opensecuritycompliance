
from typing import overload
from compliancecowcards.structs import cards
# As per the selected app, we're importing the app package
from applicationtypes.awsappconnector import awsappconnector
import uuid
import json
import pandas as pd
from compliancecowcards.utils import cowdictutils


class Task(cards.AbstractTask):

    def execute(self) -> dict:
        error = self.validate_inputs()
        if error:
            return self.upload_log_file([{'Error': error}])
        
        is_default_region_supported = False
        # If region is not specified, set the default region
        if not cowdictutils.is_valid_key(self.task_inputs.user_inputs, 'Region'):
            self.task_inputs.user_inputs['Region'] = ['us-west-2']
            is_default_region_supported = True

        aws_connector = awsappconnector.AWSAppConnector(
            user_defined_credentials=awsappconnector.UserDefinedCredentials.from_dict(
                self.task_inputs.user_object.app.user_defined_credentials
            ),
            region=self.task_inputs.user_inputs.get('Region')
        )

        db_instances_df, errors_list = aws_connector.describe_db_instances()
        if db_instances_df.empty:
            if len(errors_list) > 0:
                return self.upload_log_file(errors_list)
            else:
                error_message = ('No DB instances found for the default region us-west-2' if is_default_region_supported 
                                      else 'No DB instances found for the given region(s)')
                return self.upload_log_file([{'Error': error_message}])

        else:
            db_instances_df = aws_connector.standardize_column_names(
                db_instances_df)
            json_data = json.loads(db_instances_df.to_json())
            db_instances_json_data = aws_connector.replace_empty_dicts_with_none(
                json_data)
            db_instances_df = pd.DataFrame(db_instances_json_data)
            response = self.upload_output_file(db_instances_df)
            if len(errors_list) > 0:
                log_file_response = self.upload_log_file(errors_list)
                if cowdictutils.is_valid_key(log_file_response, 'LogFile'):
                    response['LogFile'] = log_file_response["LogFile"]
                elif cowdictutils.is_valid_key(log_file_response, 'error'):
                    return log_file_response
            return response
        

    def upload_output_file(self, df):
        absolute_file_path, error = self.upload_df_as_parquet_file_to_minio(
            df, 'RDSDBInstancesList')
        if error:
            return {'error': error}
        return {
            'RDSDBInstancesList': absolute_file_path
        }

    def upload_log_file(self, errors_list):
        absolute_file_path, error = self.upload_file_to_minio(file_content=json.dumps(errors_list).encode(
            'utf-8'), file_name=f'LogFile-{str(uuid.uuid4())}.json', content_type='application/json')
        if error:
            return {'error': error}
        return {
            'LogFile': absolute_file_path
        }

    def validate_inputs(self):
        task_inputs = self.task_inputs
        if not task_inputs:
            return 'Missing: Task inputs'

        user_object = self.task_inputs.user_object
        if (
            not user_object
            or not user_object.app
            or not user_object.app.user_defined_credentials
        ):
            return 'Missing: User defined credentials'

        if not self.task_inputs.user_inputs: 
            return 'Missing: User inputs'
            
        return None
