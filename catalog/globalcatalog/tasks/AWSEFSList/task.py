from typing import overload 
from compliancecowcards.structs import cards
#As per the selected app, we're importing the app package 
from appconnections.kubernetes import kubernetes
from compliancecowcards.utils import cowdictutils
from datetime import datetime, timezone
import urllib.parse
import json
import uuid
import pandas as pd



class Task(cards.AbstractTask):

    def execute(self) -> dict:

        response = {}

        # Not proceeding if we have KubernetesPVListLogFile
        if cowdictutils.is_valid_key(self.task_inputs.user_inputs, 'KubernetesPVListLogFile'):
            log_file_url = self.task_inputs.user_inputs.get("KubernetesPVListLogFile")
            if not isinstance(log_file_url, str):
                return self.upload_log_file([{"Error" : "'KubernetesPVListLogFile' type is not supported. Supported type is string"}])
            else:
                try:
                    result = urllib.parse.urlparse(log_file_url)
                    if not all([result.scheme, result.netloc]):
                        return self.upload_log_file([{"Error" : "'KubernetesPVListLogFile' is not valid URL. Please provide a valid URL."}])
                    if not self.task_inputs.user_inputs.get("KubernetesPVList"):
                        return {"KubernetesPVListLogFile": self.task_inputs.user_inputs.get("KubernetesPVListLogFile")}
                    else:
                        response['KubernetesPVListLogFile'] = self.task_inputs.user_inputs.get("KubernetesPVListLogFile")
                except ValueError:
                    return self.upload_log_file([{"Error" : "'KubernetesPVListLogFile' is not valid URL. Please provide a valid URL."}])

        error_list = self.validate()
        if error_list:
            result  = self.upload_log_file(self.add_key_in_list(error_list))
            if cowdictutils.is_valid_key(result, "AWSEFSListLogFile"):
                response['AWSEFSListLogFile'] = result['AWSEFSListLogFile']
            return response
        
        region = self.task_inputs.user_inputs.get("Region")
        
        aws_connector = kubernetes.awsappconnector.AWSAppConnector(
            user_defined_credentials=kubernetes.awsappconnector.UserDefinedCredentials.from_dict(
                self.task_inputs.user_object.app.linked_applications.get('AWSAppConnector')[0]['userDefinedCredentials']
            ),
            region=region
        )

        # Fetch EFS
        efs_list, error_list = aws_connector.list_efs_file_systems()
        if error_list:
            result  = self.upload_log_file(self.add_key_in_list(error_list))
            if cowdictutils.is_valid_key(result, "AWSEFSListLogFile"):
                response['AWSEFSListLogFile'] = result['AWSEFSListLogFile']
            return response
        
        if not efs_list:
            result  = self.upload_log_file([{'Error' : 'No Elastic File System was found for the provided AWS credentials or for the specified region'}])
            if cowdictutils.is_valid_key(result, "AWSEFSListLogFile"):
                response['AWSEFSListLogFile'] = result['AWSEFSListLogFile']
            return response
        # Fetch KMS Key details to get encryption details
        key_df, error_list = aws_connector.describe_kms_key()        
        if key_df is None:
            result  = self.upload_log_file([{'Error' : 'No AWS/Customer managed key was found for the provided AWS credentials.'}])
            if cowdictutils.is_valid_key(result, "AWSEFSListLogFile"):
                response['AWSEFSListLogFile'] = result['AWSEFSListLogFile']
            return response
        if key_df is None and error_list:
            result  = self.upload_log_file(self.add_key_in_list(error_list))
            if cowdictutils.is_valid_key(result, "AWSEFSListLogFile"):
                response['AWSEFSListLogFile'] = result['AWSEFSListLogFile']
            return response

        std_list = []

        for efs in efs_list:

            try:

                resource_id = efs.get('FileSystemId', '')
                # generate resource url
                resource_info = {
                                'resource_type'  : kubernetes.awsappconnector.ELASTIC_FILE_SYSTEM,
                                'Resource'       : resource_id,
                                'Region'         : efs.get('Region', '')
                                }
                resource_url, _ = aws_connector.get_resource_url(resource_info)
                if not resource_url:
                    resource_url = 'N/A'
                
                size_in_mb = 0
                size_in_bytes  = efs['SizeInBytes'].get('Value', '') if 'SizeInBytes' in efs else ''
                if size_in_bytes:
                    size_in_mb = "{:.2f}".format(size_in_bytes/ (1024 * 1024))

                data = {
                        "System"              : "aws",
                        "Source"              : "compliancecow",
                        "ResourceID"          : efs.get('FileSystemId', ''),
                        "ResourceName"        : efs.get('Name', ''),
                        "ResourceType"        : "Elastic File System",
                        "ResourceURL"         : resource_url,
                        "Account"             : efs.get('OwnerId', ''),
                        "NumberOfMountTargets": efs.get('NumberOfMountTargets', ''),
                        "SizeInMB"            : size_in_mb,
                        "CreatedDateTime"     : efs['CreationTime'].strftime('%Y-%m-%dT%H:%M:%S.%fZ') if 'CreationTime' in efs else '',
                        "IsEncrypted"         : efs.get('Encrypted', '')
                    }
                
                is_encrypted = efs['Encrypted']
                kms_key_id = ''
                key_manager = ''
                key_rotation_enabled = False
                last_rotation_date = ''
                next_rotation_date = ''

                if is_encrypted:
                    # If EFS is encrypted, fetching key rotation details
                    if cowdictutils.is_valid_key(efs, 'KmsKeyId'):
                        kms_key_id = efs['KmsKeyId'].rsplit('/', 1)[-1]
                        key_details  = key_df[key_df['KeyId'] == kms_key_id]
                        key_manager = key_details['KeyManager'].values[0]
                        key_rotation_enabled = key_details['KeyRotationEnabled'].values[0]
                        last_rotation_date = key_details['KeyLastRotatedDate'].values[0]
                        next_rotation_date = key_details['KeyNextRotatedDate'].values[0]

                data['KmsKeyID'] = kms_key_id
                data['KeyManager'] = key_manager
                data['KeyRotationEnabled'] = key_rotation_enabled
                data['KeyLastRotationDate'] = last_rotation_date
                data['KeyNextRotationDate'] = next_rotation_date

                std_list.append(data)

            except KeyError as e:
                return self.upload_log_file([{"Error" : f'Failed to generate AWS EFS List. KeyError exception occured. Invalid key : {str(e)}'}])

        if std_list:
            file_path, error = self.upload_df_as_parquet_file_to_minio(
             df=pd.json_normalize(std_list),
             file_name=f"AWSEFSList-{str(uuid.uuid4())}")
            if error:
                return self.upload_log_file([{"Error" : f"An error occurred while uplaoding 'AWSEFSList'. {error}"}])
            response['AWSEFSList'] = file_path
            
        if error_list:
            log_file_path, error = self.upload_file_to_minio(file_content=json.dumps(error_list).encode('utf-8'), 
                                                         file_name=f'LogFile-{str(uuid.uuid4())}.json', content_type='application/json')
            if error:
                return self.upload_log_file([{"Error" : f"An error occurred while uplaoding 'LogFile'. {error}"}])
            response['AWSEFSListLogFile'] = log_file_path

        return response
    

    def upload_log_file(self, errors_list):
        log_file_path, error = self.upload_file_to_minio(file_content=json.dumps(errors_list).encode('utf-8'), 
                                                         file_name=f'AWSEFSListLogFile-{str(uuid.uuid4())}.json', content_type='application/json')
        if error:
            return {'Error': error}
        return {'AWSEFSListLogFile': log_file_path}
    

    def validate(self):
        task_inputs = self.task_inputs
        if not task_inputs:
            return ['Task input is missing']

        # To track common error messages
        error_list = []

        user_object = task_inputs.user_object
        if not user_object or not user_object.app or not user_object.app.linked_applications:
            error_list.append("Linked Application is missing")
        else:
            linked_application = user_object.app.linked_applications
            if not cowdictutils.is_valid_key(linked_application, 'AWSAppConnector'):
                error_list.append("Linked Application 'AWSAppConnector' is missing")
            else:
                if not linked_application.get('AWSAppConnector')[0]['userDefinedCredentials']:
                    error_list.append("Linked Application 'AWSAppConnector' user defined credentials is missing")

        empty_inputs = []
        invalid_inputs = []

        user_inputs = task_inputs.user_inputs

        if not cowdictutils.is_valid_key(user_inputs, 'Region'):
            empty_inputs.append("Region")
        else:
            region = user_inputs.get('Region')
            if not isinstance(region, list):
                invalid_inputs.append("'Region' type is not supported. Region type is list")

        if invalid_inputs:
            error_list.append("Invalid task inputs: " + ", ".join(invalid_inputs))
        if empty_inputs:
            error_list.append("Empty task inputs: " + ", ".join(empty_inputs))

        return error_list
    

    def add_key_in_list(self, error_list: list):
        unique_list = list(set(error_list))
        updated_list = []
        for err in unique_list:
             updated_list.append({'Error': err})
        return updated_list