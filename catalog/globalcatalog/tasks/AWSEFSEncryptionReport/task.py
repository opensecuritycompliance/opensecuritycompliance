
from typing import overload
from compliancecowcards.structs import cards 
#As per the selected app, we're importing the app package 
from appconnections.kubernetes import kubernetes
from compliancecowcards.utils import cowdictutils
import json
import uuid
import urllib.parse
import pandas as pd
from datetime import datetime, timezone

class Task(cards.AbstractTask):

    def execute(self) -> dict:

        log_response = {} 

        k8s_pv_list_log_file = self.task_inputs.user_inputs.get("KubernetesPVListLogFile")
        k8s_pv_list = self.task_inputs.user_inputs.get("KubernetesPVList")
        aws_efs_list_log_file = self.task_inputs.user_inputs.get("AWSEFSListLogFile")
        aws_efs_list = self.task_inputs.user_inputs.get("AWSEFSList")

        if k8s_pv_list_log_file and not k8s_pv_list:
            log_response['KubernetesPVListLogFile'] = k8s_pv_list_log_file

        if aws_efs_list_log_file and not aws_efs_list:
            log_response['AWSEFSListLogFile'] = aws_efs_list_log_file
            if k8s_pv_list_log_file:
                log_response['KubernetesPVListLogFile'] = k8s_pv_list_log_file

        if log_response:
            return log_response
        
        error_list = self.validate()
        if error_list:
            return self.upload_log_file(self.add_key_in_list(error_list)) 

        # download and validate AWSEFSList
        aws_efs_df, error = self.download_parquet_file_from_minio_as_df(
            self.task_inputs.user_inputs.get('AWSEFSList'))
        if error:
            return self.upload_log_file([{"Error" : f"Error while downloading 'AWSEFSList'. {error}"}])
        if aws_efs_df.empty:
            return self.upload_log_file([{"Error" : "Provided 'AWSEFSList' is empty. Please provide a valid 'AWSEFSList'"}]) 
        aws_efs_columns = {
              'ResourceID', 'ResourceName', 'ResourceType', 'CreatedDateTime', 'IsEncrypted', 'KmsKeyID', 
              'KeyManager', 'KeyLastRotationDate', 'ResourceURL'}
        if not aws_efs_columns.issubset(aws_efs_df.columns):
            columns_not_present = set(aws_efs_columns) - set(aws_efs_df.columns)
            msg = ''
            if columns_not_present:
                   msg = "Missing column: " + ', '.join(columns_not_present)
            return self.upload_log_file([{'Error': f"Invalid 'AWSEFSList' file. {msg}"}])
    
        # download and validate KubernetesPVList
        k8s_pvs_df, error = self.download_parquet_file_from_minio_as_df(
            self.task_inputs.user_inputs.get('KubernetesPVList'))
        if error:
            return self.upload_log_file([{"Error" : f"Error while downloading 'KubernetesPVList'. {error}"}])
        if k8s_pvs_df.empty:
            return self.upload_log_file([{"Error" : "Provided 'KubernetesPVList' is empty. Please provide a valid 'KubernetesPVList'"}])
        k8s_pvs_columns = {'ResourceID', 'ResourceName', 'ClaimName', 'ClaimNameSpace', 'ClusterName'}
        if not k8s_pvs_columns.issubset(k8s_pvs_df.columns):
            columns_not_present = set(k8s_pvs_columns) - set(k8s_pvs_columns.columns)
            if columns_not_present:
                   msg = "Missing column: " + ', '.join(columns_not_present)
            return self.upload_log_file([{'Error': f"Invalid 'KubernetesPVList' file. {msg}"}])
        
        
        std_list, error_list = self.standardize_records(aws_efs_df, k8s_pvs_df)

        response = {}

        if not std_list:
            error_list.append({"Error": "No Elastic File System was found for the provided AWS credentials or for the specified region"})

        if error_list:
            result =  self.upload_log_file(error_list)
            if cowdictutils.is_valid_key(result, 'Error'):
                return result
            response['AWSEFSEncryptionReportLogFile'] = result['AWSEFSEncryptionReportLogFile']
        
        if std_list:
            file_path, error = self.upload_df_as_parquet_file_to_minio(
                df=pd.json_normalize(std_list),
                file_name=f"AWSEFSEncryptionReport-{str(uuid.uuid4())}")
            response['AWSEFSEncryptionReport'] = file_path

        
        if  self.task_inputs.user_inputs.get("AWSEFSListLogFile") and  self.task_inputs.user_inputs.get("AWSEFSList"):
            response['AWSEFSListLogFile'] = self.task_inputs.user_inputs.get("AWSEFSListLogFile")
        
        if  self.task_inputs.user_inputs.get("AWSEFSListLogFile") and  self.task_inputs.user_inputs.get("AWSEFSList"):
            response['AWSEFSListLogFile'] = self.task_inputs.user_inputs.get("AWSEFSListLogFile")
        
        if  self.task_inputs.user_inputs.get("KubernetesPVListLogFile") and  self.task_inputs.user_inputs.get("KubernetesPVList"):
            response['KubernetesPVListLogFile'] = self.task_inputs.user_inputs.get("KubernetesPVListLogFile")

        return response


    def standardize_records(self, aws_efs_df, k8s_pvs_df):

        # VolumeHandle conversion to EFS file system id
        # To link with EFS File List
        k8s_pvs_df['VolumeHandle'] = k8s_pvs_df['VolumeHandle'].apply(self.split_id)

        k8_pvs_list = k8s_pvs_df.to_dict('records')
        std_list = []
        err_list = []

        try:

            for pv in k8_pvs_list:

                # Fetch EFS details corresponding to K8s cluster volume
                efs_details  = aws_efs_df[aws_efs_df['ResourceID'] == pv['VolumeHandle']]

                if not efs_details.empty:

                    efs_name     = efs_details['ResourceName'].values[0]
                    is_encrypted = efs_details['IsEncrypted'].values[0]

                    data = {
                            "System"              : "aws, kubernetes",
                            "Source"              : "compliancecow",
                            "ResourceID"          : efs_details['ResourceID'].values[0],
                            "ResourceName"        : efs_name,
                            "ResourceType"        : "AWS - Elastic File System",
                            "ResourceURL"         : efs_details['ResourceURL'].values[0],
                            "CreatedDateTime"     : efs_details['CreatedDateTime'].values[0],
                            "IsEncrypted"         : is_encrypted,
                            "KmsKeyID"            : efs_details['KmsKeyID'].values[0],
                            "KeyManager"          : efs_details['KeyManager'].values[0],
                            "KeyLastRotationDate" : efs_details['KeyLastRotationDate'].values[0],
                            "K8sClusterName"      : pv['ClusterName'],
                            "K8sVolume"           : pv['ResourceName'],
                            "K8sVolumeID"         : pv['ResourceID'],
                            "K8sVolumeClaim"      : pv['ClaimName'],
                            "K8sNamespace"        : pv['ClaimNameSpace']
                        }
                    
                    val_code = "EFS_ENCR"
                    val_notes = "Elastic File System is encrypted"
                    com_status = "COMPLIANT"
                    com_reason = f"The record is compliant as the EFS '{efs_name}' is encrypted. Encrypting volumes in Kubernetes enhances data security and ensuring compliance with regulatory standards without compromising performance or scalability."

                    if not is_encrypted:
                        val_code = "EFS_NOT_ENCR"
                        val_notes = "Elastic File System is not encrypted"
                        com_status = "NON_COMPLIANT"
                        com_reason = f"The record is not compliant as the EFS '{efs_name}' is not encrypted. Not encrypting volumes in Kubernetes exposes sensitive data to unauthorized access and potential breaches, while risking non-compliance with regulatory standards and legal consequences."

                    data['ValidationStatusCode'] = val_code
                    data['ValidationStatusNotes'] = val_notes
                    data['ComplianceStatus'] = com_status
                    data['ComplianceStatusReason'] = com_reason
                    data['EvaluatedTime'] = self.get_current_datetime()
                    data['UserAction'] = ''
                    data['ActionStatus'] = ''
                    data['ActionResponseURL'] = ''

                    std_list.append(data)
            
        except KeyError as e:
            err_list.append([f'Failed to generate AWSEFSEncryptionReport. KeyError exception occured. Invalid key : {str(e)}'])
        except AttributeError as e:
            err_list.append([f'Failed to generate AWSEFSEncryptionReport. Attribute exception occured. {str(e)}'])

        return std_list, err_list
                
                
    def get_current_datetime(self):
        current_time = datetime.now(timezone.utc)
        formatted_time = current_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        return formatted_time

    def split_id(self,volume_hanlde):
        try:
           return volume_hanlde.split("::")[0]
        except (AttributeError, IndexError):
           return ''
    
    def upload_log_file(self, errors_list):
        log_file_path, error = self.upload_file_to_minio(file_content=json.dumps(errors_list).encode('utf-8'), 
                                                         file_name=f'AWSEFSEncryptionReportLogFile-{str(uuid.uuid4())}.json', content_type='application/json')
        if error:
            return {'Error': error}
        return {'AWSEFSEncryptionReportLogFile': log_file_path}
    
    def validate(self):
        task_inputs = self.task_inputs
        if not task_inputs:
            return ['Task input is missing']

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
                    error_list.append("Linked Application 'AWSAppConnector' user defined credential is missing")

        empty_inputs = []
        invalid_inputs = []

        user_inputs = task_inputs.user_inputs
        if cowdictutils.is_valid_key(user_inputs, 'KubernetesPVListLogFile'):
            log_file_url = self.task_inputs.user_inputs.get("KubernetesPVListLogFile")
            if not isinstance(log_file_url, str):
                invalid_inputs.append("'KubernetesPVListLogFile' type is not supported. Supported type is string")
            else:
                is_valid = self.is_valid_url(log_file_url)
                if not is_valid:
                    invalid_inputs.append("'KubernetesPVListLogFile' is not valid URL. Please provide a valid URL.")
        
        if cowdictutils.is_valid_key(user_inputs, 'AWSEFSListLogFile'):
            log_file_url = self.task_inputs.user_inputs.get("AWSEFSListLogFile")
            if not isinstance(log_file_url, str):
                invalid_inputs.append("'AWSEFSListLogFile' type is not supported. Supported type is string")
            else:
                is_valid = self.is_valid_url(log_file_url)
                if not is_valid:
                    invalid_inputs.append("'AWSEFSListLogFile' is not valid URL. Please provide a valid URL.")

        if not cowdictutils.is_valid_key(user_inputs, 'AWSEFSList'):
            empty_inputs.append("'AWSEFSList'")
        else:
            efs_url = self.task_inputs.user_inputs.get("AWSEFSList")
            if not isinstance(efs_url, str):
                invalid_inputs.append("'AWSEFSList' type is not supported. Supported type is string")
            else:
                is_valid = self.is_valid_url(efs_url)
                if not is_valid:
                    invalid_inputs.append("'AWSEFSList'")

        if not cowdictutils.is_valid_key(user_inputs, 'KubernetesPVList'):
            empty_inputs.append("'KubernetesPVList'")
        else:
            pvs_url = self.task_inputs.user_inputs.get("KubernetesPVList")
            if not isinstance(pvs_url, str):
                invalid_inputs.append("'KubernetesPVList'")
            else:
                is_valid = self.is_valid_url(pvs_url)
                if not is_valid:
                    invalid_inputs.append("'KubernetesPVList'")

        if empty_inputs:
            error_list.append("Empty task inputs: " + ", ".join(empty_inputs))
        if invalid_inputs:
            error_list.append("Invalid task inputs: " + ", ".join(invalid_inputs))

        return error_list
    
    
    def is_valid_url(self, url):
        try:
            result = urllib.parse.urlparse(url)
            if not all([result.scheme, result.netloc]):
                return False
        except ValueError:
            return False
        return True
    
    def add_key_in_list(self, error_list: list):
        unique_list = list(set(error_list))
        updated_list = []
        for err in unique_list:
             updated_list.append({'Error': err})
        return updated_list