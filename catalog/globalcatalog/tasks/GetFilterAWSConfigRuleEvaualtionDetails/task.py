from typing import overload
from compliancecowcards.structs import cards
#As per the selected app, we're importing the app package 
from appconnections.awsappconnector import awsappconnector 
from compliancecowcards.utils import cowdictutils
import json
import pandas as pd
from io import StringIO
import numpy as np
import uuid


class Task(cards.AbstractTask):

    def execute(self) -> dict:

        error = self.check_inputs()
        if error:
            return self.upload_log_file([{'Error': error}])
        
        user_inputs = self.task_inputs.user_inputs
        config_rule = user_inputs.get("AWSConfigRule")
        
        ruleslist_df, error = self.get_json_file_from_minio(user_inputs.get("AWSConfigRulesFile"))
        if error:
            return self.upload_log_file([{'Error': error}])

        rulesevals_df, error = self.get_json_file_from_minio(user_inputs.get("AWSConfigRuleEvaluationStatusFile"))
        if error:
            return self.upload_log_file([{'Error': error}])

        ruledetails_df, error = self.get_json_file_from_minio(user_inputs.get("RuleConfigFile"))
        if error:
            return self.upload_log_file([{'Error': error}])
        
        empty_df_list = []
        
        if ruleslist_df is None:
            empty_df_list.append('AWSConfigRulesFile')
        if rulesevals_df is None:
            empty_df_list.append('AWSConfigRuleEvaluationStatusFile')
        if ruledetails_df is None:
            empty_df_list.append('RuleConfigFile')

        if empty_df_list:    
            return self.upload_log_file([{'Error': f"Empty input files: {', '.join(empty_df_list)}"}])

        try:
        
            ruledetails_df = ruledetails_df[ruledetails_df["RuleName"] == config_rule]
            if len(ruledetails_df) == 0:
                return self.upload_log_file([{'Error': f"Failed to fetch compliance details for config rule {config_rule} in 'RuleConfigFile'"}])
            
            mapping_dict = ruledetails_df.iloc[0].to_dict()
            evidence_name = mapping_dict['EvidenceName']

            # filtering status list based on rule name 
            rulesevals_df = rulesevals_df[rulesevals_df['EvaluationResult'].apply(lambda x: x['EvaluationResultIdentifier']['EvaluationResultQualifier']['ConfigRuleName']) == config_rule]

            if ruledetails_df.empty:
                return self.upload_log_file([{'Error': f"Failed to fetch evaluation details for config rule {config_rule}"}])

            aws_connector = awsappconnector.AWSAppConnector(
            user_defined_credentials=awsappconnector.UserDefinedCredentials.from_dict(
                self.task_inputs.user_object.app.user_defined_credentials
            )
        )
            
            # process each row and update standard_schema
            data = rulesevals_df.apply(lambda row : self.update_data(row, mapping_dict, aws_connector), axis=1)
            if data.empty:
                return self.upload_log_file([{'Error': "Failed to process AWS Config evaluation report. Please contact support for further details."}])

            output_data_json = data.to_json(orient="records")

            standard_file_name = f"{evidence_name}-{str(uuid.uuid4())}.json"
            standard_file, error = self.upload_file_to_minio(
                file_content= output_data_json,
                file_name=standard_file_name,
                content_type="application/json")
            if error:
                    return self.upload_log_file([{'Error': error}])


            return { "AwsConfigRuleFile": standard_file } 
        
        except (KeyError,IndexError) as e:
            return self.upload_log_file([{'Error': "Failed to generate the AWS Config evaluation report. Please contact support for further details."}])
    
    def get_json_file_from_minio(self, file_path):
           file_bytes, error = self.download_file_from_minio(file_path)
           if error:
              return None, error
           decoded_data = file_bytes.decode("utf-8")
           json_data = pd.read_json(decoded_data)
           return json_data, None
    
    def update_data(self,row, mapping_dict, aws_connector: awsappconnector.AWSAppConnector): 
             
            try:
            
                resource_id = row['EvaluationResult']['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId']
                resource_type = row['EvaluationResult']['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceType']
                resource_name = row['ResourceName']
                compiant_type = row['EvaluationResult']['ComplianceType']
                resource_location = row['AwsRegion']
                result_recorded_time = row['EvaluationResult']['ResultRecordedTime']

                complianceStatus_reason = ""
                validationStatus_code = ""
                validationStatus_notes = ""

                if compiant_type == "COMPLIANT":
                    complianceStatus_reason = mapping_dict[compiant_type][0].get("ComplianceStatusReason")
                    validationStatus_code = mapping_dict[compiant_type][0].get("ValidationStatusCode")
                    validationStatus_notes = mapping_dict[compiant_type][0].get("ValidationStatusNotes")
                else:
                    complianceStatus_reason = mapping_dict[compiant_type][0].get("ComplianceStatusReason")
                    validationStatus_code = mapping_dict[compiant_type][0].get("ValidationStatusCode")
                    validationStatus_notes = mapping_dict[compiant_type][0].get("ValidationStatusNotes")

                # fetch resource details to fetch resource url
                resource_info = self.get_resource_details(row, mapping_dict, aws_connector)
                resource_url = ''
                if resource_info:
                    resource = resource_info.get('resource', None)
                    parent_resource = resource_info.get('parentResource', None)
                    service = resource_info.get('service', None)
                    location = resource_info.get('location', None)

                    resource_info_dict = {
                        awsappconnector.RESOURCE_TYPE: service, 
                        awsappconnector.RESOURCE_FIELD: resource, 
                        awsappconnector.REGION_FIELD: location,
                        awsappconnector.RESOURCE_PARENT_FIELD: parent_resource
                        }

                    resource_url, _ = aws_connector.get_resource_url(resource_info_dict)
                    if not resource_url:
                        resource_url = 'N/A'

                rule_status = {  
                    "System": "aws", 
                    "Source": "aws_config", 
                    "ResourceId" : resource_id, 
                    "ResourceName" : resource_name, 
                    "ResourceType" : resource_type, 
                    "ResourceLocation" :resource_location,
                    "ResourceURL" : resource_url,
                    "ConfigRuleName" :mapping_dict['RuleName'],
                    "ValidationStatusCode" : validationStatus_code,
                    "ValidationStatusNotes" : validationStatus_notes,
                    "ComplianceStatus" : compiant_type,
                    "ComplianceStatusReason" : complianceStatus_reason,
                    "EvaluationTime" : result_recorded_time,
                    "UserAction": "",
                    "ActionStatus": "",
                    "ActionResponseURL": ""
                    }
                return rule_status
            except (IndexError,KeyError,AttributeError) as e:
                return {}


    def get_service_name(self, row, mapping_dict):

        resource_type = row['EvaluationResult']['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceType']

        if resource_type == 'AWS::::Account' and 'Service' in mapping_dict:
            # If the rule is account level validation, fetch the service name from config file
            return mapping_dict['Service']
        

        service_mapping = {
            'Trail': awsappconnector.CLOUDTRAIL,
            'User': awsappconnector.IAM_USER,
            'Policy': awsappconnector.IAM_POLICY,
            'Group': awsappconnector.IAM_GROUP,
            'Role': awsappconnector.IAM_ROLE,
            'RecoveryPoint' : awsappconnector.BACKUP_RECOVERY_PT,
            'LogGroup' : awsappconnector.CLOUD_WATCH_LOG_GRP,
            'Instance' : awsappconnector.EC2_INSTANCE,
        }

        # Use the service mapping or default to the original resource_type
        return service_mapping.get(resource_type.split(':')[-1], resource_type)

    def get_resource_details(self, row, mapping_dict, aws_connector: awsappconnector.AWSAppConnector):

        service = self.get_service_name(row, mapping_dict) 
        resource_id = row['EvaluationResult']['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId']
        resource_location = row['AwsRegion'] if 'AwsRegion' in row else ''
        if resource_location == 'global':
            resource_location = 'us-east-1'
        resource_info = {}
        resource_info['location'] = resource_location
        resource_info['service'] = service
        # handled recovery point seperately , since it requires resource and parent resource for the resource url
        if service == awsappconnector.BACKUP_RECOVERY_PT:
            parent_data = resource_id.split(':')
            resource_info['parentResource'] = parent_data[1]
            data = resource_id.split(':[')
            resource = data[1]
            resource_info['resource'] =resource.replace("]", "")
        else:
            # Fetch account details since some resource ARNs require the account number
            account = ''
            identifier_details, error = aws_connector.get_caller_identity()
            if error:
                return {}
            if identifier_details.empty or "Account" not in identifier_details:
                return {}
            account = identifier_details['Account'][0]
            resource_name = row['ResourceName']
            resource_info['resource'] = self.form_resource(service, resource_location, resource_id, account, resource_name)

        return resource_info   

   # form resource based on the service name
    def form_resource(self, service, location, resource_id, account, resource_name):

        if service == awsappconnector.CLOUDTRAIL:
            return f'arn:aws:cloudtrail:{location}:{account}:trail/{resource_id}'
        elif service == awsappconnector.IAM_POLICY:
            return f'arn:aws:iam::{account}:policy/{resource_name}'
        elif service == awsappconnector.CLOUDTRAIL_LIST:
            return ''
        elif service == awsappconnector.IAM_ROLE or service == awsappconnector.IAM_GROUP or service == awsappconnector.IAM_USER :
            return resource_name
        else:
            return resource_id
        

    def check_inputs(self):
        task_inputs = self.task_inputs
        if task_inputs is None:
            return 'Task inputs are missing'

        user_object = self.task_inputs.user_object
        if (
            user_object is None
            or user_object.app is None
            or user_object.app.user_defined_credentials is None
        ):
            return 'User defined credentials are missing"'

        if self.task_inputs.user_inputs is None:
            return 'User inputs are missing'
        
        empty_inputs = []
        if not cowdictutils.is_valid_key(self.task_inputs.user_inputs, "AWSConfigRulesFile"):
            empty_inputs.append('AWSConfigRulesFile')
        if not cowdictutils.is_valid_key(self.task_inputs.user_inputs, "AWSConfigRuleEvaluationStatusFile"):
            empty_inputs.append('AWSConfigRuleEvaluationStatusFile') 
        if not cowdictutils.is_valid_key(self.task_inputs.user_inputs, "RuleConfigFile"):
            empty_inputs.append('RuleConfigFile') 
        if not cowdictutils.is_valid_key(self.task_inputs.user_inputs, "AWSConfigRule"):
            empty_inputs.append('AWSConfigRule') 

        if empty_inputs:
            return f"Empty Inputs: {', '.join(empty_inputs)}"

        return None
    

    # upload log file
    def upload_log_file(self, errors_list):
        log_file_path, error = self.upload_file_to_minio(file_content=json.dumps(errors_list).encode('utf-8'), 
                                                         file_name=f'LogFile-{str(uuid.uuid4())}.json', content_type='application/json')
        if error:
            return {'Error': f"Error while uploading 'LogFile': {error}"}
        return {'LogFile': log_file_path}