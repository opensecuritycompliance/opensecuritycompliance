from typing import overload
from compliancecowcards.structs import cards
from io import StringIO
# As per the selected app, we're importing the app package
from appconnections.awsappconnector import awsappconnector
from compliancecowcards.utils import cowdictutils
import pandas as pd
import json
import numpy as np
import uuid


class Task(cards.AbstractTask):

    def execute(self) -> dict:
        error = self.check_inputs()
        if error:
            return self.upload_audit_file([{'Error': error}])

        user_inputs = self.task_inputs.user_inputs

        findings_file = user_inputs.get('SecurityHubFindingsFile', '')
        control_config_file = user_inputs.get('ControlConfigFile', '')
        control_name = user_inputs.get('ControlName', '')

        if findings_file and control_config_file and control_name:
            findings_df, error = self.download_json_file(findings_file)
            if error:
                return self.upload_audit_file([{'Error': f"Error while downloading 'SecurityHubFindingsFile' {error}"}])

            control_config_df, error = self.download_json_file(
                control_config_file)
            if error:
                return self.upload_audit_file([{'Error': f"Error while downloading 'ControlConfigFile' {error}"}])

            findings_columns = {'Compliance',
                                'ProductFields', 'Resources', 'CreatedAt'}
            control_config_columns = {'ControlName', 'EvidenceName',
                                      'COMPLIANT', 'NON_COMPLIANT', 'NOT_DETERMINED'}

            aws_connector = awsappconnector.AWSAppConnector()

            try:
                if not findings_df.empty and findings_columns.issubset(set(findings_df.columns)) and not control_config_df.empty and control_config_columns.issubset(set(control_config_df.columns)):
                    config_df = control_config_df[control_config_df['ControlName']
                                                == control_name]
                    if config_df.empty:
                        return self.upload_audit_file([{'Error': f'Failed to {control_name} details in ControlConfigFile'}])
                    mapping_dict = config_df.iloc[0].to_dict()
                    # https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-controls-reference.html
                    filtered_df = findings_df[findings_df['Compliance'].apply(
                        lambda x: x.get('SecurityControlId', '') == control_name)]
                    if not filtered_df.empty:
                        filtered_data = filtered_df.apply(
                            lambda x: self.process_finding(x, mapping_dict, aws_connector), axis=1)
                        output_file_path, error = self.upload_output_file(
                            mapping_dict['EvidenceName'], filtered_data)
                        if error:
                            return self.upload_audit_file([{'Error': error}])
                        return {'SecurityHubReport': output_file_path}
                    else:
                        return self.upload_audit_file([{'Error': 'Failed to generate the filtered SecurityHubReport based on user inputs. Please contact support for further details.'}])             
                else:
                    return self.upload_audit_file([{'Error': 'Not a valid input data. Please contact support for further details'}])
                    
            except (IndexError,KeyError):
                return self.upload_audit_file([{'Error': 'Failed to generate SecurityHubReport. Please contact support for further details'}])
            
        else:
            return self.upload_audit_file([{'Error': 'Input file(s) should not be empty. Please try again with valid files.'}])


    def download_json_file(self, file_path):
        record_bytes, error = self.download_file_from_minio(file_url=file_path)
        if error:
            return None, error
        try:
            return pd.read_json(StringIO(record_bytes.decode('utf-8')), orient='records'), None
        except Exception as e:
            return None, str(e)

    def process_finding(self, finding, mapping_dict, aws_connector: awsappconnector.AWSAppConnector):
        response = {}
        try:
            compliance = finding['Compliance']
            resources = finding['Resources'][0] if finding['Resources'] else None

            compliance_status = compliance.get('Status')
            validation_status_code = compliance['StatusReasons'][0][
                'ReasonCode'] if 'StatusReasons' in compliance and compliance['StatusReasons'] else None
            validation_status_notes = compliance['StatusReasons'][0][
                'Description'] if 'StatusReasons' in compliance and compliance['StatusReasons'] else None

            if compliance_status == 'PASSED' and validation_status_code is None:
                compliance_status = 'COMPLIANT'
            elif compliance_status == 'FAILED':
                compliance_status = 'NON_COMPLIANT'
            else:
                compliance_status = 'NOT_DETERMINED'

            if compliance_status == 'COMPLIANT':
                compliance_status_reason = mapping_dict[compliance_status].get(
                    'ComplianceStatusReason')
            elif compliance_status == 'NON_COMPLIANT':
                if validation_status_code is None:
                    compliance_status_reason = mapping_dict[compliance_status].get(
                        'ComplianceStatusReason')
                else:
                    compliance_status_reason = validation_status_notes
            else:
                compliance_status_reason = mapping_dict[compliance_status].get(
                    'ComplianceStatusReason')

            if validation_status_code is None and validation_status_notes is None and compliance_status in mapping_dict:
                validation_status_code = mapping_dict[compliance_status].get(
                    'ValidationStatusCode')
                validation_status_notes = mapping_dict[compliance_status].get(
                    'ValidationStatusNotes')

            resource_url = ''
            # fecting resource details to fetch the resource url     
            resource_info = self.get_resource_info(resources, mapping_dict)
            resource_id = resource_info.get('resource_id', None)
            resource_name = resource_info.get('resource_name', None)
            resource_type = resource_info.get('resource_type', None)
            resource_location = resource_info.get('resource_location', None)
            service = resource_info.get('service', None)
            resource = resource_info.get('resource', None)

            if 'MULTIPLE_RESOURCE_URLS' in mapping_dict:
                for data in mapping_dict['MULTIPLE_RESOURCE_URLS']:
                    url_parts = data.split(":")
                    resource_info_dict = {
                        awsappconnector.RESOURCE_TYPE: url_parts[0], 
                        awsappconnector.REGION_FIELD: resource_location,
                        }
                    resource_url, err = aws_connector.get_resource_url(resource_info_dict)
                    if err:
                        resource_url = 'N/A'
                    response[url_parts[1]] = resource_url
            else:

                resource_info_dict = {
                        awsappconnector.RESOURCE_TYPE: service, 
                        awsappconnector.RESOURCE_FIELD: resource, 
                        awsappconnector.REGION_FIELD: resource_location,
                        }
                resource_url, err = aws_connector.get_resource_url(resource_info_dict)
                if err:
                    resource_url = 'N/A'

            
            response = {
                'System': 'aws',
                'Source': 'aws_security_hub',
                'ResourceID': resource_id,
                'ResourceName': resource_name,
                'ResourceType': resource_type,
                'ResourceLocation': resource_location,
                'ResourceTags': resources['Tags'] if resources and 'Tags' in resources else None,
                'ResourceUrl' : resource_url,
                'ValidationStatusCode': validation_status_code,
                'ValidationStatusNotes': validation_status_notes,
                'ComplianceStatus': compliance_status,
                'ComplianceStatusReason': compliance_status_reason,
                'EvaluatedTime': finding['UpdatedAt'],
                'UserAction': '',
                'ActionStatus': '',
                'ActionResponseURL': ''
            }

            return response
        except (KeyError,IndexError):
            return response        

    
    def get_resource_info(self, resources, mapping_dict):

        resource_info = {}

        try:

            resource_id = resources.get('Id')
            resource_info['resource_id'] = resource_id
            resource_name = resource_id.split('/')[-1] if resource_id else None
            resource_info['resource_name'] = resource_name

            resource_type = resources.get('Type')
            resource_info['resource_type'] = resource_type

            resource_location = resources.get('Region') if resources else None
            resource_location = resource_location if resource_location not in ('', 'global') else 'us-east-1'
            resource_info['resource_location'] = resource_location

            # fetching service and resource for resource url
            service = mapping_dict.get('Service') if resource_type == 'AwsAccount' else resource_type
            resource = '' if resource_type == 'AwsAccount' else self.form_resource(service, resource_id, resource_name)

            resource_info.update({
            'service': service,
            'resource': resource
            })

            return resource_info
        except (IndexError, KeyError):
            return resource_info

    def form_resource(self, service, resource_id, resource_name):
       # The following services have resource name as their identifier, while other resources have resource ID.
       name_as_resource = {awsappconnector.KMS, awsappconnector.EC2_SECURITY_GROUP, awsappconnector.VPC}
       return resource_name if service in name_as_resource else resource_id

    def upload_output_file(self, file_name, data):
        output_data_json = data.to_json(orient='records').encode('utf-8')
        file_name = f'{file_name}-{str(uuid.uuid4())}.json'
        absolute_file_path, error = self.upload_file_to_minio(
            file_name=file_name,
            file_content=output_data_json,
            content_type='application/json',
        )
        if error:
            return '', error

        return absolute_file_path, None
    
    def upload_audit_file(self, errors_list):
        log_file_path, error = self.upload_file_to_minio(file_content=json.dumps(errors_list).encode('utf-8'), 
                                                         file_name=f'LogFile-{str(uuid.uuid4())}.json', content_type='application/json')
        if error:
            return {'Error': f"Error while uploading 'LogFile': {error}"}
        return {'LogFile': log_file_path}

    
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
        if not cowdictutils.is_valid_key(self.task_inputs.user_inputs, "SecurityHubFindingsFile"):
            empty_inputs.append('SecurityHubFindingsFile')
        if not cowdictutils.is_valid_key(self.task_inputs.user_inputs, "ControlName"):
            empty_inputs.append('ControlName') 
        if not cowdictutils.is_valid_key(self.task_inputs.user_inputs, "ControlConfigFile"):
            empty_inputs.append('ControlConfigFile') 

        if empty_inputs:
            return f"Empty Inputs: {', '.join(empty_inputs)}"

        return None