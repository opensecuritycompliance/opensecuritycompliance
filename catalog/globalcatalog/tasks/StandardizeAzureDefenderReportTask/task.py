
from typing import Tuple
from compliancecowcards.structs import cards
#As per the selected app, we're importing the app package 
import pandas as pd
from applicationtypes.azureappconnector import azureappconnector

RESOURCE_GROUPS_TYPE_MAPPING = {
    # caseinsensitive: CorrectCase
    "virtualnetworks": "VirtualNetworks",
    "managedclusters": "ManagedClusters"
}


class Task(cards.AbstractTask):

    def execute(self) -> dict:

        error = self.check_inputs()
        if error:
            return self.upload_log_file_panic({'Error': error})
        
        user_defined_credentials = (self.task_inputs.user_object.app).to_dict()
        azure_connector = azureappconnector.AzureAppConnector.from_dict(user_defined_credentials)
        
        rule_config_list, error = self.download_json_file_from_minio_as_dict(self.task_inputs.user_inputs.get("RuleConfig"))
        if error:
            return self.upload_log_file_panic({'Error': f'Error while downloading RuleConfig :: {error}'})
        
        rule_name = self.task_inputs.user_inputs.get("RuleDisplayName" , "")

        filtered_rule_config_data = {}
        for rule_config_temp in rule_config_list :
            if rule_config_temp["RuleDisplayName"] == rule_name:
                filtered_rule_config_data = rule_config_temp # break

        evidence_name = str(filtered_rule_config_data.get("EvidenceName" , ""))
        if evidence_name == "":
            return self.upload_log_file_panic({'Error': f"EvidenceName is missing in RuleConfig for '{rule_name}'"})
        
        azure_report_df, error = self.download_json_file_from_minio_as_df(self.task_inputs.user_inputs.get("AzureReportData"))
        if error:
            return self.upload_log_file_panic({'Error': f'Error while downloading AzureReportData :: {error}'})

        output = []
        for _, azure_report in azure_report_df.iterrows():
            # Continue only if 'DisplayName' of azure_report matches with rule input 'RuleDisplayName'
            report_properties = azure_report.get('Properties', {})
            display_name = report_properties.get('DisplayName', '')
            if display_name != rule_name:
                continue

            azure_report = azure_report.to_dict()
            resource_id = ""
            status_code = ""
            properties = azure_report.get("Properties",None) 
            if properties != None  :
                status = properties.get("Status" ,None) 
                if status != None :
                    status_code = status.get("Code" , "") 
                
                resource_details = properties.get("ResourceDetails" ,None) 
                if resource_details != None :
                    resource_id = resource_details.get("ID" , "")

            validation_status_code = ""
            validation_status_notes = ""
            compliance_status = ""
            compliance_status_reason = ""
            compliant_config= {}

            if status_code == "Healthy" :
                compliant_config = filtered_rule_config_data.get("COMPLIANT" , None)
                if compliant_config == None :
                    return self.upload_log_file_panic({"Error" : "RuleConfig has no data for COMPLIANT field"})
                compliance_status = "COMPLIANT"

            elif status_code == "Unhealthy" :
                compliant_config = filtered_rule_config_data.get("NON_COMPLIANT" , None)
                if compliant_config == None :
                    return self.upload_log_file_panic({"Error" : "RuleConfig has no data for NON_COMPLIANT field"})
                compliance_status = "NON_COMPLIANT"

            elif status_code == "NotApplicable" :
                compliant_config = filtered_rule_config_data.get("NotApplicable" , None)
                if compliant_config == None :
                    return self.upload_log_file_panic({"Error" : "RuleConfig has no data for NotApplicable field"})
                compliance_status = "NOT_DETERMINED"

            validation_status_code = compliant_config.get("ValidationStatusCode" , "")
            validation_status_notes = compliant_config.get("ValidationStatusNotes" , "")
            compliance_status_reason = compliant_config.get("ComplianceStatusReason" , "")
            resource_name,resource_type = self.extract_fields_from_id(resource_id)
            evaluated_time = azure_connector.get_current_datetime()

            resource_url, error = azure_connector.get_resource_url(resource_id)
            if error:
                resource_url = ""

            output_report = {
                "System":"azure",
                "Source":"azure_defender",

                "ResourceID":resource_id,
                "ResourceURL": resource_url,
                "ResourceName": resource_name,
                "ResourceType": resource_type,
                "ResourceLocation":"",
                "ResourceTags":None,

                "RuleDisplayName": rule_name,

                "ValidationStatusCode":validation_status_code,
                "ValidationStatusNotes":validation_status_notes,
                "ComplianceStatus":compliance_status,
                "ComplianceStatusReason":compliance_status_reason,
                
                "EvaluatedTime":evaluated_time,
                'UserAction': '',
                'ActionStatus': '',
                'ActionResponseURL': ''
            }

            output.append(output_report)

        file_url, error = self.upload_output_file(
            output_data=pd.DataFrame(output),
            file_name=evidence_name
        )
        if error:
            return self.upload_log_file_panic(error)
        
        response = {
            "AzureDefenderReport" : file_url
        }

        return response

    def extract_fields_from_id(self,s) :

        resourceGroups,resourceGroupsType = "",""

        parts: list[str] = s.split("/")
        resourceGroupsType = parts[-2][:1].upper() + parts[-2][1:]
        
        resourceGroups = parts[4] if len(parts) > 3 else s
        
        for resource_type_insensitive, resource_type_sensitive in RESOURCE_GROUPS_TYPE_MAPPING.items():
            if resource_type_insensitive.casefold() == resourceGroupsType.casefold():
                resourceGroupsType = resource_type_sensitive
        
        return resourceGroups, resourceGroupsType
    
    def upload_output_file(self, output_data: pd.DataFrame, file_name) -> Tuple[str, dict]:
        if output_data.empty:
            return None, None
        
        file_url, error = self.upload_df_as_parquet_file_to_minio(
            df=output_data,
            file_name=file_name
        )
        if error:
            return None, { 'error': f"Error while uploading {file_name} file :: {error}" }
        return file_url, None
    
    def check_inputs(self) -> str:
        if self.task_inputs is None:
            return 'Task inputs are missing'
        user_object = self.task_inputs.user_object
        if (
            user_object is None
            or user_object.app is None
            or user_object.app.application_url is None
            or user_object.app.user_defined_credentials is None
        ):
            return 'User defined credentials are missing"'
        
        emptyAttrs = []
        if self.task_inputs.user_inputs is None:
            emptyAttrs.append("User inputs")
        if not self.task_inputs.user_inputs.get("RuleDisplayName"):
            emptyAttrs.append("RuleDisplayName")
        if not self.task_inputs.user_inputs.get("RuleConfig"):
            emptyAttrs.append("RuleConfig")
        if not self.task_inputs.user_inputs.get("AzureReportData"):
            emptyAttrs.append("AzureReportData")
        
        return "The following inputs: " + ", ".join(
            emptyAttrs) + " is/are empty" if emptyAttrs else ""

