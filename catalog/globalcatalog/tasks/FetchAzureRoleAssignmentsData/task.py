
from typing import Tuple
from compliancecowcards.structs import cards
#As per the selected app, we're importing the app package 
from applicationtypes.azureappconnector import azureappconnector
import pandas as pd
import copy

class Task(cards.AbstractTask):

    def execute(self) -> dict:
        error = self.check_inputs()
        if error:
            return self.upload_log_file_panic({'Error': error})

        azure_users_data, error = self.download_json_file_from_minio_as_dict(
            file_url=self.task_inputs.user_inputs["AzureUsersList"]
        )
        if error:
            return self.upload_log_file_panic({"Error": f"Error while downloading AzureUsersList file :: {error}"})
        
        azure_groups_data, error = self.download_json_file_from_minio_as_dict(
            file_url=self.task_inputs.user_inputs["AzureGroupsList"]
        )
        if error:
            return self.upload_log_file_panic({"Error": f"Error while downloading AzureGroupsList file :: {error}"})
        
        azure_service_principals_data, error = self.download_json_file_from_minio_as_dict(
            file_url=self.task_inputs.user_inputs["AzureServicePrincipalsData"]
        )
        if error:
            return self.upload_log_file_panic({"Error": f"Error while downloading AzureServicePrincipalsData file :: {error}"})
        
        role_definitions_data, error = self.download_json_file_from_minio_as_dict(
            file_url=self.task_inputs.user_inputs["AzureRoleDefinitionsData"]
        )
        if error:
            return self.upload_log_file_panic({"Error": f"Error while downloading AzureRoleDefinitionsData file :: {error}"})
        
        user_defined_credentials = (self.task_inputs.user_object.app).to_dict()
        azure_connector = azureappconnector.AzureAppConnector.from_dict(user_defined_credentials)

        role_assignments_data,error = azure_connector.get_role_assignments_details()
        if error:
            return self.upload_log_file_panic({"Error": f"Error while getting azure role assignments details :: {error}"})

        role_assignment_data = {
            "ResourceName": "",
            "ResourceID": "",
            "ResourceType": "",
            "RoleDefinitionID": "",
            "RoleAssignmentID": "",
            "RoleName": "",
            "RoleType": "",
            "RoleDescription": "",
            "Scope": "",
            "Permissions": None,
            "Condition": None,
            "ConditionVersion": None,
            "RoleCreatedOn": "",
            "RoleUpdatedOn": "",
            "RoleCreatedBy": "",
            "RoleUpdatedBy": "",
        }

        output_data = []
        for data in role_assignments_data :
            role_assignment_data_temp = copy.copy(role_assignment_data)
            properties =  data.get("properties")
            if properties :
                if properties.get("roleDefinitionId" , "")  != "":
                    filtered_role_definitions_data = self.filter_data(properties.get("roleDefinitionId") , role_definitions_data)

                    role_assignment_data_temp["RoleName"]=filtered_role_definitions_data.get("PropertiesRoleName")
                    role_assignment_data_temp["RoleType"]=filtered_role_definitions_data.get("PropertiesType")
                    role_assignment_data_temp["RoleDescription"]=filtered_role_definitions_data.get("PropertiesDescription")
                    role_assignment_data_temp["Permissions"]=filtered_role_definitions_data.get("PropertiesPermissions")

                filtered_principal_data = None

                if properties.get("principalId") :
                    if properties.get("principalType")  == "User"  :
                        filtered_principal_data = self.filter_data(properties.get("principalId") , azure_users_data)
                        if filtered_principal_data :
                            role_assignment_data_temp["ResourceName"]=filtered_principal_data.get("UserPrincipalName")
                            role_assignment_data_temp["ResourceType"] = "User"

                    elif properties.get("principalType")  == "Groups"  :
                        filtered_principal_data = self.filter_data(properties.get("principalId") , azure_groups_data)
                        if filtered_principal_data :
                            role_assignment_data_temp["ResourceName"]=filtered_principal_data.get("DisplayName")
                            role_assignment_data_temp["ResourceType"] = "Group"

                    elif properties.get("principalType")  == "ServicePrincipal"  :
                        filtered_principal_data = self.filter_data(properties.get("principalId") , azure_service_principals_data)
                        if filtered_principal_data :
                            role_assignment_data_temp["ResourceName"]=filtered_principal_data.get("AppDisplayName")
                            role_assignment_data_temp["ResourceType"] = "ServicePrincipal"

                if filtered_principal_data :
                    role_assignment_data_temp["ResourceID"]=filtered_principal_data.get("ResourceID")

                role_assignment_data_temp.update({
                    "RoleDefinitionID": properties.get("roleDefinitionId"),
                    "RoleAssignmentID": data.get("id"),
                    "Scope": properties.get("scope"),
                    "Condition": properties.get("condition"),
                    "ConditionVersion": properties.get("conditionVersion"),
                    "RoleCreatedOn": properties.get("createdOn"),
                    "RoleUpdatedOn": properties.get("updatedOn"),
                    "RoleCreatedBy": properties.get("createdBy"),
                    "RoleUpdatedBy": properties.get("updatedBy"),
                })

            new_flattened_output = azure_connector.replace_empty_dicts_with_none(role_assignment_data_temp)

            flattened_output = azure_connector.flatten_json(new_flattened_output)
            output_data.append(flattened_output)

        output_data_df = pd.DataFrame(output_data)
        file_url, error = self.upload_output_file(output_data_df, "AzureRoleAssignmentsData")
        if error:
            return self.upload_log_file_panic(error)

        response = {
            "AzureRoleAssignmentsData" : file_url
        }

        return response
    
    def filter_data(self,id_to_compare,data_list) :
        for data in data_list :
            id = data.get("ResourceID")
            if id and id == id_to_compare :
                return data
            
    def upload_log_file(self, error_data) -> Tuple[str, dict]:
        if not isinstance(error_data, list):
            error_data = [error_data]
        file_url, error = self.upload_df_as_json_file_to_minio(
            df=pd.DataFrame(error_data),
            file_name="LogFile"
        )
        if error:
            return None, {'Error': f"Error while uploading LogFile :: {error}"}
        return file_url, None
    
    def upload_log_file_panic(self, error_data) -> dict:
        file_url, error = self.upload_log_file(error_data)
        if error:
            return error
        return { 'LogFile': file_url }
    
    def upload_output_file(self, output_data: pd.DataFrame, file_name) -> Tuple[str, dict]:
        if output_data.empty:
            return None, None
        
        file_url, error = self.upload_df_as_json_file_to_minio(
            df=output_data,
            file_name=file_name
        )
        if error:
            return None, { 'Error': f"Error while uploading {file_name} file :: {error}" }
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
        if not self.task_inputs.user_inputs.get("AzureUsersList"):
            emptyAttrs.append("AzureUsersList")
        if not self.task_inputs.user_inputs.get("AzureGroupsList"):
            emptyAttrs.append("AzureGroupsList")
        if not self.task_inputs.user_inputs.get("AzureServicePrincipalsData"):
            emptyAttrs.append("AzureServicePrincipalsData")
        if not self.task_inputs.user_inputs.get("AzureRoleDefinitionsData"):
            emptyAttrs.append("AzureRoleDefinitionsData")
        
        return "The following inputs: " + ", ".join(
            emptyAttrs) + " is/are empty, please check the user inputs." if emptyAttrs else ""