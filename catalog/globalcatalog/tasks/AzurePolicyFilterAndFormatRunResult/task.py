from compliancecowcards.structs import cards
from typing import Tuple
# As per the selected app, we're importing the app package
import pandas as pd
from applicationtypes.azureappconnector import azureappconnector
import re

class Task(cards.AbstractTask):
    def execute(self) -> dict:
        error = self.check_inputs()
        if error:
            return self.upload_log_file_panic({'Error': error})

        # download policy summary file
        run_result_df, error = self.download_json_file_from_minio_as_df(
            file_url=self.task_inputs.user_inputs["AzurePolicyRunResultFilePath"]
        )
        if error:
            return self.upload_log_file_panic({"Error": f"Error while downloading AzurePolicyRunResultFilePath file :: {error}"})
        
        # download status values file
        control_status_vals_df, error = self.download_json_file_from_minio_as_df(
            file_url=self.task_inputs.user_inputs["ControlConfigFilePath"]
        )
        if error:
            return self.upload_log_file_panic({"Error": f"Error while downloading ControlConfigFilePath file :: {error}"})

        control_name = self.task_inputs.user_inputs.get("ControlName", "")
        control_status_df: pd.DataFrame = control_status_vals_df[control_status_vals_df["ControlName"] == control_name]
        control_status_dict = control_status_df.to_dict(orient="records")
        
        app = azureappconnector.AzureAppConnector(
            user_defined_credentials=azureappconnector.UserDefinedCredentials.from_dict(self.task_inputs.user_object.app.user_defined_credentials)
        )

        # List of columns
        required_columns = ["ResourceId", "ResourceType", "ResourceLocation", "PolicyDefinitionReferenceId", "ComplianceState", "Timestamp"]
        # check whether columns are present
        is_subset = set(required_columns).issubset(run_result_df.columns)
        if not is_subset:
            return self.upload_log_file_panic({"Error": f"The following columns are missing in policy summary: {set.difference(set(required_columns), run_result_df.columns)}"})

        # fiter item with control name
        control_df: pd.DataFrame = run_result_df[run_result_df["PolicyDefinitionReferenceId"] == control_name]
        response = {}
        if control_df.empty:
            return self.upload_log_file_panic({"Error": f"'{control_name}' Policy Not Found."})
        
        control_df = control_df[required_columns].rename(
            columns={
                "ResourceId": "ResourceID",
                "PolicyDefinitionReferenceId": "ControlName",
                "ComplianceState": "ComplianceStatus",
                "Timestamp": "EvaluatedTime"
            }
        )

        control_df["System"] = "azure"
        control_df["Source"] = "azure_policy"
        control_df["ResourceTags"] = ""
        control_df["UserAction"] = ""
        control_df["ActionStatus"] = ""
        control_df["ActionResponseURL"] = ""

        # Get ResourceURL
        def get_resource_url(resource_id: str):
            resource_name = resource_id.split("/")[-1] if resource_id else None
            resource_url, error = app.get_resource_url(resource_id)
            if error:
                resource_url = ""
            return pd.Series({
                "ResourceName": resource_name,
                "ResourceURL": resource_url
            })
        control_df[["ResourceName", "ResourceURL"]] = control_df["ResourceID"].apply(get_resource_url)
        
        compliance_mapping = {
            "Compliant": "COMPLIANT",
            "NonCompliant": "NON_COMPLIANT",
            None: "NOT_DETERMINED"
        }
        control_df["ComplianceStatus"] = control_df["ComplianceStatus"].map(compliance_mapping.get, 'ignore')

        # fiter item with control name
        control_df = control_df[control_df["ControlName"] == control_name]
        control_df[
            [
                "ResourceType",
                "ComplianceStatusReason",
                "ValidationStatusCode",
                "ValidationStatusNotes"
            ]
        ] = control_df.apply(self.update_status, args=(control_status_dict), axis=1, result_type='expand')

        control_df = control_df[
            [
                "System",
                "Source",
                "ResourceID",
                "ResourceURL",
                "ResourceName",
                "ResourceType",
                "ResourceLocation",
                "ResourceTags",
                "ControlName",
                "ValidationStatusCode",
                "ValidationStatusNotes",
                "ComplianceStatus",
                "ComplianceStatusReason",
                "EvaluatedTime",
                "UserAction",
                "ActionStatus",
                "ActionResponseURL"
            ]
        ]
        file_url, error = self.upload_output_file(
            output_data=control_df,
            file_name=control_status_dict[0].get("EvidenceName", control_name)
        )
        if error:
            return self.upload_log_file_panic(error)

        response = {
            "FilteredAndFormattedControlEvidence": file_url,
        }

        return response

    def update_status(self, row, control_status_dict: dict):
        col_vals = control_status_dict.get(row["ComplianceStatus"])
        resource_type = row["ResourceType"]
        resource_type_match = re.search(r"\/([^\/]+$)", resource_type)
        resource_type = resource_type_match.group(1) if resource_type_match else resource_type
        resource_type = resource_type[:1].upper() + resource_type[1:] # capitalize only first letter
        return pd.Series([
                resource_type,
                col_vals.get("ComplianceStatusReason", ""),
                col_vals.get("ValidationStatusCode", ""),
                col_vals.get("ValidationStatusNotes", "")
        ])
    
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
        if not self.task_inputs.user_inputs.get("AzurePolicyRunResultFilePath"):
            emptyAttrs.append("AzurePolicyRunResultFilePath")
        if not self.task_inputs.user_inputs.get("ControlName"):
            emptyAttrs.append("ControlName")
        if not self.task_inputs.user_inputs.get("ControlConfigFilePath"):
            emptyAttrs.append("ControlConfigFilePath")
        
        return "The following inputs: " + ", ".join(
            emptyAttrs) + " is/are empty, please check the user inputs." if emptyAttrs else ""
