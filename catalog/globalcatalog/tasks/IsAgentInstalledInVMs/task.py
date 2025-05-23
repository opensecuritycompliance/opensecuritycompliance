from applicationtypes.azureappconnector import azureappconnector
from compliancecowcards.structs import cards
import pandas as pd
from datetime import datetime

class Task(cards.AbstractTask):
    def execute(self) -> dict:
        error = self.check_inputs()
        if error:
            return self.upload_and_return_audit_file(error)
        
        self.azure_connector = azureappconnector.AzureAppConnector(
            app_url=self.task_inputs.user_object.app.application_url,
            app_port=self.task_inputs.user_object.app.application_port,
            user_defined_credentials=azureappconnector.UserDefinedCredentials.from_dict(
                self.task_inputs.user_object.app.user_defined_credentials
            )
        )
            
        # download extension summary file
        vm_extensions_df, error = self.download_csv_file_from_minio_as_df(
            file_url=self.task_inputs.user_inputs["VMsExtensionsDataFilePath"]
        )
        if error:
            return self.upload_and_return_audit_file(f"Error while downloading VMsExtensionsData file :: {error}")
        
        # download status values file
        control_status_vals_df, error = self.download_json_file_from_minio_as_df(
            file_url=self.task_inputs.user_inputs["ControlConfigFilePath"]
        )
        if error:
            return self.upload_and_return_audit_file(f"Error while downloading ControlConfig file :: {error}")

        control_name = self.task_inputs.user_inputs.get("ControlName", "")
        control_status_lis_dict = control_status_vals_df[control_status_vals_df["ControlName"] == control_name].to_dict(orient="records")
        if not control_status_lis_dict:
            return self.upload_and_return_audit_file("Couldn't find the control name in control config file")
        
        columns = {
            "Id": "ResourceID",
            "Name": "ResourceName",
            "PropertiesStorageProfileOsDiskOsType": "OS",
            "Values": "Values",
        }
        required_columns = set(columns.keys())

        if not required_columns.issubset(vm_extensions_df.columns):
            return self.upload_and_return_audit_file(f'The following columns are missing in VMsExtensionsDataFile: {", ".join(required_columns.difference(vm_extensions_df.columns))}')
        
        vm_extensions_df = vm_extensions_df.rename(columns=columns)
        vm_extensions_df["System"] = "azure"
        vm_extensions_df["Source"] = "compliancecow"
        vm_extensions_df["ResourceType"] = "Virtual Machines"
        contrl_dict = {
            "ascdependencyagentauditlinuxeffect": ["Linux"],
            "ascdependencyagentauditwindowseffect": ["Windows"],
            "installloganalyticsagentonvmmonitoring": ["Linux", "Windows"],
        }

        allowed_os_list = contrl_dict.get(control_name)
        if not allowed_os_list:
            return self.upload_and_return_audit_file("Couldn't find the control and os in control_dict")
        
        filtered_vm_extensions_df = vm_extensions_df[
            vm_extensions_df['OS'].str.contains(
                '|'.join(allowed_os_list), na=False, regex=True
            )
        ]

        if filtered_vm_extensions_df.empty:
            return self.upload_and_return_audit_file("No Resources found to evaluate")
        
        filtered_vm_extensions_df[
            [
                "ResourceURL",
                "AgentInstalledInVM",
                "ComplianceStatus",
                "ValidationStatusCode",
                "ComplianceStatusReason",
                "ValidationStatusNotes",
                "EvaluatedTime",
            ]
        ] = filtered_vm_extensions_df.apply(self.update_status, control_status_dict=control_status_lis_dict[0], axis=1)

        standard_df = filtered_vm_extensions_df[
            [
                "System",
                "Source",
                "ResourceID",
                "ResourceType",
                "ResourceName",
                "ResourceURL",
                "AgentInstalledInVM",
                "ComplianceStatus",
                "ComplianceStatusReason",
                "ValidationStatusCode",
                "ValidationStatusNotes",
                "EvaluatedTime",
            ]
        ].copy()

        standard_df['UserAction'] = ''
        standard_df['ActionStatus'] = ''
        standard_df['ActionResponseURL'] = ''

        file_url, error = self.upload_df_as_csv_file_to_minio(
            df=standard_df,
            file_name=control_name
        )
        if error:
            return self.upload_and_return_audit_file(f"Error while uploading {control_name} file :: {error}")
        
        response = {
            "AgentInstalledInVMs": file_url,
        }

        return response
    
    def upload_and_return_audit_file(self, error_message):
        audit_data = pd.DataFrame([
            {
                'Error': error_message
            }
        ])
        audit_file_path, error =  self.upload_df_as_json_file_to_minio(
            file_name='LogFile',
            df=audit_data
        )
        if error:
                return {'Error': error}
        return {'LogFile': audit_file_path}

    def update_status(self, row, control_status_dict):
        vals = {}
        status = {}
        if row["OS"] == "Linux":
            vals = control_status_dict.get("Linux")
        if row["OS"] == "windows":
            vals = control_status_dict.get("windows")

        resource_url, error = self.azure_connector.get_resource_url(row["ResourceID"])
        if error:
            resource_url = ""

        is_agent_installed_in_vm = False

        if row["Values"] and isinstance(row["Values"], list):
            for item in row["Values"]:
                properties = item.get("properties")
                if properties:
                    agent_type = properties.get("type")
                    if vals.get("AgentType") == agent_type:
                        is_agent_installed_in_vm = True
                        break

        compliance_status = "COMPLIANT" if is_agent_installed_in_vm else "NON_COMPLIANT"
        status = vals.get(compliance_status)

        return pd.Series({
            "ResourceURL": resource_url,
            "AgentInstalledInVM": is_agent_installed_in_vm,
            "ComplianceStatus": compliance_status,
            "ValidationStatusCode": status.get("ValidationStatusCode", ""),
            "ComplianceStatusReason": status.get("ComplianceStatusReason", ""),
            "ValidationStatusNotes": status.get("ValidationStatusNotes", ""),
            "EvaluatedTime": self.azure_connector.get_current_datetime(),
        })
    
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
        if not self.task_inputs.user_inputs.get("VMsExtensionsDataFilePath"):
            emptyAttrs.append("VMsExtensionsDataFilePath")
        if not self.task_inputs.user_inputs.get("ControlName"):
            emptyAttrs.append("ControlName")
        if not self.task_inputs.user_inputs.get("ControlConfigFilePath"):
            emptyAttrs.append("ControlConfigFilePath")
        
        return "The following inputs: " + ", ".join(
            emptyAttrs) + " is/are empty, please check the user inputs." if emptyAttrs else ""