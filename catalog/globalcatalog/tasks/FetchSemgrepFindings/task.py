import json
from urllib.parse import urljoin
import uuid
from typing import overload
from compliancecowcards.structs import cards
# As per the selected app, we're importing the app package
from applicationtypes.semgrepconnector import semgrepconnector
from compliancecowcards.utils import cowdictutils
import pandas as pd

class Task(cards.AbstractTask):

    def execute(self) -> dict:
        response = {}
        error = self.check_inputs()
        if error:
            log_file_url, error = self.upload_log_file([{ "Error": error }])
            if error:
                return { "Error": error }
            return { "LogFile": log_file_url }
        
        self.semgrep_app = semgrepconnector.SemgrepConnector(
            app_url=self.task_inputs.user_object.app.application_url,
            app_port=self.task_inputs.user_object.app.application_port,
            user_defined_credentials=semgrepconnector.UserDefinedCredentials.from_dict(
                self.task_inputs.user_object.app.user_defined_credentials)
        )

        # Get deployment details
        deployment_data, error = self.semgrep_app.get_deployments()
        if error:
            log_file_url, error = self.upload_log_file(f"Failed to get deployments: {error}")
            if error:
                return { "Error": error }
            return { "LogFile": log_file_url }

        validate_err = []
        deployment_slug = None
        deployment_ID = None
        # Extract deployment slug
        if cowdictutils.is_valid_key(deployment_data, 'deployments'):
            deployment = deployment_data["deployments"][0]
            if cowdictutils.is_valid_key(deployment, 'slug'):
                deployment_slug = deployment['slug']
            else:
                validate_err.append("Deployment 'slug' is missing in the 'deployments' data.")
            if cowdictutils.is_valid_key(deployment, 'id'):
                deployment_ID = deployment['id']
            else:
                validate_err.append("Deployment 'ID' is missing in the 'deployments' data.")
        else:
            validate_err.append("'deployments' key is missing in the deployment data.")

        if validate_err:
            log_file_url, error = self.upload_log_file(validate_err)
            if error:
                return {"Error": error}
            response["LogFile"] = log_file_url

        # Fetch all projects
        all_projects, error = self.semgrep_app.get_projects(deployment_slug)
        if error:
            log_file_url, error = self.upload_log_file(f"Failed to get projects: {error}")
            if error:
                return { "Error": error }
            return { "LogFile": log_file_url }

        include_criteria = self.task_inputs.user_inputs.get("IncludeCriteria") or "/project/*"
        exclude_criteria = self.task_inputs.user_inputs.get("ExcludeCriteria") or ""
        severities = self.task_inputs.user_inputs.get("Severity") or []
        
        # Validate severities and handle errors
        valid_severities, error_log = self.validate_severities(severities)
        if error_log:
            log_file_url, upload_error = self.upload_log_file(error_log)
            if upload_error:
                return { "Error": upload_error }
            return { "LogFile": log_file_url }
        # secrets_severities = self.convert_severities_for_secrets(valid_severities)
        log_messages = []
        valid_projects, validation_error = self.validate_and_filter_projects(all_projects, include_criteria, exclude_criteria, deployment_slug)

        if validation_error:
            log_messages.append({"Error": f"{validation_error}"})

        project_details = {}

        if valid_projects:
            findings_code_data, error = self.semgrep_app.list_findings(deployment_slug, issue_type="sast", repos=valid_projects, severities=valid_severities)
            if error:
                log_file_url, error = self.upload_log_file(f"Failed to list code findings: {error}")
                if error:
                    return { "Error": error }
                response["LogFile"] = log_file_url
            else:
                if not findings_code_data['findings']:
                    log_messages.append({"Error": "No Code Findings Data found."})
                else:
                    formatted_findings_code_data = self.format_findings(findings_code_data, deployment_slug, project_details, 'code')
                    file_name = "SemgrepCodeVulnerabilityReport"
                    code_file_url, error = self.upload_df_as_parquet_file_to_minio(
                        df=pd.json_normalize(formatted_findings_code_data),
                        file_name=file_name
                    )
                    if error:
                        return { "Error": f"Error while uploading {file_name} file :: {error}" }
                    response["SemgrepCodeVulnerabilityReport"] = code_file_url

            findings_supplychain_data, error = self.semgrep_app.list_findings(deployment_slug, issue_type="sca", repos=valid_projects, severities=valid_severities)
            if error:
                log_file_url, error = self.upload_log_file(f"Failed to list supplychain findings: {error}")
                if error:
                    return { "Error": error }
                response["LogFile"] = log_file_url
            else:
                if not findings_supplychain_data['findings']:
                    log_messages.append({"Error": "No Supply Chain Findings Data found."})
                else:
                    formatted_findings_supplychain_data = self.format_findings(findings_supplychain_data, deployment_slug, project_details, 'supply_chain')
                    file_name = "SemgrepSupplyChainVulnerabilityReport"
                    supplychain_file_url, error = self.upload_df_as_parquet_file_to_minio(
                        df=pd.json_normalize(formatted_findings_supplychain_data),
                        file_name=file_name
                    )
                    if error:
                        return { "Error": f"Error while uploading {file_name} file :: {error}" }
                    response["SemgrepSupplyChainVulnerabilityReport"] = supplychain_file_url
                    
            # secrets_data, error = self.fetch_and_format_secrets(deployment_ID, valid_projects, secrets_severities)
            # if error:
            #     log_file_url, upload_error = self.upload_log_file(f"Failed to list Secrets findings: {error}")
            #     if upload_error:
            #         return { "Error": upload_error }
            #     response["LogFile"] = log_file_url
            # else:
            #     if not secrets_data or secrets_data == "No Secrets Findings data found":
            #         log_messages.append({"Error": "No Secrets Findings Data found."})
            #     else:
            #         file_name = f"SemgrepSecretsVulnerabilityReport"
            #         secrets_file_url, error = self.upload_df_as_parquet_file_to_minio(
            #             df=pd.json_normalize(secrets_data),
            #             file_name=file_name
            #         )
            #         if error:
            #             return { "Error": f"Error while uploading {file_name} file :: {error}" }
            #         response["SemgrepSecretsVulnerabilityReport"] = secrets_file_url

            code_findings_summary_df, supply_chain_findings_summary_df = self.prepare_project_summary_dataframe(project_details, valid_projects, all_projects)
            if code_findings_summary_df.empty:
                log_messages.append({"Error": "No Code findings Summary Data found."})
            elif supply_chain_findings_summary_df.empty:
                log_messages.append({"Error": "No SupplyChain findings Summary Data found."})
            else:
                file_name = "SemgrepCodeFindingsSummaryReport"
                code_summary_file_url, error = self.upload_df_as_parquet_file_to_minio(
                    df=code_findings_summary_df,
                    file_name=file_name
                )
                if error:
                    return { "Error": f"Error while uploading {file_name} file :: {error}" }
                response["SemgrepCodeFindingsSummaryReport"] = code_summary_file_url
                file_name = "SemgrepSupplyChainFindingsSummaryReport"
                supply_chain_summary_file_url, error = self.upload_df_as_parquet_file_to_minio(
                    df=supply_chain_findings_summary_df,
                    file_name=file_name
                )
                if error:
                    return { "Error": f"Error while uploading {file_name} file :: {error}" }
                response["SemgrepSupplyChainFindingsSummaryReport"] = supply_chain_summary_file_url
        else:
            if "LogFile" not in response:
                log_messages.append({"Error": "No valid projects found."})
        
        if log_messages:
            log_file_url, error = self.upload_log_file(log_messages)
            if error:
                return {"Error": error}
            response["LogFile"] = log_file_url

        return response
    
    # def fetch_and_format_secrets(self, deployment_id, repo, severities):
    #     secrets_findings = []
    #     cursor = None
    #     while True:
    #         secrets_data, error = self.semgrep_app.list_secrets(deployment_id, cursor, repo, severities=severities)
    #         if error:
    #             return None, error
    #         if secrets_data:
    #             if not secrets_data['findings']:
    #                 return "No Secrets Findings data found", None
    #             for finding in secrets_data['findings']:
    #                 secrets_findings.append(self.format_secret_finding(finding, deployment_id))
    #             cursor = secrets_data.get('cursor')
    #             if not cursor:
    #                 break
    #         else:
    #             break
    #     return secrets_findings, None

    # def format_secret_finding(self, finding, deployment_id):
    #     validation_status_code = ""
    #     validation_status_notes = ""
    #     compliance_status = ""
    #     compliance_status_reason = ""

    #     if finding['validationState'] == "VALIDATION_STATE_CONFIRMED_VALID":
    #         validation_status_code = "SECRET_FOUND"
    #         validation_status_notes = "Secret has been tested and is confirmed valid by Semgrep."
    #         compliance_status = "NON_COMPLIANT"
    #         compliance_status_reason = "The secret is confirmed valid and poses a security risk as it grants access to resources."
    #     elif finding['validationState'] == "VALIDATION_STATE_CONFIRMED_INVALID":
    #         validation_status_code = "SECRET_FOUND_INV"
    #         validation_status_notes = "Secret has been tested and is confirmed invalid by Semgrep."
    #         compliance_status = "COMPLIANT"
    #         compliance_status_reason = "The secret is confirmed invalid and does not pose an active security risk."
    #     elif finding['validationState'] == "VALIDATION_STATE_VALIDATION_ERROR":
    #         validation_status_code = "VALIDATION_ERR"
    #         validation_status_notes = "Secret test was attempted and there was an error in Semgrep."
    #         compliance_status = "NON_COMPLIANT"
    #         compliance_status_reason = "The secret could not be validated, and therefore, it cannot be confirmed whether it is a risk or not. Manual review is recommended."
    #     elif finding['validationState'] == "VALIDATION_STATE_NO_VALIDATOR":
    #         validation_status_code = "NO_VALIDATOR"
    #         validation_status_notes = "There is no validator available for this secret in Semgrep."
    #         compliance_status = "NON_COMPLIANT"
    #         compliance_status_reason = "Without validation, it cannot be confirmed if the secret poses a risk. Manual review is required."

    #     return {
    #         "System": "semgrep",
    #         "Source": "compliancecow",
    #         "ResourceID": "N/A",
    #         "ResourceName": finding['repository']['name'],
    #         "ResourceType": "Repository",
    #         "ResourceLocation": "N/A",
    #         "ResourceTags": "N/A",
    #         "ResourceURL": finding['findingPathUrl'],
    #         "VulnerabilityID": finding['id'],
    #         "FilePath": finding['findingPath'],
    #         "ServiceType": finding['type'],
    #         "Status": finding['status'],
    #         "Severity": finding['severity'],
    #         "Confidence": finding['confidence'],
    #         "Mode": finding['mode'],
    #         "SemgrepURL": self.get_resource_url(deployment_id, finding['id']),
    #         "SecretValidationStatus": finding['validationState'],
    #         "ValidationStatusCode": validation_status_code,
    #         "ValidationStatusNotes": validation_status_notes,
    #         "ComplianceStatus": compliance_status,
    #         "ComplianceStatusReason": compliance_status_reason,
    #         "EvaluatedTime": self.semgrep_app.get_current_datetime(),
    #         "UserAction": "",
    #         "ActionStatus": "",
    #         "ActionResponseURL": ""
    #     }
    
    # def convert_severities_for_secrets(self, severities):
    #     severity_mapping = {
    #         "low": "SEVERITY_LOW",
    #         "medium": "SEVERITY_MEDIUM",
    #         "high": "SEVERITY_HIGH",
    #         "critical": "SEVERITY_CRITICAL"
    #     }
    #     return [severity_mapping.get(severity.lower(), "SEVERITY_UNSPECIFIED") for severity in severities]

    def validate_severities(self, severities):
        valid_severities = []
        error_log = []
        severity_mapping = {
            "low": "low",
            "medium": "medium",
            "high": "high",
            "critical": "critical",
            "severity_low": "low",
            "severity_medium": "medium",
            "severity_high": "high",
            "severity_critical": "critical",
            "severity_unspecified": ""
        }
        all_severities = ["low", "medium", "high", "critical"]

        if "*" in severities:
            valid_severities = list(all_severities)
        else:
            for severity in severities:
                if severity.lower() in severity_mapping:
                    valid_severities.append(severity_mapping[severity.lower()])
                else:
                    error_log.append(f"Invalid severity '{severity}' provided.")

        return valid_severities, error_log

    def format_findings(self, findings_data, deployment_slug, project_details, issue_type):
        findings_df = pd.json_normalize(findings_data['findings'])
        
        default_values = {
            "TotalCodeVulnerabilityCount": 0,
            "CodeVulnerabilityLowSeverityCount": 0,
            "CodeVulnerabilityMediumSeverityCount": 0,
            "CodeVulnerabilityHighSeverityCount": 0,
            "CodeVulnerabilityCriticalSeverityCount": 0,
            "CodeOpenVulnerabilityCount": 0,
            "CodeReviewingVulnerabilityCount": 0,
            "CodeFixingVulnerabilityCount": 0,
            "TotalSupplyChainVulnerabilityCount": 0,
            "SupplyChainVulnerabilityLowSeverityCount": 0,
            "SupplyChainVulnerabilityMediumSeverityCount": 0,
            "SupplyChainVulnerabilityHighSeverityCount": 0,
            "SupplyChainVulnerabilityCriticalSeverityCount": 0,
            "SupplyChainOpenVulnerabilityCount": 0,
            "SupplyChainReviewingVulnerabilityCount": 0,
            "SupplyChainFixingVulnerabilityCount": 0
        }
        
        projects_df = pd.DataFrame(columns=default_values.keys())

        findings_df['project_name'] = findings_df['repository.name'].fillna('')
        findings_df['severity'] = findings_df['severity'].str.lower().fillna('')
        findings_df['status'] = findings_df['status'].str.lower().fillna('')

        active_findings_df = findings_df[findings_df['status'] != 'fixed']

        # Update counts for each project
        if issue_type == 'code':
            projects_df = active_findings_df.groupby('project_name').apply(lambda x: pd.Series({
                'TotalCodeVulnerabilityCount': len(x),
                'CodeVulnerabilityLowSeverityCount': (x['severity'] == 'low').sum(),
                'CodeVulnerabilityMediumSeverityCount': (x['severity'] == 'medium').sum(),
                'CodeVulnerabilityHighSeverityCount': (x['severity'] == 'high').sum(),
                'CodeVulnerabilityCriticalSeverityCount': (x['severity'] == 'critical').sum(),
                'CodeOpenVulnerabilityCount': (x['status'] == 'open').sum(),
                'CodeReviewingVulnerabilityCount': (x['status'] == 'reviewing').sum(),
                'CodeFixingVulnerabilityCount': (x['status'] == 'fixing').sum()
            })).reindex(columns=projects_df.columns).fillna(0)
        elif issue_type == 'supply_chain':
            projects_df = active_findings_df.groupby('project_name').apply(lambda x: pd.Series({
                'TotalSupplyChainVulnerabilityCount': len(x),
                'SupplyChainVulnerabilityLowSeverityCount': (x['severity'] == 'low').sum(),
                'SupplyChainVulnerabilityMediumSeverityCount': (x['severity'] == 'medium').sum(),
                'SupplyChainVulnerabilityHighSeverityCount': (x['severity'] == 'high').sum(),
                'SupplyChainVulnerabilityCriticalSeverityCount': (x['severity'] == 'critical').sum(),
                'SupplyChainOpenVulnerabilityCount': (x['status'] == 'open').sum(),
                'SupplyChainReviewingVulnerabilityCount': (x['status'] == 'reviewing').sum(),
                'SupplyChainFixingVulnerabilityCount': (x['status'] == 'fixing').sum()
            })).reindex(columns=projects_df.columns).fillna(0)

        projects_df = projects_df.astype(int)

        # Merge new counts with existing counts in project_details.
        for project, counts in projects_df.to_dict(orient='index').items():
            if project in project_details:
                for key, value in counts.items():
                    project_details[project][key] = project_details[project].get(key, 0) + value
            else:
                project_details[project] = counts

        findings_df['compliance_status'] = findings_df.apply(
            lambda x: "COMPLIANT" if x['status'] == 'fixed' or x['severity'] == 'low' or x['severity'] == 'medium' else "NON_COMPLIANT",
            axis=1
        )
        findings_df['compliance_status_reason'] = findings_df.apply(
            lambda x: "The record is compliant because the vulnerabilities were found and fixed, as per the recent scan result by Semgrep."
            if x['compliance_status'] == "COMPLIANT" else 
            "The record is non-compliant because the repository scanned by Semgrep identifies vulnerabilities that pose potential security risks.",
            axis=1
        )

        findings_df['validation_status_code'] = findings_df['severity'].apply(self.format_validation_status_code)
        findings_df['validation_status_notes'] = findings_df['severity'].apply(lambda x: f"{x.capitalize()} vulnerabilities found in the repository scanned by Semgrep.")

        findings_df['formatted_findings'] = findings_df.apply(lambda x: {
            "System": "semgrep",
            "Source": "compliancecow",
            "ResourceID": "N/A",
            "ResourceName": x['repository.name'],
            "ResourceType": "Repository",
            "ResourceLocation": "N/A",
            "ResourceTags": [],
            "ResourceURL": x.get('line_of_code_url', 'N/A') or 'N/A',
            "VulnerabilityID": x.get('id', ''),
            "SemgrepRuleName": x.get('rule_name', ''),
            "Description": x.get('rule.message', ''),
            "FilePath": x.get('location.file_path', ''),
            "StartLine": x.get('location.line', ''),
            "EndLine": x.get('location.end_line', ''),
            "Status": x['status'],
            "Severity": x['severity'],
            "Confidence": x.get('confidence', ''),
            "SemgrepFindingURL": self.get_resource_url(deployment_slug, x.get('id', '')),
            "ValidationStatusCode": x['validation_status_code'],
            "ValidationStatusNotes": x['validation_status_notes'],
            "ComplianceStatus": x['compliance_status'],
            "ComplianceStatusReason": x['compliance_status_reason'],
            "EvaluatedTime": x.get('state_updated_at', '') or x.get('relevant_since', ''),
            "UserAction": "",
            "ActionStatus": "",
            "ActionResponseURL": ""
        }, axis=1)

        return findings_df['formatted_findings'].tolist()
    
    def format_validation_status_code(self, severity):
        if severity == 'medium':
            return "MED_VULN_FOUND"
        elif severity == 'critical':
            return "CRT_VULN_FOUND"
        else:
            return f"{severity.upper()}_VULN_FOUND"
    
    def prepare_code_findings_summary(self, project_details, project_url_map, all_project_details):
        code_summary_list = []
        all_projects = set(project_url_map.keys())

        for project in all_projects:
            project_metadata = next(
                (p for p in all_project_details.get("projects", []) if p["name"] == project), None
            )
            last_scan = project_metadata.get("latest_scan_at") if project_metadata else None

            if last_scan is None:
                compliance_status = "NOT_DETERMINED"
                compliance_reason = "The compliance status could not be determined as the project has not been scanned."
                validation_status_code = "SCAN_NOT_DONE"
                validation_status_notes = f"The project {project} has not undergone a scan."

                code_summary_list.append({
                    "System": "semgrep",
                    "Source": "compliancecow",
                    "ResourceID": "N/A",
                    "ResourceName": project,
                    "ResourceType": "Repository",
                    "ResourceLocation": "N/A",
                    "ResourceTags": [],
                    "ResourceURL": project_url_map.get(project, "N/A"),
                    "TotalCodeVulnerabilityCount": 0,
                    "CodeVulnerabilityLowSeverityCount": 0,
                    "CodeVulnerabilityMediumSeverityCount": 0,
                    "CodeVulnerabilityHighSeverityCount": 0,
                    "CodeVulnerabilityCriticalSeverityCount": 0,
                    "CodeOpenVulnerabilityCount": 0,
                    "CodeReviewingVulnerabilityCount": 0,
                    "CodeFixingVulnerabilityCount": 0,
                    "ValidationStatusCode": validation_status_code,
                    "ValidationStatusNotes": validation_status_notes,
                    "ComplianceStatus": compliance_status,
                    "ComplianceStatusReason": compliance_reason,
                    "EvaluatedTime": self.semgrep_app.get_current_datetime(),
                    "UserAction": "",
                    "ActionStatus": "",
                    "ActionResponseURL": ""
                })
                continue

            details = project_details.get(project, {
                "TotalCodeVulnerabilityCount": 0,
                "CodeVulnerabilityLowSeverityCount": 0,
                "CodeVulnerabilityMediumSeverityCount": 0,
                "CodeVulnerabilityHighSeverityCount": 0,
                "CodeVulnerabilityCriticalSeverityCount": 0,
                "CodeOpenVulnerabilityCount": 0,
                "CodeReviewingVulnerabilityCount": 0,
                "CodeFixingVulnerabilityCount": 0
            })

            if details["TotalCodeVulnerabilityCount"] == 0:
                compliance_status = "COMPLIANT"
                compliance_reason = "The record is compliant because no code vulnerabilities were found."
                validation_status_code = "NO_CODE_VULN_FND"
                validation_status_notes = f"This project {project} contains no code vulnerability findings."
            elif (details["TotalCodeVulnerabilityCount"] > 0 and 
                (details["CodeVulnerabilityHighSeverityCount"] > 0 or 
                details["CodeVulnerabilityCriticalSeverityCount"] > 0)):
                compliance_status = "NON_COMPLIANT"
                compliance_reason = "The record is non-compliant because high or critical severity code vulnerabilities were found."
            else:
                compliance_status = "COMPLIANT"
                compliance_reason = "The record is compliant because only low or medium severity code vulnerabilities were found."

            code_severity = f"{details['CodeVulnerabilityCriticalSeverityCount'] or 'NO'}_CRT"
            code_severity += f"_{details['CodeVulnerabilityHighSeverityCount'] or 'NO'}_HIGH_CODE_SEV_PRE"
            validation_status_code = code_severity
            validation_status_notes = (
                f"Contains {details['CodeVulnerabilityCriticalSeverityCount']} critical "
                f"and {details['CodeVulnerabilityHighSeverityCount']} high severity code vulnerabilities."
            )

            code_summary_list.append({
                "System": "semgrep",
                "Source": "compliancecow",
                "ResourceID": "N/A",
                "ResourceName": project,
                "ResourceType": "Repository",
                "ResourceLocation": "N/A",
                "ResourceTags": [],
                "ResourceURL": project_url_map.get(project, "N/A"),
                "TotalCodeVulnerabilityCount": details["TotalCodeVulnerabilityCount"],
                "CodeVulnerabilityLowSeverityCount": details["CodeVulnerabilityLowSeverityCount"],
                "CodeVulnerabilityMediumSeverityCount": details["CodeVulnerabilityMediumSeverityCount"],
                "CodeVulnerabilityHighSeverityCount": details["CodeVulnerabilityHighSeverityCount"],
                "CodeVulnerabilityCriticalSeverityCount": details["CodeVulnerabilityCriticalSeverityCount"],
                "CodeOpenVulnerabilityCount": details["CodeOpenVulnerabilityCount"],
                "CodeReviewingVulnerabilityCount": details["CodeReviewingVulnerabilityCount"],
                "CodeFixingVulnerabilityCount": details["CodeFixingVulnerabilityCount"],
                "ValidationStatusCode": validation_status_code,
                "ValidationStatusNotes": validation_status_notes,
                "ComplianceStatus": compliance_status,
                "ComplianceStatusReason": compliance_reason,
                "EvaluatedTime": self.semgrep_app.get_current_datetime(),
                "UserAction": "",
                "ActionStatus": "",
                "ActionResponseURL": ""
            })

        return pd.DataFrame(code_summary_list)

    def prepare_supply_chain_findings_summary(self, project_details, project_url_map, all_project_details):
        supply_chain_summary_list = []
        all_projects = set(project_url_map.keys())

        for project in all_projects:
            project_metadata = next(
                (p for p in all_project_details.get("projects", []) if p["name"] == project), None
            )
            last_scan = project_metadata.get("latest_scan_at") if project_metadata else None

            if last_scan is None:
                compliance_status = "NOT_DETERMINED"
                compliance_reason = "The compliance status could not be determined as the project has not been scanned."
                validation_status_code = "SCAN_NOT_DONE"
                validation_status_notes = f"The project {project} has not undergone a scan."

                supply_chain_summary_list.append({
                    "System": "semgrep",
                    "Source": "compliancecow",
                    "ResourceID": "N/A",
                    "ResourceName": project,
                    "ResourceType": "Repository",
                    "ResourceLocation": "N/A",
                    "ResourceTags": [],
                    "ResourceURL": project_url_map.get(project, "N/A"),
                    "TotalSupplyChainVulnerabilityCount": 0,
                    "SupplyChainVulnerabilityLowSeverityCount": 0,
                    "SupplyChainVulnerabilityMediumSeverityCount": 0,
                    "SupplyChainVulnerabilityHighSeverityCount": 0,
                    "SupplyChainVulnerabilityCriticalSeverityCount": 0,
                    "SupplyChainOpenVulnerabilityCount": 0,
                    "SupplyChainReviewingVulnerabilityCount": 0,
                    "SupplyChainFixingVulnerabilityCount": 0,
                    "ValidationStatusCode": validation_status_code,
                    "ValidationStatusNotes": validation_status_notes,
                    "ComplianceStatus": compliance_status,
                    "ComplianceStatusReason": compliance_reason,
                    "EvaluatedTime": self.semgrep_app.get_current_datetime(),
                    "UserAction": "",
                    "ActionStatus": "",
                    "ActionResponseURL": ""
                })
                continue

            details = project_details.get(project, {
                "TotalSupplyChainVulnerabilityCount": 0,
                "SupplyChainVulnerabilityLowSeverityCount": 0,
                "SupplyChainVulnerabilityMediumSeverityCount": 0,
                "SupplyChainVulnerabilityHighSeverityCount": 0,
                "SupplyChainVulnerabilityCriticalSeverityCount": 0,
                "SupplyChainOpenVulnerabilityCount": 0,
                "SupplyChainReviewingVulnerabilityCount": 0,
                "SupplyChainFixingVulnerabilityCount": 0
            })
            if details["TotalSupplyChainVulnerabilityCount"] == 0:
                compliance_status = "COMPLIANT"
                compliance_reason = "The record is compliant because no supply chain vulnerabilities were found."
                validation_status_code = "NO_SC_VULN_FND"
                validation_status_notes = f"This project {project} contains no supply chain vulnerability findings."
            elif (details["TotalSupplyChainVulnerabilityCount"] > 0 and 
                details["SupplyChainVulnerabilityHighSeverityCount"] > 0 or 
                details["SupplyChainVulnerabilityCriticalSeverityCount"] > 0):
                compliance_status = "NON_COMPLIANT"
                compliance_reason = "The record is non-compliant because high or critical severity supply chain vulnerabilities were found."
            else:
                compliance_status = "COMPLIANT"
                compliance_reason = "The record is compliant because only low or medium severity supply chain vulnerabilities were found."

            supplychain_severity = f"{details['SupplyChainVulnerabilityCriticalSeverityCount'] or 'NO'}_CRT"
            supplychain_severity += f"_{details['SupplyChainVulnerabilityHighSeverityCount'] or 'NO'}_HIGH_SC_SEV_PRE"

            validation_status_code = supplychain_severity
            validation_status_notes = (
                f"Contains {details['SupplyChainVulnerabilityCriticalSeverityCount']} critical "
                f"and {details['SupplyChainVulnerabilityHighSeverityCount']} high severity supply chain vulnerabilities."
            )

            supply_chain_summary_list.append({
                "System": "semgrep",
                "Source": "compliancecow",
                "ResourceID": "N/A",
                "ResourceName": project,
                "ResourceType": "Repository",
                "ResourceLocation": "N/A",
                "ResourceTags": [],
                "ResourceURL": project_url_map.get(project, "N/A"),
                "TotalSupplyChainVulnerabilityCount": details["TotalSupplyChainVulnerabilityCount"],
                "SupplyChainVulnerabilityLowSeverityCount": details["SupplyChainVulnerabilityLowSeverityCount"],
                "SupplyChainVulnerabilityMediumSeverityCount": details["SupplyChainVulnerabilityMediumSeverityCount"],
                "SupplyChainVulnerabilityHighSeverityCount": details["SupplyChainVulnerabilityHighSeverityCount"],
                "SupplyChainVulnerabilityCriticalSeverityCount": details["SupplyChainVulnerabilityCriticalSeverityCount"],
                "SupplyChainOpenVulnerabilityCount": details["SupplyChainOpenVulnerabilityCount"],
                "SupplyChainReviewingVulnerabilityCount": details["SupplyChainReviewingVulnerabilityCount"],
                "SupplyChainFixingVulnerabilityCount": details["SupplyChainFixingVulnerabilityCount"],
                "ValidationStatusCode": validation_status_code,
                "ValidationStatusNotes": validation_status_notes,
                "ComplianceStatus": compliance_status,
                "ComplianceStatusReason": compliance_reason,
                "EvaluatedTime": self.semgrep_app.get_current_datetime(),
                "UserAction": "",
                "ActionStatus": "",
                "ActionResponseURL": ""
            })

        return pd.DataFrame(supply_chain_summary_list)

    def prepare_project_summary_dataframe(self, project_details, valid_projects, all_projects):
        projects = [project for project in all_projects.get('projects', []) if project['name'] in valid_projects]
        project_url_map = {
            project['name']: project.get('url') if project.get('url') is not None else "N/A"
            for project in projects
        }

        code_findings_summary_df = self.prepare_code_findings_summary(project_details, project_url_map, all_projects)
        supply_chain_findings_summary_df = self.prepare_supply_chain_findings_summary(project_details, project_url_map, all_projects)

        return code_findings_summary_df, supply_chain_findings_summary_df
    
    def validate_and_filter_projects(self, all_projects, include_criteria, exclude_criteria, deployment_slug):
        all_project_names = [project['name'] for project in all_projects['projects']]
        invalid_repos = []

        include_criteria = self.extract_and_split_criteria(include_criteria)
        exclude_criteria = self.extract_and_split_criteria(exclude_criteria)

        if "*" in exclude_criteria:
            return None, "Cannot exclude all projects."

        for repo in exclude_criteria:
            if repo and repo not in all_project_names:
                project_data, error = self.semgrep_app.get_projects(deployment_slug, project_name=repo)
                if error:
                    continue

        for repo in include_criteria:
            if repo != "*" and repo and repo not in all_project_names:
                project_data, error = self.semgrep_app.get_projects(deployment_slug, project_name=repo)
                if error:
                    invalid_repos.append(repo)

        valid_projects = set(all_project_names)

        for pattern in exclude_criteria:
            valid_projects = {repo for repo in valid_projects if repo != pattern}

        if "*" not in include_criteria:
            included_projects = set()
            for pattern in include_criteria:
                included_projects |= {repo for repo in all_project_names if repo == pattern}
            valid_projects &= included_projects

        if invalid_repos:
            return list(valid_projects), f"Could not find repository/repositories with name(s): {', '.join(invalid_repos)}"
        else:
            return list(valid_projects), None

    def extract_and_split_criteria(self, criteria):
        if isinstance(criteria, str) and "/project/" in criteria:
            criteria = criteria.split("/project/")[-1]
        return [item.strip() for item in criteria.split(',') if item.strip()]

    def upload_log_file(self, error_data):
        if not isinstance(error_data, list):
            error_data = [error_data]
        log_file_content = json.dumps(error_data, indent=4)
        file_name = f"LogFile-{str(uuid.uuid4())}.json"
        content_type = "application/json"
        file_url, error = self.upload_file_to_minio(
            file_content=log_file_content.encode('utf-8'),
            file_name=file_name,
            content_type=content_type
        )
        if error:
            return None, f"Error while uploading LogFile: {error}"
        return file_url, None
    
    def get_resource_url(self, deployment_slug_or_id, finding_id):
        base_url = self.task_inputs.user_object.app.application_url.rstrip('/')
        org_path = f"/orgs/{deployment_slug_or_id}/findings/{finding_id}"
        return urljoin(base_url, org_path)
    
    def check_inputs(self):
        if not self.task_inputs:
            return 'Task inputs are missing'
        user_object = self.task_inputs.user_object
        if (
            user_object is None
            or user_object.app is None
            or user_object.app.application_url is None
            or user_object.app.user_defined_credentials is None
        ):
            return 'User defined credentials are missing"'

        return ""