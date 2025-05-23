from typing import List, Dict, Tuple, Optional, Union
from compliancecowcards.structs import cards
from applicationtypes.githubconnector import githubconnector
from compliancecowcards.utils import cowdictutils
import json
import uuid
import pandas as pd
import toml

from github import PaginatedList, PullRequest, Branch, BranchProtection


class Task(cards.AbstractTask):

    def execute(self) -> Dict[str, str]:
        error = self.validate_inputs()
        if error:
            return self.upload_log_file([error])

        criteria_config = self.task_inputs.user_inputs.get("CriteriaConfig", "")
        min_req_rev_count = self.task_inputs.user_inputs["MinimumRequiredReviewersCount"]

        error_details = []

        include_criterias, exclude_criterias, error = self.download_config_file_and_get_criterias(criteria_config)
        if error:
            return self.upload_log_file([error])

        app_connector = self.create_github_connector()

        filtered_queries, error_list = app_connector.filter_include_exclude_criteria(
            include_criterias,
            exclude_criterias,
        )
        if error_list:
            error_details.extend(error_list)
        if not filtered_queries:
            return self.upload_log_file(error_details)

        rule_set_details = []

        existing_repos = app_connector.list_github_repos()
        existing_repos_dict = {repo.full_name: repo for repo in existing_repos}

        for query in filtered_queries:
            for repo_query in query["repo"]:
                repo_query_full_name = f"{query['org']}/{repo_query}"

                if repo_query_full_name not in existing_repos_dict:
                    error_details.append(f"Repo with name '{repo_query_full_name}' doesn't exist. " "Check the organization or repository name.")
                    continue

                repo_obj = existing_repos_dict[repo_query_full_name]
                existing_branches = repo_obj.get_branches()

                for branch in existing_branches:
                    if branch.name in query["branch"]:
                        rule_set_info, error_info = self.create_standard_schema(
                            branch,
                            min_req_rev_count,
                            repo_obj.full_name,
                            repo_obj.html_url,
                            app_connector,
                        )
                        if rule_set_info:
                            rule_set_details.append(rule_set_info)
                        if error_info:
                            error_details.append(error_info)

        response = {}
        if rule_set_details:
            response = self.upload_output_file(
                pd.DataFrame(rule_set_details),
                "GithubBranchSettingsReport",
            )
        else:
            error_details.append({"Error": "No branch exist for the provided query."})

        if error_details:
            log_file_response = self.upload_log_file(error_details)
            if cowdictutils.is_valid_key(log_file_response, "LogFile"):
                response["LogFile"] = log_file_response["LogFile"]
            elif cowdictutils.is_valid_key(log_file_response, "Error"):
                return log_file_response

        return response

    def download_config_file_and_get_criterias(
        self,
        criteria_config: str,
    ) -> Tuple[List[Dict[str, str]], List[Dict[str, str]], Optional[str]]:
        toml_bytes, error = self.download_file_from_minio(criteria_config)
        if error:
            return [], [], error

        criteria_config_data = toml.loads(toml_bytes.decode("utf-8"))
        include_criteria = criteria_config_data["IncludeCriteria"]
        exclude_criteria = criteria_config_data["ExcludeCriteria"]

        return include_criteria, exclude_criteria, None

    def get_required_approving_review_count(
        self,
        app_connector: githubconnector.GitHubConnector,
        repo_name: str,
        branch: Branch.Branch,
    ) -> Tuple[Optional[int], bool, str]:
        require_reviewers_enabled = False
        rule_set_count = 0

        ruleset_details, error = app_connector.get_rule_sets_details(
            repo_name,
            branch.name,
        )
        if error:
            return None, require_reviewers_enabled, error

        if not ruleset_details:
            return 0, require_reviewers_enabled, ""

        ruleset_df = pd.DataFrame(ruleset_details)
        pull_request_df = ruleset_df[ruleset_df["type"] == "pull_request"]
        if not pull_request_df.empty:
            require_reviewers_enabled = True
            rule_set_count = int(pull_request_df["parameters"].apply(lambda x: x["required_approving_review_count"]).max())

        branch_protect_count = 0
        if branch.protected:
            try:
                protection = branch.get_protection()
            except Exception:
                protection = None
            if protection:
                require_reviewers_enabled = True
                branch_protect_count = protection.required_pull_request_reviews.required_approving_review_count

        return max(rule_set_count, branch_protect_count), require_reviewers_enabled, ""

    def create_standard_schema(
        self,
        branch: Branch.Branch,
        min_req_rev_count: int,
        repo_full_name: str,
        repo_url: str,
        app_connector: githubconnector.GitHubConnector,
    ) -> Tuple[Dict[str, Union[str, int, bool]], Union[str, Dict[str, str]]]:
        validation_details = {}
        review_count, require_reviewers_enabled, error = self.get_required_approving_review_count(
            app_connector,
            repo_full_name,
            branch,
        )
        if error:
            if isinstance(error, dict):
                return {}, error
            return {}, {"Error": error}

        if not require_reviewers_enabled:
            validation_details = self.get_validation_details("2", int(min_req_rev_count))
        elif review_count < int(min_req_rev_count):
            validation_details = self.get_validation_details("3", int(min_req_rev_count))

        if not validation_details:
            validation_details = self.get_validation_details("1", int(min_req_rev_count))

        rule_set_info = {
            "System": "github",
            "Source": "compliancecow",
            "ResourceID": "N/A",
            "ResourceName": branch.name,
            "ResourceType": "Branch",
            "ResourceLocation": "N/A",
            "ResourceTags": "N/A",
            "ResourceURL": f"{repo_url}/tree/{branch.name}",
            "RepositoryName": repo_full_name,
            "RequiredReviewersEnabled": require_reviewers_enabled,
            "MinimumRequiredReviewersCount": min_req_rev_count,
            "ActualReviewerCount": review_count,
            "ValidationStatusCode": validation_details["ValidationStatusCode"],
            "ValidationStatusNotes": validation_details["ValidationStatusNotes"],
            "ComplianceStatus": validation_details["ComplianceStatus"],
            "ComplianceStatusReason": validation_details["ComplianceStatusReason"],
            "EvaluatedTime": app_connector.get_current_utc_time(),
            "UserAction": "",
            "ActionStatus": "",
            "ActionResponseURL": "",
        }

        return rule_set_info, ""

    def get_validation_details(
        self,
        validation_number: str,
        min_req_count: int,
    ) -> Dict[str, str]:
        validation_data = {
            "1": {
                "ComplianceStatus": "COMPLIANT",
                "ComplianceStatusReason": f"Required reviewers are properly configured in the branch ruleset with at least {min_req_count} reviewers.",
                "ValidationStatusCode": "RS_SUFF_REV_CNF",
                "ValidationStatusNotes": f"The branch ruleset has required reviewers enabled and meets the compliance requirement of having {min_req_count} or more reviewers.",
            },
            "2": {
                "ComplianceStatus": "NON_COMPLIANT",
                "ComplianceStatusReason": "Required reviewers are not enabled in the branch ruleset.",
                "ValidationStatusCode": "MSNG_RS",
                "ValidationStatusNotes": "The branch ruleset does not have required reviewers enabled.",
            },
            "3": {
                "ComplianceStatus": "NON_COMPLIANT",
                "ComplianceStatusReason": f"The number of required reviewers is less than {min_req_count}.",
                "ValidationStatusCode": "INS_REV_RS",
                "ValidationStatusNotes": f"Required reviewers are enabled, but the number is below the compliance threshold of {min_req_count}.",
            },
        }
        return validation_data.get(validation_number, {})

    def validate_inputs(self) -> Optional[str]:
        task_inputs = self.task_inputs
        if not task_inputs:
            return "missing: Task inputs"

        user_object = self.task_inputs.user_object
        if not user_object or not user_object.app or not user_object.app.user_defined_credentials:
            return "missing: User defined credentials"

        if not self.task_inputs.user_inputs:
            return "missing: User inputs"

        input_validation_report = ""

        criteria_config_file = self.task_inputs.user_inputs.get("CriteriaConfig", "")
        if criteria_config_file is None or criteria_config_file == "" or criteria_config_file == "<<MINIO_FILE_PATH>>":
            input_validation_report += "'CriteriaConfig' cannot be empty."

        min_req_rev_count = self.task_inputs.user_inputs.get("MinimumRequiredReviewersCount", 0)

        if min_req_rev_count is None:
            input_validation_report += "'MinimumRequiredReviewersCount' cannot be empty."
        elif not isinstance(min_req_rev_count, int):
            input_validation_report += "'MinimumRequiredReviewersCount' expected type is 'Integer'."
        elif min_req_rev_count == 0:
            input_validation_report += "'MinimumRequiredReviewersCount' cannot be '0'."

        if not input_validation_report:
            return None

        return input_validation_report

    def create_github_connector(self) -> githubconnector.GitHubConnector:
        app_connector = githubconnector.GitHubConnector(
            app_url=self.task_inputs.user_object.app.application_url,
            app_port=self.task_inputs.user_object.app.application_port,
            user_defined_credentials=githubconnector.UserDefinedCredentials.from_dict(self.task_inputs.user_object.app.user_defined_credentials),
        )
        return app_connector

    def upload_output_file(
        self,
        output: pd.DataFrame,
        file_name: str,
    ) -> Dict[str, str]:
        absolute_file_path, error = self.upload_df_as_parquet_file_to_minio(
            df=output,
            file_name=file_name,
        )
        if error:
            return {"Error": error}
        return {"GithubBranchSettingsReport": absolute_file_path}

    def format_log_file(
        self,
        error_msg: List[Union[str, Dict[str, str]]],
    ) -> List[Dict[str, str]]:
        formatted_error_msg = []
        for msg in error_msg:
            if not isinstance(msg, dict):
                formatted_error_msg.append({"Error": msg})
            else:
                formatted_error_msg.append(msg)
        return formatted_error_msg

    def upload_log_file(
        self,
        error_msg: List[Union[str, Dict[str, str]]],
    ) -> Dict[str, str]:
        formatted_error_msg = self.format_log_file(error_msg)
        absolute_file_path, error = self.upload_file_to_minio(
            file_name=f"LogFile-{str(uuid.uuid4())}.json",
            file_content=json.dumps(formatted_error_msg).encode(),
            content_type="application/json",
        )
        if error:
            return {"Error": error}
        return {"LogFile": absolute_file_path}
