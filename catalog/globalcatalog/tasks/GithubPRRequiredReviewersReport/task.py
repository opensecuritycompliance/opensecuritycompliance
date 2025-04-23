from typing import List, Dict, Tuple, Optional, Union
from compliancecowcards.structs import cards

# As per the selected app, we're importing the app package
from appconnections.githubconnector import githubconnector
from compliancecowcards.utils import cowdictutils
import json
import csv
import uuid
import pandas as pd
from io import BytesIO
from datetime import datetime, date
import toml
import copy
from github import PaginatedList, PullRequest


class Task(cards.AbstractTask):

    def execute(self) -> Dict[str, str]:
        error_details = []

        error = self.validate_inputs()
        if error:
            return self.upload_log_file([error])

        criteria_config = self.task_inputs.user_inputs.get("CriteriaConfig", "")
        hierarchy_report = self.task_inputs.user_inputs["HRISHierarchyReport"]
        min_req_rev_count = self.task_inputs.user_inputs["MinimumRequiredReviewersCount"]

        from_date = datetime.fromisoformat(str(self.task_inputs.from_date)).date()
        to_date = datetime.fromisoformat(str(self.task_inputs.to_date)).date()

        hierarchy_report_result, error = self.download_hierarchy_report(hierarchy_report)
        if error:
            return self.upload_log_file([error])

        pr_details = []

        include_criteria, exclude_criteria, error = self.download_config_file_and_get_criterias(criteria_config)
        if error:
            return self.upload_log_file([error])

        app_connector = self.create_github_connector()

        filtered_queries, error_list = app_connector.filter_include_exclude_criteria(include_criteria, exclude_criteria)
        if error_list:
            error_details.extend(error_list)
        if not filtered_queries:
            return self.upload_log_file(error_details)

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
                        open_pull_requests = repo_obj.get_pulls(state="all", base=branch.name)
                        pr_info, error_info = self.create_standard_schema(repo_obj.name, open_pull_requests, min_req_rev_count, hierarchy_report_result, app_connector, from_date, to_date)
                        pr_details.extend(pr_info)
                        error_details.extend(error_info)

        response = {}
        if pr_details:
            response = self.upload_output_file(pd.DataFrame(pr_details), "GithubPRRequiredReviewersReport")
        else:
            error_details.append({"Error": "No pull requests exist for the provided query."})

        if error_details:
            log_file_response = self.upload_log_file(error_details)
            if cowdictutils.is_valid_key(log_file_response, "LogFile"):
                response["LogFile"] = log_file_response["LogFile"]
            elif cowdictutils.is_valid_key(log_file_response, "Error"):
                return log_file_response

        return response

    def download_hierarchy_report(self, hierarchy_report: str) -> Tuple[List[Dict[str, str]], Optional[str]]:
        hierarchy_report_bytes, error = self.download_file_from_minio(hierarchy_report)
        if error:
            return None, error

        csv_file = BytesIO(hierarchy_report_bytes)
        csv_text = csv_file.read().decode("utf-8")
        csv_file.seek(0)
        hierarchy_report_data = list(csv.DictReader(csv_text.splitlines()))

        return hierarchy_report_data, None

    def get_managers_list(self, hierarchy_report_df: pd.DataFrame, user_name: str) -> Tuple[Optional[List[str]], Optional[str]]:
        managers = []
        manager_id_filter = hierarchy_report_df.loc[hierarchy_report_df["Name"] == user_name, "Manager ID"]

        if manager_id_filter.empty:
            return None, f"User {user_name} is not available in the 'HRISHierarchyReport' CSV file."

        manager_id = manager_id_filter.values[0]
        if manager_id == "NULL":
            return ["*"], None

        managers_name_filter = hierarchy_report_df.loc[hierarchy_report_df["Employee ID"] == manager_id, "Name"]
        if managers_name_filter.empty:
            return None, f"No information is available for the user with ID {manager_id} " "in the 'HRISHierarchyReport' CSV file."

        managers_name = managers_name_filter.values[0]
        managers.append(managers_name)

        manager_temp, error = self.get_managers_list(hierarchy_report_df, managers_name)
        if error:
            return [], error

        if manager_temp:
            managers.extend(manager_temp)

        if len(managers) > 1 and "*" in managers:
            managers.remove("*")

        return managers, None

    def check_req_rev_are_exist_in_hier_report(self, requested_reviewers: List[str], hierarchy_report_df: pd.DataFrame) -> List[str]:
        users = hierarchy_report_df["Name"].tolist()
        return [req_rev for req_rev in requested_reviewers if req_rev not in users]

    def check_manager_or_above_reviewer(self, hierarchy_report: List[Dict[str, str]], requester_name: str, requested_reviewers: List[str]) -> Tuple[bool, Optional[str]]:
        hierarchy_report_df = pd.DataFrame(hierarchy_report)
        managers, error = self.get_managers_list(hierarchy_report_df, requester_name)
        if error:
            return False, error

        if len(managers) == 1 and managers[0] == "*":
            return True, None

        if any(reviewer in managers for reviewer in requested_reviewers):
            return True, None

        missing_users = self.check_req_rev_are_exist_in_hier_report(requested_reviewers, hierarchy_report_df)
        if not missing_users:
            return False, None

        req_revs = copy.deepcopy(requested_reviewers)
        for req_rev in requested_reviewers:
            if req_rev in missing_users:
                req_revs.remove(req_rev)

        error_msg = ""
        if req_revs:
            if len(req_revs) == 1:
                error_msg = f"GitHub reviewer {req_revs[0]} does not satisfy " "the required hierarchy level. "
            else:
                user_list = ", ".join(req_revs[:-1]) + " and " + req_revs[-1]
                error_msg = f"GitHub reviewers {user_list} does not satisfy " "the required hierarchy level. "

        if missing_users:
            if len(missing_users) == 1:
                error_msg += f"The following reviewer is missing from the hierarchy report: {missing_users[0]}."
            else:
                user_list = ", ".join(missing_users[:-1]) + " and " + missing_users[-1]
                error_msg += f"The following reviewers are missing from the hierarchy report: {user_list}."

        return True, error_msg

    def create_standard_schema(self, repo_name: str, open_pull_requests: PaginatedList[PullRequest], min_req_rev_count: int, hierarchy_report: List[Dict[str, str]], app_connector: githubconnector.GitHubConnector, from_date: date, to_date: date) -> Tuple[List[Dict[str, Union[str, int, bool, None]]], List[str]]:
        error_details = []
        pr_details = []

        for pr in open_pull_requests:
            state = pr.state
            pr_created_date = datetime.fromisoformat(str(pr.created_at)).date()
            if from_date <= pr_created_date <= to_date:
                if pr.state == "closed" and not pr.merged_at:
                    continue
                if pr.state == "closed":
                    state = "merged"

                meets_min_req_rev_count = False
                labels = []
                validation_details = {}
                requested_reviewers = [reviewer.login for reviewer in pr.requested_reviewers]

                if int(min_req_rev_count) <= len(requested_reviewers):
                    meets_min_req_rev_count = True

                if not requested_reviewers:
                    validation_details = self.get_validation_details("2", int(min_req_rev_count))
                elif not meets_min_req_rev_count:
                    validation_details = self.get_validation_details("3", int(min_req_rev_count))
                else:
                    has_manager_or_above_rev, error = self.check_manager_or_above_reviewer(hierarchy_report, pr.user.login, requested_reviewers)
                    if error:
                        if "missing from the hierarchy report:" in error:
                            validation_details = self.get_validation_details("5", int(min_req_rev_count), error_msg=error)
                        else:
                            error_details.append(f"Error while processing PR '{pr.html_url}': {error}")
                            continue
                    elif not has_manager_or_above_rev:
                        validation_details = self.get_validation_details("4", int(min_req_rev_count))

                if not validation_details:
                    validation_details = self.get_validation_details("1", int(min_req_rev_count))

                labels = [label.name for label in pr.labels]

                pr_info = {
                    "System": "github",
                    "Source": "compliancecow",
                    "ResourceID": pr.number,
                    "ResourceName": pr.title,
                    "ResourceType": "Pull Request",
                    "ResourceLocation": "N/A",
                    "ResourceTags": labels or None,
                    "ResourceURL": pr.html_url,
                    "RepositoryName": repo_name,
                    # "BranchName": pr.head.ref,
                    "BranchName": pr.base.ref,
                    "PRRequester": pr.user.login,
                    "PRRequestedDateTime": pr.created_at.isoformat(),
                    "PRReviewers": requested_reviewers or None,
                    "PullRequestState": state,
                    "MinimumRequiredReviewersCount": int(min_req_rev_count),
                    "ActualReviewerCount": len(requested_reviewers),
                    "MeetsMinimumRequiredReviewersCount": meets_min_req_rev_count,
                    "HasManagerOrAboveReviewer": has_manager_or_above_rev,
                    "ValidationStatusCode": validation_details["ValidationStatusCode"],
                    "ValidationStatusNotes": validation_details["ValidationStatusNotes"],
                    "ComplianceStatus": validation_details["ComplianceStatus"],
                    "ComplianceStatusReason": validation_details["ComplianceStatusReason"],
                    "EvaluatedTime": app_connector.get_current_utc_time(),
                    "UserAction": "",
                    "ActionStatus": "",
                    "ActionResponseURL": "",
                }
                pr_details.append(pr_info)

        return pr_details, error_details

    def get_validation_details(self, validation_number: str, min_req_count: int, error_msg: str = "") -> Dict[str, str]:
        validation_data = {
            "1": {
                "ComplianceStatus": "COMPLIANT",
                "ComplianceStatusReason": "PR is created properly with all the requirements.",
                "ValidationStatusCode": "VLD_REV",
                "ValidationStatusNotes": "PR has sufficient reviewers and includes at least one manager or higher as a reviewer.",
            },
            "2": {
                "ComplianceStatus": "NON_COMPLIANT",
                "ComplianceStatusReason": f"Required reviewers is mandatory, PR should have at least {min_req_count} required reviewers. Ensure at least one reviewer in 'Required reviewers' should have a higher hierarchy than requester.",
                "ValidationStatusCode": "MSNG_REV",
                "ValidationStatusNotes": "PR has missing reviewers.",
            },
            "3": {
                "ComplianceStatus": "NON_COMPLIANT",
                "ComplianceStatusReason": f"PR should have at least {min_req_count} required reviewers. Ensure at least one reviewer in 'Required reviewers' should have a higher hierarchy than requester.",
                "ValidationStatusCode": "INS_REV",
                "ValidationStatusNotes": "PR has fewer than the required number of reviewers.",
            },
            "4": {
                "ComplianceStatus": "NON_COMPLIANT",
                "ComplianceStatusReason": "At least one reviewer in 'Required reviewers' should have a higher hierarchy than requester.",
                "ValidationStatusCode": "NO_MGR_APP",
                "ValidationStatusNotes": "PR does not have a required manager or higher-level reviewer.",
            },
            "5": {
                "ComplianceStatus": "NOT_DETERMINED",
                "ComplianceStatusReason": error_msg,
                "ValidationStatusCode": "MSNG_REV_IN_HIR",
                "ValidationStatusNotes": "PR 'Required reviewers' are missing in hierarchy report.",
            },
        }
        return validation_data.get(validation_number, {})

    def download_config_file_and_get_criterias(self, criteria_config: str) -> Tuple[List[Dict[str, str]], List[Dict[str, str]], Optional[str]]:
        toml_bytes, error = self.download_file_from_minio(criteria_config)
        if error:
            return [], [], error

        criteria_config_data = toml.loads(toml_bytes.decode("utf-8"))

        include_criteria = criteria_config_data["IncludeCriteria"]
        exclude_criteria = criteria_config_data["ExcludeCriteria"]

        return include_criteria, exclude_criteria, None

    def create_github_connector(self) -> githubconnector.GitHubConnector:
        return githubconnector.GitHubConnector(app_url=self.task_inputs.user_object.app.application_url, app_port=self.task_inputs.user_object.app.application_port, user_defined_credentials=githubconnector.UserDefinedCredentials.from_dict(self.task_inputs.user_object.app.user_defined_credentials))

    def validate_inputs(self) -> Optional[str]:
        if not self.task_inputs:
            return "missing: Task inputs"

        user_object = self.task_inputs.user_object
        if not user_object or not user_object.app or not user_object.app.user_defined_credentials:
            return "missing: User defined credentials"

        if not self.task_inputs.user_inputs:
            return "missing: User inputs"

        min_req_rev_count = self.task_inputs.user_inputs.get("MinimumRequiredReviewersCount", 0)
        input_validation_report = ""

        hierarchy_report = self.task_inputs.user_inputs.get("HRISHierarchyReport", "")
        if not hierarchy_report or hierarchy_report == "<<MINIO_FILE_PATH>>":
            input_validation_report += "'HRISHierarchyReport' cannot be empty."

        criteria_config_file = self.task_inputs.user_inputs.get("CriteriaConfig", "")
        if not criteria_config_file or criteria_config_file == "<<MINIO_FILE_PATH>>":
            input_validation_report += "'CriteriaConfig' cannot be empty."

        if min_req_rev_count is None:
            input_validation_report += "'MinimumRequiredReviewersCount' cannot be empty."
        elif not isinstance(min_req_rev_count, int):
            input_validation_report += "'MinimumRequiredReviewersCount' expected type is 'Integer'."
        elif min_req_rev_count == 0:
            input_validation_report += "'MinimumRequiredReviewersCount' cannot be '0'."

        return input_validation_report or None

    def upload_output_file(self, output: pd.DataFrame, file_name: str) -> Dict[str, str]:
        absolute_file_path, error = self.upload_df_as_parquet_file_to_minio(df=output, file_name=file_name)
        if error:
            return {"Error": error}
        return {"GithubPRRequiredReviewersReport": absolute_file_path}

    def format_log_file(self, error_msg: List[Union[str, Dict[str, str]]]) -> List[Dict[str, str]]:
        return [{"Error": msg} if not isinstance(msg, dict) else msg for msg in error_msg]

    def upload_log_file(self, error_msg: List[Union[str, Dict[str, str]]]) -> Dict[str, str]:
        formatted_error_msg = self.format_log_file(error_msg)
        absolute_file_path, error = self.upload_file_to_minio(
            file_name=f"LogFile-{str(uuid.uuid4())}.json",
            file_content=json.dumps(formatted_error_msg).encode(),
            content_type="application/json",
        )
        if error:
            return {"Error": error}
        return {"LogFile": absolute_file_path}
