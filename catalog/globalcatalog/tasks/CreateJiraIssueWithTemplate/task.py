from typing import Optional, Dict, List, Tuple, Any
from compliancecowcards.structs import cards
import json
import uuid
from applicationtypes.jiracloud import jiracloud
import jmespath
import re

logger = (
    cards.Logger()
)  # Initializes a Logger instance to log data, use logger.log_data(dict) to log a data

DEFAULT_MINIO_PLACEHOLDER = "<<MINIO_URL>>"


class Task(cards.AbstractTask):

    def execute(self) -> dict:

        self.set_log_file_name("Error")

        if error := self._check_inputs():
            return self.upload_log_file_panic(error)

        jira_issue_template_url = self.task_inputs.user_inputs.get("JiraIssueTemplate")

        jira_issue_template, error = self._download_json_file(
            url=jira_issue_template_url,
        )
        if error:
            return self.upload_log_file_panic(error)

        jira_instance_config_file_url = self.task_inputs.user_inputs.get(
            "JiraInstanceConfigFile"
        )
        jira_instance_url = ""

        if (
            jira_instance_config_file_url
            and jira_instance_config_file_url != DEFAULT_MINIO_PLACEHOLDER
        ):
            jira_instance_config_data, error = self._download_json_file(
                url=jira_instance_config_file_url,
            )
            if error:
                return self.upload_log_file_panic(error)

            if isinstance(jira_instance_config_data, list):
                jira_instance_url = jmespath.search(
                    "[0].JIRA_INSTANCE_URL", jira_instance_config_data
                )
                pattern = r"^https:\/\/[a-zA-Z0-9\-]+\.atlassian\.net"
                if isinstance(jira_instance_url, str) and re.match(
                    pattern, jira_instance_url
                ):
                    jira_instance_url = jira_instance_url.rstrip("/")
                else:
                    jira_instance_url = ""

        if jira_instance_url:
            self.task_inputs.user_object.app.application_url = jira_instance_url

        self.jira_app = jiracloud.JiraCloud(
            app_url=self.task_inputs.user_object.app.application_url,
            app_port=self.task_inputs.user_object.app.application_port,
            user_defined_credentials=jiracloud.UserDefinedCredentials.from_dict(
                self.task_inputs.user_object.app.user_defined_credentials
            ),
        )

        if isinstance(jira_issue_template, list):
            jira_issue_template = jira_issue_template[0]

        created_issue, error = self._create_jira_issue(
            issue_template=jira_issue_template,
        )
        response = {}
        if error:
            return self.upload_log_file_panic(error)
        if not created_issue:
            return self.upload_log_file_panic("Created issue is empty")
        if created_issue:
            file_url, error = self._upload_output_file(
                "OutputFile",
                {
                    "id": created_issue.id,
                    "key": created_issue.key,
                    "url": self.jira_app.get_jira_issue_url(created_issue.key),
                },
            )
            if error:
                return self.upload_log_file_panic(error)
            response["CreatedTicket"] = file_url
        return response

    def _create_jira_issue(self, issue_template: Dict) -> Tuple[Dict, Optional[Dict]]:
        """
        Create a Jira issue using the provided template.
        Args:
            issue_template (Dict): The template for the Jira issue.
        Returns:
            Tuple[Dict, Optional[Dict]]: The created issue and any error encountered.
        """
        try:
            issue_template_fields: dict = issue_template.get("fields", {})

            description = issue_template_fields.get("description", "")

            priority = jmespath.search("priority.name", issue_template_fields)
            jira_priorities, error = self.jira_app.get_priorities()
            if error:
                return {}, {
                    "Error": f"Failed to create Jira issue :: Error while getting priorities: {error}"
                }

            valid_priority_names = [
                jira_priority.name for jira_priority in jira_priorities
            ]
            if not priority or priority not in valid_priority_names:
                issue_template_fields.pop("priority", "")

            issue, err = self.jira_app.create_issue_v3(
                issue_template_fields, 3 if isinstance(description, dict) else 2
            )
            if err:
                return {}, {"Error": f"Failed to create Jira issue: {err}"}
            return issue, None
        except Exception as e:
            return {}, {"Error": f"Failed to create Jira issue: {e}"}

    def _check_inputs(self) -> Optional[str]:
        """Validate task inputs."""
        if not self.task_inputs or not self.task_inputs.user_inputs:
            return "Missing task or user inputs"
        user_obj = self.task_inputs.user_object
        if (
            not user_obj
            or not user_obj.app
            or not user_obj.app.application_url
            or not user_obj.app.user_defined_credentials
        ):
            return "Missing user credentials"
        jira_issue_template = self.task_inputs.user_inputs.get("JiraIssueTemplate", "")
        if not jira_issue_template or jira_issue_template == DEFAULT_MINIO_PLACEHOLDER:
            return "JiraIssueTemplate is empty"

        return None

    def _download_json_file(self, url: str) -> Tuple[List[Dict], Optional[str]]:
        """Download and parse JSON file from MinIO."""
        file_bytes, error = self.download_file_from_minio(url)
        if error:
            return [], f"Failed to download file: {error}"
        try:
            data = json.loads(file_bytes.decode("utf-8"))
            return data, None
        except json.JSONDecodeError as e:
            return [], f"Invalid JSON: {e}"

    def _upload_output_file(
        self, file_name: str, data: List[Any]
    ) -> Tuple[str, Optional[str]]:
        """Upload output file to MinIO."""
        file_url, error = self.upload_file_to_minio(
            file_name=f"{file_name}-{uuid.uuid4()}.json",
            file_content=json.dumps(data).encode("utf-8"),
            content_type="application/json",
        )
        return file_url, error
