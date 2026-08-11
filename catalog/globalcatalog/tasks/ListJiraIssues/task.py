
from typing import overload
from compliancecowcards.structs import cards
#As per the selected app, we're importing the app package 
from applicationtypes.jiracloud import jiracloud
from datetime import timezone
from datetime import datetime
import pandas as pd
import uuid
import json



class Task(cards.AbstractTask):

    def execute(self) -> dict:

        error = self.validate()
        if error:
            return self.upload_log_file(error)    
        
        from_date_obj = self.task_inputs.from_date
        to_date_obj = self.task_inputs.to_date

        try:
            if from_date_obj > to_date_obj:
              return self.upload_log_file([{'Error': f"The 'fromDate' must be earlier than the 'toDate'.Please give a valid 'fromDate'"}])
        except ValueError as error:
                return self.upload_log_file([{"Error" : "Invalid format - 'fromDate' or 'toDate'"}])
        
        # conversion required for jira api
        formatted_from_date = from_date_obj.strftime("%Y/%m/%d %H:%M")
        formatted_to_date = to_date_obj.strftime("%Y/%m/%d %H:%M")

        # req body dict 
        req_body_dict = {}
        req_body_dict['fields'] = "*all" # *all Returns all fields.
        req_body_dict['jql'] = f"created >= '{formatted_from_date}' AND created <= '{formatted_to_date}'"
        # default 
        req_body_dict['max_results'] = 100 # maximum max_results

        connector = jiracloud.JiraCloud(
            user_defined_credentials=jiracloud.UserDefinedCredentials.from_dict(
                self.task_inputs.user_object.app.user_defined_credentials
            ),
            app_url=self.task_inputs.user_object.app.application_url
        )

        issue_list, error_list = connector.search_issues_using_jql(req_body_dict)

        if error_list:
            return self.upload_log_file(error_list)
        
        if not issue_list:
            return self.upload_log_file([{"Error" : f"No issues found between the time period fromDate - '{from_date_obj}' and  toDate - '{to_date_obj}'"}])
        

        standard_data = self.standardize_issue(issue_list)
        file_url, error = self.upload_df_as_parquet_file_to_minio(
                    df= pd.json_normalize(standard_data),
                    file_name= f"JiraIssueList-{str(uuid.uuid4())}"
                    )
        if error:
            return self.upload_log_file([{"Error while uploading JiraIssueList" : error}])
        
        return { 'JiraIssueList': file_url}

    
    def standardize_issue(self, issue_list):
        standard_list = []

        for issue in issue_list:
            fields = issue.get("fields", {}) or {}

            project = fields.get("project") or {}
            issuetype = fields.get("issuetype") or {}
            priority = fields.get("priority") or {}
            status = fields.get("status") or {}
            creator = fields.get("creator") or {}
            assignee = fields.get("assignee") or {}
            reporter = fields.get("reporter") or {}
            project_name = project.get("name", "")

            data = {
                "System": "jira",
                "Source": "compliancecow",
                "ResourceName": issue.get("key", ""),
                "ResourceID": issue.get("id", ""),
                "ResourceLocation": "N/A",
                "ResourceTags": "N/A",
                "ResourceType": issuetype.get("name", ""),
                "ResourceURL": (
                    f"{self.task_inputs.user_object.app.application_url}/browse/{issue.get('key', '')}"
                ),
                "Project": project_name,
                "Description": self.get_description_text(fields.get("description")),
                "Summary": fields.get("summary", ""),
                "Priority": priority.get("name", ""),
                "Status": status.get("name", ""),
                "StatusCategoryChangeDate": fields.get("statuscategorychangedate", ""),
                "CreatedDate": fields.get("created", ""),
                "UpdatedDate": fields.get("updated", ""),
                "Creator": creator.get("displayName", ""),
                "Assignee": assignee.get("displayName", ""),
                "Reporter": reporter.get("displayName", ""),
                "IssueLinks": fields.get("issuelinks", []) or [],
                "Labels": fields.get("labels", []) or [],
                "EvaluatedTime": self.get_current_datetime(),
                "UserAction": "",
                "ActionStatus": "",
                "ActionResponseURL": "",
            }

            standard_list.append(data)

        return standard_list

    def get_description_text(self, description):
        if not description:
            return ""

        # Plain text description
        if isinstance(description, str):
            return description

        # Unexpected type
        if not isinstance(description, dict):
            return str(description)

        content = description.get("content", [])
        text_parts = []

        for block in content:
            for item in block.get("content", []):
                if item.get("type") == "text":
                    text_parts.append(item.get("text", ""))

        return "\n".join(text_parts)

    def upload_log_file(self, errors_list):
        log_file_path, error = self.upload_file_to_minio(file_content=json.dumps(errors_list).encode('utf-8'), 
                                                         file_name=f'LogFile-{str(uuid.uuid4())}.json', content_type='application/json')
        if error:
            return {'Error': error}
        return { 'LogFile': log_file_path,}
    
        
    def validate(self):
        task_inputs = self.task_inputs
        if not task_inputs:
            return ["Task input is missing"]

        err_list = []
        empty_attrs = []
        invalid_attrs = []

        if self.task_inputs.from_date is None:
            empty_attrs.append("fromDate")
        elif not isinstance(self.task_inputs.from_date, datetime):
            invalid_attrs.append("fromDate")

        if self.task_inputs.to_date is None:
            empty_attrs.append("toDate")
        elif not isinstance(self.task_inputs.to_date, datetime):
            invalid_attrs.append("toDate")

        user_object = self.task_inputs.user_object
        if not user_object or not user_object.app or not user_object.app.user_defined_credentials:
            err_list.append({"Error" : "User defined credential is missing"})
        else:
            if not self.task_inputs.user_object.app.application_url:
              empty_attrs.append("appURL")

        if empty_attrs:
            err_list.append({"Error" :"Empty field(s): " + ", ".join(empty_attrs)})

        if invalid_attrs:
            err_list.append({"Error" : "Invalid field(s): " + ", ".join(invalid_attrs)})

        return err_list
    

    def get_current_datetime(self):       
        current_time = datetime.now(timezone.utc)
        formatted_time = current_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        return formatted_time
    