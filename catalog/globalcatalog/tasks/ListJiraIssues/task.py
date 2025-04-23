
from typing import overload
from compliancecowcards.structs import cards
#As per the selected app, we're importing the app package 
from appconnections.jiracloud import jiracloud
from datetime import timezone
from datetime import datetime
import pandas as pd
import uuid
import json



class Task(cards.AbstractTask):

    def execute(self) -> dict:

        error = self.validate()
        if error:
            return self.upload_log_file([{'Error': error}])    
        
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
            if not hasattr(issue, 'fields') or issue.fields is None:
              continue

            is_valid_fields = True

            data = {
                "System"                   : "jira",
                "Source"                   : "compliancecow",
                "ResourceName"             : issue.key if hasattr(issue, 'key') and issue.key is not None else "",
                "ResourceID"               : issue.id if hasattr(issue, 'id') and issue.id is not None else "",
                "ResourceLocation"         : "N/A",
                "ResourceTags"             : "N/A",
                "ResourceType"             : issue.fields.issuetype.name if is_valid_fields and hasattr(issue.fields, 'issuetype') and issue.fields.issuetype is not None and hasattr(issue.fields.issuetype, 'name') and issue.fields.issuetype.name is not None else "",
                "ResourceURL"              : self.task_inputs.user_object.app.application_url + "/jira/software/c/projects/" + issue.fields.project.name + "/issues/" + issue.key if is_valid_fields and hasattr(issue.fields, 'project') and issue.fields.project is not None and hasattr(issue.fields.project, 'name') and issue.fields.project.name is not None else "",
                "Project"                  : issue.fields.project.name if hasattr(issue.fields, 'project') and issue.fields.project is not None and hasattr(issue.fields.project, 'name') and issue.fields.project.name is not None else "",
                "Description"              : issue.fields.description if hasattr(issue.fields, 'description') and issue.fields.description is not None else "",
                "Summary"                  : issue.fields.summary if hasattr(issue.fields, 'summary') and issue.fields.summary is not None else "",
                "Priority"                 : issue.fields.priority.name if hasattr(issue.fields, 'priority') and issue.fields.priority is not None and hasattr(issue.fields.priority, 'name') and issue.fields.priority.name is not None else "",
                "Status"                   : issue.fields.status.name if is_valid_fields and hasattr(issue.fields, 'status') and issue.fields.status is not None and hasattr(issue.fields.status, 'name') and issue.fields.status.name is not None else "",
                "StatusCategoryChangeDate" : issue.fields.statuscategorychangedate if is_valid_fields and hasattr(issue.fields, 'statuscategorychangedate') and issue.fields.statuscategorychangedate is not None else "",
                "CreatedDate"              : issue.fields.created if is_valid_fields and hasattr(issue.fields, 'created') and issue.fields.created is not None else "",
                "UpdatedDate"              : issue.fields.updated if is_valid_fields and hasattr(issue.fields, 'updated') and issue.fields.updated is not None else "",
                "Creator"                  : issue.fields.creator.displayName if is_valid_fields and hasattr(issue.fields, 'creator') and issue.fields.creator is not None and hasattr(issue.fields.creator, 'displayName') and issue.fields.creator.displayName is not None else "",
                "Assignee"                 : issue.fields.assignee.displayName if is_valid_fields and hasattr(issue.fields, 'assignee') and issue.fields.assignee is not None and hasattr(issue.fields.assignee, 'displayName') and issue.fields.assignee.displayName is not None else "",
                "Reporter"                 : issue.fields.reporter.displayName if is_valid_fields and hasattr(issue.fields, 'reporter') and issue.fields.reporter is not None and hasattr(issue.fields.reporter, 'displayName') and issue.fields.reporter.displayName is not None else "",
                "IssueLinks"               : issue.fields.issuelinks if is_valid_fields and hasattr(issue.fields, 'issuelinks') and issue.fields.issuelinks is not None else [],
                "Labels"                   : issue.fields.labels if is_valid_fields and hasattr(issue.fields, 'labels') and issue.fields.labels is not None else [],
                "EvaluatedTime"            : self.get_current_datetime(),
                "UserAction"               : "",
                "ActionStatus"             : "",
                "ActionResponseURL"        : ""
            }

            is_valid_fields = False
            if hasattr(issue, 'fields') and issue.fields is not None:
                is_valid_fields = True

            standard_list.append(data)

        return standard_list


    
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
            err_list.append("User defined credential is missing")
        else:
            if not self.task_inputs.user_object.app.application_url:
              empty_attrs.append("appURL")

        if empty_attrs:
            err_list.append("Empty field(s): " + ", ".join(empty_attrs))

        if invalid_attrs:
            err_list.append("Invalid field(s): " + ", ".join(invalid_attrs))

        return err_list
    

    def get_current_datetime(self):       
        current_time = datetime.now(timezone.utc)
        formatted_time = current_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        return formatted_time
    