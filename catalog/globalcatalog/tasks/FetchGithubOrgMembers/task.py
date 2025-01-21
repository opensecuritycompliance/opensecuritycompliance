from typing import overload
from compliancecowcards.structs import cards
from compliancecowcards.utils import cowdictutils
# As per the selected app, we're importing the app package
from appconnections.githubconnector import githubconnector
from github import Github
import json
import uuid
import pandas as pd
from datetime import datetime

# Initializes a Logger instance to log data, use logger.log_data(dict) to log a data
logger = cards.Logger()

class Task(cards.AbstractTask):

    def execute(self) -> dict:
        response = {}

        error = self.check_inputs()
        if error:
            return self.upload_log_file([{'Error': error}])

        error = self.check_apps()
        if error:
            return self.upload_log_file([{'Error': error}])

        self.github_app_connector = githubconnector.GitHubConnector(
            app_url=self.task_inputs.user_object.app.application_url,
            app_port=self.task_inputs.user_object.app.application_port,
            user_defined_credentials=githubconnector.UserDefinedCredentials.from_dict(
                self.task_inputs.user_object.app.user_defined_credentials)
        )

        organization_names = list(
            map(str.strip, self.task_inputs.user_inputs.get('OrganizationName').split(','))
        )

        github_user_list, error_list = self.list_organization_members(
            organization_names=organization_names)

        if github_user_list:
            absolute_file_path, error = self.upload_output_file(
                file_content=github_user_list, evidence_name='GitHubOrganizationMembers')
            if error:
                return {'Error': error}
            response['GitHubOrganizationMembers'] = absolute_file_path

        if error_list:
            log_file_info = self.upload_log_file(error_list=error_list)
            if cowdictutils.is_valid_key(log_file_info, 'LogFile'):
                response['LogFile'] = log_file_info['LogFile']
            else:
                return {'Error': log_file_info['Error']}

        return response

    def list_organization_members(self, organization_names: list) -> tuple[list, list]:
        error_list = []
        github_user_list = []
        for organization_name in organization_names:
            org_members, error = self.github_app_connector.list_organization_members(
                organization_name=organization_name)
            if error:
                error_list.append({'Error': error})
                continue
            org_repos, error = self.github_app_connector.list_organization_repos(
                organization_name=organization_name)
            if error:
                error_list.append({'Error': error})
                continue
            for member in org_members:
                user_repos = []
                for repo in org_repos:
                    if repo.has_in_collaborators(member.login):
                        user_repos.append(repo.name)
                std_data = {
                    'System': 'github',
                    'Source': 'compliancecow',
                    'ResourceID': member.id,
                    'ResourceName': member.login,
                    'ResourceType': 'User',
                    'ResourceLocation': 'N/A',
                    'ResourceTags': [],
                    'ResourceURL': f'https://github.com/orgs/{organization_name}/people/{member.login}',
                    'OrganizationName': organization_name,
                    'UserEmail': member.email if member.email else 'N/A',
                    'UserCreatedAt': self.convert_github_timestamp(github_timestamp=member.created_at),
                    'UserUpdatedAt': self.convert_github_timestamp(github_timestamp=member.updated_at),
                    'UserCompany': member.company if member.company else 'N/A',
                    'UserIsSiteAdmin': member.site_admin,
                    'UserPublicReposCount': member.public_repos,
                    'UserFollowersCount': member.followers,
                    'UserAccessRepos': user_repos
                }
                github_user_list.append(std_data)
        return github_user_list, error_list

    def check_inputs(self) -> str:
        if not self.task_inputs:
            return 'Task inputs are missing.'
        user_inputs = self.task_inputs.user_inputs
        if not user_inputs:
            return 'User inputs are missing.'
        if not cowdictutils.is_valid_key(user_inputs, 'OrganizationName'):
            return 'OrganizationName is empty. Please provide a valid name for OrganizationName.'

    def check_apps(self) -> str:
        task_inputs = self.task_inputs
        if not task_inputs:
            return 'Task inputs are missing.'

        user_object = task_inputs.user_object
        if (
            user_object is None
            or user_object.app is None
            or user_object.app.application_url is None
            or user_object.app.user_defined_credentials is None
        ):
            return 'GitHub app credentials are missing.'

        if cowdictutils.is_valid_key(user_object.app.user_defined_credentials, 'AccessToken'):
            if not cowdictutils.is_valid_key(user_object.app.user_defined_credentials.get('AccessToken'), 'AccessToken'):
                return 'GitHub AccessToken is missing.'
        else:
            return 'GitHub AccessToken is missing.'

        return None

    def convert_github_timestamp(self, github_timestamp: datetime) -> str:
        formatted_time = github_timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
        return formatted_time

    def upload_log_file(self, error_list: list) -> dict:
        absolute_file_path, error = self.upload_file_to_minio(file_content=json.dumps(error_list).encode(
            'utf-8'), file_name=f'LogFile-{str(uuid.uuid4())}.json', content_type='application/json')
        if error:
            return {'Error': error}
        return {
            'LogFile': absolute_file_path
        }

    def upload_output_file(self, file_content: list, evidence_name: str) -> tuple[str, dict]:
        df = pd.DataFrame(file_content)
        absolute_file_path, error = self.upload_df_as_parquet_file_to_minio(
            df, evidence_name)
        return absolute_file_path, error
