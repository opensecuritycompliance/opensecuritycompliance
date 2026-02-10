from typing import List
from github import GithubException
from github import Github, Auth
from github.Membership import Membership
from github.NamedUser import NamedUser
from github.AuthenticatedUser import AuthenticatedUser
import datetime
from  datetime import timezone
import requests
from github.GithubException import UnknownObjectException, GithubException, BadCredentialsException
import pandas as pd
import github
import copy
import http
from github.AuthenticatedUser import AuthenticatedUser
from github.Repository import Repository
class AccessToken:
    access_token: str

    def __init__(self, access_token: str) -> None:
        self.access_token = access_token

    @staticmethod
    def from_dict(obj) -> 'AccessToken':
        access_token = ""
        if isinstance(obj, dict):
            access_token = obj.get("AccessToken", "")

        return AccessToken(access_token)

    def to_dict(self) -> dict:
        result: dict = {}
        result["AccessToken"] = self.access_token
        return result

    def validate_attributes(self) -> str:
        emptyAttrs = []
        if not self.access_token:
            emptyAttrs.append("AccessToken")

        return "Invalid Credentials: " + ", ".join(
            emptyAttrs) + " is empty" if emptyAttrs else ""


class UserDefinedCredentials:
    access_token: AccessToken

    def __init__(self, access_token: AccessToken) -> None:
        self.access_token = access_token

    @staticmethod
    def from_dict(obj) -> 'UserDefinedCredentials':
        access_token = None
        if isinstance(obj, dict):
            access_token = AccessToken.from_dict(obj.get("AccessToken", None))
        return UserDefinedCredentials(access_token)

    def to_dict(self) -> dict:
        result: dict = {}
        result["AccessToken"] = self.access_token.to_dict()
        return result


class GitHubConnector:
    app_url: str
    app_port: int
    user_defined_credentials: UserDefinedCredentials

    def __init__(
            self,
            app_url: str = None,
            app_port: int = None,
            user_defined_credentials: UserDefinedCredentials = None) -> None:
        self.app_url = app_url
        self.app_port = app_port
        self.user_defined_credentials = user_defined_credentials

    @staticmethod
    def from_dict(obj) -> 'GitHubConnector':
        app_url, app_port, user_defined_credentials = "", "", None
        if isinstance(obj, dict):
            app_url = obj.get("AppURL", "")
            if not app_url:
                app_url = obj.get("appURL", "")
            app_port = obj.get("AppPort", 0)
            if not app_port:
                app_port = obj.get("appPort", 0)
            user_defined_credentials_dict = obj.get("UserDefinedCredentials",
                                                    None)
            if user_defined_credentials_dict is None:
                user_defined_credentials_dict = obj.get(
                    "userDefinedCredentials", None)
            if bool(user_defined_credentials_dict):
                user_defined_credentials = UserDefinedCredentials.from_dict(
                    user_defined_credentials_dict)

        return GitHubConnector(app_url, app_port, user_defined_credentials)

    def to_dict(self) -> dict:
        result: dict = {}
        result["AppURL"] = self.app_url
        result["AppPort"] = self.app_port
        result[
            "UserDefinedCredentials"] = self.user_defined_credentials.to_dict(
            )
        return result

    def validate(self) -> bool and dict:
        err = self.validate_github_credential()
        if err:
            return False, err
        return True, None
    
    def validate_github_credential(self):
        err = self.user_defined_credentials.access_token.validate_attributes()
        if err:
            return err
        access_token = self.user_defined_credentials.access_token.access_token
        auth = Auth.Token(access_token)
        github_client = Github(auth=auth)

        try:
            user = github_client.get_user()
            user.login
        except github.BadCredentialsException:
            return "Invalid AccessToken."
        except Exception as e:
            return str(e)
        return None
    
    def create_github_client(self) : 
        
        access_token = self.user_defined_credentials.access_token.access_token
        auth = Auth.Token(access_token)
        github_client = Github(auth=auth)
        
        return github_client
    
    def list_github_repos(self) :
        
        github_client = self.create_github_client()
        user = github_client.get_user()
        repos = user.get_repos()
        return repos

    def get_github_repo(self, repo_name) :
        
        github_client = self.create_github_client()
        repo = None
        try:
            repo = github_client.get_repo(repo_name)
        except Exception as e:
            repo = None 
        return repo

    def list_github_orgs(self):
        try:
            github_client = self.create_github_client()
            orgs = github_client.get_user().get_orgs()
            return orgs, None
        except GithubException as ge:
            return None, f"An error occurred while fetching GitHub organizations: {ge}"
        except ConnectionError:
            return None, "Failed to connect to GitHub API."
        except TimeoutError:
            return None, "Connection to GitHub API timed out."
    
    def validate_organization_repo_branch(self, x_criterias_as_dict_list):
        github_client = self.create_github_client()
        validation_message = []
        validated_crterias = []

        for criteria in x_criterias_as_dict_list:
            org_name = criteria.get("org", "")
            repos = criteria.get("repo", [])
            branches = criteria.get("branch", [])

            # Validate organization
            try:
                org_details = github_client.get_organization(org_name)
            except GithubException as e:
                if e.status == http.HTTPStatus.NOT_FOUND: 
                    validation_message.append(f"Organization '{org_name}' does not exist.")
                else:
                    validation_message.append(f"An error occurred while checking organization '{org_name}': {e}")
                continue  
            
            if not (len(repos) == 1 and repos[-1] == "*"):
                valid_repos = []
                for repo in repos:
                    current_repo = repo
                    # Validate repository
                    try:
                        repo_details = org_details.get_repo(repo)
                        valid_repos.append(current_repo)
                    except GithubException as e:
                        if e.status == http.HTTPStatus.NOT_FOUND:
                            validation_message.append(f"Repository '{current_repo}' does not exist in organization '{org_name}'.")
                        else:
                            validation_message.append(f"An error occurred while checking repository '{current_repo}' in organization '{org_name}': {e}")
                        continue  
                    if not (len(branches) == 1 and branches[-1] == "*"):
                        valid_branches = []
                        for branch in branches:
                            current_branch = branch
                            # Validate branch
                            try:
                                repo_details.get_branch(branch)
                                valid_branches.append(current_branch)
                            except GithubException as e:
                                if e.status == http.HTTPStatus.NOT_FOUND:
                                    validation_message.append(f"Branch '{current_branch}' does not exist in repository '{current_repo}'.")
                                else:
                                    validation_message.append(f"An error occurred while checking branch '{current_branch}' in repository '{current_repo}': {e}")
                                continue
                        criteria["branch"] = valid_branches
                criteria["repo"] = valid_repos
                
                        
            validated_crterias.append(criteria)
            
        return validated_crterias , validation_message

    def get_current_utc_time(self):
        current_time = datetime.datetime.now(timezone.utc)
        formatted_time = current_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        return formatted_time
    
    def get_rule_sets_details(self,repo , branch ) :
        
        access_token = self.user_defined_credentials.access_token.access_token
        url = f"https://api.github.com/repos/{repo}/rules/branches/{branch}"
        headers = {
            'Accept': 'application/vnd.github+json',
            'Authorization': f'Bearer {access_token}',
            'X-GitHub-Api-Version': '2022-11-28'
            }

        response = requests.request("GET", url, headers=headers, data= {})
        
        rule_set_details = response.json() if response.status_code == 200 else None
        if rule_set_details == None :
            if "Upgrade to GitHub Pro or make this repository public to enable this feature." in response.text:
                return None , f"Cannot fetch ruleset for private branch '{branch}' within repo '{repo}'."
            return None , response.text
        
        return rule_set_details, ""
    
    def apply_filter_to_query_org(self,org , include_criteria):
        
        include_criteria_df = pd.DataFrame(include_criteria)
        filtered_df = include_criteria_df[include_criteria_df["org"] != org]
        return filtered_df.to_dict(orient = "records")

    def apply_filter_to_query_repo(self, org , repos , include_criteria):
        
        include_criteria_df = pd.DataFrame(include_criteria)
        no_filter_apply = (include_criteria_df[(include_criteria_df["org"] != org)]).to_dict(orient = "records")
        filtered_df = include_criteria_df[(include_criteria_df["org"] == org)]

        for index,row in filtered_df.iterrows() :
            
            for repo in repos :
                if repo in row["repo"] :
                    row["repo"].remove(repo)
            if len(row["repo"]) > 0 :
                no_filter_apply.append(row.to_dict())
            
        return no_filter_apply

    def apply_filter_to_query_branch(self, org, repos, branches, include_criteria):
        include_criteria_df = pd.DataFrame(include_criteria)
        
        # Filter out rows where org does not match
        filter_applied = (include_criteria_df[(include_criteria_df["org"] != org)]).to_dict(orient="records")
        filtered_df = include_criteria_df[(include_criteria_df["org"] == org)]

        need_to_apply_branch = []
        # Process rows with matching org
        for index, row in filtered_df.iterrows():
            is_repo_found = any(repo in row["repo"] for repo in repos)
            row_dict = row.to_dict()
            
            if is_repo_found:
                need_to_apply_branch.append(copy.deepcopy(row_dict))
            else:
                filter_applied.append(row_dict)
                    
        # Remove branches as needed
        for row in need_to_apply_branch:
            row_copy = copy.deepcopy(row)
            row_copy["branch"] = [branch for branch in row_copy["branch"] if branch not in branches]
            if len(row_copy["branch"]) > 0 :
                filter_applied.append(row_copy)
                
        return filter_applied


    def apply_exclude_filter_to_include_query(self, include_criteria ,exclude_criteria) :
        
        updated_include_criteria = copy.deepcopy(include_criteria)
        for exclude in exclude_criteria :
            
            org = exclude.get("org" , "" )
            repo = exclude.get("repo" , [] )
            branch = exclude.get("branch" , [] )
            
            if len(repo) == 0 :
                updated_include_criteria = self.apply_filter_to_query_org(org , updated_include_criteria)
            elif len(branch) == 0 :
                updated_include_criteria = self.apply_filter_to_query_repo(org , repo , updated_include_criteria)
            else:
                updated_include_criteria = self.apply_filter_to_query_branch(org ,repo, branch , updated_include_criteria)
                
        return updated_include_criteria
        
    
    
    def filter_criterias(self, x_criterias , criteria_name):
        
        validate_filter = []
        x_criterias_as_dict_list = []
        
        for x_criteria in x_criterias :
            x_criteria_as_dict = {}
            
            x_criteria_list = x_criteria.split("/")
            if len(x_criteria_list) % 2 != 0:
                    validate_filter.append(f"{criteria_name}: Invalid formate '{x_criteria}'")
            else:
                for i in range(0, len(x_criteria_list), 2):
                    if x_criteria_list[i] == "org" :
                        org_data = x_criteria_list[i+1].split(",")
                        if len(org_data) > 1 or (len(org_data) == 1 and  org_data[-1] == "*"):
                            x_criteria_str = "/".join(x_criteria_list)
                            validate_filter.append(f"{criteria_name}: Organization cannot be more than one for a query '{x_criteria_str}'.")
                            break
                        else:
                            x_criteria_as_dict[x_criteria_list[i]] = x_criteria_list[i+1]
                        continue
                    x_criteria_as_dict[x_criteria_list[i]] = x_criteria_list[i+1].split(",")
            if x_criteria_as_dict :
                x_criterias_as_dict_list.append(x_criteria_as_dict)
        
        validated_crterias = []
        if len(x_criterias_as_dict_list) > 0 :
            validated_crterias,validation_data = self.validate_organization_repo_branch(x_criterias_as_dict_list)
            if len(validation_data) > 0 :
                validate_filter.extend(validation_data)
        return validated_crterias, validate_filter
    
    def handle_wildcard_in_query(self,filter_criterias) :

        updated_filter = []
        
        for filter in filter_criterias :
            
            org = filter.get("org" , "" )
            repos = filter.get("repo" , [] )
            branches = filter.get("branch" , [] )
            
            if len(repos) == 1 and repos[-1] == "*" :
                collected_repos = []
                available_repo = self.list_github_repos()
                for repo in available_repo :
                    if org in repo.full_name :
                        collected_repos.append(repo.name)
                filter["repo"] = collected_repos
            
            if len(branches) == 1 and branches[-1] == "*" :
                for repo in filter["repo"] :
                    collected_branch = []
                    
                    available_repo = self.get_github_repo(f'{org}/{repo}')
                    
                    available_branches = available_repo.get_branches()
                    for branch in available_branches :
                        collected_branch.append(branch.name)
                    
                    filter["branch"] = list(set(collected_branch))
                    filter_temp = filter.copy()
                    filter_temp["repo"] = [repo]
                    updated_filter.append(filter_temp)
            else:
                updated_filter.append(filter)    
                          
        return updated_filter

    def remove_duplicates(self,criteria_list):
        unique_entries = []
        seen = set()

        for criteria in criteria_list:
            org = criteria["org"]
            repos = criteria["repo"]
            branches = criteria["branch"]

            for repo in repos:
                for branch in branches:
                    key = (org, repo, branch)
                    if key not in seen:
                        seen.add(key)
                        unique_entries.append({
                            "org": org,
                            "repo": [repo],
                            "branch": [branch]
                        })

        # Consolidate the unique entries by merging branches for the same org/repo
        consolidated_entries = []
        consolidated_map = {}

        for entry in unique_entries:
            org = entry["org"]
            repo = entry["repo"][0]
            branch = entry["branch"][0]

            key = (org, repo)
            if key not in consolidated_map:
                consolidated_map[key] = {"org": org, "repo": [repo], "branch": []}

            consolidated_map[key]["branch"].append(branch)

        # Convert the map back to a list
        for value in consolidated_map.values():
            consolidated_entries.append(value)

        return consolidated_entries

    def filter_include_exclude_criteria(self, include_criterias, exclude_criteria):
        
        include_list, include_filter_errors = self.filter_criterias(include_criterias , "Include Criteria")
        exclude_list, enclude_filter_errors = self.filter_criterias( exclude_criteria , "Exclude Criteria")
        
        if len(include_list) == 0 :
            return [] , include_filter_errors
        
        include_list = self.handle_wildcard_in_query(include_list)
        exclude_list = self.handle_wildcard_in_query(exclude_list)
        filter_errors = include_filter_errors + enclude_filter_errors
        
        updated_include_list = self.apply_exclude_filter_to_include_query(include_list,exclude_list )
        
        consolidated_list = self.remove_duplicates(updated_include_list)
        return consolidated_list , filter_errors
        
    def get_organization_membership_for_user(self, member: NamedUser | AuthenticatedUser, organization_name: str) -> tuple[Membership | None, str]:
        try:
            membership = member.get_organization_membership(organization_name)
            return membership, ""
        except GithubException as ge:
            return None, f"An error occurred while fetching GitHub organizations: {ge}"
        except ConnectionError:
            return None, "Failed to connect to GitHub API."
        except TimeoutError:
            return None, "Connection to GitHub API timed out."

    def list_organization_members(self, organization_name: str) -> tuple[list[AuthenticatedUser], str]:
        try:
            github_client = self.create_github_client()
            org = github_client.get_organization(organization_name)
            members = org.get_members()
            return members, ""
        except UnknownObjectException:
            return None, f"Organization '{organization_name}' not found. Please provide a valid organization name."
        except BadCredentialsException:
            return None, f"Unauthorized access to organization '{organization_name}'. Please provide a valid access token."

    def list_organization_repos(self, organization_name: str) -> tuple[list[Repository], str]:
        try:
            github_client = self.create_github_client()
            org = github_client.get_organization(organization_name)
            repos = org.get_repos()
            return repos, ""
        except UnknownObjectException:
            return None, f"Organization '{organization_name}' not found. Please provide a valid organization name."
        except BadCredentialsException:
            return None, f"Unauthorized access to organization '{organization_name}'. Please provide a valid access token."

# INFO : You can implement methods (to access the application) which can be then invoked from your task code
