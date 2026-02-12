from datetime import datetime, timezone
from typing import List, Tuple, Optional, Dict, Any
import base64
import re
from google.auth.exceptions import GoogleAuthError
from google.oauth2 import service_account
from google.auth.transport.requests import Request 
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseDownload
from googleapiclient.http import MediaIoBaseUpload
from compliancecowcards.utils import cowdictutils
from googleapiclient.http import BatchHttpRequest
from google.auth.exceptions import DefaultCredentialsError
from google.auth.exceptions import RefreshError
import logging
import os
import io
import pandas as pd



class GoogleWorkSpace:
    user_email: str
    service_account_key_file: str

    def __init__(self, user_email: str, service_account_key_file: str) -> None:
        self.user_email = user_email
        self.service_account_key_file = service_account_key_file

    @staticmethod
    def from_dict(obj) -> 'GoogleWorkSpace':
        user_email, service_account_key_file = "", ""
        if isinstance(obj, dict):
            user_email = obj.get("UserEmail", "")
            service_account_key_file = obj.get("ServiceAccountKeyFile", "")

        return GoogleWorkSpace(user_email, service_account_key_file)

    def to_dict(self) -> dict:
        result: dict = {}
        result["UserEmail"] = self.user_email
        result["ServiceAccountKeyFile"] = self.service_account_key_file
        return result

    def validate_attributes(self) -> str:
        emptyAttrs = []
        if not self.user_email:
            emptyAttrs.append("UserEmail")

        if not self.service_account_key_file:
            emptyAttrs.append("ServiceAccountKeyFile")

        return "Invalid Credentials: " + ", ".join(
            emptyAttrs) + " is empty" if emptyAttrs else ""


class UserDefinedCredentials:
    google_work_space: GoogleWorkSpace

    def __init__(self, google_work_space: GoogleWorkSpace) -> None:
        self.google_work_space = google_work_space

    @staticmethod
    def from_dict(obj) -> 'UserDefinedCredentials':
        google_work_space = None
        if isinstance(obj, dict):
            google_work_space = GoogleWorkSpace.from_dict(
                obj.get("GoogleWorkSpace", None))
        return UserDefinedCredentials(google_work_space)

    def to_dict(self) -> dict:
        result: dict = {}
        result["GoogleWorkSpace"] = self.google_work_space.to_dict()
        return result


class GoogleWorkSpaceAppConnector:
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
    def from_dict(obj) -> 'GoogleWorkSpaceAppConnector':
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

        return GoogleWorkSpaceAppConnector(app_url, app_port,
                                           user_defined_credentials)

    def to_dict(self) -> dict:
        result: dict = {}
        result["AppURL"] = self.app_url
        result["AppPort"] = self.app_port
        result[
            "UserDefinedCredentials"] = self.user_defined_credentials.to_dict(
            )
        return result

    def validate(self):
        try:
            err_msg = self.user_defined_credentials.google_work_space.validate_attributes()
            if err_msg:
                return False, err_msg
            email_regex = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
            if not email_regex.match(self.user_defined_credentials.google_work_space.user_email):
                return False, "Invalid 'UserEmail'"
            projects, error = self.list_projects()
            if error:
                return False, error
            return True, ''
        except GoogleAuthError as e:
            logging.exception("An exception occurred while fetching domain details: %s", str(e))
            if len(e.args) >= 1:
                if cowdictutils.is_valid_key(e.args[1],'error_description'):
                    if e.args[1]['error_description'] == 'Invalid email or User ID':
                        return False, "Invalid 'UserEmail'"
            return False, "Invalid 'UserEmail' or 'ServiceAccountKeyFile'"            

    def create_admin_service(self):
        try:
            scope = 'https://www.googleapis.com/auth/admin.directory.domain.readonly'
            token_source, err = self.create_config(scope)
            if err:
                return None, err
            token_source._subject = self.user_defined_credentials.google_work_space.user_email
            service = build('admin', 'directory_v1', credentials=token_source)
            return service, None
        except GoogleAuthError as e:
            logging.exception("An exception occurred while creating application: %s", str(e))
            return None, "Invalid 'UserEmail' or 'ServiceAccountKeyFile'"  

    def create_config(self, scope):
        try:
            service_account_json_key_decoded = base64.b64decode(self.user_defined_credentials.google_work_space.service_account_key_file)
            with open('service_account.json', 'wb') as f:
                f.write(service_account_json_key_decoded)
            credentials = service_account.Credentials.from_service_account_file(
                'service_account.json',
                scopes=[scope]            
            )
            return credentials, None
        except (GoogleAuthError, IOError, ValueError, TypeError) as e:
            logging.exception("An exception occurred while creating config: %s", str(e))
            return None, "Invalid 'UserEmail' or 'ServiceAccountKeyFile'"  
        finally:
            # Ensure the file is always removed, whether an exception occurred or not
            if os.path.exists('service_account.json'):
                os.remove('service_account.json')
        

    def get_domain_name(self):
        google_work_space_credentials = self.user_defined_credentials.google_work_space
        split_values = google_work_space_credentials.user_email.split("@")
        if len(split_values) > 1:
            return split_values[1]
        return ""
    
    def download_file_from_url(self, file_url):
        try:
            scope = 'https://www.googleapis.com/auth/drive.readonly'
            token_source, err = self.create_config(scope)
            if err:
                return None, err
            token_source._subject = self.user_defined_credentials.google_work_space.user_email
            service = build('drive', 'v3', credentials=token_source)
            
            target_id = self.extract_drive_file_url(file_url)
            if target_id is None:
                return None, "Invalid file URL"

            # Get the target's metadata to check if it's a file or folder
            target_metadata = service.files().get(fileId=target_id, fields="name, mimeType").execute()
            mime_type = target_metadata['mimeType']

            # If it's a file, download directly
            if mime_type != 'application/vnd.google-apps.folder':
                file_name = target_metadata['name']
                file_content = self.download_file_content(service, target_id)
                if file_content is None:
                    return None, "Failed to download file content"
                
                fileData = {
                    "FileName": file_name,
                    "FileType": mime_type,
                    "FileContent": file_content
                }
                return fileData, None
            else:
                # If it's a folder, find the most recently UPLOADED file recursively
                latest_file_id, latest_file_name, latest_mime_type = self.find_latest_file_recursively(service, target_id)
                if latest_file_id is None:
                    return None, "No files found in the folder"
                
                file_content = self.download_file_content(service, latest_file_id)
                if file_content is None:
                    return None, "Failed to download file content"
                
                fileData = {
                    "FileName": latest_file_name,
                    "FileType": latest_mime_type,
                    "FileContent": file_content
                }
                return fileData, None

        except GoogleAuthError as e:
            logging.exception("An exception occurred while creating application: %s", str(e))
            return None, "Invalid 'UserEmail' or 'ServiceAccountKeyFile'" 
        except HttpError as error:
            return None, f"An error occurred: {error}"

    def find_latest_file_recursively(self, service, folder_id):
        """
        Recursively find the LATEST file in a Google Drive folder
        Latest = max(createdTime, modifiedTime) across all files
        """
        latest_time = None
        candidate_id = None
        candidate_name = None
        candidate_mime_type = None

        # Step 1: Get all files and subfolders
        query = f"'{folder_id}' in parents and trashed=false"
        
        results = service.files().list(
            q=query,
            fields="files(id, name, mimeType, createdTime, modifiedTime)",
            orderBy="modifiedTime desc"  # Start with most recently modified
        ).execute()
        items = results.get('files', [])

        print(f"DEBUG: Checking folder - found {len(items)} items")
        for item in items:
            created = item.get('createdTime', 'N/A')
            modified = item.get('modifiedTime', 'N/A')
            print(f"  - {item['name']} (Created: {created}, Modified: {modified})")

        # Step 2: Process files and folders separately
        files = []
        folders = []
        
        for item in items:
            if item['mimeType'] == 'application/vnd.google-apps.folder':
                folders.append(item)
            else:
                files.append(item)

        # Step 3: Find file with the MOST RECENT timestamp (created OR modified)
        for file_item in files:
            created_time = self.parse_drive_timestamp(file_item.get('createdTime'))
            modified_time = self.parse_drive_timestamp(file_item.get('modifiedTime'))
            
            # Use the MOST RECENT timestamp between created and modified
            file_latest_time = max(created_time, modified_time)
            
            if latest_time is None or file_latest_time > latest_time:
                latest_time = file_latest_time
                candidate_id = file_item['id']
                candidate_name = file_item['name']
                candidate_mime_type = file_item['mimeType']
                print(f"DEBUG: New candidate: {candidate_name} (Time: {file_latest_time})")

        # Step 4: Check subfolders recursively
        for folder_item in folders:
            subfolder_id = folder_item['id']
            sub_result = self.find_latest_file_recursively(service, subfolder_id)
            
            if sub_result[0]:  # If we found a file in subfolder
                sub_file_id, sub_file_name, sub_mime_type = sub_result
                # Get the timestamps for the subfile to compare
                sub_file_metadata = service.files().get(
                    fileId=sub_file_id, 
                    fields="createdTime,modifiedTime"
                ).execute()
                
                sub_created_time = self.parse_drive_timestamp(sub_file_metadata.get('createdTime'))
                sub_modified_time = self.parse_drive_timestamp(sub_file_metadata.get('modifiedTime'))
                sub_latest_time = max(sub_created_time, sub_modified_time)
                
                if sub_latest_time > latest_time:
                    latest_time = sub_latest_time
                    candidate_id = sub_file_id
                    candidate_name = sub_file_name
                    candidate_mime_type = sub_mime_type

        # Step 5: Return result
        if candidate_id:
            return candidate_id, candidate_name, candidate_mime_type
        
        return None, None, None

    def get_last_uploaded_in_folder(self, service, folder_id):
        """
        Get the most recently UPLOADED file in a folder (including subfolders recursively)
        Returns: (latest_time, file_id, file_name, mime_type)
        """
        try:
            # First, check files in current folder
            query = f"'{folder_id}' in parents and trashed=false and mimeType != 'application/vnd.google-apps.folder'"
            results = service.files().list(
                q=query,
                fields="files(id, name, mimeType, createdTime)",
                orderBy="createdTime desc",
                pageSize=1
            ).execute()
            current_files = results.get('files', [])
            
            current_latest_time = None
            current_latest_file = None
            
            if current_files:
                current_latest_file = current_files[0]
                current_latest_time = self.parse_drive_timestamp(current_latest_file.get('createdTime'))

            # Check subfolders recursively
            query_folders = f"'{folder_id}' in parents and trashed=false and mimeType = 'application/vnd.google-apps.folder'"
            folder_results = service.files().list(
                q=query_folders,
                fields="files(id, name)",
                pageSize=10
            ).execute()
            subfolders = folder_results.get('files', [])
            
            subfolder_latest_time = None
            subfolder_latest_file = None
            
            for subfolder in subfolders:
                sub_time, sub_id, sub_name, sub_mime = self.get_last_uploaded_in_folder(service, subfolder['id'])
                if sub_time and (subfolder_latest_time is None or sub_time > subfolder_latest_time):
                    subfolder_latest_time = sub_time
                    subfolder_latest_file = (sub_id, sub_name, sub_mime)

            # Compare current folder files vs subfolder files
            if current_latest_time and subfolder_latest_time:
                if current_latest_time >= subfolder_latest_time:
                    return current_latest_time, current_latest_file['id'], current_latest_file['name'], current_latest_file['mimeType']
                else:
                    return subfolder_latest_time, subfolder_latest_file[0], subfolder_latest_file[1], subfolder_latest_file[2]
            elif current_latest_time:
                return current_latest_time, current_latest_file['id'], current_latest_file['name'], current_latest_file['mimeType']
            elif subfolder_latest_time:
                return subfolder_latest_time, subfolder_latest_file[0], subfolder_latest_file[1], subfolder_latest_file[2]
            else:
                return None, None, None, None
                
        except Exception as e:
            logging.error(f"Error getting last uploaded for folder {folder_id}: {str(e)}")
            return None, None, None, None

    def download_file_content(self, service, file_id):
        """Download file content from Google Drive"""
        try:
            request = service.files().get_media(fileId=file_id)
            file = io.BytesIO()
            downloader = MediaIoBaseDownload(file, request)
            done = False
            while done is False:
                status, done = downloader.next_chunk()
            return file.getvalue()
        except Exception as e:
            logging.error(f"Error downloading file {file_id}: {str(e)}")
            return None

    def parse_drive_timestamp(self, timestamp_str):
        """Parse Google Drive timestamp string to datetime object"""
        if not timestamp_str:
            return datetime.min.replace(tzinfo=timezone.utc)
        
        try:
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except ValueError:
            formats = [
                '%Y-%m-%dT%H:%M:%S.%fZ',
                '%Y-%m-%dT%H:%M:%SZ'
            ]
            for fmt in formats:
                try:
                    return datetime.strptime(timestamp_str, fmt).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
            return datetime.min.replace(tzinfo=timezone.utc)

    def extract_drive_file_url(self, file_url):  
        # Pattern for file URLs: /file/d/FILE_ID/view
        file_pattern = r'/file/d/([a-zA-Z0-9_-]{25,})'
        
        # Pattern for folder URLs: /folders/FOLDER_ID
        folder_pattern = r'/folders/([a-zA-Z0-9_-]{25,})'
        
        # Pattern for open?id= format
        open_pattern = r'[?&]id=([a-zA-Z0-9_-]{25,})'
        
        # Try file pattern first
        match = re.search(file_pattern, file_url)
        if match:
            return match.group(1)
        
        # Try folder pattern
        match = re.search(folder_pattern, file_url)
        if match:
            return match.group(1)
        
        # Try open?id= pattern
        match = re.search(open_pattern, file_url)
        if match:
            return match.group(1)
        
        # If it's already just an ID (no URL structure)
        if re.match(r'^[a-zA-Z0-9_-]{25,}$', file_url):
            return file_url
        
        return None
    
    def upload_file_to_drive(self, file_content, file_name, folder_name):
        try:
            scope = 'https://www.googleapis.com/auth/drive.file'
            token_source, err = self.create_config(scope)
            if err:
                return None, err
            
            token_source._subject = self.user_defined_credentials.google_work_space.user_email
            service = build('drive', 'v3', credentials=token_source)

            folder_id, err = self.get_folder_id(folder_name)
            if err:
                return None, err  

            file_metadata = {
                "name": file_name,
                "parents": [folder_id]
            }

            file_stream = io.BytesIO(file_content)
            media = MediaIoBaseUpload(file_stream, mimetype='application/octet-stream')
            
            file = service.files().create(body=file_metadata, media_body=media, fields="id").execute()

            file_upload_date_and_time = self.get_current_datetime()

            file_url = f"https://drive.google.com/drive/folders/{folder_id}"

            return {
                "file_id": file.get("id"),
                "file_url": file_url,
                "upload_time": file_upload_date_and_time
            }, None

        except Exception as e:
            return None, f"An error occurred during file upload: {e}"

    def get_folder_id(self, folder_name):
        try:
            scope = 'https://www.googleapis.com/auth/drive.readonly'
            token_source, err = self.create_config(scope)
            if err:
                return None, err
            
            token_source._subject = self.user_defined_credentials.google_work_space.user_email
            service = build('drive', 'v3', credentials=token_source)

            query = f"name = '{folder_name}' and mimeType = 'application/vnd.google-apps.folder'"
            results = service.files().list(q=query).execute()
            folders = results.get('files', [])

            if folders:
                return folders[0]['id'], None
            
            return None, f"Folder '{folder_name}' not found."

        except HttpError as error:
            return None, f"An error occurred while retrieving the folder: {error}"
               
    def get_current_datetime(self):
        current_time = datetime.now(timezone.utc)
        formatted_time = current_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        return formatted_time
    
    def list_db_instances(self, project_id: str) -> Tuple[any, str]:
        try:
            scope = 'https://www.googleapis.com/auth/cloud-platform'
            token_source, err = self.create_config(scope)
            if err:
                return None, err
            token_source._subject = self.user_defined_credentials.google_work_space.user_email
            service = build('sqladmin', 'v1', credentials=token_source)
            
            request = service.instances().list(project=project_id)
            response = request.execute()
            if response:
                return response, ''
            else:
                return None, 'Got empty response'
        except GoogleAuthError as e:
            logging.exception("An exception occurred while creating application: %s", str(e))
            return None, "Invalid 'UserEmail' or 'ServiceAccountKeyFile'" 
        except HttpError as error:
            return None,f"An error occurred: {error.reason}"
        except AttributeError as e:
            return None, f"Attribute error occurred while fetching project lists: {e}"
        
    def list_firewall_rules(self, project_id: str) -> Tuple[list, str]:
        try:
            scope = 'https://www.googleapis.com/auth/cloud-platform'
            token_source, err = self.create_config(scope)
            if err:
                return [], err
            token_source.refresh(Request())
            token_source._subject = self.user_defined_credentials.google_work_space.user_email
            service = build('compute', 'v1', credentials=token_source)
            
            firewall_rules = []
            request = service.firewalls().list(project=project_id)
            while request is not None:
                response = request.execute()

                new_firewall_rules = response.get('items', [])
                firewall_rules.extend(new_firewall_rules)

                request = service.firewalls().list_next(previous_request=request, previous_response=response)

            if not firewall_rules:
                return [], f"No service accounts found in the provided project: {project_id}."
            
            return firewall_rules, ''
        except GoogleAuthError as e:
            logging.exception("An exception occurred while creating application: %s", str(e))
            return [], "Invalid 'UserEmail' or 'ServiceAccountKeyFile'" 
        except HttpError as error:
            return [],f"An error occurred: {error.reason}"
        except AttributeError as e:
            return [], f"Attribute error occurred while fetching project lists: {e}"

    # https://cloud.google.com/resource-manager/reference/rest/v1/projects/list
    def list_projects(self):
        try:
            scope = 'https://www.googleapis.com/auth/cloud-platform.read-only'
            token_source, err = self.create_config(scope)
            if err:
              return None, err
            token_source.refresh(Request())
            token_source._subject = self.user_defined_credentials.google_work_space.user_email
            service = build('cloudresourcemanager', 'v1', credentials=token_source)
            request = service.projects().list()
            response = request.execute()
            projects = response.get('projects', [])
            if not projects:
                return None, "No projects found for the provided service account credentials."
            return projects, None
        except HttpError as e:
               return None, f"Http error occurred while fetching project lists: {e}"
        except AttributeError as e:
                return None, f"Attribute error occurred while fetching project lists: {e}"

    # https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances/list
    def list_instances(self, project_id):
        try:
            scope = 'https://www.googleapis.com/auth/cloud-platform'
            token_source, err = self.create_config(scope)
            if err:
              return None, err
            token_source._subject = self.user_defined_credentials.google_work_space.user_email
            service = build('sqladmin', 'v1', credentials=token_source)
            request = service.instances().list(project=project_id)
            response = request.execute()
            instances = response.get("items", [])
            if not instances:
                return None, f"No instance found for project id - {project_id}"
            return instances, None
        except HttpError as e:
               return None, f"HTTP error occurred while fetching the instance list for project ID {project_id}: {e}."
        except AttributeError as e:
                return None, f"Attribute error occurred while fetching the instance list for project ID {project_id}: {e}."

    # duplicated need to handle
    # https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/databases/list
    def list_databases(self, project_id, instance_id):

        try:
            scope = 'https://www.googleapis.com/auth/cloud-platform'
            token_source, err = self.create_config(scope)
            if err:
                return None, err
            token_source._subject = self.user_defined_credentials.google_work_space.user_email
            service = build('sqladmin', 'v1beta4', credentials=token_source)
            # Call the API to list databases for the given instance
            request = service.databases().list(project=project_id, instance=instance_id)
            response = request.execute()
            # Get the list of databases
            databases = response.get('items', [])
            if not databases:
                return None, f"No databases found for project id - {project_id}"
            return databases, None
        except HttpError as e:
               return None, f"HTTP error occurred while fetching the database list for project ID {project_id}: {e}."
        except AttributeError as e:
                return None, f"Attribute error occurred while fetching the database list for project ID {project_id}: {e}."

    # https://cloud.google.com/logging/docs/reference/v2/rest/v2/entries/list
    def get_logging_entities(self, project_id, filter, from_date, to_date):
        try:
            scope = 'https://www.googleapis.com/auth/logging.read'
            token_source, err = self.create_config(scope)
            if err:
                return None, err
            token_source.refresh(Request())
            token_source._subject = self.user_defined_credentials.google_work_space.user_email
            service = build('logging', 'v2', credentials=token_source)

            modified_from_date, err = self.convert_timestamp(str(from_date))
            if err:
                return None, err
            modified_to_date, err = self.convert_timestamp(str(to_date))
            if err:
                return None, err

            request_body = {
                'resourceNames': [f'projects/{project_id}'],
                'filter': f'resource.type = "{filter}" AND (severity = "INFO" OR "NOTICE") AND timestamp >= "{modified_from_date}" AND timestamp <= "{modified_to_date}"',
                "orderBy": "timestamp desc",
                'pageSize': 5000
            }
            
            request = service.entries().list(
                body=request_body
            )
            response = request.execute()
            entries = response.get('entries', [])
            next_page_token = response.get('nextPageToken')
            while next_page_token:
                request = service.entries().list(
                    body={
                        **request_body,
                        'pageToken': next_page_token,
                    }
                )
                response = request.execute()
                entries.extend(response.get('entries', []))
                next_page_token = response.get('nextPageToken')

            return entries, None
        except HttpError as e:
               return None, f"HTTP error occurred while fetching the database list"
        except AttributeError as e:
                return None, f"Attribute error occurred while fetching the database list"

    def convert_timestamp(self, data):
        try:
            timestamp = pd.to_datetime(data)
            return timestamp.strftime('%Y-%m-%dT%H:%M:%S.%fZ'), None
        except Exception as e:
            return None, f"Error while modifying timestamp. str{e}"

    # https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/users/get
    def is_valid_user(self, project_id, instance_id, user_name):
        
        try:

            scope = 'https://www.googleapis.com/auth/cloud-platform'
            token_source, err = self.create_config(scope)
            if err:
                return False
            token_source._subject = self.user_defined_credentials.google_work_space.user_email
            service = build('sqladmin', 'v1beta4', credentials=token_source)

            request = service.users().get(
                project=project_id,
                instance=instance_id,
                name=user_name
            )
            response = request.execute()
            if response:
               return True
            
        except HttpError as e:
            logging.exception(str(e))
            return False
        except AttributeError as e:
            logging.exception(str(e))
            return False
        except Exception as e:
            logging.exception(str(e))
            return False

    def generate_log_url(self,log_time_stamp,project_id):
        try:
          return f'{self.app_url.strip("/")}/logs/query;cursorTimestamp={log_time_stamp};query=timestamp=\"{log_time_stamp}\"?project={project_id}'
        except Exception as e:
            return ''
    
    def generate_db_url(self,instance_name,project_id):
        try:
          return f'{self.app_url.strip("/")}/sql/instances/{instance_name}/databases?project={project_id}'
        except Exception as e:
            return ''
           
    def handle_batch_response(self, request_id: str, response: Optional[Dict[str, Any]], exception: Optional[Exception] ):
        """
        The function `handle_batch_response` processes batch responses from API requests, handling
        success and failure cases and recursively fetching additional pages of data if available.
        """
        email = request_id
        if exception:
            self.results[email] = f"Failed : {exception}"
        else:
            all_activities = []
            if not response:
                all_activities.append("No API Response.")
            else:
                if 'items' in response:
                    all_activities.extend(response['items'])

            next_page_token = response.get('nextPageToken')
            if next_page_token:
                self.batch.add(
                    self.service.activities().list(
                        userKey = email,
                        applicationName = self.applicationName,
                        maxResults = 1000,
                        pageToken = next_page_token
                    ),
                    callback = self.handle_batch_response,
                    request_id = email
                )
            else:
                self.results[email] = all_activities

    # https://admin.googleapis.com/admin/reports/v1/activity/users/{userKey}/applications/login
    def get_activities(self, emailID_list: list, applicationName: str) -> Tuple[any, str]:
        """
        The function `get_activities` retrieves user activities from Google Workspace using the Admin
        SDK Reports API in batches.
        """
        try:
            scope = 'https://www.googleapis.com/auth/admin.reports.audit.readonly'
            token_source, err = self.create_config(scope)
            if err:
                return None, err
            try:
                token_source.refresh(Request())
            except RefreshError as re:
                return None, f"Token refresh failed: {re}"
            try:
                token_source._subject = self.user_defined_credentials.google_work_space.user_email
            except AttributeError as ae:
                return None, f"User email is not properly set in credentials: {ae}"
            try:
                service = build('admin', 'reports_v1', credentials=token_source)
            except DefaultCredentialsError as ce:
                return None, f"Failed to build Google API client: {ce}"

            self.applicationName = applicationName
            self.results = {}
            self.log_file = ""

            batch_size = 1000
            batches = [emailID_list[i:i + batch_size] for i in range(0, len(emailID_list), batch_size)]
            for batch_emails in batches:
                self.batch = BatchHttpRequest(callback=self.handle_batch_response, batch_uri='https://admin.googleapis.com/batch')
                for email in batch_emails:
                    self.batch.add(
                        service.activities().list(
                            userKey = email,
                            applicationName = applicationName,
                            maxResults = 1000
                        ),
                        callback = self.handle_batch_response,
                        request_id = email
                    )
                
                try: 
                    self.batch.execute()
                except HttpError as he:
                    return None, f"HTTP error during batch execution: {he.reason}"
                except Exception as be:
                    return None, f"Unexpected error during batch execution: {be}"

            final_results = [
                {
                    'email' : email,
                    'activities' : self.results.get(email, "No data returned")
                }
                for email in emailID_list
            ]
            return final_results, None
        except Exception as e:
            self.log_file = f"API request failed: {e}"
            return None, self.log_file