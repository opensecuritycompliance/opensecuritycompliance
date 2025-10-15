from typing import Tuple, List, Dict, Any
import pyarrow
import io
import base64
import requests
import http
import pandas as pd
from datetime import datetime, timezone
import json
from urllib.parse import urlparse
from compliancecowcards.utils import wsutils, cowutils
from compliancecowcards.vo import exception
import time


class OAuth:
    client_id: str
    client_secret: str

    def __init__(self, client_id: str, client_secret: str) -> None:
        self.client_id = client_id
        self.client_secret = client_secret

    @staticmethod
    def from_dict(obj) -> "OAuth":
        client_id, client_secret = "", ""
        if isinstance(obj, dict):
            client_id = obj.get("ClientID", "")
            client_secret = obj.get("ClientSecret", "")

        return OAuth(client_id, client_secret)

    def to_dict(self) -> dict:
        result: dict = {}
        result["ClientID"] = self.client_id
        result["ClientSecret"] = self.client_secret
        return result

    def validate_attributes(self) -> str:
        emptyAttrs = []
        if not self.client_id:
            emptyAttrs.append("ClientID")

        if not self.client_secret:
            emptyAttrs.append("ClientSecret")

        return "Invalid Credentials: " + ", ".join(emptyAttrs) if emptyAttrs else ""


class UserDefinedCredentials:
    o_auth: OAuth

    def __init__(self, o_auth: OAuth) -> None:
        self.o_auth = o_auth

    @staticmethod
    def from_dict(obj) -> "UserDefinedCredentials":
        o_auth = None
        if isinstance(obj, dict):
            o_auth = OAuth.from_dict(obj.get("OAuth", None))
        return UserDefinedCredentials(o_auth)

    def to_dict(self) -> dict:
        result: dict = {}
        result["OAuth"] = self.o_auth.to_dict()
        return result


class ComplianceCow:
    FETCH_AUTH_TOKEN = "/v1/oauth2/token"
    FETCH_CONTROL_USER_INPUTS = "/v5/partner/assessment-runs/{assessment_run_id}/controls/{control_id}/user-inputs"
    ASSIGN_FORM_TO_USER = "/v5/partner/forms/assign"
    GET_USER_ASSIGNED_FORMS = "/v5/partner/forms/assignments?user_id={user_id}&is_ignored={include_ignored}&is_delegated={include_delegated}&is_submitted={include_submitted}"
    FETCH_FORMS = "/v5/partner/forms"  # USE SAME API FOR CREATE
    FETCH_FORM = "/v5/partner/forms/{form_id}"
    FETCH_FORM_ELEMENT = "/v5/partner/forms/elements/{element_id}"
    FETCH_FORM_RESPONSE = "/v5/partner/forms/{form_id}/responses"
    LIST_USERS = "/v5/partner/users"
    GET_USER = "/v5/partner/users/{user_id}"
    UPDATE_CONTROL_META_DATA = "/v5/partner/assessment-runs/{assessment_run_id}/controls/{control_id}/meta-data"
    UPLOAD_CONTROL_ATTACHMENT = "/v5/partner/assessment-runs/{assessment_run_id}/controls/{control_id}/attachments"
    DELETE_CONTROL_ATTACHMENT = "/v5/partner/assessment-runs/{assessment_run_id}/controls/{control_id}/attachments/{attachment_id}"
    CREATE_CONTROL_NOTE = (
        "/v5/partner/assessment-runs/{assessment_run_id}/controls/{control_id}/notes"
    )
    UPDATE_CONTROL_NOTE = "/v5/partner/assessment-runs/{assessment_run_id}/controls/{control_id}/notes/{note_id}"
    DELETE_CONTROL_NOTE = "/v5/partner/assessment-runs/{assessment_run_id}/controls/{control_id}/notes/{note_id}"
    UPDATE_ASSESSMENT_RUN_META_DATA = "/v1/plan-instances/{assessment_run_id}"
    FETCH_EVIDENCE = "/v5/partner/assessment-runs/{assesment_run_id}/controls/{control_id}/evidence/{evidence_id}?fileFormat=PARQUET"
    FETCH_EVIDENCE_V1 = "/v5/partner/assessment-runs/{assesment_run_id}/controls/{control_id}/evidence/{evidence_id}?include_file_content=true&fileFormat=PARQUET"
    GET_PLANS = "/v1/plans"
    GET_ASSESSMENT_RUN_DETAILS_BY_ASSESSMENT_ID = "/v5/partner/assessment-runs?page={page}&page_size={page_size}&assessment_id={assessment_id}"
    GET_ASSESSMENT_RUN_DETAILS = "/v5/partner/assessment-runs/{assessment_run_id}"
    CREATE_ASSESSMENT = "/v5/partner/assessments"
    FETCH_ASSESSMENT = (
        "/v5/partner/assessments?name={assessment_name}&include_all_controls=true"
    )
    CREATE_ASSESSMENT_CONTROL = "/v5/partner/assessments/{assessment_id}/controls"
    UPDATE_ASSESSMENT_CONTROL = (
        "/v5/partner/assessments/{assessment_id}/controls/{control_id}"
    )
    CREATE_CATEGORY = "/v5/partner/assessments/categories"
    FETCH_CATEGORY = "/v5/partner/assessments/categories?name={category_name}"
    DOWNLOAD_FILE = "/v5/partner/file-download/{input_file_hash}"
    FETCH_ASSESSMENTS = "/v5/partner/assessments"
    CREATE_CITATION = (
        "/v5/partner/assessments/{assessment_id}/controls/{control_id}/citations"
    )
    UPDATE_CITATION = "/v5/partner/assessments/{assessment_id}/controls/{control_id}/citations/{citation_id}"
    DELETE_CITATION = "/v5/partner/assessments/{assessment_id}/controls/{control_id}/citations/{citation_id}"
    DELETE_ASSESSMENT_CONTROL = (
        "/v5/partner/assessments/{assessment_id}/controls/{control_id}"
    )
    UPDATE_EVIDENCE = (
        "/v5/partner/assessment-runs/{assessment_run_id}/controls/{control_id}/evidence"
    )
    CREATE_EVIDENCE_TEMPLATE = (
        "/v5/partner/assessments/{assessment_id}/controls/{control_id}/evidence"
    )
    CREATE_ASSESSMENT_RUN = "/v1/customer/runs"
    COMMIT_CONTROL_EVIDENCE = "/v5/partner/assessment-runs/{assessment_run_id}/controls/{control_id}/evidence/{evidence_id}/commit"
    GET_MATCHED_UCF_CONTROLS = "/v5/partner/llm/local-embeddings/query"
    LINK_EVIDENCE_RECORDS = (
        "/v5/partner/assessment-runs/{assessment_run_id}/link-records"
    )

    # PATHS USING INTERNAL APIs
    CREATE_FORM = "/v1/forms"  # Use FETCH_FORMS instead of this after POST method is added to this Partner API
    DELETE_FORM = (
        "/v1/forms/{form_id}"  # Change to Partner API after this is added to it
    )
    CREATE_FORM_RESPONSE = "/v1/forms/{form_id}/responses"
    SAVE_FORM_RESPONSE = "/v1/forms/{form_id}/responses/{response_id}/elements"
    GET_USER_BLOCK = "/v1/actions/userblocks?name={user_block_name}"
    GET_USERS_FROM_EMAILS = "/v1/users?emails={email_in_comma_seperated}"
    ASSIGN_CONTROL = "/v1/plan-instance-controls/{control_id}/reassign"
    CHECKOUT_USER = "/v1/plan-instance-controls/checkout"
    COMPLETE_USER = "/v1/plan-instance-controls/{control_id}/complete"
    SEND_SLACK_NOTIFICATION = "/v1/notification"
    GET_WORKFLOW_DETAILS = "/v1/workflow-instances/{workflow_id}"
    GET_HASH = "/v1/plan-instance-controls/{control_id}/generate-user-inputs-link"
    FETCH_PLAN_DETAILS = "/v1/framework/assessments/{assesment_id}"
    UPDATE_EVIDENCE_INTERNAL = "/v1/datahandler/"
    GET_APPLICATION_SCOPES = "/v2/configuration"
    GET_USER_MEDIUM_CONFIGS = (
        "/v1/user-medium-configurations?medium_user_id={medium_user_id}"
    )
    LIST_USER_MEDIUM_CONFIGS = '/v1/user-medium-configurations'
    GET_SLACK_HANDLE = "/v5/partner/users/user-mediums"
    

    app_url: str
    app_port: int
    user_defined_credentials: UserDefinedCredentials

    def __init__(
        self,
        app_url: str = None,
        app_port: int = None,
        user_defined_credentials: UserDefinedCredentials = None,
    ) -> None:
        self.app_url = app_url
        self.app_port = app_port
        self.user_defined_credentials = user_defined_credentials

    @staticmethod
    def from_dict(obj) -> "ComplianceCow":
        app_url, app_port, user_defined_credentials = "", "", None
        if isinstance(obj, dict):
            app_url = obj.get("AppURL", "")
            if not app_url:
                app_url = obj.get("appURL", "")
            if not app_url:
                app_url = obj.get("appurl", "")
            app_port = obj.get("AppPort", 0)
            if not app_port:
                app_port = obj.get("appPort", 0)
            user_defined_credentials_dict = obj.get("UserDefinedCredentials", None)
            if user_defined_credentials_dict is None:
                user_defined_credentials_dict = obj.get("userDefinedCredentials", None)
            if bool(user_defined_credentials_dict):
                user_defined_credentials = UserDefinedCredentials.from_dict(
                    user_defined_credentials_dict
                )

        return ComplianceCow(app_url, app_port, user_defined_credentials)

    def to_dict(self) -> dict:
        result: dict = {}
        result["AppURL"] = self.app_url
        result["AppPort"] = self.app_port
        result["UserDefinedCredentials"] = self.user_defined_credentials.to_dict()
        return result

    def validate(self) -> bool and dict:
        response, error = self.fetch_auth_token()
        if error:
            return False, error
        return True, None

    def fetch_auth_token(self):
        api_endpoint_url = self.build_api_url(self.FETCH_AUTH_TOKEN)
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        payload_data = {
            "grant_type": "client_credentials",
            "client_id": self.user_defined_credentials.o_auth.client_id,
            "client_secret": self.user_defined_credentials.o_auth.client_secret,
        }

        hostname = urlparse(self.app_url).hostname
        if hostname and len(hostname.split(".")) == 4:
            payload_data["domain_name"] = hostname.split(".")[0]

        response, error = self.make_api_request(
            api_endpoint_url, headers=headers, method="POST", data=payload_data
        )
        if error:
            print(f"Unable to retrieve ComplianceCow auth token : {error}")
            if "Connection error:" in error:
                return None, "Invalid URL."
            return None, f"Unable to retrieve ComplianceCow auth token :: {error}"

        if response.ok and response.status_code == http.HTTPStatus.OK:
            try:
                return response.json(), None
            except ValueError:
                return None, "Error decoding JSON response."
        elif response.status_code == http.HTTPStatus.BAD_REQUEST:
            return None, "Invalid ClientID and/or ClientSecret."
        else:
            return (
                None,
                f"Validation failed. Exception occurred while validating app. {response.status_code} :: {response.text}",
            )

    def fetch_control_user_inputs(self, assessment_run_id, control_id):
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return None, error
        api_endpoint_url = self.build_api_url(self.FETCH_CONTROL_USER_INPUTS).format(
            assessment_run_id=assessment_run_id, control_id=control_id
        )
        headers = {"Authorization": auth_token}
        response, error = self.make_api_request(
            api_endpoint_url, headers=headers, method="GET"
        )
        if error:
            print(f"Unable to retrieve ComplianceCow control user input : {error}")
            return (
                None,
                "Unable to retrieve ComplianceCow control user input. Please contact admin/support to fix this issue.",
            )

        if response.ok and response.status_code == http.HTTPStatus.OK:
            return response.json(), None
        else:
            print(
                f"Unable to retrieve ComplianceCow control user input : Status Code: {response.status_code}, Response: {response.text}"
            )
            return (
                None,
                "Unable to retrieve ComplianceCow control user input. Please contact admin/support to fix this issue.",
            )

    def update_control_meta_data(self, assessment_run_id, control_id, payload_data):
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return error
        api_endpoint_url = self.build_api_url(self.UPDATE_CONTROL_META_DATA).format(
            assessment_run_id=assessment_run_id, control_id=control_id
        )
        headers = {"Authorization": auth_token}
        response, error = self.make_api_request(
            api_endpoint_url, headers=headers, method="POST", json=payload_data
        )

        if error:
            print(f"Unable to update the ComplianceCow control metadata : {error}")
            return "Unable to update the ComplianceCow control metadata. Please contact admin/support to fix this issue."

        if response.ok and response.status_code == http.HTTPStatus.NO_CONTENT:
            return ""
        else:
            print(
                f"Unable to update the ComplianceCow control metadata : Status Code: {response.status_code}, Response: {response.text}"
            )
            return "Unable to update the ComplianceCow control metadata. Please contact admin/support to fix this issue."

    def update_assessment_run_meta_data(self, assessment_run_id, payload_data):
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return error
        api_endpoint_url = self.build_api_url(
            self.UPDATE_ASSESSMENT_RUN_META_DATA
        ).format(assessment_run_id=assessment_run_id)
        headers = {"Authorization": auth_token}
        response, error = self.make_api_request(
            api_endpoint_url, headers=headers, method="PATCH", json=payload_data
        )

        if error:
            print(
                f"Unable to update the ComplianceCow assessment run metadata : {error}"
            )
            return "Unable to update the ComplianceCow assessment run metadata. Please contact admin/support to fix this issue."

        if response.ok and response.status_code == http.HTTPStatus.NO_CONTENT:
            return ""
        else:
            print(
                f"Unable to update the ComplianceCow assessment run metadata : Status Code: {response.status_code}, Response: {response.text}"
            )
            return "Unable to update the ComplianceCow assessment run metadata. Please contact admin/support to fix this issue."

    def upload_control_attachment(
        self, assessment_run_id, control_id, payload_data, files
    ):
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return error
        api_endpoint_url = self.build_api_url(self.UPLOAD_CONTROL_ATTACHMENT).format(
            assessment_run_id=assessment_run_id, control_id=control_id
        )
        headers = {"Authorization": auth_token}
        response, error = self.make_api_request(
            api_endpoint_url,
            headers=headers,
            method="POST",
            data=payload_data,
            files=files,
        )

        if error:
            print(
                f"Unable to upload the attachment to the ComplianceCow control : {error}"
            )
            return "Unable to upload the attachment to the ComplianceCow control. Please contact admin/support to fix this issue."

        if response.ok and response.status_code == http.HTTPStatus.CREATED:
            return ""
        else:
            print(
                f"Unable to upload the attachment to the ComplianceCow control : Status Code: {response.status_code}, Response: {response.text}"
            )
            return "Unable to upload the attachment to the ComplianceCow control. Please contact admin/support to fix this issue."

    def delete_control_attachment(self, attachment_id, assessment_run_id, control_id):
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return error
        api_endpoint_url = self.build_api_url(self.DELETE_CONTROL_ATTACHMENT).format(
            assessment_run_id=assessment_run_id,
            control_id=control_id,
            attachment_id=attachment_id,
        )
        headers = {"Authorization": auth_token}
        response, error = self.make_api_request(
            api_endpoint_url, headers=headers, method="DELETE"
        )

        if error:
            print(
                f"Unable to delete the attachment to the ComplianceCow control : {error}"
            )
            return "Unable to delete the attachment to the ComplianceCow control. Please contact admin/support to fix this issue."

        if response.ok and response.status_code == http.HTTPStatus.NO_CONTENT:
            return ""
        else:
            print(
                f"Unable to delete the attachment to the ComplianceCow control : Status Code: {response.status_code}, Response: {response.text}"
            )
            return "Unable to delete the attachment to the ComplianceCow control. Please contact admin/support to fix this issue."

    def create_control_note(self, assessment_run_id, control_id, payload_data):
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return error
        api_endpoint_url = self.build_api_url(self.CREATE_CONTROL_NOTE).format(
            assessment_run_id=assessment_run_id, control_id=control_id
        )
        headers = {
            "Authorization": auth_token,
            "Content-Type": "application/json",
        }
        response, error = self.make_api_request(
            api_endpoint_url, headers=headers, method="POST", data=payload_data
        )

        if error:
            print(f"Unable to create the note for the ComplianceCow control : {error}")
            return "Unable to create the note for the ComplianceCow control. Please contact admin/support to fix this issue."

        if response.ok and response.status_code == http.HTTPStatus.CREATED:
            return ""
        else:
            print(
                f"Unable to create the note for the ComplianceCow control : Status Code: {response.status_code}, Response: {response.text}"
            )
            return "Unable to create the note for the ComplianceCow control. Please contact admin/support to fix this issue."

    def update_control_note(self, assessment_run_id, control_id, note_id, payload_data):
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return error
        api_endpoint_url = self.build_api_url(self.UPDATE_CONTROL_NOTE).format(
            assessment_run_id=assessment_run_id, control_id=control_id, note_id=note_id
        )
        headers = {
            "Authorization": auth_token,
            "Content-Type": "application/json",
        }
        response, error = self.make_api_request(
            api_endpoint_url, headers=headers, method="PUT", data=payload_data
        )

        if error:
            print(f"Unable to update the note for the ComplianceCow control : {error}")
            return "Unable to update the note for the ComplianceCow control. Please contact admin/support to fix this issue."

        if response.ok and response.status_code == http.HTTPStatus.NO_CONTENT:
            return ""
        else:
            print(
                f"Unable to update the note for the ComplianceCow control : Status Code: {response.status_code}, Response: {response.text}"
            )
            return "Unable to update the note for the ComplianceCow control. Please contact admin/support to fix this issue."

    def delete_control_note(self, note_id, assessment_run_id, control_id):
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return error
        api_endpoint_url = self.build_api_url(self.DELETE_CONTROL_NOTE).format(
            assessment_run_id=assessment_run_id, control_id=control_id, note_id=note_id
        )
        headers = {"Authorization": auth_token}
        response, error = self.make_api_request(
            api_endpoint_url, headers=headers, method="DELETE"
        )

        if error:
            print(f"Unable to delete the note for the ComplianceCow control : {error}")
            return "Unable to delete the note for the ComplianceCow control. Please contact admin/support to fix this issue."

        if response.ok and response.status_code == http.HTTPStatus.NO_CONTENT:
            return ""
        else:
            print(
                f"Unable to delete the note for the ComplianceCow control : Status Code: {response.status_code}, Response: {response.text}"
            )
            return "Unable to delete the note for the ComplianceCow control. Please contact admin/support to fix this issue."

    def get_form(self, form_id: str) -> Tuple[dict, str]:
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return None, error
        api_endpoint_url = self.build_api_url(self.FETCH_FORM).format(form_id=form_id)
        headers = {"Authorization": auth_token}
        response, error = self.make_api_request(
            api_endpoint_url, headers=headers, method="GET"
        )
        if error:
            return None, error

        if response.ok and response.status_code == http.HTTPStatus.OK:
            try:
                return response.json(), None
            except requests.JSONDecodeError as e:
                return None, f"Response is in an invalid format :: {e}"
        else:
            return (
                None,
                f"Received error from response :: Status Code: {response.status_code}, Response: {response.text}",
            )

    def get_form_element(self, element_id: str) -> Tuple[dict, str]:
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return None, error
        api_endpoint_url = self.build_api_url(self.FETCH_FORM_ELEMENT).format(
            element_id=element_id
        )
        headers = {"Authorization": auth_token}
        response, error = self.make_api_request(
            api_endpoint_url, headers=headers, method="GET"
        )
        if error:
            return None, error

        if response.ok and response.status_code == http.HTTPStatus.OK:
            try:
                return response.json(), None
            except requests.JSONDecodeError as e:
                return None, f"Response is in an invalid format :: {e}"
        else:
            return (
                None,
                f"Received error from response :: Status Code: {response.status_code}, Response: {response.text}",
            )

    def get_form_response(self, form_id: str) -> Tuple[dict, str]:
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return None, error
        api_endpoint_url = self.build_api_url(self.FETCH_FORM_RESPONSE).format(
            form_id=form_id
        )
        headers = {"Authorization": auth_token}
        response, error = self.make_api_request(
            api_endpoint_url, headers=headers, method="GET"
        )
        if error:
            return None, error

        if response.ok and response.status_code == http.HTTPStatus.OK:
            try:
                return response.json(), None
            except requests.JSONDecodeError as e:
                return None, f"Response is in an invalid format :: {e}"
        else:
            return (
                None,
                f"Received error from response :: Status Code: {response.status_code}, Response: {response.text}",
            )

    def create_form_response(
        self, form_id: str, user_id: str, assign_id: str
    ) -> Tuple[str, str]:
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return "", error
        api_endpoint_url = self.build_api_url(self.CREATE_FORM_RESPONSE).format(
            form_id=form_id
        )
        headers = {"Authorization": auth_token}
        payload = {"formId": form_id, "userId": user_id, "assignId": assign_id}
        response, error = self.make_api_request(
            api_endpoint_url, headers=headers, method="POST", json=payload
        )
        if error:
            return "", error

        if response.ok and response.status_code == http.HTTPStatus.CREATED:
            try:
                response_dict = response.json()
                return response_dict.get("_id", ""), None
            except requests.JSONDecodeError as e:
                return "", f"Response is in an invalid format :: {e}"
        else:
            return (
                "",
                f"Received error from response :: Status Code: {response.status_code}, Response: {response.text}",
            )

    def update_form_response(
        self, form_id: str, response_id: str, assign_id: str, data: dict
    ) -> Tuple[str, str]:
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return None, error
        api_endpoint_url = self.build_api_url(self.SAVE_FORM_RESPONSE).format(
            form_id=form_id, response_id=response_id
        )
        headers = {"Authorization": auth_token}

        # get form element id & values from 'data' dict
        form, error = self.get_form(form_id)
        if error:
            return None, error

        elements_to_update = {}

        for element in form.get("elementIDs", []):
            if not data:
                break

            element_id = element.get("id", "")
            element_data, error = self.get_form_element(element_id)
            if error:
                return None, error

            element_title = element_data.get("title", "")
            if element_title in data:
                elements_to_update[element_id] = data.pop(element_title)

        if data:
            return (
                None,
                f"The form does not have the following data: '{', '.join(data.keys())}'",
            )

        payload = {
            "formResponseId": response_id,
            "formResponses": elements_to_update,
            "assignId": assign_id,
        }
        response, error = self.make_api_request(
            api_endpoint_url, headers=headers, method="POST", json=payload
        )
        if error:
            return None, error

        if response.ok and response.status_code == http.HTTPStatus.CREATED:
            try:
                return response.json(), None
            except requests.JSONDecodeError as e:
                return None, f"Response is in an invalid format :: {e}"
        else:
            return (
                None,
                f"Received error from response :: Status Code: {response.status_code}, Response: {response.text}",
            )

    def list_forms(self, form_type: str = "") -> Tuple[pd.DataFrame, str]:
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return None, error
        api_endpoint_url = self.build_api_url(self.FETCH_FORMS)
        headers = {"Authorization": auth_token}

        params = {}
        if form_type:
            params["type"] = form_type

        cur_page = 1
        page_size = 10
        has_next = True
        forms_list: List[dict] = []

        while has_next:
            params = {**params, "page": cur_page, "pageSize": page_size}
            response, error = self.make_api_request(
                api_endpoint_url, headers=headers, method="GET", params=params
            )
            if error:
                return None, error

            if response.ok and response.status_code == http.HTTPStatus.OK:
                try:
                    response_dict: Dict[str, dict] = response.json()

                    # Handle pagination
                    if "pagination" not in response_dict:
                        has_next = False
                    else:
                        total_pages = int(
                            response_dict["pagination"].get("totalPages", 0)
                        )
                        cur_page += 1
                        has_next = cur_page <= total_pages

                    new_forms_list = response_dict.get("items")
                    if not isinstance(new_forms_list, list):
                        raise ValueError("Response is not in list format")
                    forms_list.extend(new_forms_list)
                except (requests.JSONDecodeError, ValueError) as e:
                    return None, f"Response is in an invalid format :: {e}"
            else:
                return (
                    None,
                    f"Received error from response :: Status Code: {response.status_code}, Response: {response.text}",
                )

        return pd.DataFrame(forms_list), None

    def get_form_by_name(
        self, form_name: str, form_type: str = ""
    ) -> Tuple[pd.DataFrame, str]:
        forms_df, error = self.list_forms(form_type)
        if error:
            return pd.DataFrame(), f"Error while fetching forms :: {error}"

        if forms_df.empty:
            return pd.DataFrame(), f"No form found with the given name: {form_name}"

        if "name" not in forms_df.columns:
            return (
                pd.DataFrame(),
                "Error while fetching forms :: 'name' field not found in response",
            )

        form_df = forms_df[forms_df["name"] == form_name]
        if form_df.empty:
            return pd.DataFrame(), f"No form found with the given name: {form_name}"

        return form_df, ""

    def create_form(self, form_data: dict) -> Tuple[str, str]:
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return None, error
        api_endpoint_url = self.build_api_url(self.CREATE_FORM)
        headers = {"Authorization": auth_token}
        response, error = self.make_api_request(
            api_endpoint_url, json=form_data, headers=headers, method="POST"
        )
        if error:
            return None, error

        if response.ok and response.status_code == http.HTTPStatus.CREATED:
            try:
                new_form_id = response.json().get("_id")
                return new_form_id, None
            except (requests.JSONDecodeError, ValueError) as e:
                return None, f"Response is in an invalid format :: {e}"
        else:
            return (
                None,
                f"Received error from response :: Status Code: {response.status_code}, Response: {response.text}",
            )

    def delete_form(self, form_id: str) -> str:
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return error
        api_endpoint_url = self.build_api_url(self.DELETE_FORM).format(form_id=form_id)
        headers = {"Authorization": auth_token}
        response, error = self.make_api_request(
            api_endpoint_url, headers=headers, method="DELETE"
        )
        if error:
            return error

        if response.ok and response.status_code == http.HTTPStatus.NO_CONTENT:
            return None
        else:
            return f"Received error from response :: Status Code: {response.status_code}, Response: {response.text}"

    def assign_form_to_user(
        self,
        user_ids: List[str],
        form_id: str,
        due_date: datetime,
        purpose: str = "",
        delegatable_form_assign_id: str = "",
        should_preserve_response=True,
    ) -> str:
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return error
        api_endpoint_url = self.build_api_url(self.ASSIGN_FORM_TO_USER)
        headers = {"Authorization": auth_token}
        data = {
            "dueDate": due_date.strftime("%m/%d/%Y"),
            "formId": form_id,
            "userID": user_ids,
            "purpose": purpose,
        }
        if delegatable_form_assign_id:
            data.update(
                {
                    "delegatableFormAssignID": delegatable_form_assign_id,
                    "shouldPreserveResponse": should_preserve_response,
                }
            )
        response, error = self.make_api_request(
            api_endpoint_url, headers=headers, method="POST", json=data
        )
        if error:
            return error

        if response.ok and response.status_code == http.HTTPStatus.NO_CONTENT:
            return None
        else:
            return f"Received error from response :: Status Code: {response.status_code}, Response: {response.text}"

    def get_form_assignments_for_user(
        self,
        user_id: str,
        include_ignored: bool = False,
        include_submitted: bool = False,
        include_delegated: bool = False,
    ):
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return error
        api_endpoint_url = self.build_api_url(self.GET_USER_ASSIGNED_FORMS).format(
            user_id=user_id,
            include_ignored=include_ignored,
            include_delegated=include_delegated,
            include_submitted=include_submitted,
        )
        headers = {"Authorization": auth_token}
        response, error = self.make_api_request(
            api_endpoint_url, headers=headers, method="GET"
        )
        if error:
            return None, error

        if response.ok and response.status_code == http.HTTPStatus.OK:
            try:
                assignments_list = response.json().get("items")
                if not isinstance(assignments_list, list):
                    raise ValueError("Response is not in list format")
                assignments_df = pd.DataFrame(assignments_list)
                return assignments_df, None
            except (requests.JSONDecodeError, ValueError) as e:
                return None, f"Response is in an invalid format :: {e}"
        else:
            return (
                None,
                f"Received error from response :: Status Code: {response.status_code}, Response: {response.text}",
            )

    def list_users(self, email_ids: List[str] | str = ""):
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return None, error
        api_endpoint_url = self.build_api_url(self.LIST_USERS)
        headers = {"Authorization": auth_token}

        cur_page = 1
        page_size = 10
        has_next = True
        users_list: List[dict] = []
        email_ids = ",".join(email_ids) if isinstance(email_ids, list) else email_ids

        while has_next:
            params = {"page": cur_page, "pageSize": page_size, "email_ids": email_ids}
            response, error = self.make_api_request(
                api_endpoint_url, headers=headers, method="GET", params=params
            )
            if error:
                return None, error

            if response.ok and response.status_code == http.HTTPStatus.OK:
                try:
                    response_dict: Dict[str, dict] = response.json()

                    # Handle pagination
                    if "pagination" not in response_dict:
                        has_next = False
                    else:
                        total_pages = int(
                            response_dict["pagination"].get("totalPages", 0)
                        )
                        cur_page += 1
                        has_next = cur_page <= total_pages

                    new_users_list = response_dict.get("items")
                    if not isinstance(new_users_list, list):
                        raise ValueError("Response is not in list format")
                    users_list.extend(new_users_list)
                except (requests.JSONDecodeError, ValueError) as e:
                    return None, f"Response is in an invalid format :: {e}"
            else:
                return (
                    None,
                    f"Received error from response :: Status Code: {response.status_code}, Response: {response.text}",
                )

        return pd.DataFrame(users_list), None

    def get_user(self, user_id: str) -> tuple[Dict[str, Any], str]:
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return {}, error
        api_endpoint_url = self.build_api_url(self.GET_USER.format(user_id=user_id))
        headers = {"Authorization": auth_token}

        response, error = self.make_api_request(
            api_endpoint_url, headers=headers, method="GET"
        )
        if error:
            return {}, error

        if response.ok and response.status_code == http.HTTPStatus.OK:
            try:
                user_data: Dict[str, dict] = response.json()
                return user_data, ""
            except (requests.JSONDecodeError, ValueError) as e:
                return {}, f"Response is in an invalid format :: {e}"
        elif response.status_code == http.HTTPStatus.NOT_FOUND:
            return {}, f"User with id '{user_id}' does not exist."
        else:
            return (
                {},
                f"Received error from response :: Status Code: {response.status_code}, Response: {response.text}",
            )

    def get_user_medium_config(self, medium_user_id: str) -> tuple[Dict[str, Any], str]:
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return {}, error
        api_endpoint_url = self.build_api_url(
            self.GET_USER_MEDIUM_CONFIGS.format(medium_user_id=medium_user_id)
        )
        headers = {"Authorization": auth_token}

        response, error = self.make_api_request(
            api_endpoint_url, headers=headers, method="GET"
        )
        if error:
            return {}, error

        if response.ok and response.status_code == http.HTTPStatus.OK:
            try:
                user_medium_config_response: Dict[str, Any] = response.json()
                user_medium_config = user_medium_config_response.get("items")
                if not user_medium_config or not isinstance(user_medium_config, list):
                    return {}, f"User with Medium ID '{medium_user_id}' does not exist."

                return user_medium_config[0], ""
            except (requests.JSONDecodeError, ValueError) as e:
                return {}, f"Response is in an invalid format :: {e}"
        else:
            return (
                {},
                f"Received error from response :: Status Code: {response.status_code}, Response: {response.text}",
            )

    def list_user_medium_config(self) -> tuple[Dict[str, Any], str]:
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return {}, error

        api_endpoint_url = self.build_api_url(self.LIST_USER_MEDIUM_CONFIGS)
        headers = {
            'Authorization': auth_token
        }

        response, error = self.make_api_request(
            api_endpoint_url,
            headers=headers,
            method='GET'
        )
        if error:
            return {}, error

        if response.ok and response.status_code == http.HTTPStatus.OK:
            try:
                user_medium_config_response: Dict[str, Any] = response.json()
                user_medium_config = user_medium_config_response.get('items')
                if not user_medium_config or not isinstance(user_medium_config, list):
                    return {}, "User medium IDs do not exist."

                return user_medium_config, ''

            except (requests.JSONDecodeError, ValueError) as e:
                return {}, f"Response is in an invalid format :: {e}"
        else:
            return {}, f"Received error from response :: Status Code: {response.status_code}, Response: {response.text}"

    def create_evidence_template(
        self,
        assessment_id: str,
        control_id: str,
        evd_name: str,
        evd_description,
        syn_name: str,
        file_content: str,
    ) -> str:

        api_endpoint_url = self.build_api_url(self.CREATE_EVIDENCE_TEMPLATE).format(
            assessment_id=assessment_id, control_id=control_id
        )

        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return None, error

        payload = {
            "name": evd_name,
            "description": evd_description,
            "userSelectedComplianceWeight": 5,
            "userDefinedSynthesizerName": syn_name,
            "fileContent": file_content,
            "graphConfigYamlFileContent": "",
            "sqlRuleYamlFileContent": "",
        }
        headers = {"Authorization": auth_token}

        response, error = self.make_api_request(
            url=api_endpoint_url, headers=headers, method="POST", json=payload
        )
        if error:
            return None, error
        if response.ok and response.status_code == http.HTTPStatus.CREATED:
            return response.json(), ""
        elif "EVIDENCE_ALREADY_AVAILABLE" in response.text:
            return response.json(), ""
        else:
            return (
                None,
                f"Received error from the ComplianceCow Create Assessment API response: Status Code: {response.status_code}, Response: {response.text}",
            )

    def fetch_evidence(
        self, assesment_run_id: str, control_id: str, evidence_id: str
    ) -> Tuple[pd.DataFrame, dict, str]:
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return None, None, error
        api_endpoint_url = self.build_api_url(
            self.FETCH_EVIDENCE.format(
                assesment_run_id=assesment_run_id,
                control_id=control_id,
                evidence_id=evidence_id,
            )
        )
        headers = {"Authorization": auth_token}
        response, error = self.make_api_request(
            api_endpoint_url, headers=headers, method="GET"
        )
        if error:
            return None, None, error

        if response.ok and response.status_code == http.HTTPStatus.OK:
            try:
                evidence_details = response.json()
                if "fileContent" not in evidence_details:
                    return pd.DataFrame(), evidence_details, None
                evidence_bytes = base64.b64decode(evidence_details["fileContent"])
                evidence_df = pd.read_parquet(io.BytesIO(evidence_bytes))
                del evidence_details["fileContent"]
                return evidence_df, evidence_details, None
            except (
                requests.JSONDecodeError,
                ValueError,
                KeyError,
                pyarrow.ArrowInvalid,
            ) as e:
                return (
                    None,
                    None,
                    f"Error while fetching evidence :: Response is in an invalid format :: {e}",
                )
        else:
            return (
                None,
                None,
                f"Error while fetching evidence :: Status Code: {response.status_code}, Response: {response.text}",
            )

    def fetch_evidence_data_in_encoded_formate(
        self, assesment_run_id: str, control_id: str, evd_id: str
    ) -> Tuple[str, dict, str]:

        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return "", None, error

        api_endpoint_url = self.build_api_url(
            self.FETCH_EVIDENCE_V1.format(
                assesment_run_id=assesment_run_id,
                control_id=control_id,
                evidence_id=evd_id,
            )
        )
        headers = {"Authorization": auth_token}
        response, error = self.make_api_request(
            api_endpoint_url, headers=headers, method="GET"
        )
        if error:
            return "", None, error

        if response.ok and response.status_code == http.HTTPStatus.OK:
            evidence_details = response.json()

            if "fileContent" not in evidence_details:
                return "", evidence_details, None
            file_content = evidence_details["fileContent"]
            del evidence_details["fileContent"]
            return file_content, evidence_details, None
        else:
            return (
                "",
                None,
                f"Error while fetching evidence :: Status Code: {response.status_code}, Response: {response.text}",
            )

    def update_evidence(
        self,
        assessment_id: str,
        assesment_run_id: str,
        assessment_control_id: str,
        run_control_id: str,
        evidence_id: str,
        evidence_name: str,
        evidence_desc: str,
        evidence_file_name: str,
        evidence_df: pd.DataFrame,
        compliance_calculation_infos: dict,
        send_email_notification: bool = True,
        send_notification: bool = True,
        timeout=None,
    ) -> str:
        
        # send_notification takes higher priority than send_email_notification.
        # If 'send_notification' is False, no notifications will be sent - 
        # neither email nor web notifications - even if 'send_email_notification' is True.

        # Sample complianceCalculationInfos struct  ::::::
        # 'complianceCalculationInfos': {
        #     "gocel": {
        #         "include": "ComplianceStatus != \"\" && ComplianceStatus != \"NOT_DETERMINED\"",
        #         "compliance": "ComplianceStatus == \"COMPLIANT\""
        #         }
        # }

        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return error
        api_endpoint_url = self.build_api_url(self.UPDATE_EVIDENCE).format(
            assessment_run_id=assesment_run_id, control_id=run_control_id
        )
        headers = {"Authorization": auth_token}
        body = {
            "data": base64.b64encode(evidence_df.to_parquet()).decode(),
            "name": evidence_name,
            "description": evidence_desc,
            "fileName": evidence_file_name,
            "assessmentID": assessment_id,
            "assessmentControlID": assessment_control_id,
            "userSelectedComplianceWeight": 5,
            "ComplianceWeight": 5,
            "reCalculateCompliancePCT": True,
            "initialCommit": True,
            "sendEmailNotification": send_email_notification,
            "sendNotification": send_notification,
        }

        if compliance_calculation_infos:
            body["complianceCalculationInfos"] = compliance_calculation_infos

        if evidence_id:
            body["evidenceID"] = evidence_id

        response, error = self.make_api_request(
            api_endpoint_url, headers=headers, method="POST", json=body, timeout=timeout
        )
        if error:
            return error
        if response.ok and response.status_code == http.HTTPStatus.NO_CONTENT:
            try:
                return ""
            except (
                requests.JSONDecodeError,
                ValueError,
                KeyError,
                pyarrow.ArrowInvalid,
            ) as e:
                return f"Error while updating evidence :: Response is in an invalid format :: {e}"
        else:
            return f"Error while updating evidence :: Status Code: {response.status_code}, Response: {response.text}"

    def upload_evidence_to_ccow(
        self,
        assessment_run_id: str,
        assessment_run_control_id: str,
        evidence_name: str,
        evidence_desc: str,
        evidence_file_name: str,
        evidence_parquet_base_64: base64,
        compliance_calculation_infos: dict = {},
        send_email_notification: bool = True,
    ) -> Tuple[dict, str]:

        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return error
        api_endpoint_url = self.build_api_url(self.UPDATE_EVIDENCE).format(
            assessment_run_id=assessment_run_id, control_id=assessment_run_control_id
        )
        headers = {"Authorization": auth_token}
        body = {
            "data": evidence_parquet_base_64,
            "name": evidence_name,
            "description": evidence_desc,
            "fileName": evidence_file_name,
            "userSelectedComplianceWeight": 5,
            "ComplianceWeight": 5,
            "reCalculateCompliancePCT": True,
            "initialCommit": True,
            "sendEmailNotification": send_email_notification,
        }

        if compliance_calculation_infos:
            body["complianceCalculationInfos"] = compliance_calculation_infos

        response, error = self.make_api_request(
            api_endpoint_url, headers=headers, method="POST", json=body
        )
        if error:
            return {}, error
        if response.ok and response.status_code == http.HTTPStatus.NO_CONTENT:
            try:
                return {
                    "FileUploadStatusDescription": f"{evidence_name} uploaded successfully in the target assessment run {assessment_run_id} and target control {assessment_run_control_id}",
                    "isFileUploaded": True,
                    "UploadedFileName": evidence_file_name
                }, ""
            except (
                requests.JSONDecodeError,
                ValueError,
                KeyError,
                pyarrow.ArrowInvalid,
            ) as e:
                return (
                    {},
                    f"Error while uploading evidence {evidence_name}:: Response is in an invalid format :: {e}",
                )
        else:
            return (
                {},
                f"Error while uploading evidence  {evidence_name}:: Status Code: {response.status_code}, Response: {response.text}",
            )

    def link_evidence_records(
        self,
        mapper=None,
        assesment_id=None,
        assesment_run_id=None,
        src_control_id=None,
        des_control_id=None,
        src_file_name=None,
        des_file_name=None,
        src_evidence_id=None,
        des_evidence_id=None,
        src_record_ids=None,
        des_record_ids=None,
        src_run_control_id=None,
        des_run_control_id=None,
        timeout=None
    ):

        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return error
        api_endpoint_url = self.build_api_url(self.LINK_EVIDENCE_RECORDS).format(
            assessment_run_id=assesment_run_id
        )

        headers = {"Authorization": auth_token}
        body = {
            "fileName": src_file_name,
            "assessmentControlID": src_control_id,
            "assessmentRunControlID": src_run_control_id,
            "evidenceID": src_evidence_id,
            "recordIds": src_record_ids,
            "notes": "Link records",
            "mapper": mapper,
            "relatedData": {
                "assessmentControlID": des_control_id,
                "assessmentRunControlID": des_run_control_id,
                "evidenceID": des_evidence_id,
                "fileName": des_file_name,
                "recordIds": des_record_ids,
            },
        }

        response, error = self.make_api_request(
            api_endpoint_url, headers=headers, method="POST", json=body,timeout=timeout
        )
        if error:
            return f"Error while linking evidence record :: {error}"
        if response.ok and response.status_code == http.HTTPStatus.NO_CONTENT:
            return ""
        else:
            return f"Error while linking evidence records :: Status Code: {response.status_code}, Response: {response.text}"

    def commit_evidence(
        self,
        assessment_id: str,
        assesment_run_id: str,
        control_id: str,
        evidence_id: str,
        evidence_file_name: str,
        is_super_admin: bool = True,
        is_src_commit: bool = True,
    ) -> str:
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return error
        api_endpoint_url = self.build_api_url(self.UPDATE_EVIDENCE)
        headers = {"Authorization": auth_token}
        body = {
            "fileName": evidence_file_name,
            "planGUID": assessment_id,
            "planExecGUID": assesment_run_id,
            "controlGUID": control_id,
            "evidenceID": evidence_id,
            "ownerType": "user",
            "isSuperAdmin": is_super_admin,
            "isSrcCommit": is_src_commit,
            "type": "commit",
        }
        response, error = self.make_api_request(
            api_endpoint_url, headers=headers, method="POST", json=body
        )
        if error:
            return error

        if response.ok and response.status_code == http.HTTPStatus.OK:
            try:
                return ""
            except (
                requests.JSONDecodeError,
                ValueError,
                KeyError,
                pyarrow.ArrowInvalid,
            ) as e:
                return f"Response is in an invalid format :: {e}"
        else:
            return f"Received error from response :: Status Code: {response.status_code}, Response: {response.text}"

    def commit_control_evidence(
        self,
        assesment_run_id: str,
        control_id: str,
        evidence_id: str,
        commit_for_all: bool,
        commit_msg: str,
    ) -> str:

        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return error
        api_endpoint_url = self.build_api_url(self.COMMIT_CONTROL_EVIDENCE).format(
            assessment_run_id=assesment_run_id,
            control_id=control_id,
            evidence_id=evidence_id,
        )
        headers = {"Authorization": auth_token}
        body = {"commitMessage": commit_msg, "commitForAll": commit_for_all}
        response, error = self.make_api_request(
            api_endpoint_url, headers=headers, method="POST", json=body
        )
        if error:
            return error

        if response.ok and response.status_code == http.HTTPStatus.OK:
                return ""
        else:
            return f"Error while commiting evidence :: Status Code: {response.status_code}, Response: {response.text}"

    def commit_existing_control_evidence(
        self,
        assesment_run_id: str,
        control_id: str,
        evidence_id: str,
        evidence_df: pd.DataFrame,
        commit_msg: str,
    ) -> str:

        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return error
        api_endpoint_url = self.build_api_url(self.COMMIT_CONTROL_EVIDENCE).format(
            assessment_run_id=assesment_run_id,
            control_id=control_id,
            evidence_id=evidence_id,
        )
        headers = {"Authorization": auth_token}
        body = {
            "data": base64.b64encode(evidence_df.to_parquet()).decode(),
            "commitMessage": commit_msg
        }
        response, error = self.make_api_request(
            api_endpoint_url, headers=headers, method="POST", json=body
        )
        if error:
            return error

        if response.ok and response.status_code == http.HTTPStatus.OK:
                return ""
        else:
            return f"Error while commiting evidence :: Status Code: {response.status_code}, Response: {response.text}"

    def get_plans(self, fields: str = "basic"):
        try:
            auth_token, error = self.fetch_and_extract_auth_token()
            if error:
                return None, error
            api_endpoint_url = self.build_api_url(f"{self.GET_PLANS}?fields={fields}")
            headers = {"Authorization": auth_token}

            response, error = self.make_api_request(
                api_endpoint_url, headers=headers, method="GET"
            )

            if not response:
                return None, "Failed to get a response from the API."
            if response.ok and response.status_code == http.HTTPStatus.OK:
                plan_details = response.json()
                return plan_details, None
            else:
                return (
                    None,
                    f"Received error from response :: Status Code: {response.status_code}, Response: {response.text}",
                )

        except requests.exceptions.ConnectionError as ce:
            return None, f"Connection error occurred: {ce}"
        except requests.exceptions.Timeout as te:
            return None, f"Request timed out: {te}"
        except requests.exceptions.RequestException as re:
            return None, f"An error occurred while making the request: {re}"

    def fetch_assessments(
        self, assessment_name: str = "", detailed: bool = False
    ) -> Tuple[List[dict], str]:
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return None, error
        api_endpoint_url = self.build_api_url(self.FETCH_ASSESSMENTS)
        headers = {"Authorization": auth_token}

        cur_page = 1
        page_size = 5 if detailed else 100
        has_next = True
        assessments_list: List[dict] = []

        while has_next:
            params = {
                "page": cur_page,
                "page_size": page_size,
                "fields": "detailed" if detailed else "basic",
            }
            if assessment_name:
                params["name"] = assessment_name
            response, error = self.make_api_request(
                api_endpoint_url, headers=headers, method="GET", params=params
            )
            if error:
                return None, error

            if response.ok and response.status_code == http.HTTPStatus.OK:
                try:
                    response_dict: Dict[str, dict] = response.json()

                    # Handle pagination
                    if "pagination" not in response_dict:
                        has_next = False
                    else:
                        total_pages = int(
                            response_dict["pagination"].get("totalPages", 0)
                        )
                        cur_page += 1
                        has_next = cur_page <= total_pages

                    new_assessments_list = response_dict.get("items")
                    if not isinstance(new_assessments_list, list):
                        raise ValueError("Response is not in list format")
                    assessments_list.extend(new_assessments_list)
                except (requests.JSONDecodeError, ValueError) as e:
                    return None, f"Response is in an invalid format :: {e}"
            else:
                return (
                    None,
                    f"Received error from response :: Status Code: {response.status_code}, Response: {response.text}",
                )

        return assessments_list, None

    def get_latest_assessment_run_details(self, assessment_id):
        try:
            auth_token, error = self.fetch_and_extract_auth_token()
            if error:
                return None, error
            page = 1
            page_size = 1
            while True:
                api_endpoint_url = self.build_api_url(
                    self.GET_ASSESSMENT_RUN_DETAILS_BY_ASSESSMENT_ID.format(
                        page=page, page_size=page_size, assessment_id=assessment_id
                    )
                )
                headers = {"Authorization": auth_token}

                response, error = self.make_api_request(
                    api_endpoint_url, headers=headers, method="GET"
                )

                if not response:
                    return None, "Failed to get a response from the API."

                if response.ok and response.status_code == http.HTTPStatus.OK:
                    assessment_details = response.json()
                    items = assessment_details.get("items", [])

                    completed_run = None
                    for item in items:
                        if item.get("runStatus") == "Completed":
                            completed_run = item
                            break

                    if completed_run:
                        return completed_run, None

                    if len(items) < page_size:
                        return None, "No completed assessment run found."
                    page_size = 4

                else:
                    return (
                        None,
                        f"Received error from response :: Status Code: {response.status_code}, Response: {response.text}",
                    )

        except requests.exceptions.ConnectionError as ce:
            return None, f"Connection error occurred: {ce}"
        except requests.exceptions.Timeout as te:
            return None, f"Request timed out: {te}"
        except requests.exceptions.RequestException as re:
            return None, f"An error occurred while making the request: {re}"

    def get_assessment_run_details_by_assesment_id(
        self,
        assessment_id,
        created_at_start_time=None,
        created_at_end_time=None,
        fields=None,
    ) -> Tuple[List[dict], str]:

        try:
            auth_token, error = self.fetch_and_extract_auth_token()
            if error:
                return None, error

            headers = {"Authorization": auth_token}

            cur_page = 1
            page_size = 10
            has_next = True
            combined_assessment_runs: List[dict] = []

            while has_next:

                api_endpoint_url = self.build_api_url(
                    self.GET_ASSESSMENT_RUN_DETAILS_BY_ASSESSMENT_ID.format(
                        page=cur_page,
                        page_size=page_size,
                        assessment_id=assessment_id,
                    )
                )

                if fields:
                    api_endpoint_url = f"{api_endpoint_url}&fields={fields}"
                if created_at_start_time:
                    api_endpoint_url = f"{api_endpoint_url}&created_at_start_time={created_at_start_time}"
                if created_at_end_time:
                    api_endpoint_url = (
                        f"{api_endpoint_url}&created_at_end_time={created_at_end_time}"
                    )

                response, error = self.make_api_request(
                    api_endpoint_url,
                    headers=headers,
                    method="GET",
                )

                if not response or error:
                    return None, (
                        error if error else "Failed to get a response from the API."
                    )

                if response.ok and response.status_code == http.HTTPStatus.OK:

                    response_dict: Dict[str, dict] = response.json()

                    assessment_runs = response_dict.get("items", [])

                    for assessment_run in assessment_runs:
                        if assessment_run.get("runStatus") != "Completed":
                            continue
                        combined_assessment_runs.append(assessment_run)

                    if "pagination" not in response_dict:
                        has_next = False
                    else:
                        total_pages = int(
                            response_dict["pagination"].get("totalPages", 0)
                        )
                        cur_page += 1
                        has_next = cur_page <= total_pages

                else:
                    return (
                        None,
                        f"Received error from response :: Status Code: {response.status_code}, Response: {response.text}",
                    )

        except requests.exceptions.ConnectionError as ce:
            return None, f"Connection error occurred: {ce}"
        except requests.exceptions.Timeout as te:
            return None, f"Request timed out: {te}"
        except requests.exceptions.RequestException as re:
            return None, f"An error occurred while making the request: {re}"

        return combined_assessment_runs, None

    def fetch_assessment_run_details(self, assessment_run_id):
        try:
            auth_token, error = self.fetch_and_extract_auth_token()
            if error:
                return None, error
            api_endpoint_url = self.build_api_url(
                self.GET_ASSESSMENT_RUN_DETAILS.format(
                    assessment_run_id=assessment_run_id
                )
            )
            headers = {"Authorization": auth_token}

            response, error = self.make_api_request(
                api_endpoint_url, headers=headers, method="GET"
            )

            if not response:
                return None, "Failed to get a response from the API."
            if response.ok and response.status_code == http.HTTPStatus.OK:
                assessment_run_details = response.json()
                return assessment_run_details, None
            else:
                return (
                    None,
                    f"Received error from response :: Status Code: {response.status_code}, Response: {response.text}",
                )

        except requests.exceptions.ConnectionError as ce:
            return None, f"Connection error occurred: {ce}"
        except requests.exceptions.Timeout as te:
            return None, f"Request timed out: {te}"
        except requests.exceptions.RequestException as re:
            return None, f"An error occurred while making the request: {re}"

    def download_file(self, input_file_hash, auth_token="") -> Tuple[str, str, str]:
        try:
            if not auth_token:
                auth_token, error = self.fetch_and_extract_auth_token()
                if error:
                    return None, "", error
            api_endpoint_url = self.build_api_url(
                self.DOWNLOAD_FILE.format(input_file_hash=input_file_hash)
            )
            headers = {"Authorization": auth_token}

            response, error = self.make_api_request(
                api_endpoint_url, headers=headers, method="GET"
            )

            if not response:
                return None, "", "Failed to get a response from the API."
            if response.ok and response.status_code == http.HTTPStatus.OK:
                response_dict = response.json()
                file_name = response_dict.get("fileName", "")
                file_bytes = response_dict.get("fileContent", "")
                if not file_bytes:
                    return None, "", "File is empty"
                return file_bytes, file_name, None
            else:
                return (
                    None,
                    "",
                    f"Received error from response :: Status Code: {response.status_code}, Response: {response.text}",
                )

        except requests.exceptions.ConnectionError as ce:
            return None, "", f"Connection error occurred: {ce}"
        except requests.exceptions.Timeout as te:
            return None, "", f"Request timed out: {te}"
        except requests.exceptions.RequestException as re:
            return None, "", f"An error occurred while making the request: {re}"

    def fetch_and_extract_auth_token(self):
        auth_response, error = self.fetch_auth_token()
        if error:
            return None, error
        if "tokenType" in auth_response and "authToken" in auth_response:
            token_type = auth_response["tokenType"]
            auth_token = auth_response["authToken"]
            return f"{token_type} {auth_token}", None
        return (
            None,
            "Unable to fetch the 'tokenType' and 'authToken' from the ComplianceCow authentication API response. Please contact admin/support to fix this issue.",
        )

    def get_resource_url(self, ui_endpoint: str):
        resource_url = self.app_url
        if resource_url.endswith("/api"):
            resource_url.replace("/api", "/ui/")
        else:
            resource_url = resource_url.rstrip("/")
            resource_url += "/ui/"
        ui_endpoint = ui_endpoint.lstrip("/")
        return resource_url + ui_endpoint

    def build_api_url(self, endpoint):
        base_url = self.ensure_api_suffix(self.app_url)
        return f"{base_url}{endpoint}"

    def ensure_api_suffix(self, url):
        url = url.rstrip("/")
        if not url.endswith("api"):
            url += "/api"
        return url

    def make_api_request(
        self,
        url,
        headers,
        method="GET",
        json=None,
        data=None,
        files=None,
        params=None,
        timeout=1200,
        max_retries=3,
        retry_backoff=2,  # seconds between retries
    ):
        attempt = 0

        while attempt < max_retries:
            try:
                response = requests.request(
                    method=method,
                    url=url,
                    json=json,
                    data=data,
                    headers=headers,
                    params=params,
                    verify=False,
                    files=files,
                    timeout=timeout,
                )

                # Retry manually on 5xx server errors
                if response.status_code == 500:
                    attempt += 1
                    if attempt < max_retries:
                        time.sleep(retry_backoff)
                        continue
                    return (
                        None,
                        f"Server error ({response.status_code}): {response.text}",
                    )

                return response, None  # Successful response

            except requests.exceptions.Timeout as e:
                attempt += 1
                if attempt < max_retries:
                    time.sleep(retry_backoff)
                    continue
                return None, f"Request timed out after {max_retries} attempts: {e}"

            except requests.exceptions.ConnectionError as e:
                attempt += 1
                if attempt < max_retries:
                    time.sleep(retry_backoff)
                    continue
                return None, f"Connection error after {max_retries} attempts: {e}"

            except requests.exceptions.RequestException as e:
                # For other, non-retryable request exceptions
                return None, f"Other request exception: {e}"

        return None, "Failed after maximum retry attempts"

    def get_current_datetime(self):
        current_time = datetime.now(timezone.utc)
        formatted_time = current_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        return formatted_time

    def get_user_block(self, user_block_name) -> tuple[dict, str]:
        if not user_block_name:
            return None, "User block name is empty"

        api_endpoint_url = self.build_api_url(
            self.GET_USER_BLOCK.format(user_block_name=user_block_name)
        )
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return None, error

        headers = {"Authorization": auth_token}

        response, error = self.make_api_request(
            url=api_endpoint_url,
            headers=headers,
            method="GET",
            params={"isStatusToBeIncluded": "true"},
        )

        if error:
            return None, error

        if response.ok:
            return response.json(), ""

        if "ErrorMessage" in response.json():
            return None, response.json()["ErrorMessage"]

        return None, f"Failed to fetch user block details. {response.text}"

    def get_users_from_user_mails(self, user_mails) -> tuple[dict, str]:
        if not user_mails:
            return None, "User mail is empty"

        user_mails_str = ""

        if isinstance(user_mails, list):
            user_mails_str = ",".join(user_mails)
        else:
            user_mails_str = user_mails

        api_endpoint_url = self.build_api_url(
            self.GET_USERS_FROM_EMAILS.format(email_in_comma_seperated=user_mails_str)
        )
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return None, error

        headers = {"Authorization": auth_token}

        response, error = self.make_api_request(
            url=api_endpoint_url, headers=headers, method="GET"
        )

        if error:
            return None, error

        if response.ok:
            return response.json(), ""

        if "ErrorMessage" in response.json():
            return None, response.json()["ErrorMessage"]

        return None, f"Failed to fetch user(s) info -  {user_mails_str}"

    def get_ids_from_users(self, users) -> tuple[dict, str]:
        users_id = []
        try:
            if not users:
                return users_id, "users list is empty"
            for user in users:
                if "ID" in user:
                    users_id.append(user["ID"])
            return users_id, None
        except Exception as e:
            return (
                users_id,
                f"Exception occured while fetching IDs for user(s) - {','.join(users)}. {str(e)}",
            )

    def get_user_mails_from_user_blocks(self, userblocks) -> tuple[dict, str]:
        user_mails = []
        try:
            if not userblocks:
                return user_mails, None
            for userblock in userblocks:
                user_mails.extend(userblock[0]["status"]["matchingUsers"])
            return user_mails, None
        except (AttributeError, KeyError, IndexError) as e:
            return (
                user_mails,
                f"Exception occured while fetching emails for userbock(s) - {','.join(userblocks)}. {str(e)}",
            )

    def assign_control(self, control_id, users_id):
        if not control_id:
            return "Control ID is empty"

        api_endpoint_url = self.build_api_url(
            self.ASSIGN_CONTROL.format(control_id=control_id)
        )
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return error

        headers = {"Authorization": auth_token}

        payload = {"assignedTo": users_id}

        response, error = self.make_api_request(
            url=api_endpoint_url, headers=headers, method="POST", json=payload
        )

        if error:
            return error

        if response.status_code == http.HTTPStatus.NO_CONTENT:
            return ""

        description = "Failed to assign control. "
        error_dict = response.json()
        if "Description" in error_dict:
            description = error_dict["Description"]

        return (
            f'{description}. Control ID - {control_id}. User(s) - {",".join(users_id)}'
        )

    def checkout_user(self, token, control_ids):
        if not token:
            return "User token is empty."

        api_endpoint_url = self.build_api_url(self.CHECKOUT_USER)

        headers = {"Authorization": token}

        payload = {"planInstanceControlIds": control_ids}

        response, error = self.make_api_request(
            url=api_endpoint_url, headers=headers, method="POST", json=payload
        )

        if error:
            return error

        if response.ok:
            return ""

        return f'Failed to checkout user from controls - {", ".join(control_ids)}'

    def complete_user(self, token, control_id):
        if not token:
            return "User token is empty."

        api_endpoint_url = self.build_api_url(
            self.COMPLETE_USER.format(control_id=control_id)
        )

        headers = {"Authorization": token}

        response, error = self.make_api_request(
            url=api_endpoint_url, headers=headers, method="POST"
        )

        if error:
            return error

        if response.ok:
            return ""

        if "ErrorMessage" in response.json():
            return response.json()["ErrorMessage"]

        return f"Failed to complete user from control - {control_id}"

    # Get the list of user ids from the user mails
    def get_user_ids_from_user_mails(self, user_mails):
        users, err = self.get_users_from_user_mails(user_mails)
        if err:
            return None, err
        if "items" in users:
            user_ids, err = self.get_ids_from_users(users["items"])
            if err:
                return None, err
            return user_ids, None
        return None, f'Failed to fetch user ids for users - {", ".join(user_mails)}'

    # Get the list of user mails from the user block name
    def get_user_mails_from_user_block_name(self, user_block_name):
        user_block, err = self.get_user_block(user_block_name)
        if err:
            return None, err
        if "items" in user_block:
            user_mails, err = self.get_user_mails_from_user_blocks(
                [user_block["items"]]
            )
            if err:
                return None, err
            return user_mails, None
        return None, f"Failed to fetch user mails from user block {user_block_name}"

    # Need to handle later
    def send_slack_notification(self, control_id, workflow_instance_id, user_mails):
        try:
            if not workflow_instance_id:
                return "WorkflowInstanceId is empty"

            api_endpoint_url = self.build_api_url(self.SEND_SLACK_NOTIFICATION)
            auth_token, error = self.fetch_and_extract_auth_token()
            if error:
                return error

            headers = {"Content-Type": "application/json", "Authorization": auth_token}

            # get hash used for user input files download
            hash, err = self.get_hash(control_id)
            if err:
                return error

            workflow_details_res, error = self.get_workflow_details(
                workflow_instance_id
            )
            if error:
                return error

            ass_name = ""
            ass_run_name = ""
            control_name = ""
            control_num = ""
            plan_instance_id = ""
            plan_instance_con_id = ""

            if "metaData" in workflow_details_res:
                if "planName" in workflow_details_res["metaData"]:
                    ass_name = f"*Assessment Name:*\n{workflow_details_res['metaData']['planName']}"
                if "planInstanceName" in workflow_details_res["metaData"]:
                    ass_run_name = f"*Run Name:*\n{workflow_details_res['metaData']['planInstanceName']}"
                if "planInstanceControlName" in workflow_details_res["metaData"]:
                    control_name = f"*Control Name:*\n{workflow_details_res['metaData']['planInstanceControlName']}"
                if "planInstanceControlNumber" in workflow_details_res["metaData"]:
                    control_num = f"*Control No:*\n{workflow_details_res['metaData']['planInstanceControlNumber']}"
                if "planInstanceId" in workflow_details_res["metaData"]:
                    plan_instance_id = workflow_details_res["metaData"][
                        "planInstanceId"
                    ]
                if "planInstanceControlId" in workflow_details_res["metaData"]:
                    plan_instance_con_id = workflow_details_res["metaData"][
                        "planInstanceControlId"
                    ]

            if (
                not ass_name
                or not ass_run_name
                or not control_name
                or not control_num
                or not plan_instance_id
                or not plan_instance_con_id
            ):
                return f"Failed to fetch control {control_id} details from workflow{workflow_instance_id} response."

            url = f"{self.app_url}ui/assign-control/{plan_instance_id}/{plan_instance_con_id}?src=controllist"
            updated_url = f"*Click <{url}| here > to view the control"

            not_cha_info = [{"ChannelType": "bot-slack"}]

            user_ids, err = self.get_user_ids_from_user_mails(user_mails)
            if err:
                return err

            approve_value, reject_value = self.get_button_values(workflow_instance_id)

            payload = json.dumps(
                {
                    "NotificationChannelInfo": not_cha_info,
                    "UsersToShow": user_ids,
                    "MessageBody": hash,
                    "Blocks": [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": "Control waiting for approval",
                                "emoji": True,
                            },
                        },
                        {
                            "type": "section",
                            "fields": [
                                {"type": "mrkdwn", "text": ass_name},
                                {"type": "mrkdwn", "text": ass_run_name},
                                {"type": "mrkdwn", "text": control_name},
                                {"type": "mrkdwn", "text": control_num},
                            ],
                        },
                        {
                            "type": "actions",
                            "elements": [
                                {
                                    "type": "button",
                                    "text": {
                                        "type": "plain_text",
                                        "emoji": True,
                                        "text": "Approve",
                                    },
                                    "style": "primary",
                                    "value": approve_value,
                                },
                                {
                                    "type": "button",
                                    "text": {
                                        "type": "plain_text",
                                        "emoji": True,
                                        "text": "Reject",
                                    },
                                    "style": "danger",
                                    "value": reject_value,
                                },
                            ],
                        },
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": f"{updated_url}. To know about the user input responses, please refer to the attachments in the following message.*",
                            },
                        },
                    ],
                }
            )

            response, error = self.make_api_request(
                url=api_endpoint_url, headers=headers, method="POST", data=payload
            )

            if error:
                return error

            if response.status_code == http.HTTPStatus.NO_CONTENT:
                return ""

            if response.json()["ErrorMessage"]:
                return response.json()["ErrorMessage"]

            return f"Failed to send slack notification"
        except Exception as e:
            return f"Exception occured while sending slack notification. {str(e)}"

    # Need to handle later
    def get_button_values(self, workflow_instance_id):

        text1 = {
            "uri": "/api/v2/workflow-instances/trigger-event",
            "method": "POST",
            "body": {
                "event": "When an assessment run control is approved",
                "instanceId": "<workflowInstanceId>",
            },
        }
        text1["body"]["syncAction"] = True
        text1["body"]["instanceId"] = workflow_instance_id
        text2 = {
            "uri": "/api/v2/workflow-instances/trigger-event",
            "method": "POST",
            "body": {
                "event": "When an assessment run control is rejected",
                "instanceId": "<workflowInstanceId>",
            },
        }
        text2["body"]["syncAction"] = True
        text2["body"]["instanceId"] = workflow_instance_id

        return self.text_to_base64(json.dumps(text1)), self.text_to_base64(
            json.dumps(text2)
        )

    def text_to_base64(self, plain_text):

        try:
            plain_bytes = plain_text.encode("utf-8")
            base64_bytes = base64.b64encode(plain_bytes)
            base64_string = base64_bytes.decode("utf-8")
            return base64_string
        except Exception:
            return ""

    def get_workflow_details(self, workflow_id):
        if not workflow_id:
            return None, "WorkFlowId is empty."

        api_endpoint_url = self.build_api_url(
            self.GET_WORKFLOW_DETAILS.format(workflow_id=workflow_id)
        )

        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return None, error

        headers = {"Authorization": auth_token}

        response, error = self.make_api_request(
            url=api_endpoint_url, headers=headers, method="GET"
        )

        if error:
            return None, error

        if response.ok:
            return response.json(), None

        if "ErrorMessage" in response.json():
            return "", response.json()["ErrorMessage"]

        return None, f"Failed to get workflow details - {workflow_id}"

    # This method will return hash, that is used for downloading user input files( slack notification )
    def get_hash(self, control_id):
        try:
            if not control_id:
                return (
                    None,
                    "Control ID is mandatory to get the hash for control user inputs.",
                )

            api_endpoint_url = self.build_api_url(
                self.GET_HASH.format(control_id=control_id)
            )
            auth_token, error = self.fetch_and_extract_auth_token()
            if error:
                return None, error

            headers = {"Authorization": auth_token}

            response, error = self.make_api_request(
                url=api_endpoint_url, headers=headers, method="POST"
            )
            if error:
                return None, error

            if response.ok and "hash" in response.json():
                hash = response.json()["hash"]
                app_url = self.app_url.rstrip("/")
                hash_url = f"{app_url}/ui/download/{hash}"
                return hash_url, None

            if "ErrorMessage" in response.json():
                return (
                    "",
                    f"Failed to get hash for control: {response.json()['ErrorMessage']}",
                )

            return None, f"Failed to get hash for control - {control_id}"
        except Exception as e:
            return (
                None,
                f"An exception occurred while fetching the hash for the user inputs of control (Control ID - '{control_id}'). {str(e)}",
            )

    def get_user_token(self, system_objects):
        try:
            if not system_objects:
                return "", "System Objects are empty."

            for system_object in system_objects:
                if (
                    system_object.app is not None
                    and system_object.app.application_name is not None
                    and system_object.app.application_name == "COW_API"
                ):
                    if system_object.credentials is not None:
                        creds = system_object.credentials
                        for cred in creds:
                            return cred.other_cred_info["token"], ""
                    else:
                        return (
                            "",
                            "Invalid COW_API credentials. Failed to fetch user token",
                        )

        except Exception as e:
            return (
                "",
                f"Unable to find the COW_API credentials in the system objects. Please contact admin/support to fix this issue. {e}",
            )

    def create_category(self, category_name: str) -> str:
        api_endpoint_url = self.build_api_url(self.CREATE_CATEGORY)
        payload = {"name": category_name}
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return error
        headers = {"Authorization": auth_token}
        response, error = self.make_api_request(
            url=api_endpoint_url, headers=headers, method="POST", json=payload
        )
        if error:
            return error
        if response.ok and response.status_code == http.HTTPStatus.CREATED:
            return None
        else:
            return f"Received error from the ComplianceCow Create Category API response: Status Code: {response.status_code}, Response: {response.text}"

    def fetch_category_details(self, category_name: str) -> tuple[dict, str]:
        api_endpoint_url = self.build_api_url(self.FETCH_CATEGORY).format(
            category_name=category_name
        )
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return None, error
        headers = {"Authorization": auth_token}
        response, error = self.make_api_request(
            url=api_endpoint_url, headers=headers, method="GET"
        )
        if error:
            return None, error
        if response.ok and response.status_code == http.HTTPStatus.OK:
            try:
                return response.json(), None
            except ValueError as e:
                return (
                    None,
                    f"Error decoding the JSON response from the ComplianceCow Fetch Category Details API: {e}",
                )
        else:
            return (
                None,
                f"Received error from the ComplianceCow Fetch Category Details API response: Status Code: {response.status_code}, Response: {response.text}",
            )

    def create_assessment(self, payload: dict) -> tuple[dict, str]:
        api_endpoint_url = self.build_api_url(self.CREATE_ASSESSMENT)
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return None, error
        headers = {"Authorization": auth_token}
        response, error = self.make_api_request(
            url=api_endpoint_url, headers=headers, method="POST", json=payload
        )
        if error:
            return None, error
        if response.ok and response.status_code == http.HTTPStatus.CREATED:
            return response.json(), ""
        else:
            return (
                None,
                f"Received error from the ComplianceCow Create Assessment API response: Status Code: {response.status_code}, Response: {response.text}",
            )

    def create_assessment_control(self, assessment_id: str, payload: dict) -> str:
        api_endpoint_url = self.build_api_url(self.CREATE_ASSESSMENT_CONTROL).format(
            assessment_id=assessment_id
        )
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return error
        headers = {"Authorization": auth_token}
        response, error = self.make_api_request(
            url=api_endpoint_url, headers=headers, method="POST", json=payload
        )
        if error:
            return error
        if response.ok and response.status_code == http.HTTPStatus.CREATED:
            return ""
        else:
            return f"Received an error from the ComplianceCow Create Assessment Control API response: Status Code: {response.status_code}, Response: {response.text}"

    def update_assessment_control(
        self, assessment_id: str, control_id: str, payload: list
    ) -> str:
        api_endpoint_url = self.build_api_url(self.UPDATE_ASSESSMENT_CONTROL).format(
            assessment_id=assessment_id, control_id=control_id
        )
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return error
        headers = {"Authorization": auth_token}
        response, error = self.make_api_request(
            url=api_endpoint_url, headers=headers, method="PATCH", json=payload
        )
        if error:
            return error
        if response.ok and response.status_code == http.HTTPStatus.NO_CONTENT:
            return ""
        else:
            return f"Received error from the ComplianceCow Update Assessment Control API response: Status Code: {response.status_code}, Response: {response.text}"

    def delete_assessment_control(self, assessment_id: str, control_id: str) -> str:
        api_endpoint_url = self.build_api_url(self.DELETE_ASSESSMENT_CONTROL).format(
            assessment_id=assessment_id, control_id=control_id
        )
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return error
        headers = {"Authorization": auth_token}
        response, error = self.make_api_request(
            url=api_endpoint_url, headers=headers, method="DELETE"
        )
        if error:
            return error
        if response.ok and response.status_code == http.HTTPStatus.NO_CONTENT:
            return ""
        else:
            return f"Received error from the ComplianceCow Delete Assessment Control API response: Status Code: {response.status_code}, Response: {response.text}"

    def fetch_assessment_details(self, assessment_name: str) -> tuple[dict, str]:
        api_endpoint_url = self.build_api_url(self.FETCH_ASSESSMENT).format(
            assessment_name=assessment_name
        )
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return None, error
        headers = {"Authorization": auth_token}
        response, error = self.make_api_request(
            url=api_endpoint_url, headers=headers, method="GET"
        )
        if error:
            return None, error
        if response.ok and response.status_code == http.HTTPStatus.OK:
            try:
                return response.json(), None
            except ValueError as e:
                return (
                    None,
                    f"Error decoding the JSON response from the ComplianceCow Fetch Assessment Details API: {e}",
                )
        else:
            return (
                None,
                f"Received an error from the ComplianceCow Fetch Assessment Details API response: Status Code: {response.status_code}, Response: {response.text}",
            )

    def get_application_scopes(self) -> Tuple[pd.DataFrame, str]:
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return None, error
        api_endpoint_url = self.build_api_url(self.GET_APPLICATION_SCOPES)
        headers = {"Authorization": auth_token}

        response, error = self.make_api_request(
            api_endpoint_url, headers=headers, method="GET"
        )
        if error:
            return None, error

        if response.ok and response.status_code == http.HTTPStatus.OK:
            try:
                response_dict: Dict[str, dict] = response.json()

                app_scope_list: List[dict] = response_dict.get("items")
                if not isinstance(app_scope_list, list):
                    raise ValueError("Response is not in list format")

                return pd.DataFrame(app_scope_list), None
            except (requests.JSONDecodeError, ValueError) as e:
                return None, f"Response is in an invalid format :: {e}"
        else:
            return (
                None,
                f"Received error from response :: Status Code: {response.status_code}, Response: {response.text}",
            )

    def create_assessment_run(
        self,
        assessment_id: str,
        app_scope_id: str,
        run_name: str,
        inputs: dict,
        from_date: str,
        to_date: str,
    ) -> Tuple[str, str]:
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return "", error
        api_endpoint_url = self.build_api_url(self.CREATE_ASSESSMENT_RUN)
        headers = {"Authorization": auth_token}

        try:
            datetime.strptime(from_date, r"%m/%d/%Y")
            datetime.strptime(to_date, r"%m/%d/%Y")
        except ValueError as e:
            return "", f"Please check the format of from_date and to_date :: {e}"

        body = {
            "assessmentId": assessment_id,
            "appScopeId": app_scope_id,
            "fromDate": from_date,
            "toDate": to_date,
            "tags": {},
            "name": run_name,
            "description": run_name,
            "otherInfos": {"disableAutomatedAction": True},
            "inputs": inputs,
        }

        response, error = self.make_api_request(
            api_endpoint_url, headers=headers, method="POST", json=body
        )
        if error:
            return "", error

        if response.ok:
            response_data = response.json()
            return response_data.get("id"), ""
        else:
            return (
                "",
                f"Received error from response :: Status Code: {response.status_code}, Response: {response.text}",
            )

    def get_matched_ucf_controls(self, control_name):

        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return None, error
        api_endpoint_url = self.build_api_url(self.GET_MATCHED_UCF_CONTROLS)
        headers = {"Authorization": auth_token}

        body = {"query": control_name, "identifier": "ucf-leaf-controls-collection"}

        response, error = self.make_api_request(
            api_endpoint_url, headers=headers, method="POST", json=body
        )
        if error:
            return None, error

        if response.ok and response.status_code == http.HTTPStatus.OK:
            response_data = response.json()
            return response_data, ""
        else:
            return (
                None,
                f"Received error from response :: Status Code: {response.status_code}, Response: {response.text}",
            )

    def create_control_citation(self, assessment_id, control_id, payload_data) -> str:
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return error
        api_endpoint_url = self.build_api_url(self.CREATE_CITATION).format(
            assessment_id=assessment_id, control_id=control_id
        )
        headers = {"Authorization": auth_token, "Content-Type": "application/json"}
        response, error = self.make_api_request(
            api_endpoint_url,
            headers=headers,
            method="POST",
            data=json.dumps(payload_data),
        )

        if error:
            print(
                f"Unable to create the citation for the ComplianceCow control{control_id} : {error}"
            )
            return f"Unable to create the citation for the ComplianceCow control{control_id}. Please contact admin/support to fix this issue."

        if response.ok and response.status_code == http.HTTPStatus.CREATED:
            return ""
        else:
            print(
                f"Unable to create the citation for the ComplianceCow control{control_id} : Status Code: {response.status_code}, Response: {response.text}"
            )
            return f"Unable to create the citation for the ComplianceCow control{control_id}. Please contact admin/support to fix this issue."

    def update_control_citation(
        self, assessment_id, control_id, citation_id, payload_data
    ) -> str:
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return error
        api_endpoint_url = self.build_api_url(self.UPDATE_CITATION).format(
            assessment_id=assessment_id, control_id=control_id, citation_id=citation_id
        )
        headers = {"Authorization": auth_token, "Content-Type": "application/json"}
        response, error = self.make_api_request(
            api_endpoint_url,
            headers=headers,
            method="PUT",
            data=json.dumps(payload_data),
        )

        if error:
            print(
                f"Unable to update the citation for the ComplianceCow control: {control_id} : {error}"
            )
            return f"Unable to update the citation for the ComplianceCow control: {control_id}. Please contact admin/support to fix this issue."

        if response.ok and response.status_code == http.HTTPStatus.NO_CONTENT:
            return ""
        else:
            print(
                f"Unable to update the citation for the ComplianceCow control: {control_id} : Status Code: {response.status_code}, Response: {response.text}"
            )
            return f"Unable to update the citation for the ComplianceCow control: {control_id}. Please contact admin/support to fix this issue."

    def delete_control_citation(self, assessment_id, control_id, citation_id) -> str:
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return error
        api_endpoint_url = self.build_api_url(self.DELETE_CITATION).format(
            assessment_id=assessment_id, control_id=control_id, citation_id=citation_id
        )
        headers = {"Authorization": auth_token}
        response, error = self.make_api_request(
            api_endpoint_url, headers=headers, method="DELETE"
        )

        if error:
            print(
                f"Unable to delete the citation for the ComplianceCow control{control_id} : {error}"
            )
            return f"Unable to delete the citation for the ComplianceCow control{control_id}. Please contact admin/support to fix this issue."

        if response.ok and response.status_code == http.HTTPStatus.NO_CONTENT:
            return ""
        else:
            print(
                f"Unable to delete the citation for the ComplianceCow control{control_id} : Status Code: {response.status_code}, Response: {response.text}"
            )
            return f"Unable to delete the citation for the ComplianceCow control{control_id}. Please contact admin/support to fix this issue."

    def trigger_workflow(self, workflow_event, input_obj) -> tuple[list[Any], str]:
        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return [], error
        api_endpoint_url = self.build_api_url("/v5/partner/workflows/trigger")
        headers = {"Authorization": auth_token}

        body = {"event": workflow_event, "input": input_obj}

        response, error = self.make_api_request(
            api_endpoint_url, headers=headers, method="POST", json=body
        )
        if error:
            return [], error

        if response.status_code == http.HTTPStatus.OK:
            try:
                response_data = response.json()
                return response_data["workflowInstanceIds"], ""
            except requests.exceptions.JSONDecodeError:
                return (
                    [],
                    f"Error while decoding response data :: Response: {response.text}",
                )
            except KeyError:
                return (
                    [],
                    f"Response does not have the 'workflowInstanceIds' field :: Response: {response.text}",
                )
        else:
            return (
                [],
                f"Error while triggering workflow :: Status Code: {response.status_code}, Response: {response.text}",
            )

    def trigger_workflow_v2(self, workflow_event: str, input_obj: Dict) -> Dict:
        auth_token, error = self.fetch_and_extract_auth_token()

        if error:
            cowutils.raise_unauthorised_error(
                message="UNAUTHORISED_ERROR", description=error, retryable=False
            )

        api_endpoint_url = self.build_api_url("/v5/partner/workflows/trigger")
        headers = {"Authorization": auth_token}

        body = {"event": workflow_event, "input": input_obj}
        return wsutils.post(path=api_endpoint_url, data=body, header=headers)
    
        
    def get_userdetails_with_slackhandle(self, user_email: str):
        if not user_email:
            return "", "User email is empty."

        auth_token, error = self.fetch_and_extract_auth_token()
        if error:
            return "", error
        
        query_params = {
            "search_name": user_email,
            "medium_id": "slack"
        }
        api_endpoint_url = self.build_api_url(endpoint=self.GET_SLACK_HANDLE)

        headers = {
            "Authorization": auth_token,  # already includes 'Bearer '
            "Content-Type": "application/json",
        }

        try:
            response = requests.get(url=api_endpoint_url, headers=headers, params=query_params)
        except requests.RequestException as e:
            return "", f"Request failed: {str(e)}"

        if response.ok and response.status_code == http.HTTPStatus.OK:
            try:
                data = response.json()
                return data, ""
            except json.JSONDecodeError:
                return "", f"Response is not valid JSON. Raw response: {response.text}"
            except ValueError:
                return "", f"Response is not valid JSON. Raw response: {response.text}"

        return "", f"Failed to fetch Slack user ID for {user_email}. Status Code: {response.status_code}, Response: {response.text}"
