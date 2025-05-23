import csv
import datetime
from io import StringIO
import json
import logging
from typing import List
import pandas as pd
from compliancecowcards.structs import cards
import urllib.parse
from applicationtypes.privacybisonconnector import privacybisonconnector
import uuid


class CookieLog:
    def __init__(self, System: str, Source: str, ResourceId: str, ResourceName: str, ResourceType: str, name: str, path: str, domain: str, created_at: str, secure: bool, http_only: bool, classification: str, sub_classification: str, description: str, ComplianceStatus: str, ComplianceReason: str, ValidationCode: str, ValidationNotes: str,  UserAction: str, ActionStatus: str, ActionResponseURL: str):
        self.System = System
        self.Source = Source
        self.ResourceId = ResourceId
        self.ResourceName = ResourceName
        self.ResourceType = ResourceType
        self.CookieName = name
        self.Path = path
        self.Domain = domain
        self.CreatedAt = created_at
        self.Secure = secure
        self.HttpOnly = http_only
        self.Classification = classification
        self.SubClassification = sub_classification
        self.Description = description
        self.ComplianceStatus = ComplianceStatus
        self.ComplianceReason = ComplianceReason
        self.ValidationCode = ValidationCode
        self.ValidationNotes = ValidationNotes
        self.UserAction = UserAction
        self.ActionStatus = ActionStatus
        self.ActionResponseURL = ActionResponseURL

def update_status(row):
    validation_code = ""
    compliance_reason = ""
    validation_notes = ""

    if row['HttpOnly'] and row['Secure'] and row['Classification'] != 'ThirdParty':
        compliance_status = "COMPLIANT"
        compliance_reason = "The record is compliant because it adheres to security best practices by having the HttpOnly and Secure attributes set to true and not being classified as a third-party cookie"
        validation_code = "HTTP_ONLY_SECURE_NON_THIRD_PARTY"
        validation_notes = "Record is compliant due to being HTTP only, secure, and not classified as third-party."
    elif not row['HttpOnly'] and row['Secure'] and row['Classification'] != 'ThirdParty':
        compliance_status = "NON_COMPLIANT"
        compliance_reason = "The record is non-compliant because the HttpOnly attribute is set to false"
        validation_code = "NOT_HTTP_ONLY_SECURE_NON_THIRD_PARTY"
        validation_notes = "Record is non-compliant because it is not HTTP only, although it is secure and not classified as third-party."
    elif row['HttpOnly'] and not row['Secure'] and row['Classification'] != 'ThirdParty':
        compliance_status = "NON_COMPLIANT"
        compliance_reason = "The record is non-compliant because the Secure attribute is set to false"
        validation_code = "HTTP_ONLY_NOT_SECURE_NON_THIRD_PARTY"
        validation_notes = "Record is non-compliant because it is HTTP only but not secure, and not classified as third-party."
    elif row['HttpOnly'] and row['Secure'] and row['Classification'] == 'ThirdParty':
        compliance_status = "NON_COMPLIANT"
        compliance_reason = "The record is non-compliant because the cookie is classified as a third-party cookie"
        validation_code = "HTTP_ONLY_SECURE_THIRD_PARTY"
        validation_notes = "Record is non-compliant because it is classified as third-party, although it is HTTP only and secure."
    elif not row['HttpOnly'] and not row['Secure'] and row['Classification'] != 'ThirdParty':
        compliance_status = "NON_COMPLIANT"
        compliance_reason = "The record is non-compliant because the HttpOnly and Secure attributes are set to false"
        validation_code = "NOT_HTTP_ONLY_NOT_SECURE_NON_THIRD_PARTY"
        validation_notes = "Record is non-compliant because it is neither HTTP only nor secure, and not classified as third-party."
    elif not row['HttpOnly'] and row['Secure'] and row['Classification'] == 'ThirdParty':
        compliance_status = "NON_COMPLIANT"
        compliance_reason = "The record is non-compliant because the HttpOnly attribute is set to false and the cookie is also classified as a third-party cookie"
        validation_code = "NOT_HTTP_ONLY_SECURE_THIRD_PARTY"
        validation_notes = "Record is non-compliant because it is not HTTP only and classified as third-party, although it is secure."
    elif row['HttpOnly'] and not row['Secure'] and row['Classification'] == 'ThirdParty':
        compliance_status = "NON_COMPLIANT"
        compliance_reason = "The record is non-compliant because the Secure attribute is set to false and the cookie is also classified as a third-party cookie"
        validation_code = "HTTP_ONLY_NOT_SECURE_THIRD_PARTY"
        validation_notes = "Record is non-compliant because it is classified as third-party and not secure, although it is HTTP only."
    elif not row['HttpOnly'] and not row['Secure'] and row['Classification'] == 'ThirdParty':
        compliance_status = "NON_COMPLIANT"
        compliance_reason = "The record is non-compliant because the HttpOnly and Secure attributes are set to false and the cookie is also classified as a third-party cookie"
        validation_code = "NOT_HTTP_ONLY_NOT_SECURE_THIRD_PARTY"
        validation_notes = "Record is non-compliant because it is neither HTTP only nor secure, and classified as third-party." 
    return pd.Series([compliance_status, compliance_reason, validation_code,  validation_notes])

class Task(cards.AbstractTask):
    def execute(self) -> dict:

        privacybison = privacybisonconnector.PrivacyBisonConnector(user_defined_credentials=privacybisonconnector.UserDefinedCredentials.from_dict(
            self.task_inputs.user_object.app.user_defined_credentials))
        har_file_url = self.task_inputs.user_inputs.get("HarFile")
        cookie_db_file_url = self.task_inputs.user_inputs.get("CookieDBFile")

        error = None
        src_file_names = []

        if not har_file_url:
            error = "HAR file URL is not provided"
            log_url, log_error = self.upload_log_file([{ 'error': error }])
            if log_error:
                return {"error": log_error}
            return {"LogFile": log_url}
        else:
            try:
               if har_file_url:
                    har_file_bytes, error = self.download_file_from_minio(file_url=har_file_url)
                    if not error:
                        src_file_names.append(har_file_bytes)
                    else:
                        raise Exception(error)
            except Exception as e:
                error = f"Error downloading HAR file: {str(e)}"
                log_url, log_error = self.upload_log_file([{ 'error': error }])
                if log_error:
                    return {"error": log_error}
                return {"LogFile": log_url}

        rows = []
        try:
            if cookie_db_file_url:
                cookiedb_file_bytes, error = self.download_file_from_minio(file_url=cookie_db_file_url)
                if not error:
                    rows = self.read_csv_file(cookiedb_file_bytes)
                else:
                    raise Exception(error)
        except Exception as e:
            error = f"Error downloading CSV DB file: {str(e)}"
            log_url, log_error = self.upload_log_file([{ 'error': error }])
            if log_error:
                return {"error": log_error}
            return {"LogFile": log_url}

        cookie_report = []
        total = 0
        string_data = har_file_bytes.decode('utf-8')
        har_file_data = json.loads(string_data)
        domain, error = privacybison.get_company_name_from_har_file(har_file_data)
        if error:
            return self.upload_log_file([{'Error': f'{error}'}])

        for src_file_bytes in src_file_names:
            file_details = self.process_logs(src_file_bytes, rows, domain)
            cookie_report += file_details["cookie_report"]
            total += file_details["total"]

        cookie_df = pd.DataFrame(cookie_report)
        cookie_df = cookie_df.apply(privacybison.replace_empty_dicts_with_none)
        
        file_name = f'HARCookieReport-{str(uuid.uuid4())}.json'
        absolute_file_path, error = self.upload_file_to_minio(file_content=cookie_df.to_json(orient='records').encode('utf-8'), file_name=file_name, content_type="application/json")
        if error:
            log_url, log_error = self.upload_log_file([{'error': f"Error uploading file to Minio: {error}"}])
            if log_error:
                return {"error": log_error}
            return {"LogFile": log_url} 

        response = {
            "HARCookieReport": absolute_file_path
        }
        return response

    def process_logs(self, src_file_bytes, rows, domain):  
        input_payload = src_file_bytes.decode('utf-8')
        if input_payload:
            try:
                file_details = json.loads(input_payload)
            except json.JSONDecodeError as e:
                logging.error(f"Error decoding JSON: {e}")
                return {"cookie_report": [], "compliant": 0, "noncompliant": 0, "total": 0}
        else:
            logging.error("Empty input payload")
            return {"cookie_report": [], "compliant": 0, "noncompliant": 0, "total": 0}

        logs = file_details.get("log", {}).get("entries", [])

        if not logs:
            logging.warning("No log entries found")
            return {"cookie_report": [], "compliant": 0, "noncompliant": 0, "total": 0}

        cookie_report = []

        for entry in logs:
            request = entry.get("request", {})
            headers = request.get("headers", [])
            base_path = ""
            for header in headers:
                if header["name"].lower() in ["origin", "referer", "host"]:
                    base_path = header["value"]
                    break

            u = urllib.parse.urlparse(base_path)

            cookies = []
            request = entry.get("request", {})
            response = entry.get("response", {})
            url = request.get("url", "")
            cookies_interface_response = response.get("cookies", [])
            cookies_interface_request = request.get("cookies", [])

            for cookie in cookies_interface_response:
                cookies.append((cookie, url))
            for cookie in cookies_interface_request:
                cookies.append((cookie, url))

            for cookie, org_url in cookies:
                parsed_url = urllib.parse.urlparse(org_url)
                site_domain = parsed_url.hostname
                temp_cookie = {
                    "System": domain,
                    "Source": "compliancecow",
                    "ResourceID": org_url,
                    "ResourceName": "N/A",
                    "ResourceType": "Cookie",
                    "CookieName": cookie.get("name", ""),
                    "Path": cookie.get("path", ""),
                    "Domain": cookie.get("domain", ""),
                    "CreatedAt": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "Secure": cookie.get("secure", False),
                    "HttpOnly": cookie.get("httpOnly", False),
                    "Classification": "",
                    "SubClassification": "",
                    "Description": "",
                    "ComplianceStatus": "",
                    "ComplianceReason": "",
                    "ValidationCode": "",
                    "ValidationNotes": "",
                    "UserAction": "",
                    "ActionStatus": "",
                    "ActionResponseURL": ""
                }
                domain_lower = temp_cookie.get("Domain", "").lower()
                if self.is_first_party(site_domain, domain_lower):
                    temp_cookie["Classification"] = "FirstParty"
                else:
                    temp_cookie["Classification"] = "ThirdParty"

                cookiepresentindb = False
                for row in rows:
                    if row[0] == temp_cookie.get("CookieName"):
                        cookiepresentindb = True
                        temp_cookie["SubClassification"] = row[2]
                        temp_cookie["Description"] = {
                            "StrictlyNecessary": "These cookies are essential in order to enable you to move around the website and use its features, such as accessing secure areas of the website. Without these cookies services you have asked for, like shopping baskets or e-billing, cannot be provided.",
                            "Functionality": "These cookies allow the website to remember choices you make (such as your user name, language or the region you are in) and provide enhanced, more personal features. For instance, a website may be able to provide you with local weather reports or traffic news by storing in a cookie the region in which you are currently located. These cookies can also be used to remember changes you have made to text size, fonts and other parts of web pages that you can customise. They may also be used to provide services you have asked for such as watching a video or commenting on a blog. The information these cookies collect may be anonymised and they cannot track your browsing activity on other websites.",
                            "Performance": "These cookies collect information about how visitors use a website, for instance which pages visitors go to most often, and if they get error messages from web pages. These cookies don't collect information that identifies a visitor. All information these cookies collect is aggregated and therefore anonymous. It is only used to improve how a website works.",
                            "Marketing": "These cookies are used to deliver adverts more relevant to you and your interests. They are also used to limit the number of times you see an advertisement as well as help measure the effectiveness of the advertising campaign. They are usually placed by advertising networks with the website operator's permission. They remember that you have visited a website and this information is shared with other organisations such as advertisers. Quite often targeting or advertising cookies will be linked to site functionality provided by the other organisation.",
                            "Unknown": "These are unknown at the moment and needs manual intervention"
                        }.get(temp_cookie["SubClassification"], "Unknown")

                if not cookiepresentindb:
                    temp_cookie["SubClassification"] = "Cookie data not in database"
                    temp_cookie["Description"] = "Cookie details are not present in the cookie database."

                cookie_report.append(temp_cookie)

        df = pd.DataFrame(cookie_report)
        
        if df.empty :
            logging.warning("No log entries found")
            return {"cookie_report": [], "compliant": 0, "noncompliant": 0, "total": 0}
        df[['ComplianceStatus', 'ComplianceReason','ValidationCode', 'ValidationNotes']] = df.apply(update_status, axis=1)
        updated_cookie_report = df.to_dict(orient='records')
        return {
            "cookie_report": updated_cookie_report,
            "compliant": df[df['ComplianceStatus'] == 'COMPLIANT'].shape[0],
            "noncompliant": df[df['ComplianceStatus'] == 'NON_COMPLIANT'].shape[0],
            "total": df.shape[0]
        }

    def read_file(self, file_bytes) -> List[List[str]]:
        input_payload = file_bytes.decode('utf-8')
        rows = [row for row in csv.reader(input_payload.splitlines())]
        return rows
    
    def upload_log_file(self, error_data):
        if not isinstance(error_data, list):
            error_data = [error_data]
        file_url, error = self.upload_file_to_minio(
            file_content=error_data,
            file_name=f"LogFile-{str(uuid.uuid4())}.json",
            content_type="application/json"
        )
        if error:
            return None, {'error': f"Error while uploading LogFile :: {error}"}
        return file_url, None

    def read_csv_file(self, file_bytes):
        input_payload = file_bytes.decode('utf-8')
        if input_payload:
            df = pd.read_csv(StringIO(input_payload))
            return df.values.tolist()
        else:
            error_msg = "The uploaded CookieDBFile is empty. Please make sure to upload a non-empty CookieDBFile and provide the CookieDBFile."
            logging.error(error_msg)
            return []
        
    def is_first_party(self, site_domain, cookie_domain):
        site_domain = site_domain.lstrip('.').lower()
        cookie_domain = cookie_domain.lstrip('.').lower()
        
        site_parts = site_domain.split('.')
        cookie_parts = cookie_domain.split('.')
        
        if site_parts[-len(cookie_parts):] == cookie_parts:
            return True
        return False