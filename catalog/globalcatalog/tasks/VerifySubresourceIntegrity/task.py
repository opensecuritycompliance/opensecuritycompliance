from compliancecowcards.structs import cards
from appconnections.privacybisonconnector import privacybisonconnector
from compliancecowcards.utils import cowdictutils
import base64
import hashlib
import requests
from bs4 import BeautifulSoup
import pandas as pd
import urllib.parse
from datetime import datetime
import uuid


class Task(cards.AbstractTask):

    def execute(self) -> dict:

        error = self.check_inputs()
        if error:
            return self.upload_log_file_panic({'error': error})

        self.app = privacybisonconnector.PrivacyBisonConnector(
            app_url=self.task_inputs.user_object.app.application_url,
            app_port=self.task_inputs.user_object.app.application_port,
            user_defined_credentials=privacybisonconnector.UserDefinedCredentials.from_dict(
                self.task_inputs.user_object.app.user_defined_credentials)
        )

        harfile_name = self.task_inputs.user_inputs.get('HarFile')

        file_content, error = self.download_json_file_from_minio_as_dict(harfile_name)
        if error:
            return self.upload_log_file_panic({'error': f'Error while downloading HarFile :: {error}'})
        
        if not self.app.is_valid_har(file_content):
            return self.upload_log_file_panic({'error': 'HarFile is in an invalid format, please check'})
        
        company_name, _ = self.app.get_company_name_from_har_file(file_content)

        urisWithSriDetails = []

        entries = file_content["log"]["entries"]
        for entry in entries:
            entry_response_content = entry.get("response", {}).get("content")
            if not entry_response_content:
                continue
            if entry_response_content.get("mimeType") != "text/html" or not entry_response_content.get("text"):
                continue

            newUrisWithSriDetails, error = self.check_sri_integrity_for_html_content(
                base_url=entry.get("request", {}).get("url", ""),
                html_content=entry_response_content.get("text", "")
            )
            if error:
                return self.upload_log_file_panic({'error': error})

            system = urllib.parse.urlparse(entry.get("request", {}).get("url", "")).netloc
            for newUriWithSriDetails in newUrisWithSriDetails:
                newUriWithSriDetails["System"] = system
                newUriWithSriDetails["ResourceURL"] = entry.get("request", {}).get("url", "")

            urisWithSriDetails.extend(newUrisWithSriDetails)

        urisWithSriDetailsStandardized = []
        for uriWithSriDetails in urisWithSriDetails:
            url = uriWithSriDetails.get('URI')
            if not url:
                continue

            parsed_url = urllib.parse.urlparse(url)
            isValid = uriWithSriDetails.get("IsValidIntegrity", False)
            status_description = "Integrity matches with the generated hash"
            compliance_status = "COMPLIANT"
            status_code = "INTEGRITY_VALID"

            if not isValid:
                if uriWithSriDetails.get("Integrity"):
                    compliance_status = "NON_COMPLIANT"
                    status_code = "INTEGRITY_INVALID"
                    status_description = "Integrity does not match generated hash"
                else:
                    compliance_status = "NOT_DETERMINED"
                    if "Reason" in uriWithSriDetails and "Response error: " in uriWithSriDetails["Reason"]:
                        status_code = "RESPONSE_ERROR"
                        status_description = uriWithSriDetails["Reason"]

                    if not parsed_url.netloc or not parsed_url.scheme:
                        status_code = "INVALID_URL"
                        status_description = "URL is not valid"
                    else:
                        status_code = "INTEGRITY_NOT_FOUND"
                        status_description = "Integrity doesn't exist"
                        compliance_status = "NON_COMPLIANT"

            urisWithSriDetailsStandardized.append({
                # Meta
                "System": company_name,
                "Source": "compliancecow",

                # Resource info
                "ResourceID": url,
                "ResourceName": "N/A",
                "ResourceType": "Web Application",
                "ResourceURL": uriWithSriDetails["ResourceURL"],
                "ResourceLocation": "N/A",
                "ResourceTags": "N/A",

                # Data
                "Integrity": uriWithSriDetails["Integrity"] if uriWithSriDetails["Integrity"] else "N/A",
                "IsValidIntegrity": isValid,

                # Compliance details
                "ValidationStatusCode": status_code,
                "ValidationStatusNotes": status_description,
                "ComplianceStatus": compliance_status,
                "ComplianceStatusReason": status_description,
                "EvaluatedTime": uriWithSriDetails["EvaluatedTime"],

                # User editable data
                "UserAction":"",

                # Action editable data
                "ActionStatus":"",
                "ActionResponseURL":""
            })

        file_url, error = self.upload_df_as_json_file_to_minio(
            df=pd.DataFrame(urisWithSriDetailsStandardized),
            file_name=f"URIsWithSRIDetails",
        )

        if error:
            if error:
                return self.upload_log_file_panic({ 'error': error })

        compliancePCT, complianceStatus = self.app.get_compliance_status(
            compliant_count=len([item for item in urisWithSriDetailsStandardized if item["ComplianceStatus"] == "COMPLIANT"]),
            non_compliant_count=len([item for item in urisWithSriDetailsStandardized if item["ComplianceStatus"] == "NON_COMPLIANT"])
        )

        response = {
            "ComplianceStatus_": complianceStatus,
            "CompliancePCT_": round(compliancePCT, 2),
            "URIsWithSRIDetails": file_url,
        }

        return response

    
    
    def check_inputs(self):
        task_inputs = self.task_inputs
        if task_inputs is None:
            return 'Task inputs are missing'
        user_object = self.task_inputs.user_object
        if (
            user_object is None
            or user_object.app is None
            or user_object.app.application_url is None
            or user_object.app.user_defined_credentials is None
        ):
            return 'User defined credentials are missing"'
        if self.task_inputs.user_inputs is None:
            return 'User inputs are missing'
        if self.task_inputs.user_inputs.get("HarFile") is None or self.task_inputs.user_inputs.get("HarFile") == "<<MINIO_FILE_PATH>>":
            return 'HarFile is missing. Please upload a valid HarFile'
        return None
    
    # -------------------------------------------- CHECK Subresource Integrity for 1 request -------------------------------------------- 
    def check_sri_integrity_for_html_content(
        self,
        base_url,
        html_content
    ):
        urisWithSriDetails = []

        parsed_html = BeautifulSoup(html_content, features="html.parser")
        link_elements = parsed_html.find_all("link")
        link_elements += parsed_html.find_all("script")
        for element in link_elements:
            attribute = None
    
            if "href" in element.attrs:
                attribute = "href"
            elif "src" in element.attrs:
                attribute = "src"
            else:
                continue

            if "integrity" not in element.attrs:
                urisWithSriDetails.append({
                    "URI": element[attribute],
                    "Integrity": None,
                    "IsValidIntegrity": False,
                    "EvaluatedTime": self.get_current_datetime()
                })
                continue

            uriWithSriDetails = self.check_sri_integrity(
                integrity=element["integrity"],
                base_url=base_url,
                link=element[attribute]
            )
            
            urisWithSriDetails.append(uriWithSriDetails)

        return urisWithSriDetails, None
    
    # -------------------------------------------- CHECK SRI INTEGRITY FOR A LINK --------------------------------------------
    def check_sri_integrity(self, integrity: str, base_url: str, link: str):
        isValid = True
        proper_link, error = self.get_proper_url(base_url, link)
        if error:
            uriWithSriDetails = {
                "URI": proper_link,
                "Integrity": integrity,
                "IsValidIntegrity": isValid,
                "Reason": "Link is invalid",
                "EvaluatedTime": self.get_current_datetime()
            }
            return uriWithSriDetails
        
        response = requests.get(proper_link)

        if not response.ok:
            uriWithSriDetails = {
                "URI": proper_link,
                "Integrity": integrity,
                "IsValidIntegrity": False,
                "Reason": f"Response error: {response.text}",
                "EvaluatedTime": self.get_current_datetime()
            }

        integrities = integrity.split(" ")

        for single_integrity in integrities:
            [algorithm, integrity_hash] = single_integrity.split("-")
            if not self.get_sri_hash(algorithm, response.content) in integrity_hash:
                isValid = False

        uriWithSriDetails = {
            "URI": proper_link,
            "Integrity": integrity,
            "IsValidIntegrity": isValid,
            "EvaluatedTime": self.get_current_datetime()
        }
    
        return uriWithSriDetails
    
    # -------------------------------------------- GET SRI HASH VALUE --------------------------------------------
    def get_sri_hash(self, algorithm, content):
        hash = None
        # sha256
        if algorithm == "sha256":
            hash = hashlib.sha256(content).digest()
        # sha384
        elif algorithm == "sha384":
            hash = hashlib.sha384(content).digest()
        # sha512
        elif algorithm == "sha512":
            hash = hashlib.sha512(content).digest()
        else:
            print("Invalid algorithm!")
            return None
        
        base64_hash = base64.b64encode(hash).decode('utf-8')

        return base64_hash
    
    def get_proper_url(self, base_url: str, link: str):
        parsed_link = urllib.parse.urlparse(link)
        proper_link = parsed_link.geturl()
        error = None
        if not parsed_link.netloc and not parsed_link.scheme:
            proper_link = urllib.parse.urljoin(base_url, link)
            parsed_link = urllib.parse.urlparse(proper_link)
        
        if not parsed_link.scheme:
            proper_link = f"https://{link}"
            parsed_link = urllib.parse.urlparse(proper_link)

        if not parsed_link.netloc:
            error = "No domain found in url!"

        return proper_link, error
    
    def get_headers_dict_from_list(self, headers: list):
        headers_dict = {}
        invalid_characters = ['\n', '\r', '\t', ':']  # Reserved characters and return characters
        for header in headers:
            if not any(char in invalid_characters for char in header["name"]):
                headers_dict[header["name"]] = header["value"]
        
        return headers_dict
    
    def upload_log_file(self, error_data):
        if not isinstance(error_data, list):
            error_data = [error_data]
        file_url, error = self.upload_df_as_json_file_to_minio(
            df=pd.DataFrame(error_data),
            file_name=f"LogFile",
        )
        if error:
            return None, {'error': f"Error while uploading LogFile :: {error}"}
        return file_url, None
    
    def upload_log_file_panic(self, error_data) -> dict:
        file_url, error = self.upload_log_file(error_data)
        if error:
            return error
        return { 'LogFile': file_url }
    
    def get_current_datetime(self):
        current_time = datetime.utcnow()
        formatted_time = current_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        return formatted_time