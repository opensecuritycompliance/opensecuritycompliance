from typing import Tuple
from datetime import datetime, timezone
import urllib.parse



class NoCred:
    dummy: str

    def __init__(self, dummy: str) -> None:
        self.dummy = dummy

    @staticmethod
    def from_dict(obj) -> 'NoCred':
        dummy = ""
        if isinstance(obj, dict):
            dummy = obj.get("Dummy", "")

        return NoCred(dummy)

    def to_dict(self) -> dict:
        result: dict = {}
        result["Dummy"] = self.dummy
        return result

    def validate_attributes(self) -> str:
        emptyAttrs = []
        return "Invalid Credentials: " + ", ".join(
            emptyAttrs) + " is empty" if emptyAttrs else ""


class UserDefinedCredentials:
    no_cred: NoCred

    def __init__(self, no_cred: NoCred) -> None:
        self.no_cred = no_cred

    @staticmethod
    def from_dict(obj) -> 'UserDefinedCredentials':
        no_cred = None
        if isinstance(obj, dict):
            no_cred = NoCred.from_dict(obj.get("NoCred", None))
        return UserDefinedCredentials(no_cred)

    def to_dict(self) -> dict:
        result: dict = {}
        result["NoCred"] = self.no_cred.to_dict()
        return result


class PrivacyBisonConnector:
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
    def from_dict(obj) -> 'PrivacyBisonConnector':
        app_url, app_port, user_defined_credentials, linked_applications = "", "", None, None
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

        return PrivacyBisonConnector(app_url, app_port,
                                     user_defined_credentials)

    def to_dict(self) -> dict:
        result: dict = {}
        result["AppURL"] = self.app_url
        result["AppPort"] = self.app_port
        result[
            "UserDefinedCredentials"] = self.user_defined_credentials.to_dict(
            )

        return result

    def validate(self) -> bool and dict:
        # PLACE-HOLDER
        return True, None
    
    def get_compliance_status(self, compliant_count = 0, non_compliant_count = 0):
        total_count = compliant_count + non_compliant_count
        if not non_compliant_count == 0:
            complianceStatus = "NON_COMPLIANT"
            compliancePCT = 100 - ((non_compliant_count * 100) / total_count)
        elif total_count == 0:
            complianceStatus = "NOT_DETERMINED"
            compliancePCT = 0
        else:
            complianceStatus = "COMPLIANT"
            compliancePCT = 100

        return compliancePCT, complianceStatus
    
    def replace_empty_dicts_with_none(self, json_obj):
        if isinstance(json_obj, dict):
            for key, value in json_obj.items():
                if isinstance(value, dict):
                    if not value:
                        json_obj[key] = None
                    else:
                        self.replace_empty_dicts_with_none(value)
                elif isinstance(value, list):
                    if not value:
                        json_obj[key] = None
                    for item in value:
                        self.replace_empty_dicts_with_none(item)
        elif isinstance(json_obj, list):
            for item in json_obj:
                self.replace_empty_dicts_with_none(item)
        return json_obj
    
    def is_valid_har(self, har_data: dict) -> bool:
        if 'log' not in har_data:
            return False
        
        har_log = har_data['log']
        for key in ['version', 'creator', 'entries']:
            if key not in har_log:
                return False
            
        if not har_log['entries']:
            return False
        
        return True

    def get_company_name_from_har_file(self, har_data: dict) -> Tuple[str, Exception]:
        if not self.is_valid_har(har_data):
            return "", Exception('HarFile is in an invalid format, please check')

        found_name = False
        referer = ""
        origin = ""
        parser_referer = ""
        
        for entry in har_data["log"]["entries"]:
            if entry["_initiator"]["type"] == "other":
                for header in entry["request"]["headers"]:
                    header_name = header["name"].lower()
                    if header_name == "origin":
                        found_name = True
                        origin = header["value"]
                        break
                    if header_name == "referer":
                        referer = header["value"]
                if found_name:
                    break
                
            elif entry["_initiator"]["type"] == "parser" and parser_referer=="" :
                for header in entry["request"]["headers"]:
                    header_name = header["name"].lower()
                    if header_name == "referer":
                        parser_referer = header["value"]
                
                
        
        site_url = origin if origin else referer
        
        if site_url =="" and parser_referer !="" :
            site_url = parser_referer

        if site_url:
            try:
                parsed_url = urllib.parse.urlparse(site_url)
                host = parsed_url.netloc
                host = host.replace("www.", "")
                return host, None
            except ValueError as ve:
                return "", Exception(f"Invalid URL structure - {ve}")
            except Exception as e:
                site_url = site_url.replace("http://", "").replace("https://", "").replace("www.", "")
                return site_url, None
        else:
            return "", None

    def get_current_datetime(self):       
        current_time = datetime.now(timezone.utc)
        formatted_time = current_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        return formatted_time        

# INFO : You can implement methods (to access the application) which can be then invoked from your task code
