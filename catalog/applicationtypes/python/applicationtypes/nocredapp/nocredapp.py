import json
from typing import List
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Tuple, Optional


class NoCred:
    dummy: str

    def __init__(self, dummy: str) -> None:
        self.dummy = dummy

    @staticmethod
    def from_dict(obj) -> "NoCred":
        dummy = ""
        if isinstance(obj, dict):
            dummy = obj.get("Dummy", "")

        return NoCred(dummy)

    def to_dict(self) -> dict:
        result: dict = {}
        result["Dummy"] = self.dummy
        return result


class UserDefinedCredentials:
    no_cred: NoCred

    def __init__(self, no_cred: NoCred) -> None:
        self.no_cred = no_cred

    @staticmethod
    def from_dict(obj) -> "UserDefinedCredentials":
        no_cred = None
        if isinstance(obj, dict):
            no_cred = NoCred.from_dict(obj.get("NoCred", None))
        return UserDefinedCredentials(no_cred)

    def to_dict(self) -> dict:
        result: dict = {}
        result["NoCred"] = self.no_cred.to_dict()
        return result


class NoCredApp:
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
    def from_dict(obj) -> "NoCredApp":
        app_url, app_port, user_defined_credentials = "", "", None
        if isinstance(obj, dict):
            app_url = obj.get("AppURL", "")
            if not app_url:
                app_url = obj.get("appURL", "")
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

        return NoCredApp(app_url, app_port, user_defined_credentials)

    def to_dict(self) -> dict:
        result: dict = {}
        result["AppURL"] = self.app_url
        result["AppPort"] = self.app_port
        result["UserDefinedCredentials"] = self.user_defined_credentials.to_dict()
        return result

    def validate(self) -> bool and dict:
        # PLACE-HOLDER
        return True, None

    def validate_input_file_config(
        self, data_list: List[Dict], config: Dict
    ) -> Tuple[Optional[List[Dict]], Optional[Dict]]:
        """
        The function `validate_input_file_config` checks for missing required fields in a list of data
        records and removes duplicates based on specified configuration.
        """

        required_fields = set(config.get("RequiredFields", []))
        remove_duplicates = config.get("RemoveDuplicates", False)
        file_name = config.get("FileName", "user inputs")

        existing_values = set()
        unique_data = []
        missing_records = []

        data_list = data_list if isinstance(data_list, list) else [data_list]

        for index, obj in enumerate(data_list, start=1):
            missing = required_fields - obj.keys()
            if missing:
                missing_records.append(
                    f"Missing field(s) in Record {index}: {', '.join(missing)}"
                )
                continue

            if remove_duplicates:
                key = tuple(map(obj.get, required_fields))
                if key not in existing_values:
                    existing_values.add(key)
                    unique_data.append(obj)
            else:
                unique_data.append(obj)

        if missing_records:
            return None, {
                "Error": (
                    f"Missing the following required fields from {file_name}:\n"
                    + "\n".join(missing_records)
                )
            }

        return unique_data, None
