from typing import Tuple
from typing import overload
from compliancecowcards.structs import cards
from compliancecowcards.utils import cowdictutils
import pandas as pd

logger = (
    cards.Logger()
)  # Initializes a Logger instance to log data, use logger.log_data(dict) to log a data


class Task(cards.AbstractTask):

    def execute(self) -> dict:
        """
        Execute the task to validates input JSON files based on specified required fields and checks for
        missing or duplicate records.
        """

        self.prev_log_data: list = []
        prev_log_file_url = ""
        input_file_url = ""
        if cowdictutils.is_valid_key(self.task_inputs.user_inputs, "LogFile"):
            prev_log_file_url = self.task_inputs.user_inputs["LogFile"]
        if cowdictutils.is_valid_key(self.task_inputs.user_inputs, "InputFile"):
            input_file_url = self.task_inputs.user_inputs["InputFile"]

        if prev_log_file_url and not input_file_url:
            return {"LogFile": prev_log_file_url}

        if prev_log_file_url and input_file_url:
            self.prev_log_data, error = self.download_json_file_from_minio_as_dict(
                prev_log_file_url
            )
            if error:
                return error

        if not input_file_url:
            return self.upload_log_file(
                [{"Error": "InputFile is missing in user inputs."}]
            )
        if not str(input_file_url).endswith(".json"):
            return self.upload_log_file(
                [
                    {
                        "Error": f" InputFile must be a JSON file, got file with '{str(input_file_url).split('.')[-1]}' extension instead"
                    }
                ]
            )

        data_list, error = self.download_json_file_from_minio_as_dict(input_file_url)
        if error:
            return self.upload_log_file(
                [{"Error": f"Error while downloading InputFile :: {error}"}]
            )
        if not data_list:
            return self.upload_log_file(
                [{"Error": "InputFile is empty, please check."}]
            )

        input_field = self.task_inputs.user_inputs.get("RequiredFields")

        if not input_field:
            return self.upload_log_file(
                [{"Error": "InputField is empty. No fields specified for validation."}]
            )

        missing_records = []
        duplicate_records = []
        existing_values = {}

        for index, obj in enumerate(data_list, start=1):
            missing_fields = list(set(input_field) - set(obj.keys()))
            if missing_fields:
                missing_records.append(
                    f"Missing field(s) in Record {index}: {', '.join(missing_fields)}"
                )

            key = tuple(map(obj.get, input_field))
            if key in existing_values:
                duplicate_records.append(
                    f"Duplicate record found at Record {index} (same as Record {existing_values[key]}): {', '.join(map(str, key))}"
                )
            else:
                existing_values[key] = index

        error_data = []

        if missing_records:
            error_data.append({
                "Error": (
                    f"Required Fields: {', '.join(input_field)}.\\n"
                    f"Following records Required fields are missing:\\n"
                    + "\\n".join(missing_records)
                )}
            )

        if duplicate_records:
            error_data.append(
                {"Error": "Duplicate records found:\n" + "\n".join(duplicate_records)}
            )

        if error_data:
            return self.upload_log_file(error_data)

        return {"ValidDataFile": input_file_url}

    def upload_log_file(self, error_data: list | dict) -> dict:
        """
        Uploads a log file containing error data to the Minio.

        Parameters:
        - error_data (list | dict): The error data to be uploaded, which can be either a list or a dictionary.
        Returns:
        - dict: A dictionary containing information about the upload process or any relevant data.
        """
        if not isinstance(error_data, list):
            error_data = [error_data]

        self.prev_log_data.extend(error_data)

        file_url, error = self.upload_df_as_json_file_to_minio(
            df=pd.DataFrame(self.prev_log_data), file_name="LogFile"
        )
        if error:
            return {"Error": f"Error while uploading LogFile:: {error}"}
        return {"LogFile": file_url}
