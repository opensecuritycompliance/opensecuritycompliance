from typing import overload
import uuid
from compliancecowcards.structs import cards
from applicationtypes.nocredapp import nocredapp
from compliancecowcards.utils import cowdictutils
import pandas as pd
import json
import jq

logger = (
    cards.Logger()
)  # Initializes a Logger instance to log data, use logger.log_data(dict) to log a data


class Task(cards.AbstractTask):

    def execute(self) -> dict:

        response = {}
        self.previous_log_data = []
        previous_log_file_url = ""
        data_file_url = ""
        output_file_name = ""

        if cowdictutils.is_valid_key(self.task_inputs.user_inputs, "LogFile"):
            previous_log_file_url = self.task_inputs.user_inputs["LogFile"]
        if cowdictutils.is_valid_key(self.task_inputs.user_inputs, "InputFile"):
            data_file_url = self.task_inputs.user_inputs["InputFile"]
        if cowdictutils.is_valid_key(
            self.task_inputs.user_inputs, "ColumnSelectorExpression"
        ):
            column_jq_expression = self.task_inputs.user_inputs[
                "ColumnSelectorExpression"
            ]
        if cowdictutils.is_valid_key(self.task_inputs.user_inputs, "RowDataExpression"):
            row_jq_expression = self.task_inputs.user_inputs["RowDataExpression"]
        if cowdictutils.is_valid_key(self.task_inputs.user_inputs, "OutputFileName"):
            output_file_name = self.task_inputs.user_inputs["OutputFileName"]

        if previous_log_file_url and not data_file_url:
            return {"LogFile": previous_log_file_url}

        if previous_log_file_url and data_file_url:
            self.previous_log_data, error = self.download_json_file_from_minio_as_dict(
                previous_log_file_url
            )
            if error:
                return self.upload_log_file(
                    {"Error": f"Error while downloading LogFile :: {error}"}
                )

        if not data_file_url:
            return self.upload_log_file(
                {"Error": "InputFile is missing in user inputs."}
            )
        if not str(data_file_url).endswith(".json"):
            return self.upload_log_file(
                {
                    "Error": f"InputFile must be a JSON file, got file with '{str(data_file_url).split('.')[-1]}' extension instead."
                }
            )

        data_file_dict, error = self.download_json_file_from_minio_as_dict(
            data_file_url
        )
        if error:
            return self.upload_log_file(
                {"Error": f"Error while downloading InputFile :: {error}"}
            )

        if not column_jq_expression or not isinstance(column_jq_expression, str):
            return self.upload_log_file(
                {
                    "Error": "Invalid ColumnSelectorExpression provided. It must be a non-empty string."
                }
            )

        if not row_jq_expression or not isinstance(row_jq_expression, str):
            return self.upload_log_file(
                {
                    "Error": "Invalid RowDataExpression provided. It must be a non-empty string."
                }
            )

        formatted_df, error = self.format_response(
            data_file_dict, column_jq_expression, row_jq_expression
        )
        if error:
            return self.upload_log_file(error)

        file_name = "OutputFile"
        if output_file_name:
            file_name = output_file_name

        if formatted_df is not None:
            output_file_url, error = self.upload_df_as_json_file_to_minio(
                df=formatted_df, file_name=file_name
            )
            if error:
                return {"Error": f"Error while uploading {file_name} file :: {error}"}
            response["OutputFile"] = output_file_url
        if previous_log_file_url:
            response["LogFile"] = previous_log_file_url

        return response

    def format_response(
        self, response: dict | list, jq_columns: str, jq_rows: str
    ) -> tuple[pd.DataFrame | None, dict | None]:
        try:
            formatted_output = []

            if not isinstance(response, list):
                response = [response]

            if not response:
                raise ValueError("The response is empty.")

            for item in response:
                if not isinstance(item, dict):
                    raise TypeError("Each item in the response must be a dictionary.")

                columns = jq.compile(jq_columns).input(item).all()
                rows = jq.compile(jq_rows).input(item).all()

                if not columns or columns == [None]:
                    raise KeyError(
                        f"Could not find columns with jq query '{jq_columns}'."
                    )
                if not rows or rows == [None]:
                    raise KeyError(f"Could not find rows with jq query '{jq_rows}'.")

                if not isinstance(columns[0], list):
                    raise TypeError(
                        f"Expected columns to be a list, but got {type(columns[0])}."
                    )
                if not isinstance(rows[0], list):
                    raise TypeError(
                        f"Expected rows to be a list, but got {type(rows[0])}."
                    )

                column_names = [col.get("name") for col in columns[0]]
                if not column_names:
                    raise ValueError(
                        f"No valid column names found in the columns data."
                    )

                formatted_df = pd.DataFrame(rows[0], columns=column_names)

                formatted_df = formatted_df.applymap(self.parse_json)

                for col in formatted_df.columns:
                    non_null_values = formatted_df[col].dropna()
                    if not pd.api.types.is_numeric_dtype(non_null_values):
                        formatted_df[col] = formatted_df[col].fillna("N/A")

                formatted_output.append(formatted_df)

            combined_df = pd.concat(formatted_output, ignore_index=True)

            if combined_df.empty:
                raise ValueError(
                    f"No output was generated for the provided input file, column expression ({jq_columns}), and row expression ({jq_rows})."
                )

            return combined_df, None

        except json.JSONDecodeError as e:
            return None, {"Error": f"A JSON decode error occurred :: {str(e)}."}
        except ValueError as e:
            return None, {"Error": f"A value error occurred :: {str(e)}."}
        except TypeError as e:
            return None, {"Error": f"A type error occurred :: {str(e)}."}
        except KeyError as e:
            return None, {"Error": f"A key error occurred :: {str(e)}."}
        except IndexError as e:
            return None, {"Error": f"An index error occurred :: {str(e)}."}

    def parse_json(self, value):
        if isinstance(value, str):
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return value
        return value

    def upload_log_file(self, error_data: list | dict) -> dict:
        if not isinstance(error_data, list):
            error_data = [error_data]
        file_name = f"LogFile-{str(uuid.uuid4())}.json"

        if self.previous_log_data is None:
            self.previous_log_data = []

        self.previous_log_data.extend(error_data)

        file_url, error = self.upload_df_as_json_file_to_minio(
            df=pd.DataFrame(self.previous_log_data), file_name=file_name
        )
        if error:
            return {"Error": f"Error while uploading LogFile:: {error}"}
        return {"LogFile": file_url}