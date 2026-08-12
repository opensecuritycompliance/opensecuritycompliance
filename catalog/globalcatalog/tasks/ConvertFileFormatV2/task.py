from typing import Dict, List, Optional, Tuple, Any
import json
import ast
import uuid
from compliancecowcards.structs import cards
from compliancecowcards.utils import cowdfutils, cowutils, cowparserutils
import numpy as np
import pandas as pd
import toml
import yaml
import xmltodict
from io import BytesIO
from abc import ABC, abstractmethod
from pathlib import Path
import pyarrow
import pyarrow.parquet as pq
from io import BytesIO

logger = cards.Logger()

MINIO_PLACEHOLDER = "<<MINIO_FILE_PATH>>"


class FileParser(ABC):
    """Abstract base class for parsing file content."""

    @abstractmethod
    def parse(
        self, file_bytes: bytes
    ) -> Tuple[Any, Optional[str], Optional[Dict[str, Any]]]:
        """Parse file bytes into a Python object."""
        pass


class JSONParser(FileParser):
    def parse(
        self, file_bytes: bytes
    ) -> Tuple[Any, Optional[str], Optional[Dict[str, Any]]]:
        parsed_data, error = cowparserutils.json_parse(file_bytes)
        if error:
            return (
                None,
                "ConvertFileFormat.Exception.InputFile.Parser.json_parsing_error",
                {"error": error},
            )
        return parsed_data, None, None

class NDJSONParser(FileParser):
    def parse(
        self, file_bytes: bytes
    ) -> Tuple[Any, Optional[str], Optional[Dict[str, Any]]]:
        try:
            content = file_bytes.decode("utf-8")
            records = []
            for line in content.splitlines():
                stripped = line.strip()
                if stripped:
                    try:
                        records.append(json.loads(stripped))
                    except json.JSONDecodeError:
                        parsed = try_parse_literal(stripped)
                        if parsed is not None:
                            records.append(parsed)
                        else:
                            raise
            return records, None, None
        except Exception as e:
            return (
                None,
                "ConvertFileFormat.Exception.InputFile.Parser.ndjson_parsing_error",
                {"error": f"{str(e)}"},
            )


class YAMLParser(FileParser):
    def parse(
        self, file_bytes: bytes
    ) -> Tuple[Any, Optional[str], Optional[Dict[str, Any]]]:
        parsed_data, error = cowparserutils.yaml_parse(file_bytes)
        if error:
            return (
                None,
                "ConvertFileFormat.Exception.InputFile.Parser.yaml_parsing_error",
                {"error": error},
            )
        return parsed_data, None, None
class TOMLParser(FileParser):
    def parse(
        self, file_bytes: bytes
    ) -> Tuple[Any, Optional[str], Optional[Dict[str, Any]]]:
        parsed_data, error = cowparserutils.toml_parse(file_bytes)
        if error:
            return (
                None,
                "ConvertFileFormat.Exception.InputFile.Parser.toml_parsing_error",
                {"error": error},
            )
        return parsed_data, None, None

class XMLParser(FileParser):
    def parse(
        self, file_bytes: bytes
    ) -> Tuple[Any, Optional[str], Optional[Dict[str, Any]]]:
        parsed_data, error = cowparserutils.xml_parse(file_bytes)
        if error:
            return (
                None,
                "ConvertFileFormat.Exception.InputFile.Parser.xml_parsing_error",
                {"error": error},
            )
        return parsed_data, None, None

class CSVParser(FileParser):
    def parse(
        self, file_bytes: bytes
    ) -> Tuple[Any, Optional[str], Optional[Dict[str, Any]]]:
            df, error = cowparserutils.csv_parse(file_bytes)
            if error:            
                return (
                    None,
                    "ConvertFileFormat.Exception.InputFile.Parser.csv_parsing_error",
                    {"error": error},
                )
            return df, None, None



class ParquetParser(FileParser):

    def parse(
        self, file_bytes: bytes
    ) -> Tuple[Any, Optional[str], Optional[Dict[str, Any]]]:
        try:
            buffer = BytesIO(file_bytes)
            table = pq.read_table(buffer)
            records = table.to_pylist()
            
            return records, None, None

        except (pyarrow.ArrowInvalid, OSError, ValueError) as e:
            return (
                None,
                "ConvertFileFormat.Exception.InputFile.Parser.parquet_parsing_error",
                {"error": f"Invalid file format: {str(e)}"},
            )

        except Exception as e:
            return (
                None,
                "ConvertFileFormat.Exception.InputFile.Parser.parquet_parsing_error",
                {"error": f"Error parsing Parquet file: {str(e)}"},
            )


class XLSXParser(FileParser):
    def parse(
        self, file_bytes: bytes
    ) -> Tuple[Any, Optional[str], Optional[Dict[str, Any]]]:
        try:
            with BytesIO(file_bytes) as excel_file:
                df = pd.read_excel(excel_file)
                return df.to_dict(orient="records"), None, None
        except Exception as e:
            return (
                None,
                "ConvertFileFormat.Exception.InputFile.Parser.xlsx_parsing_error",
                {"error": f"{str(e)}"},
            )


class FileConverter(ABC):
    """Abstract base class for converting data to a specific format."""

    @abstractmethod
    def convert(
        self, data: Any, preserve_type: bool = False
    ) -> Tuple[bytes, Optional[str], Optional[Dict[str, Any]]]:
        """Convert data into bytes for the target format."""
        pass


class JSONConverter(FileConverter):
    def convert(
        self, data: Any, preserve_type: bool = False
    ) -> Tuple[bytes, Optional[str], Optional[Dict[str, Any]]]:
        try:
            # Option 1: If it's tabular data (list of dicts), use pandas for efficiency
            if isinstance(data, list) and data and isinstance(data[0], dict):
                df = pd.DataFrame(data)
                json_str = df.to_json(orient='records', indent=4)
                return json_str.encode("utf-8"), None, None

            # Option 2: For other data types, clean NaN recursively
            def clean_nan(obj):
                if isinstance(obj, list):
                    return [clean_nan(item) for item in obj]
                elif isinstance(obj, dict):
                    return {k: clean_nan(v) for k, v in obj.items()}
                elif isinstance(obj, float) and (np.isnan(obj) or pd.isna(obj)):
                    return None
                else:
                    return obj

            cleaned_data = clean_nan(data)
            return json.dumps(cleaned_data, indent=4).encode("utf-8"), None, None
        except Exception as e:
            return (
                None,
                "ConvertFileFormat.Exception.InputFile.Converter.json_conversion_error",
                {"error": f"{str(e)}"},
            )


class NDJSONConverter(FileConverter):
    def convert(
        self, data: Any, preserve_type: bool = False
    ) -> Tuple[bytes, Optional[str], Optional[Dict[str, Any]]]:
        try:
            def clean_nan(obj):
                if isinstance(obj, list):
                    return [clean_nan(item) for item in obj]
                elif isinstance(obj, dict):
                    return {k: clean_nan(v) for k, v in obj.items()}
                elif isinstance(obj, float) and (np.isnan(obj) or pd.isna(obj)):
                    return None
                else:
                    return obj

            cleaned_data = clean_nan(data)
            if isinstance(cleaned_data, list):
                lines = [json.dumps(item) for item in cleaned_data]
                ndjson_str = "\n".join(lines) + "\n"
            else:
                ndjson_str = json.dumps(cleaned_data) + "\n"
            return ndjson_str.encode("utf-8"), None, None
        except Exception as e:
            return (
                None,
                "ConvertFileFormat.Exception.InputFile.Converter.ndjson_conversion_error",
                {"error": f"{str(e)}"},
            )


class YAMLConverter(FileConverter):
    def convert(
        self, data: Any, preserve_type: bool = False
    ) -> Tuple[bytes, Optional[str], Optional[Dict[str, Any]]]:
        try:
            return yaml.dump(data).encode("utf-8"), None, None
        except Exception as e:
            return (
                None,
                "ConvertFileFormat.Exception.InputFile.Converter.yaml_conversion_error",
                {"error": f"{str(e)}"},
            )


class TOMLConverter(FileConverter):
    def convert(
        self, data: Any, preserve_type: bool = False
    ) -> Tuple[bytes, Optional[str], Optional[Dict[str, Any]]]:
        try:
            if isinstance(data, dict):
                return toml.dumps(data).encode("utf-8"), None, None
            elif isinstance(data, list) and all(
                isinstance(item, dict) for item in data
            ):
                return toml.dumps({"data": data}).encode("utf-8"), None, None
            return (
                None,
                "ConvertFileFormat.Exception.InputFile.Converter.toml_conversion_error",
                {"error": "Invalid data format for TOML conversion"},
            )
        except Exception as e:
            return (
                None,
                "ConvertFileFormat.Exception.InputFile.Converter.toml_conversion_error",
                {"error": f"{str(e)}"},
            )


class CSVConverter(FileConverter):
    def convert(
        self, data: Any, preserve_type: bool = False
    ) -> Tuple[bytes, Optional[str], Optional[Dict[str, Any]]]:
        try:
            if isinstance(data, dict):
                data = [data]
            df = pd.DataFrame(data)
            with BytesIO() as output:
                df.to_csv(output, index=False)
                return output.getvalue(), None, None
        except Exception as e:
            return (
                None,
                "ConvertFileFormat.Exception.InputFile.Converter.csv_conversion_error",
                {"error": f"{str(e)}"},
            )


class ParquetConverter(FileConverter):
    def convert(
        self, data: Any, preserve_type: bool = False
    ) -> Tuple[bytes, Optional[str], Optional[Dict[str, Any]]]:
        try:
            # Expecting tabular data: a list of dicts (e.g. from CSVParser.parse)
            if not (isinstance(data, list) and data and isinstance(data[0], dict)):
                return (
                    None,
                    "ConvertFileFormat.Exception.InputFile.Converter.parquet_conversion_error",
                    {"error": "Data must be a non-empty list of dict records for Parquet conversion."},
                )

            if preserve_type:
                data = self._restore_nested_types(data)

            df = pd.DataFrame(data)

            buffer = BytesIO()
            df.to_parquet(buffer, engine="pyarrow", index=False)
            return buffer.getvalue(), None, None

        except Exception as e:
            return (
                None,
                "ConvertFileFormat.Exception.InputFile.Converter.parquet_conversion_error",
                {"error": f"{str(e)}"},
            )

    @classmethod
    def _restore_nested_types(cls, data: list) -> list:
        """Detects columns holding stringified list/dict values (using the
        first non-null value per column as a sample) and converts those
        columns' values back to real list/dict objects via ast.literal_eval.
        """
        candidate_columns = set()
        parsed_cache: Dict[Tuple[int, str], Any] = {}

        keys = list(data[0].keys()) if isinstance(data[0], dict) else []
        for k in keys:
            for idx, record in enumerate(data):
                if not isinstance(record, dict):
                    continue
                v = record.get(k)
                if isinstance(v, str) and v.strip():
                    parsed = try_parse_literal(v)
                    if parsed is not None:
                        candidate_columns.add(k)
                        parsed_cache[(idx, k)] = parsed
                    break  # only check first non-null value per column

        if not candidate_columns:
            return data

        processed_data = []
        for idx, record in enumerate(data):
            if isinstance(record, dict):
                new_record = record.copy()
                for k in candidate_columns:
                    if (idx, k) in parsed_cache:
                        new_record[k] = parsed_cache[(idx, k)]
                    else:
                        v = record.get(k)
                        parsed = try_parse_literal(v)
                        if parsed is not None:
                            new_record[k] = parsed
                processed_data.append(new_record)
            else:
                processed_data.append(record)

        return processed_data


class XLSXConverter(FileConverter):
    def convert(
        self, data: Any, preserve_type: bool = False
    ) -> Tuple[bytes, Optional[str], Optional[Dict[str, Any]]]:
        try:
            df = pd.DataFrame(data if isinstance(data, list) else [data])
            with BytesIO() as output:
                df.to_excel(output, index=False, engine="openpyxl")
                return output.getvalue(), None, None
        except Exception as e:
            return (
                None,
                "ConvertFileFormat.Exception.InputFile.Converter.xlsx_conversion_error",
                {"error": f"{str(e)}"},
            )
def try_parse_literal(val: str) -> Any:
    """Attempts to parse a string into a list or dict using ast.literal_eval."""
    if not isinstance(val, str):
        return None
    stripped = val.strip()
    if (stripped.startswith('[') and stripped.endswith(']')) or (stripped.startswith('{') and stripped.endswith('}')):
        try:
            parsed = ast.literal_eval(stripped)
            if isinstance(parsed, (list, dict)):
                return parsed
        except Exception:
            pass
    return None


class Task(cards.AbstractTask):
    """Task to convert input file format to a specified output format."""

    def __init__(self) -> None:
        """Initialize the Task with empty log data."""
        super().__init__()
        self.prev_log_data: List[Dict[str, Any]] = []

    JSON_FORMAT = "json"
    NDJSON_FORMAT = "ndjson"
    YAML_FORMAT = "yaml"
    TOML_FORMAT = "toml"
    CSV_FORMAT = "csv"
    PARQUET_FORMAT = "parquet"
    XML_FORMAT = "xml"
    XLSX_FORMAT = "xlsx"
    HAR_FORMAT = "har"

    CONTENT_TYPES = {
        JSON_FORMAT: "application/json",
        NDJSON_FORMAT: "application/x-ndjson",
        YAML_FORMAT: "application/x-yaml",
        TOML_FORMAT: "application/toml",
        CSV_FORMAT: "text/csv",
        PARQUET_FORMAT: "application/parquet",
        XLSX_FORMAT: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        HAR_FORMAT: "application/json",
    }

    FORMAT_PARSERS = {
        JSON_FORMAT: JSONParser(),
        NDJSON_FORMAT: NDJSONParser(),
        YAML_FORMAT: YAMLParser(),
        TOML_FORMAT: TOMLParser(),
        XML_FORMAT: XMLParser(),
        CSV_FORMAT: CSVParser(),
        PARQUET_FORMAT: ParquetParser(),
        XLSX_FORMAT: XLSXParser(),
        HAR_FORMAT: JSONConverter(),
    }

    FORMAT_CONVERTERS = {
        JSON_FORMAT: JSONConverter(),
        NDJSON_FORMAT: NDJSONConverter(),
        YAML_FORMAT: YAMLConverter(),
        TOML_FORMAT: TOMLConverter(),
        CSV_FORMAT: CSVConverter(),
        PARQUET_FORMAT: ParquetConverter(),
        XLSX_FORMAT: XLSXConverter(),
        HAR_FORMAT: JSONConverter(),
    }

    def execute(self) -> Dict[str, Any]:
        """Execute the task to convert file format."""
        response = {}

        user_inputs = self.task_inputs.user_inputs

        log_file_url = (
            user_inputs.get("LogFile", "")
            if user_inputs.get("LogFile", "") != MINIO_PLACEHOLDER
            else ""
        )

        self.proceed_if_log_exists = cowutils.str_to_bool(value=user_inputs.get("ProceedIfLogExists"),default_val=True)
        self.proceed_if_error_exists = cowutils.str_to_bool(value=user_inputs.get("ProceedIfErrorExists"),default_val=True)

        self.set_log_file_name(
            "LogFile" if self.proceed_if_error_exists else "Errors")

        default_log_config_filepath = str(
            Path(__file__).parent.joinpath("LogConfig_default.toml").resolve()
        )
        custom_log_config_url = self.task_inputs.user_inputs.get(
            "LogConfigFile")

        log_manager, error = cards.LogConfigManager.from_minio_file_url(
            (
                custom_log_config_url
                if custom_log_config_url
                and custom_log_config_url != "<<MINIO_FILE_PATH>>"
                else ""
            ),
            self.download_toml_file_from_minio_as_dict,
            default_log_config_filepath,
            default_context_data={
                'fromdate': self.task_inputs.from_date.strftime('%d/%m/%Y %H:%M'),
                'todate': self.task_inputs.to_date.strftime('%d/%m/%Y %H:%M')
            }
        )
        if error:
            return {"Error": error}

        self.prev_log_data, error_info = self.download_log_file(log_file_url)
        if error_info:
            return self.upload_log_file_panic(
                error_data=log_manager.get_error_message(
                    "ConvertFileFormat.Exception.LogFile.download_failed", error_info
                )
            )
        elif not self.proceed_if_log_exists and log_file_url:
            return {"LogFile": log_file_url}

        validate_flow = cowutils.str_to_bool(user_inputs.get("ValidateFlow", False))
        preserve_type = cowutils.str_to_bool(value=user_inputs.get("PreserveType"), default_val=False)

        validation_error_info = self.check_inputs()
        if validation_error_info:
            return self.upload_log_file_panic(
                error_data=log_manager.get_error_message(
                    "ConvertFileFormat.Validation.UserInputs.missing_fields",
                    validation_error_info,
                )
            )

        input_file_url = user_inputs.get("InputFile", "")
        output_file_format = user_inputs.get("OutputFileFormat", "").lower()

        file_bytes, error = self.download_file_from_minio(input_file_url)
        if error:
            return self.upload_log_file_panic(
                error_data=log_manager.get_error_message(
                    "ConvertFileFormat.Exception.InputFile.download_failed",
                    {"error": error.get("error")},
                )
            )

        input_format, extension = self.detect_input_format(input_file_url)
        try:
            if not preserve_type and self.can_use_select_object_content(
                input_format, output_file_format, input_file_url
            ):
               
                output_bytes, error = self.select_object_content_stream(
                    file_url=input_file_url,
                    input_format=input_format,
                    output_format=output_file_format,
                )
                

                if not error:
                    output_file_name = f"OutputFile-{uuid.uuid4()}"
                    if user_inputs.get("OutputFileName", ""):
                        output_file_name = user_inputs.get("OutputFileName")

                    output_url, error = self.upload_output_file(
                        output_file_name,
                        output_bytes,
                        output_file_format,
                    )
                    
                    if not error:
                        return {"OutputFile": output_url}

        except Exception as e:
            pass

        file_bytes, error = self.download_file_from_minio(input_file_url)
        if error:
            return self.upload_log_file_panic(error)

        if not input_format:
            input_format, extension = self.detect_input_format_from_bytes(
                file_bytes)
        if not input_format or input_format not in self.FORMAT_PARSERS:
            return self.upload_log_file_panic(
                error_data=log_manager.get_error_message(
                    f"ConvertFileFormat.Exception.InputFile.{'invalid_format' if extension else 'unknown_format'}",
                    {"file_format": extension},
                )
            )

        parser = self.FORMAT_PARSERS[input_format]
        data, error_type, error_info = parser.parse(file_bytes)
        if error_info:
            return self.upload_log_file_panic(
                error_data=log_manager.get_error_message(
                    error_type, error_info)
            )

        if preserve_type and input_format == self.CSV_FORMAT and output_file_format in {self.JSON_FORMAT, self.NDJSON_FORMAT} and isinstance(data, list):
            candidate_columns = set()
            if data:
                keys = list(data[0].keys()) if isinstance(data[0], dict) else []
                for k in keys:
                    for record in data:
                        if not isinstance(record, dict):
                            continue
                        v = record.get(k)
                        if isinstance(v, str) and v.strip():
                            if try_parse_literal(v) is not None:
                                candidate_columns.add(k)
                                break

            if candidate_columns:
                processed_data = []
                for record in data:
                    if isinstance(record, dict):
                        new_record = record.copy()
                        for k in candidate_columns:
                            v = record.get(k)
                            parsed = try_parse_literal(v)
                            if parsed is not None:
                                new_record[k] = parsed
                            elif pd.isna(v) or (isinstance(v, str) and not v.strip()):
                                new_record[k] = None
                        processed_data.append(new_record)
                    else:
                        processed_data.append(record)
                data = processed_data

        if output_file_format not in self.FORMAT_CONVERTERS:
            return self.upload_log_file_panic(
                error_data=log_manager.get_error_message(
                    "ConvertFileFormat.Validation.OutputFile.invalid_format",
                    {"file_format": output_file_format},
                )
            )

        if validate_flow:
            return {"ValidationStatus": "Input data validated successfully"}

        converter = self.FORMAT_CONVERTERS[output_file_format]
        output_data, error_type, error_info = converter.convert(data, preserve_type)
        if error_info:
            return self.upload_log_file_panic(
                error_data=log_manager.get_error_message(
                    error_type, error_info)
            )

        output_file_name=f'OutputFile-{str(uuid.uuid4())}'  
        if self.task_inputs.user_inputs.get("OutputFileName",""):
            output_file_name = self.task_inputs.user_inputs.get("OutputFileName","")

        output_file_url, error = self.upload_output_file(
            output_file_name, output_data, output_file_format
        )
        if error:
            return self.upload_log_file_panic(
                error_data=log_manager.get_error_message(
                    "ConvertFileFormat.Exception.OutputFile.upload_failed",
                    {"error": error.get("error")},
                )
            )

        response["OutputFile"] = output_file_url
        if log_file_url:
            response["LogFile"] = log_file_url

        return response

    def check_inputs(self) -> Dict[str, Any]:
        """Validate required task inputs."""
        if self.task_inputs is None:
            return {"missing_fields": "Task inputs"}

        user_object = self.task_inputs.user_object
        if (
            user_object is None
            or user_object.app is None
            or user_object.app.application_url is None
            or user_object.app.user_defined_credentials is None
        ):
            return {"missing_fields": "User defined credentials"}

        empty_attrs = []
        if self.task_inputs.user_inputs is None:
            empty_attrs.append("User inputs")
        if not self.task_inputs.user_inputs.get("InputFile"):
            empty_attrs.append("InputFile")
        if not self.task_inputs.user_inputs.get("OutputFileFormat"):
            empty_attrs.append("OutputFileFormat")

        return {"missing_fields": ", ".join(empty_attrs)} if empty_attrs else None

    def download_log_file(
        self, path: str
    ) -> Tuple[Optional[List[Dict[str, Any]]], Dict[str, Any]]:
        """Validates the given path and downloads the corresponding log file from MinIO"""
        if not path:
            return [], None
        content, error = self.download_json_file_from_minio_as_iterable(path)
        return (content, None) if not error else ([], {"error": error.get("error")})

    def upload_output_file(
        self, file_name: str, data: bytes, format_to_convert: str
    ) -> Tuple[str, Optional[str]]:
        """Upload converted output file to MinIO."""
        file_name = f"{file_name}.{format_to_convert}"
        content_type = self.CONTENT_TYPES.get(format_to_convert, "text/plain")

        absolute_file_path, error = self.upload_file_to_minio(
            file_name=file_name, file_content=data, content_type=content_type
        )
        return absolute_file_path, error if error else None

    def detect_input_format(
        self, file_name: str
    ) -> Tuple[Optional[str], Optional[str]]:
        """Detect input file format based on extension."""
        if not file_name:
            return None, None

        # Define format mapping
        format_mapping = {
            ".json": self.JSON_FORMAT,
            ".ndjson":self.NDJSON_FORMAT,
            ".har": self.JSON_FORMAT,
            ".yaml": self.YAML_FORMAT,
            ".yml": self.YAML_FORMAT,  # Common alternative for YAML
            ".toml": self.TOML_FORMAT,
            ".csv": self.CSV_FORMAT,
            ".parquet": self.PARQUET_FORMAT,
            ".xml": self.XML_FORMAT,
            ".xlsx": self.XLSX_FORMAT,
        }
        # Get lowercase extension and look up in mapping
        extension = Path(file_name).suffix.lower()
        return format_mapping.get(extension), extension.lstrip(".")

    def detect_input_format_from_bytes(self, file_bytes: bytes) -> tuple[Optional[str], Optional[str]]:
        """Detect input file format by trying to parse file bytes."""
        try:
            json.loads(file_bytes.decode('utf-8'))
            return self.JSON_FORMAT, 'json'
        except Exception:
            pass
        try:
            lines = file_bytes.decode('utf-8').splitlines()
            non_empty_lines = [l.strip() for l in lines if l.strip()]
            if non_empty_lines:
                for line in non_empty_lines:
                    json.loads(line)
                return self.NDJSON_FORMAT, 'ndjson'
        except Exception:
            pass
        try:
            yaml.safe_load(file_bytes.decode('utf-8'))
            return self.YAML_FORMAT, 'yaml'
        except Exception:
            pass
        try:
            toml.loads(file_bytes.decode('utf-8'))
            return self.TOML_FORMAT, 'toml'
        except Exception:
            pass
        try:
            pd.read_csv(BytesIO(file_bytes))
            return self.CSV_FORMAT, 'csv'
        except Exception:
            pass
        try:
            pd.read_parquet(BytesIO(file_bytes))
            return self.PARQUET_FORMAT, 'parquet'
        except Exception:
            pass
        try:
            xmltodict.parse(file_bytes.decode())
            return self.XML_FORMAT, 'xml'
        except Exception:
            pass
        try:
            pd.read_excel(BytesIO(file_bytes))
            return self.XLSX_FORMAT, 'xlsx'
        except Exception:
            pass
        return None, None

    def can_use_select_object_content(self, input_format, output_format, input_url):
        """Checks if MinIO Select can be used for this conversion.

        MinIO Select is used only as an optimization.
        If it fails, the code safely falls back to the normal DataFrame logic."""

        return input_format in {
            self.NDJSON_FORMAT,
            self.CSV_FORMAT,
        } and output_format in {
            self.NDJSON_FORMAT,
            self.CSV_FORMAT,
        }