from typing import Dict, List, Optional, Tuple, Any
import json
import uuid
from compliancecowcards.structs import cards
import numpy as np
import pandas as pd
import toml
import yaml
import xmltodict
from io import BytesIO
import pyarrow.parquet as pq
from abc import ABC, abstractmethod
from pathlib import Path

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
        try:
            return json.loads(file_bytes), None, None
        except json.JSONDecodeError as e:
            return (
                None,
                "ConvertFileFormat.Exception.InputFile.Parser.json_parsing_error",
                {"error": f"{str(e)}"},
            )


class YAMLParser(FileParser):
    def parse(
        self, file_bytes: bytes
    ) -> Tuple[Any, Optional[str], Optional[Dict[str, Any]]]:
        try:
            return yaml.safe_load(file_bytes), None, None
        except yaml.YAMLError as e:
            return (
                None,
                "ConvertFileFormat.Exception.InputFile.Parser.yaml_parsing_error",
                {"error": f"{str(e)}"},
            )


class TOMLParser(FileParser):
    def parse(
        self, file_bytes: bytes
    ) -> Tuple[Any, Optional[str], Optional[Dict[str, Any]]]:
        try:
            return toml.loads(file_bytes.decode("utf-8")), None, None
        except toml.TomlDecodeError as e:
            return (
                None,
                "ConvertFileFormat.Exception.InputFile.Parser.toml_parsing_error",
                {"error": f"{str(e)}"},
            )


class XMLParser(FileParser):
    def parse(
        self, file_bytes: bytes
    ) -> Tuple[Any, Optional[str], Optional[Dict[str, Any]]]:
        try:
            return xmltodict.parse(file_bytes.decode("utf-8")), None, None
        except Exception as e:
            return (
                None,
                "ConvertFileFormat.Exception.InputFile.Parser.xml_parsing_error",
                {"error": f"{str(e)}"},
            )


class CSVParser(FileParser):
    def parse(
        self, file_bytes: bytes
    ) -> Tuple[Any, Optional[str], Optional[Dict[str, Any]]]:
        try:
            df = pd.read_csv(BytesIO(file_bytes))
            return df.to_dict(orient="records"), None, None
        except pd.errors.ParserError as e:
            return (
                None,
                "ConvertFileFormat.Exception.InputFile.Parser.csv_parsing_error",
                {"error": f"{str(e)}"},
            )


class ParquetParser(FileParser):
    def parse(
        self, file_bytes: bytes
    ) -> Tuple[Any, Optional[str], Optional[Dict[str, Any]]]:
        try:
            df = pd.read_parquet(BytesIO(file_bytes), engine="fastparquet")
            return df.to_dict(orient="records"), None, None
        except OSError as e:
            return (
                None,
                "ConvertFileFormat.Exception.InputFile.Parser.parquet_parsing_error",
                {"error": f"{str(e)}"},
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
        self, data: Any
    ) -> Tuple[bytes, Optional[str], Optional[Dict[str, Any]]]:
        """Convert data into bytes for the target format."""
        pass


class JSONConverter(FileConverter):
    def convert(
        self, data: Any
    ) -> Tuple[bytes, Optional[str], Optional[Dict[str, Any]]]:
        try:
            return json.dumps(data, indent=4).encode("utf-8"), None, None
        except Exception as e:
            return (
                None,
                "ConvertFileFormat.Exception.InputFile.Converter.json_conversion_error",
                {"error": f"{str(e)}"},
            )


class YAMLConverter(FileConverter):
    def convert(
        self, data: Any
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
        self, data: Any
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
        self, data: Any
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
        self, data: Any
    ) -> Tuple[bytes, Optional[str], Optional[Dict[str, Any]]]:
        try:
            if isinstance(data, dict):
                data = [data]
            df = pd.DataFrame(data)
            return df.to_parquet(), None, None
        except Exception as e:
            return (
                None,
                "ConvertFileFormat.Exception.InputFile.Converter.parquet_conversion_error",
                {"error": f"{str(e)}"},
            )


class XLSXConverter(FileConverter):
    def convert(
        self, data: Any
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


class Task(cards.AbstractTask):
    """Task to convert input file format to a specified output format."""

    def __init__(self) -> None:
        """Initialize the Task with empty log data."""
        super().__init__()
        self.prev_log_data: List[Dict[str, Any]] = []

    JSON_FORMAT = "json"
    YAML_FORMAT = "yaml"
    TOML_FORMAT = "toml"
    CSV_FORMAT = "csv"
    PARQUET_FORMAT = "parquet"
    XML_FORMAT = "xml"
    XLSX_FORMAT = "xlsx"
    HAR_FORMAT = "har"

    CONTENT_TYPES = {
        JSON_FORMAT: "application/json",
        YAML_FORMAT: "application/x-yaml",
        TOML_FORMAT: "application/toml",
        CSV_FORMAT: "text/csv",
        PARQUET_FORMAT: "application/parquet",
        XLSX_FORMAT: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        HAR_FORMAT: "application/json",
    }

    FORMAT_PARSERS = {
        JSON_FORMAT: JSONParser(),
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

        self.proceed_if_log_exists = user_inputs.get("ProceedIfLogExists")
        self.proceed_if_log_exists = (
            self.proceed_if_log_exists
            if self.proceed_if_log_exists is not None
            else True
        )

        self.proceed_if_error_exists = user_inputs.get("ProceedIfErrorExists")
        self.proceed_if_error_exists = (
            self.proceed_if_error_exists
            if self.proceed_if_error_exists is not None
            else True
        )

        self.set_log_file_name("LogFile" if self.proceed_if_error_exists else "Errors")

        default_log_config_filepath = str(
            Path(__file__).parent.joinpath("LogConfig_default.toml").resolve()
        )
        custom_log_config_url = self.task_inputs.user_inputs.get("LogConfigFile")

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
        if not input_format:
            input_format, extension = self.detect_input_format_from_bytes(file_bytes)
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
                error_data=log_manager.get_error_message(error_type, error_info)
            )

        if output_file_format not in self.FORMAT_CONVERTERS:
            return self.upload_log_file_panic(
                error_data=log_manager.get_error_message(
                    "ConvertFileFormat.Exception.OutputFile.invalid_format",
                    {"file_format": output_file_format},
                )
            )

        converter = self.FORMAT_CONVERTERS[output_file_format]
        output_data, error_type, error_info = converter.convert(data)
        if error_info:
            return self.upload_log_file_panic(
                error_data=log_manager.get_error_message(error_type, error_info)
            )

        output_file_url, error = self.upload_output_file(
            "OutputFile", output_data, output_file_format
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
        file_name = f"{file_name}-{str(uuid.uuid4())}.{format_to_convert}"
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
