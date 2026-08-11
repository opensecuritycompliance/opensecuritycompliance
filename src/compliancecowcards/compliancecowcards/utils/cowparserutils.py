
from typing import Dict, List, Optional, Tuple, Any
import json
import pandas as pd
import toml
import yaml
from io import BytesIO
import xmltodict
from io import BytesIO

ENCODEING = [
        "utf-8",       
        "windows-1252", 
        "iso-8859-1",  
        "utf-16",       
        "ascii"         
    ]
def csv_parse(
    file_bytes: bytes
) -> Tuple[Any, Optional[str], Optional[Dict[str, Any]]]:
    error = None
    for encoding in ENCODEING:
        try:
            df = pd.read_csv(BytesIO(file_bytes), encoding=encoding)
            return df.to_dict(orient="records"), None
        except UnicodeDecodeError as e:
            error = e
            continue
        except pd.errors.ParserError as e:
            return (
                None,
                str(e),
            )
    return (
        None,
        str(error),
    )
def json_parse(
    file_bytes: bytes
) -> Tuple[Any, Optional[str], Optional[Dict[str, Any]]]:
    error = None
    for encoding in ENCODEING:
        try:
            return json.loads(file_bytes.decode(encoding)), None
        except UnicodeDecodeError as e:
            error = e
            continue
        except json.JSONDecodeError as e:
            return (
                None,
                str(e),
            )
    return (
        None,
        str(error),
    )

def yaml_parse(
    file_bytes: bytes  
) -> Tuple[Any, Optional[str], Optional[Dict[str, Any]]]:
    error = None
    for encoding in ENCODEING:
        try:
            return yaml.safe_load(file_bytes.decode(encoding)), None
        except UnicodeDecodeError as e:
            error = e
            continue
        except yaml.YAMLError as e:
            return (
                None,
                str(e),
            )
    return (
        None,
        str(error),
    )
def toml_parse(
    file_bytes: bytes
) -> Tuple[Any, Optional[str], Optional[Dict[str, Any]]]:
    error = None
    for encoding in ENCODEING:
        try:
            return toml.loads(file_bytes.decode(encoding)), None
        except UnicodeDecodeError as e:
            error = e
            continue
        except toml.TomlDecodeError as e:
            return (
                None,
                str(e),
            )
    return (
        None,
        str(error),
    )
def xml_parse(
    file_bytes: bytes
) -> Tuple[Any, Optional[str], Optional[Dict[str, Any]]]:
    error = None
    for encoding in ENCODEING:
        try:
            return xmltodict.parse(file_bytes.decode(encoding)), None
        except UnicodeDecodeError as e:
            error = e
            continue
        except Exception as e:
            return (
                None,
                str(e),
            )
    return (
        None,
        str(error),
    )
