"""
Validation utilities for task inputs against their metadata definitions.

task_inputs:       runtime values supplied for a task, e.g.
                    {"InputFile": "http://localhost:9000/...", "OutputMethod": "FIRST"}

task_meta_inputs:  metadata describing each input field, keyed by name, e.g.
                    {
                        "InputFile": {
                            "name": "InputFile",
                            "dataType": "FILE",
                            "required": True,
                            "allowedValues": [],
                            "format": "json",
                            "defaultValue": None,
                        },
                        ...
                    }
                    (typically produced by TaskMetaTemplate.get_inputs_to_dict())
"""

from typing import Any, Dict, List, Optional

# Reusable global type mapping (avoids recreating dictionary on every call)
DATATYPE_TO_PYTHON_TYPE_MAP = {
    "STRING": str,
    "INT": int,
    "BOOLEAN": bool,
    "LIST": list,
    "DICT": dict,
    "FILE": str,
    "JQ_EXPRESSION": str,
}


def datatype_to_python_type(data_type: str) -> Any:
    """
    Maps a metadata `dataType` string to the Python type it should
    resolve to at runtime.

    FILE and JQ_EXPRESSION are treated as `str` because they arrive as
    URLs/paths/expression strings, not native Python file or query objects.

    Unknown/unmapped dataTypes fall back to `Any`, meaning no type check
    is enforced for them (avoids false-positive errors on new/uncovered types).
    """
    return DATATYPE_TO_PYTHON_TYPE_MAP.get(data_type, Any)


def is_placeholder(val: Any) -> bool:
    """
    Checks if a value is a task placeholder string
    (e.g., '<<MINIO_FILE_PATH>>', '<<>>', or any value starting/ending with '<<' and '>>').
    """
    if isinstance(val, str):
        stripped = val.strip()
        return stripped.startswith("<<") and stripped.endswith(">>")
    return False


def _validate_file_value(name: str, value: str) -> Optional[str]:
    """
    Validates a FILE-type input value against standard patterns (MinIO URL or local path).
    Uses fast string start checks rather than regex to save memory and CPU cycles.

    Returns:
        an error message string if the value matches neither pattern,
        otherwise None (valid).
    """
    # Verify prefix and check for any whitespace characters (equivalent to ^[^\s]+$)
    if value.startswith(("http://", "https://", "file://")) and not any(c.isspace() for c in value):
        return None

    return (
        f"'{name}' must be a valid MinIO URL (http(s)://...) "
        f"or local path (file://...), got '{value}'."
    )


def validate_inputs(
    task_inputs: Dict[str, Any],
    task_meta_inputs: Dict[str, Dict[str, Any]],
    optional_inputs: Optional[List[str]] = None,
) -> Optional[str]:
    """
    Validates `task_inputs` against the field definitions in `task_meta_inputs`.
    Short-circuits and returns the first error message string encountered.

    Checks performed per field (in order):
        1. required + missing/empty/placeholder  -> error
        2. allowedValues mismatch                -> error
        3. dataType mismatch                     -> error
        4. FILE dataType pattern mismatch        -> error
        5. FILE dataType format validation       -> error

    Also flags any keys present in `task_inputs` that aren't declared at all
    in `task_meta_inputs` (unrecognized inputs).

    Args:
        task_inputs:       runtime input values, keyed by field name.
        task_meta_inputs:  field metadata, keyed by field name.
        optional_inputs:   field names to treat as optional for this call,
                            even if metadata marks them required=True
                            (e.g. LogFile not needed on a first run).

    Returns:
        The first validation error message string if any, otherwise None (valid).
    """
    # Convert optional_inputs to a set to achieve O(1) membership lookups (saves CPU/memory)
    optional_set = set(optional_inputs) if optional_inputs else set()

    for name, meta in task_meta_inputs.items():
        data_type = meta.get("dataType")
        allowed_values = meta.get("allowedValues") or []
        
        # Field is required unless explicitly overridden via optional_inputs set
        required = bool(meta.get("required")) and name not in optional_set

        value = task_inputs.get(name)
        is_empty = value is None or value == "" or is_placeholder(value)

        # --- Check 1: required but missing/empty/placeholder ------------------
        if required and is_empty:
            return f"'{name}' is a required input but is missing or empty."

        # Optional field with no value provided -> nothing further to validate
        if is_empty:
            continue

        # --- Check 2: value must be one of allowedValues (if defined) --------
        if allowed_values and value not in allowed_values:
            return f"'{name}' has value '{value}' which is not in allowed values: {allowed_values}"

        # --- Check 3: value must match the expected Python type --------------
        expected_type = datatype_to_python_type(data_type)
        if expected_type is not Any and not isinstance(value, expected_type):
            return f"'{name}' expected type '{data_type}' ({expected_type.__name__}), got '{type(value).__name__}'."

        # --- Check 4: FILE values must match one of the accepted patterns ----
        if data_type == "FILE" and isinstance(value, str):
            file_error = _validate_file_value(name, value)
            if file_error:
                return file_error
            
            # Validate file format extension if format is defined in metadata
            expected_format = meta.get("format")
            if expected_format and isinstance(expected_format, str):
                clean_path = value.split("?")[0]
                ext = clean_path.split(".")[-1].lower().strip("/") if "." in clean_path else ""
                expected_format_lower = expected_format.strip().lower()
                
                if ext != expected_format_lower:
                    return f"'{name}' expected a file with format/extension '{expected_format_lower}', got '{ext}'."

    # --- Check 5: flag any inputs not declared in the metadata at all --------
    for name in task_inputs:
        if name not in task_meta_inputs:
            return f"'{name}' is not a recognized input for this task."

    return None
