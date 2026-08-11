import math

def validate_numeric_input(
    value,
    field_name: str = "Value",
    value_type: str = "number",
    allow_zero: bool = True,
    min_value: float = None,
    max_value: float = None,
    allow_negative: bool = False,
    allow_float: bool = True,
    custom_validators: list = None
) -> tuple[bool, str]:
    """Generic numeric input validation method.
    
    Validates numeric values with comprehensive checks for type, range, and special cases.
    Can be customized for different use cases without creating field-specific methods.
    
    Args:
        value: The value to validate.
        field_name: Descriptive name of the field (for error messages).
        value_type: Expected type - "int", "float", or "number" (accepts both).
        allow_zero: Whether zero is a valid value.
        min_value: Minimum allowed value (inclusive). None = no minimum.
        max_value: Maximum allowed value (inclusive). None = no maximum.
        allow_negative: Whether negative values are allowed.
        allow_float: Whether float values are allowed (for int type).
        custom_validators: List of tuples (condition, error_message) for custom validation.
    
    Returns:
        tuple: (is_valid, error_message) - Empty string means valid.
        
    Examples:
        # Validate positive integer
        is_valid, msg = validate_numeric_input(5, "MaxRetry", "int", allow_zero=True, min_value=0)
        
        # Validate float in range
        is_valid, msg = validate_numeric_input(2.5, "ExponentialBase", "float", min_value=2, max_value=10)
        
        # Validate with custom rules
        validators = [(lambda x: x % 1 == 0, "Must be a whole number")]
        is_valid, msg = validate_numeric_input(5.5, "Count", "float", custom_validators=validators)
    """
    # Step 1: Null/None check
    if value is None:
        return False, f"{field_name} cannot be None"
    
    # Step 2: Exclude booleans (bool is subclass of int, so check explicitly)
    if isinstance(value, bool):
        return False, f"{field_name} must be a number, got boolean"
    
    # Step 3: Type validation
    if value_type.lower() == "int":
        if not isinstance(value, int):
            return False, f"{field_name} must be an integer, got {type(value).__name__}"
        if isinstance(value, float) and not allow_float:
            return False, f"{field_name} must be an integer, got float"
    
    elif value_type.lower() == "float":
        if not isinstance(value, (int, float)):
            return False, f"{field_name} must be a float, got {type(value).__name__}"
    
    elif value_type.lower() == "number":
        if not isinstance(value, (int, float)):
            return False, f"{field_name} must be a number, got {type(value).__name__}"
    
    else:
        return False, f"Invalid value_type specified: {value_type}"
    
    # Step 4: Special value checks (NaN and Infinity)
    try:
        if math.isnan(value):
            return False, f"{field_name} cannot be NaN"
        if math.isinf(value):
            return False, f"{field_name} cannot be Infinity"
    except (TypeError, ValueError):
        # Some types might not support isnan/isinf, proceed with other checks
        pass
    
    # Step 5: Zero validation
    if value == 0 and not allow_zero:
        return False, f"{field_name} cannot be zero"
    
    # Step 6: Negative value validation
    if value < 0 and not allow_negative:
        return False, f"{field_name} cannot be negative, got {value}"
    
    # Step 7: Range validation
    if min_value is not None and value < min_value:
        return False, f"{field_name} must be >= {min_value}, got {value}"
    
    if max_value is not None and value > max_value:
        return False, f"{field_name} must be <= {max_value}, got {value}"
    
    # Step 8: Custom validators
    if custom_validators is not None and len(custom_validators) > 0:
        for condition_func, error_msg in custom_validators:
            try:
                if not condition_func(value):
                    return False, f"{field_name}: {error_msg}"
            except Exception as e:
                return False, f"{field_name}: Custom validation failed - {str(e)}"
    
    # All validations passed
    return True, ""