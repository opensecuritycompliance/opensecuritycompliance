from typing import Tuple, Dict, Any, List, Optional, Union
import jq
import re


def evaluate_jq_filter(
    input_data: Any, jq_expression: str, output_method: str = "FIRST"
) -> Tuple[Any, str]:
    """
    Apply JQ filter to input data.

    Args:
        input_data: Input data to process
        jq_expression: JQ filter expression
        output_method: Method to determine output (ALL or FIRST)

    Returns:
        Tuple containing result and error string (if any)
    """
    try:
        # Validate filter before execution
        try:
            validate_jq_expression(jq_expression)
        except ValueError as e:
            return None, str(e)

        # Compile and apply filter
        compiled_filter = jq.compile(jq_expression).input(input_data)
        output_method = output_method.lower()

        # Validate output method
        valid_methods = ["all", "first", ""]
        if output_method not in valid_methods:
            return (
                None,
                f"The provided OutputMethod: '{output_method}' is invalid. Expected one of: {', '.join(valid_methods)}",
            )

        # Get results based on output method
        jq_result = (
            compiled_filter.all() if output_method == "all" else compiled_filter.first()
        )

        return jq_result, None

    except ValueError as e:
        return (
            None,
            f"Got an error while executing JQExpression, ensure whether the JQExpression that you entered is correct :: {str(e)}",
        )
    except Exception as e:
        # Catch broader exceptions for more robust error handling
        return (
            None,
            f"An unexpected error occurred while executing JQExpression :: {str(e)}",
        )


def validate_jq_expression(jq_expression: str) -> None:
    """
    Validate a JQ Expression for security concerns.

    Args:
        jq_expression: JQ Expression to validate

    Raises:
        ValueError: If filter contains potentially dangerous patterns
    """
    # Validate filter to catch potential security issues
    # This is a basic check - more comprehensive validation might be needed
    dangerous_patterns = [
        r"`.*?`",  # Backtick execution
        r"\bsystem\s*\(",  # System command execution
        r"\bexec\s*\(",  # Code execution
        r"\|\s*(sh|bash)\b",  # Pipe to shell
        r"\b(cat|grep|wget|curl|nc|rm|kill|ps)\b",  # Shell utilities
        r"\b(python[0-9.]*|perl|lua|node|bash|sh)\b",  # Script interpreters
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, jq_expression):
            raise ValueError(
                f"JQ filter contains potentially dangerous pattern: {pattern}"
            )
