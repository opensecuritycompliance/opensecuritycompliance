from typing import Tuple, Any
import jq
import re


def evaluate_jq_streaming_filter(
    input_item: Any,
    streaming_jq_filter: str,
    output_method: str = "FIRST"
):
    """
    Args:
        input_data: Input data to process
        streaming_jq_filter: Streaming JQ filter expression
        output_method: Method to determine output (ALL or FIRST)

    Returns:
        Tuple containing result and error string (if any)
    """

    if not streaming_jq_filter:
        return None, None

    try:
        compiled = jq.compile(streaming_jq_filter).input(input_item)

        if output_method.lower() == "all":
            return compiled.all(), None
        return compiled.first(), None

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
