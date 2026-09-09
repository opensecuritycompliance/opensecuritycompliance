from typing import Any, Callable
import re
import jmespath
from jmespath.exceptions import ParseError as JMESPathParseError
from compliancecowcards.utils.cowjqutils import evaluate_jq_filter

def get_placeholders_in_template(template: str, placeholder_prefix: str = "") -> set[str]:
    placeholder_prefix = (placeholder_prefix + ".") if placeholder_prefix and not placeholder_prefix.endswith(".") else placeholder_prefix
    placeholder_prefix = re.escape(placeholder_prefix) if placeholder_prefix else ""
    
    braces_perc_pattern = r"\{%\{" + placeholder_prefix + r"([^{}%]+)\}%\}"
    braces_pattern = r"\{\{" + placeholder_prefix + r"([^{}]+)\}\}"
    angle_bracket_pattern = fr"<<{placeholder_prefix}([^<>]+)>>"

    braces_perc_matches = re.findall(braces_perc_pattern, template)
    braces_matches = re.findall(braces_pattern, template)
    angle_bracket_matches = re.findall(angle_bracket_pattern, template)

    matches = set(braces_perc_matches + braces_matches + angle_bracket_matches)
    
    return matches
    
def _replace_placeholders(
    template: str,
    resolution_func: Callable[[str], tuple[Any, str | None]],
    placeholder_prefix: str = "",
    strict: bool = True,
    replace_double_quotes: bool = False,
    placeholders: list[str] | set[str] = [],
    default_missing_placeholder_value: str | None = None
) -> tuple[str, list[str], str | None]:
    placeholder_prefix = (placeholder_prefix + ".") if placeholder_prefix and not placeholder_prefix.endswith(".") else placeholder_prefix
    if not placeholders:
        placeholders = get_placeholders_in_template(template, placeholder_prefix)
        if not placeholders:
            return template, [], None
            
    missing_placeholders = []
    result = template
    for key in placeholders:
        value, error = resolution_func(key)
        
        if value is not None:
            # return value before serializing if there is only 1 placeholder
            if len(placeholders) == 1 and template in [
                f"<<{placeholder_prefix}{key}>>",
                "{{" + placeholder_prefix + key + "}}",
                "{%{" + placeholder_prefix + key + "}%}"
            ]:
                return value, [], None
                
            value = str(value).strip()
            if replace_double_quotes:
                value = value.replace('"', "'")
                
            result = result \
                .replace(f"<<{placeholder_prefix}{key}>>", value) \
                .replace("{{" + placeholder_prefix + key + "}}", value) \
                .replace("{%{" + placeholder_prefix + key + "}%}", value)
        elif strict or error:
            error_message = f"Cannot resolve query '{placeholder_prefix}{key}'."
            if error:
                error_message += f" More info :: {error}"
            else:
                error_message += f" Field '{key}' is not present."
            return "", [], error_message
        else:
            missing_placeholders.append(key)
            if default_missing_placeholder_value is not None:
                            result = result \
                .replace(f"<<{placeholder_prefix}{key}>>", default_missing_placeholder_value) \
                .replace("{{" + placeholder_prefix + key + "}}", default_missing_placeholder_value) \
                .replace("{%{" + placeholder_prefix + key + "}%}", default_missing_placeholder_value)

    return result, missing_placeholders, None
    
def replace_placeholders_using_jmespath(
    template: str,
    data: list[dict[str, Any]] | dict[str, Any],
    placeholder_prefix: str = "",
    strict: bool = True,
    placeholders: list[str] | set[str] = []
):
    def resolve(key: str, data):
        try:
            key = key.lstrip(".")
            return jmespath.search(f"{key}", data), None
        except JMESPathParseError as e:
            return "", f"{e}"
            
    resolution_func = lambda key: resolve(key, data)
            
    return _replace_placeholders(template, resolution_func, placeholder_prefix, strict, placeholders=placeholders)

def replace_placeholders_using_jq(
    template: str,
    data: list[dict[str, Any]] | dict[str, Any],
    placeholder_prefix: str = "",
    strict: bool = True,
    replace_double_quotes: bool = False,
    placeholders: list[str] | set[str] = [],
    default_missing_placeholder_value: str | None = None
):
    resolution_func = lambda key: evaluate_jq_filter(
        data, 
        (key if key.startswith(".") else f".{key}").replace('\\"', '"')
    )
            
    return _replace_placeholders(template, resolution_func, placeholder_prefix, strict, replace_double_quotes, placeholders, default_missing_placeholder_value)
    
def get_delimited_placeholder_variants(string: str):
    return [
        r'{{{{{match}}}}}'.format(match=string),
        f'<<{string}>>',
        "{%{" + f'{string}' + "}%}"
    ]
    
def strip_placeholder_delimiters(template: str):
    return template \
        .replace('<<', '').replace('>>', '') \
        .replace("{{", '').replace("}}", "") \
        .replace("{%{", "").replace("}%}", "")