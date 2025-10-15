import requests
import logging
import json
from django.http import JsonResponse
from requests.exceptions import RequestException, ConnectionError, Timeout, TooManyRedirects, HTTPError
import re
import urllib.parse

from typing import Union


from compliancecowcards.utils import cowdictutils
from compliancecowcards.constants import cowconstants, errordesc, cowenums

from compliancecowcards.vo import exception


GET = "GET"
POST = "POST"
PUT = "PUT"
DELETE = "DELETE"
PATCH = "PATCH"


logger = logging.getLogger(__name__)


def post(path: str = None, data: dict = None, header: dict = None, timeout: int = 600):
    return make_call_and_process_response(request_method=POST, path=path, data=data, headers=headerbuilder(header), timeout=timeout)


def put(path: str = None, data: dict = None, header: dict = None, timeout: int = 600):
    return make_call_and_process_response(request_method=PUT, data=data, path=path, headers=headerbuilder(header), timeout=timeout)


def patch(path: str = None, data: dict = None, header: dict = None, timeout: int = 600):
    return make_call_and_process_response(request_method=PATCH, data=data, path=path, headers=headerbuilder(header), timeout=timeout)


def delete(path: str = None, data: dict = None, header: dict = None, timeout: int = 600):
    return make_call_and_process_response(request_method=DELETE, data=data, path=path, headers=headerbuilder(header), timeout=timeout)


def get(path: str = None, params: dict = None, header: dict = None, timeout: int = 600):
    return make_call_and_process_response(request_method=GET, params=params, path=path, headers=headerbuilder(header), timeout=timeout)


def headerbuilder(header):
    if header:
        modifiedheader = dict()
        if cowdictutils.is_valid_key(header, cowconstants.SecurityContext):
            securityCtx = header[cowconstants.SecurityContext]
            if not isinstance(securityCtx, str):
                securityCtx = json.dumps(securityCtx)
            modifiedheader[cowconstants.SecurityContext] = securityCtx
            return modifiedheader
        elif cowdictutils.is_valid_key(header, "Authorization"):
            return header
        else:
            modifiedheader[cowconstants.SecurityContext] = "{}"
            return modifiedheader

    return None


def getJsonResponse(response):
    status = 200
    if "status" in response:
        status = response["status"]
        del response["status"]
    return JsonResponse(response, safe=False, status=status)


def make_call_and_process_response(request_method: str = None, path: str = None, data: dict = None, params: dict = None, headers: dict = None, timeout: int = 600) -> dict:

    return make_call_and_process_response_with_resource_type(request_method=request_method, path=path, data=data, params=params, headers=headers, timeout=timeout)


def make_call_and_process_response_with_resource_type(request_method: str = None, path: str = None, data: dict = None, params: dict = None, headers: dict = None, timeout: int = 600, resource_type: str = None, error_message: str = None) -> dict:

    error_vo = exception.ErrorVO()

    service_name = get_service_name(path)

    try:
        response = requests.request(method=request_method, url=path, json=data, headers=headerbuilder(headers), timeout=timeout , params=params, verify=False)
    except Exception as err:
        logger.error(f"Unable to process request: {err}")
        error_vo.retryable = True
        error_vo.message = camel_to_upper_snake(type(err).__name__)
        error_vo.description = get_friendly_error_message(err, service_name=service_name, resource_type=resource_type)
        error_vo.error_type = cowenums.ErrorType.SYSTEM_ERROR
        raise exception.CCowExceptionVO(status_code=500, error_vo=error_vo)

    if response.status_code == 204 and not response.text:
        return None

    if response.status_code in [200, 201] and not response.text:
        return None

    try:
        response_dict = response.json()
    except Exception as err:
        logger.error(f"Unable to convert the response to JSON: {err}")
        error_vo.retryable = True
        if not error_message:
            error_message = f"Unable to convert the response to JSON: {err}"

        error_vo.message = error_message
        error_vo.description = get_resource_specific_error(resource_type=resource_type, error_message=error_message)
        error_vo.error_type = cowenums.ErrorType.SYSTEM_ERROR
        raise exception.CCowExceptionVO(status_code=500, error_vo=error_vo)

    if response.status_code in [200, 201, 204]:
        return response_dict

    error_vo = exception.ErrorVO()

    if isinstance(response_dict, dict):
        error_vo = exception.ErrorVO.from_dict(response_dict)

    logger.error(f"Error while getting responses: {response.status_code}, {response.reason}, {path}")
    match (response.status_code):
        case 500:
            if error_vo and (error_vo.description or error_vo.message) and response.status_code:
                raise exception.CCowExceptionVO(status_code=response.status_code, error_vo=error_vo)
            error_vo.retryable = True
            error_vo.message = errordesc.InternalServerError
            error_vo.description = get_resource_specific_error(resource_type=resource_type, error_message=error_message)
            error_vo.error_type = cowenums.ErrorType.SYSTEM_ERROR
        case 400 | 401 | 403 | 404:
            error_vo.retryable = False
            if error_vo and (error_vo.description or error_vo.message) and response.status_code:
                raise exception.CCowExceptionVO(status_code=response.status_code, error_vo=error_vo)
            error_vo.message = response.reason
            error_vo.description = get_resource_specific_error(resource_type=resource_type, error_message=error_message)
            error_vo.error_type = cowenums.ErrorType.USER_ERROR
        case _:
            error_vo.retryable = True
            error_vo.message = f"Unexpected status code: {response.status_code}"
            error_vo.description = response.reason
            error_vo.error_type = cowenums.ErrorType.UNKNOWN_ERROR

    raise exception.CCowExceptionVO(status_code=response.status_code, error_vo=error_vo)


def get_resource_specific_error(resource_type: str = None, error_message: str = None):
    if resource_type and error_message:
        return f"An error occurred while retrieving the '{resource_type}'. {error_message}"
    if resource_type:
        return f"An error occurred while retrieving the '{resource_type}'"
    return error_message


def get_friendly_error_message(e, service_name: str = None, resource_type: str = None, error_message: str = None):
    if error_message:
        return error_message
    if resource_type:
        return f"An error occurred while retrieving '{resource_type}'"
    if isinstance(e, ConnectionError):
        server_name = "server"
        if service_name:
            server_name = f"'{service_name}'"
        return f"Failed to connect to the {server_name}. Please check your network connection."
    elif isinstance(e, Timeout):
        return "The request timed out. The server may be busy, or your network connection is slow."
    elif isinstance(e, TooManyRedirects):
        return "The request exceeded the maximum number of redirects. The URL might be misconfigured."
    elif isinstance(e, HTTPError):
        return f"HTTP error occurred: {e.response.status_code} - {e.response.reason}"
    elif isinstance(e, RequestException):
        return "An error occurred while making the request. Please try again later."
    else:
        return str(e)


def camel_to_upper_snake(name):
    snake_case = re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()
    upper_snake_case = snake_case.upper()
    return upper_snake_case


def get_service_name(url):
    """Extracts the service name from a URL.

    Args:
      url: The URL to extract the service name from.

    Returns:
      The service name, or None if the URL is invalid or lacks a service name.
    """

    try:
        parsed_url = urllib.parse.urlparse(url)
        netloc = parsed_url.netloc

        if not netloc:
            return None
        service_name, _, _ = netloc.partition(":")
        return service_name
    except ValueError:
        return None
