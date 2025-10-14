from compliancecowcards.constants import cowenums
from compliancecowcards.vo import exception

from typing import List, Optional



def raise_internal_server_error(message: str = None, description: str = None, component: str = None, retryable: bool = True, error_details: Optional[List[exception.ErrorDetailVO]] = None):
    error_vo = exception.ErrorVO(
        retryable=retryable,
        component=component,
        message=message,
        description=description,
        error_type=cowenums.ErrorType.SYSTEM_ERROR,
        error_details=error_details,
    )
    raise exception.CCowExceptionVO(status_code=500, error_vo=error_vo)


def raise_validation_error(message: str = None, description: str = None, component: str = None, retryable: bool = False, error_details: Optional[List[exception.ErrorDetailVO]] = None):
    raise_400_series_error(message=message, description=description, component=component, retryable=retryable, status_code=400, error_details=error_details)


def raise_unauthorised_error(message: str = None, description: str = None, component: str = None, retryable: bool = False, error_details: Optional[List[exception.ErrorDetailVO]] = None):
    raise_400_series_error(message=message, description=description, component=component, retryable=retryable, status_code=401, error_details=error_details)


def raise_404_error(message: str = None, description: str = None, component: str = None, retryable: bool = False, error_details: Optional[List[exception.ErrorDetailVO]] = None):
    raise_400_series_error(message=message, description=description, component=component, retryable=retryable, status_code=404, error_details=error_details)


def raise_400_series_error(message: str = None, description: str = None, component: str = None, retryable: bool = False, error_details: Optional[List[exception.ErrorDetailVO]] = None, status_code: int = None):
    error_vo = exception.ErrorVO(
        retryable=retryable,
        component=component,
        message=message,
        description=description,
        error_type=cowenums.ErrorType.USER_ERROR,
        error_details=error_details,
    )
    raise exception.CCowExceptionVO(status_code=status_code, error_vo=error_vo)


def str_to_bool(value):
    truthy_values = {"true", "yes", "1"}
    if isinstance(value, bool):
        return value
    elif isinstance(value, str):
        return value.lower() in truthy_values
    return False
