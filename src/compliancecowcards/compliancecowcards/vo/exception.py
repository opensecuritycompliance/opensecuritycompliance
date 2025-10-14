from typing import List, Optional, Any, Dict
from django.http import JsonResponse

from compliancecowcards.constants import cowenums


class ErrorVO:
    def __init__(self, service: Optional[str] = None, component: Optional[str] = None, error_type: Optional[cowenums.ErrorType] = None, specific_issue: Optional[str] = None, retryable: bool = False, criticality: Optional[str] = None, message: Optional[str] = None, description: Optional[str] = None, error_details: Optional[List["ErrorDetailVO"]] = None, debug_id: Optional[str] = None):
        self.service: Optional[str] = service
        self.component: Optional[str] = component
        self.error_type: Optional[cowenums.ErrorType] = error_type
        self.specific_issue: Optional[str] = specific_issue
        self.retryable: bool = retryable

        self.criticality: Optional[str] = criticality
        self.message: Optional[str] = message
        self.description: Optional[str] = description
        self.error_details: List["ErrorDetailVO"] = error_details or []
        self.debug_id: Optional[str] = debug_id

    def __str__(self) -> str:
        error_code_slice = [
            self.service or "NA",
            self.component or "NA",
            self.error_type or "NA",
            self.specific_issue or "NA",
            "Y" if self.retryable else "N",
        ]
        error_code_str = "-".join(error_code_slice)
        return f"{error_code_str} | Criticality: {self.criticality} | Message: {self.message}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "service": self.service,
            "component": self.component,
            "errorType": self.error_type,
            "specificIssue": self.specific_issue,
            "retryable": self.retryable,
            "Criticality": self.criticality,
            "Message": self.message,
            "Description": self.description,
            "ErrorDetails": [detail.to_dict() for detail in self.error_details],
            "DebugID": self.debug_id,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ErrorVO":
        error_details = [ErrorDetailVO.from_dict(detail) for detail in data.get("errorDetails", [])]
        return cls(
            service=data.get("service", None),
            component=data.get("component", None),
            error_type=data.get("errorType", None),
            specific_issue=data.get("specificIssue", None),
            retryable=data.get("retryable", False),
            criticality=data.get("Criticality", None),
            message=data.get("Message", None),
            description=data.get("Description", None),
            error_details=error_details,
            debug_id=data.get("DebugID", None),
        )


class ErrorDetailVO:
    def __init__(self, field: Optional[str] = None, value: Optional[Any] = None, location: Optional[str] = None, issue: Optional[str] = None):
        self.field: Optional[str] = field
        self.value: Optional[Any] = value
        self.location: Optional[str] = location
        self.issue: Optional[str] = issue

    def to_dict(self) -> Dict[str, Any]:
        return {
            "Field": self.field,
            "Value": self.value,
            "Location": self.location,
            "Issue": self.issue,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ErrorDetailVO":
        return cls(
            field=data.get("Field", None),
            value=data.get("Value", None),
            location=data.get("Location", None),
            issue=data.get("Issue", None),
        )


class ErrorResponseVO:
    def __init__(self, error=None, status_code=None):
        self.error = error or ErrorVO()
        self.status_code = status_code

    def to_dict(self) -> Dict[str, Any]:
        return {
            "Error": self.error,
            "StatusCode": self.status_code,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ErrorDetailVO":
        return cls(
            field=data.get("Error", None),
            value=data.get("StatusCode", None),
        )


class CCowExceptionVO(Exception):
    def __init__(self, message: str = None, status_code: int = None, error_vo: "ErrorVO" = None, other_info: dict = None):
        # super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.error_vo = error_vo
        self.other_info = other_info

    def to_dict(self) -> dict:
        if self.error_vo:
            if not self.error_vo.message and self.message:
                self.error_vo.message = self.message
        return self.error_vo.to_dict()

    def __str__(self):
        base_message = super().__str__()
        if self.status_code:
            base_message += f" (Status code: {self.status_code})"
        if self.error_vo and self.error_vo.description:
            base_message += f" - Details: {self.error_vo.description}"
        return base_message

    def to_json_response(self) -> JsonResponse:
        return JsonResponse(remove_none_values(self.error_vo.to_dict()), safe=False, status=self.status_code)


def remove_none_values(d):
    if isinstance(d, dict):
        return {k: remove_none_values(v) for k, v in d.items() if v is not None and v != {} and v != []}
    elif isinstance(d, list):
        return [remove_none_values(i) for i in d if i is not None and i != [] and i != {}]
    else:
        return d
