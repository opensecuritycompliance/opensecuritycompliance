from enum import Enum


class Purpose(str, Enum):
    ASKMEANYTHING = "AskMeAnything"
    USERQUERY = "UserQuery"
    EVIDENCEQUERY = "EvidenceQuery"

    @staticmethod
    def from_str(label):
        if label in ("askmeanything", "askme", "AskMeAnything"):
            return Purpose.ASKMEANYTHING
        else:
            return Purpose.USERQUERY

    @staticmethod
    def check_Purpose_member(value):
        PurposeMember = [member.value for member in Purpose]
        return value in PurposeMember


class ErrorType(str, Enum):
    SYSTEM_ERROR = "SYSTEM_ERROR"
    USER_ERROR = "USER_ERROR"
    UNKNOWN_ERROR = "UNKNOWN_ERROR"


class UserError(str, Enum):
    INVALID_USER = "Invalid User"
