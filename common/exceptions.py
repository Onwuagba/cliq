from rest_framework import status
from rest_framework.exceptions import APIException

from common.utilities.api_response import CustomAPIResponse


class AccountLocked(APIException):
    status_code = status.HTTP_423_LOCKED
    default_detail = "Account temporarily locked, try again later."
    default_code = "account_locked"


class AlreadyExists(APIException):
    status_code = status.HTTP_409_CONFLICT
    default_detail = "Resource already exists"
    default_code = "already_exists"


class ThrottledException(APIException):
    status_code = 429
    default_detail = "Too many requests. Please wait."
    default_code = "throttled"

    def to_representation(self):
        return CustomAPIResponse(self.default_detail, self.status_code, "failed").send()
