from rest_framework import status
from rest_framework.exceptions import APIException


class AccountLocked(APIException):
    status_code = status.HTTP_423_LOCKED
    default_detail = "Account temporarily locked, try again later."
    default_code = "account_locked"


class AlreadyExists(APIException):
    status_code = status.HTTP_409_CONFLICT
    default_detail = "Resource already exists"
    default_code = "already_exists"
