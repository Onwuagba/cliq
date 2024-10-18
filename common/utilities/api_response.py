from rest_framework.exceptions import ValidationError
from rest_framework.response import Response


class CustomAPIResponse:
    def __init__(self, message, status_code, status):
        """
        Set the response data and status code.

        Args:
            message (str or dict): The message or data to be set in the response.
            status_code (int): The HTTP status code to be set in the response.
            status (str): The status string to be set in the response.

        Raises:
            ValidationError: If message and status code are empty.

        """
        self.message = message
        self.status_code = status_code
        self.status = status

    def send(self) -> Response:
        """
        Sends data back as an HTTP response.

        Returns:
            A Response object with the data and status code.
        """
        if not all([self.message, self.status_code, self.status]):
            raise ValidationError(
                "message, status_code, and status cannot be empty")

        data = {"status": self.status, "data": "", "error": ""}

        if self.status == "failed":
            data["error"] = self._get_error_message()
        else:
            data["data"] = self.message

        return Response(data, status=self.status_code)

    def _get_error_message(self):
        """
        Extracts the error message from the given error.

        If the error is a dict with an 'error' key, it will be extracted.
        If the error is an instance of ValidationError, ValueError, or Exception, it will be converted to a str.
        Otherwise, the error is converted to a str directly.

        :return: The error message as a str.
        """
        if isinstance(self.message, dict) and 'error' in self.message:
            return self._extract_error_detail(self.message['error'])
        elif isinstance(self.message, (ValidationError, ValueError, Exception)):
            return self._extract_error_detail(self.message)
        else:
            return str(self.message)

    def _extract_error_detail(self, error):
        """
        Extracts the error message from the given error.

        If the error has a 'detail' attribute, it is checked first. If it is a list, the first element is returned as a str.
        If it is a dict, the first value is returned as a str.
        If the error is a list, the first element is returned as a str.
        If the error is an instance of ValidationError, ValueError, or Exception, the first argument is returned as a str.
        Otherwise, the error is converted to a str directly.

        :param error: The error to extract the message from.
        :return: The error message as a str.
        """
        if hasattr(error, 'detail'):
            error_detail = error.detail
            if isinstance(error_detail, list):
                return str(error_detail[0])
            elif isinstance(error_detail, dict):
                return str(next(iter(error_detail.values()))[0])
        elif isinstance(error, list) and error:
            return str(error[0])
        elif hasattr(error, 'args') and error.args:
            return str(error.args[0])
        return str(error)
