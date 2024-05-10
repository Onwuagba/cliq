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
        Sends data back as a HTTP response.

        Args:
            self: The instance of the class.

        Returns:
            A Response object with the data and status code.
        """

        if not all([self.message, self.status_code, self.status]):
            raise ValidationError("message and status code cannot be empty")

        data = {"status": self.status}
        if self.status == "failed":
            if isinstance(self.message, (ValidationError, ValueError)):
                data["message"] = self.message.args[0]
            elif isinstance(self.message, dict):
                data["message"] = self.convert_to_string(self.message)
            else:
                data["message"] = self.message
        else:
            data["data"] = self.message
        status_code = self.status_code

        return Response(data, status=status_code)

    def convert_to_string(self, message):
        res = []
        for key, value in message.items():
            if isinstance(value, list):
                value = " ".join(value)
            res.append(f"{key.upper().replace('_', ' ')}: {value}")
        return "| ".join(res)
