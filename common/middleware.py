import hashlib
import hmac
import json
from datetime import datetime
import time
import logging

from django.conf import settings

from django.contrib import auth
from django.utils import timezone
from django.http import HttpResponseForbidden, JsonResponse
from django.utils.deprecation import MiddlewareMixin
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from rest_framework_simplejwt.authentication import JWTAuthentication

from shortlink.settings import ALLOWED_ADMIN_IPS

logger = logging.getLogger("app")


class RestrictAdminMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if (request.path.startswith("/admin/")) and self.get_client_ip(
            request
        ) not in ALLOWED_ADMIN_IPS:
            return HttpResponseForbidden(
                "You are not authorized to access the admin interface."
            )

        return self.get_response(request)

    def get_client_ip(self, request):
        return (
            x_forwarded_for.split(",")[0].strip()
            if (x_forwarded_for := request.META.get("HTTP_X_FORWARDED_FOR"))
            else request.META.get("REMOTE_ADDR")
        )


class AutoLogoutMiddleware:
    """
    Middleware to logout admin after 5 mins of inactivity
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated and request.user.is_staff:
            if last_activity := request.session.get("last_activity"):
                # last_activity comes back as str so I convert to datetime
                date_string = last_activity
                date_format = "%Y-%m-%d %H:%M:%S.%f%z"
                datetime_obj = datetime.strptime(
                    date_string, date_format)

                inactive_duration = timezone.now() - datetime_obj
                if inactive_duration.total_seconds() > 300:
                    auth.logout(request)

            # timezone is set to str cos datetime is not serializable
            request.session["last_activity"] = str(timezone.now())

        return self.get_response(request)


class ChecksumMiddleware(MiddlewareMixin):
    # security middleware to secure communication and ensure data integrity
    def compute_hmac(self, request, key):
        """
        Compute the HMAC (Hash-based Message Authentication Code) of the given data using the provided key.

        Parameters:
            request: HTTPRequest Object.
            key (bytes): The secret key used for HMAC computation.

        Returns:
            str: The computed HMAC as a hexadecimal string, or None if the data type is not supported.
        """
        data = request.body
        if request.content_type == 'multipart/form-data':
            # For multipart form data, use only the POST data for HMAC
            # for image upload in qr generation
            data = json.dumps(request.POST.dict(), sort_keys=True).encode("utf-8")
            return hmac.new(key, data, hashlib.sha256).hexdigest()
        elif isinstance(data, bytes):
            return hmac.new(key, data, hashlib.sha256).hexdigest()
        elif isinstance(data, str):
            return hmac.new(key, data.encode("utf-8"), hashlib.sha256).hexdigest()
        elif isinstance(data, dict):
            return hmac.new(
                key, json.dumps(data, sort_keys=True).encode(
                    "utf-8"), hashlib.sha256
            ).hexdigest()
        return None

    def process_request(self, request):
        """
        Process the incoming request and check if it contains a valid HMAC.

        Args:
            request (HttpRequest): The incoming request object.

        Returns:
            JsonResponse: If the received HMAC is invalid, returns a JSON response with an error message and the computed and received HMACs. If an exception occurs during the HMAC computation, returns a JSON response with the error message.

        Raises:
            None
        """
        if request.method in ["POST", "PUT", "PATCH"]:
            try:
                if not request.body or request.path.startswith("/admin/"):
                    # qr code generation is a POST request & may not have a body
                    return
                received_hmac = request.META.get("HTTP_X_HMAC")
                if not received_hmac:
                    return JsonResponse(
                        {
                            "message": "Invalid request",
                            "status": "failed",
                        },
                        status=401,
                    )

                secret_key = settings.SECRET_KEY.encode("utf-8")
                computed_hmac = self.compute_hmac(request, secret_key)

                if received_hmac != computed_hmac:
                    return JsonResponse(
                        {
                            "message": "Request validation failed. Ensure request is correctly signed",
                            "status": "failed",
                            # "computed_hmac": computed_hmac,
                            # "received_hmac": received_hmac,
                        },
                        status=401,
                    )

            except Exception as e:
                return JsonResponse({"error": str(e)}, status=401)

    def process_response(self, request, response):
        """
        Process the response by adding an HMAC header if the content type is JSON.

        Parameters:
            request (HttpRequest): The incoming request object.
            response (HttpResponse): The response object to be processed.

        Returns:
            HttpResponse: The processed response object with an HMAC header added if the content type is JSON.

        Raises:
            None
        """
        if response["Content-Type"] == "application/json":
            try:
                payload = response.content
                secret_key = settings.SECRET_KEY.encode("utf-8")
                computed_hmac = self.compute_hmac(payload, secret_key)
                response["X-HMAC"] = computed_hmac
            except Exception as e:
                response["X-HMAC-Error"] = str(e)
        return response


class JWTCookieMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        access_cookie = settings.SIMPLE_JWT["AUTH_COOKIE"]
        refresh_cookie = settings.SIMPLE_JWT["REFRESH_COOKIE"]
        access_token = request.COOKIES.get(access_cookie)
        refresh_token = request.COOKIES.get(refresh_cookie)

        if access_token:
            jwt_authenticator = JWTAuthentication()
            try:
                # raw_token = access_token.encode(HTTP_HEADER_ENCODING)
                validated_token = jwt_authenticator.get_validated_token(
                    access_token)
                exp_time = validated_token["exp"]
                current_time = int(time.time())

                # Check if token is about to expire in 1 minute
                if exp_time - current_time < 60 and refresh_token:
                    new_access_token = self.refresh_access_token(
                        refresh_token)
                    if new_access_token:
                        self.set_jwt_cookie(request, new_access_token)
                        request.META["HTTP_AUTHORIZATION"] = (
                            f"Bearer {new_access_token}"
                        )

                # Update request authorization header with the access token
                # request.META['HTTP_AUTHORIZATION'] = f'Bearer {access_token}'
                request.user = jwt_authenticator.get_user(
                    validated_token)
            except TokenError:
                if refresh_token:
                    new_access_token = self.refresh_access_token(
                        refresh_token)
                    if new_access_token:
                        self.set_jwt_cookie(request, new_access_token)
                        request.META["HTTP_AUTHORIZATION"] = (
                            f"Bearer {new_access_token}"
                        )
                        validated_token = jwt_authenticator.get_validated_token(
                            new_access_token
                        )
                        request.user = jwt_authenticator.get_user(
                            validated_token)
                else:
                    request.user = None
            except Exception as e:
                logger.error(f"Error from JWT middleware: {
                             str(e.args[0])}")
                request.user = None
        else:
            request.user = None

        response = self.get_response(request)
        return response

    def refresh_access_token(self, refresh_token):
        try:
            refresh = RefreshToken(refresh_token)
            return str(refresh.access_token)
        except TokenError:
            return None

    def set_jwt_cookie(self, response, token):
        cookie_max_age = settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"].total_seconds(
        )
        response.set_cookie(
            key=settings.SIMPLE_JWT["AUTH_COOKIE"],
            value=token,
            max_age=cookie_max_age,
            secure=settings.SIMPLE_JWT["AUTH_COOKIE_SECURE"],
            httponly=settings.SIMPLE_JWT["AUTH_COOKIE_HTTP_ONLY"],
            samesite=settings.SIMPLE_JWT["AUTH_COOKIE_SAMESITE"],
        )
