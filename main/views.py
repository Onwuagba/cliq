# Hello! Welcome to shortlink API.
# All authentication endpoints were copied from existing code - Affily

import base64
import json
import logging

from base64 import urlsafe_b64decode
import os
from django.contrib.auth import get_user_model, logout

from django.contrib.auth.tokens import default_token_generator
from django.db.models import Q

from django.utils import timezone

from rest_framework import status
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.generics import CreateAPIView, UpdateAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt import views as jwt_views
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from common.utilities.api_response import CustomAPIResponse
from common.utilities.generics import check_email_username
from main.serializers import (
    ChangePasswordSerializer,
    ConfirmEmailSerializer,
    CustomTokenSerializer,
    ForgotPasswordSerializer,
    LogoutSerializer,
    RegenerateEmailVerificationSerializer,
    RegistrationSerializer,
    ResetPasswordSerializer,
)
from main.constants import admin_support_sender, email_sender
from main.tasks import send_notif_email
from main.models import CustomToken
from common.exceptions import AccountLocked, AlreadyExists
from dotenv import load_dotenv

logger = logging.getLogger("app")
UserModel = get_user_model()
load_dotenv()


class Home(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args):
        user_name = request.user
        message = f"Welcome {user_name.first_name}"
        status_code = status.HTTP_200_OK
        status_msg = "success"

        return CustomAPIResponse(message, status_code, status_msg).send()


class RegisterAPIView(CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = RegistrationSerializer
    http_method_names = ["post"]

    def post(self, request):
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        try:
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                message = (
                    "Registration successful."
                    "Please confirm your email to complete set up"
                )
                status_code = status.HTTP_201_CREATED
                status_msg = "success"
            else:
                message = serializer.errors
                status_code = status.HTTP_400_BAD_REQUEST
                status_msg = "failed"
        except Exception as e:
            logger.error(
                f"Exception in registration. Email {request.data.get('email')}: str(e.args[0])"
            )
            message = e.args[0]
            status_code = status.HTTP_400_BAD_REQUEST
            status_msg = "failed"

        return CustomAPIResponse(message, status_code, status_msg).send()


class ConfirmEmailView(UpdateAPIView):
    """
    User confirms their emails after registration.
    """

    permission_classes = (AllowAny,)
    serializer_class = ConfirmEmailSerializer
    http_method_names = ["patch"]

    def get_object(self, uid, token):
        try:
            token_obj = self.get_user(uid, token)
        except Exception as e:
            raise ValidationError(e) from e

        return token_obj

    def get_user(self, uid, token):
        if not all([uid, token]):
            raise ValidationError("Invalid confirmation link.")

        uid = urlsafe_b64decode(uid).decode("utf-8")
        user = UserModel.objects.filter(id=uid).first()
        token_obj = CustomToken.objects.filter(key=token).first()

        if not user or not token_obj or token_obj.user != user:
            raise ValidationError(
                "Invalid verification link. Unable to retrieve user information"
            )

        if (
            token_obj.expiry_date is not None
            and token_obj.expiry_date < timezone.localtime()
        ):
            raise ValidationError("Confirmation link has expired")

        return token_obj

    def patch(self, request, **kwargs):
        uid = kwargs.get("uid", None)
        token = kwargs.get("token", None)

        try:
            obj = self.get_object(uid, token)
            serializer = self.serializer_class(
                obj, data=request.data, context={"request": request}
            )
            serializer.is_valid(raise_exception=True)
            serializer.save()
            message = "Account activation is complete. Please proceed to login"
            status_msg = "success"
            status_code = status.HTTP_200_OK
        except Exception as e:
            logger.error(
                f"Exception in confirming email - {request.data.get('email')}: str(e.args[0])"
            )
            message = e.args[0]
            status_msg = "failed"
            status_code = status.HTTP_400_BAD_REQUEST

        return CustomAPIResponse(message, status_code, status_msg).send()


class ForgotPasswordView(APIView):
    permission_classes = (AllowAny,)
    serializer_class = ForgotPasswordSerializer
    http_method_names = ["post"]

    def post(self, request, **kwargs):
        """
        Params:
        - Email/Username

        Returns:
        - A JSON response containing a message and status.
        """
        reset_data = request.data

        try:
            # check if email or username is in request
            check_email_username(reset_data)

            change_serializer = self.serializer_class(data=reset_data)
            change_serializer.is_valid(raise_exception=True)
            change_serializer.create_token_send_email(request)
            message = "Password reset link sent successfully. Please check your email."
            status_msg = "success"
            status_code = status.HTTP_200_OK
        except Exception as e:
            logger.error(
                f"Exception in forgot password - {reset_data.get('email')}: str(e.args[0])"
            )
            message = e.args[0]
            status_msg = "failed"
            status_code = status.HTTP_400_BAD_REQUEST

        return CustomAPIResponse(message, status_code, status_msg).send()


class ChangePasswordView(UpdateAPIView):
    """change password endpoint is called from the email clicking forgot password"""

    permission_classes = (AllowAny,)
    serializer_class = ChangePasswordSerializer
    http_method_names = ["patch"]

    def get_object(self, uid, token):

        if not all([uid, token]):
            raise ValidationError(
                "Link is invalid or expired."
                " Please begin the forgot password process again"
            )

        uid = urlsafe_b64decode(uid).decode("utf-8")
        try:
            user = UserModel.objects.get(uid=uid)
        except UserModel.DoesNotExist as e:
            raise ValidationError(
                "No user found with user ID. "
                "Please begin the forgot password process again"
            ) from e

        if not default_token_generator.check_token(user, token):
            raise ValidationError("Reset password link has expired.")

        return user

    def patch(self, request, **kwargs):
        uid = kwargs.get("uid", "")
        token = kwargs.get("token", "")

        try:
            user = self.get_object(uid, token)
            data = request.data
            serializer = self.serializer_class(user, data=data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            message = "Password changed successfully. Please proceed to login"
            status_msg = "success"
            status_code = status.HTTP_200_OK
        except Exception as e:
            logger.error(f"Exception in change password: str(e.args[0])")
            message = e.args[0]
            status_msg = "failed"
            status_code = status.HTTP_400_BAD_REQUEST

        return CustomAPIResponse(message, status_code, status_msg).send()


class RegenerateEmailVerificationView(CreateAPIView):
    # endpoint to resend account confirmation instructions
    permission_classes = (AllowAny,)
    serializer_class = RegenerateEmailVerificationSerializer
    http_method_names = ["post"]

    def post(self, request, **kwargs):
        """
        Params:
        - Email

        Returns:
        - A JSON response containing a message and status.
        """

        try:
            # check if email is in request
            check_email_username(request.data)

            change_serializer = self.serializer_class(
                data=request.data, context={"request": request}
            )
            change_serializer.is_valid(raise_exception=True)
            message = "Verification email sent."
            status_msg = "success"
            status_code = status.HTTP_200_OK
        except Exception as e:
            logger.error(f"Exception in regenerate email: str(e.args[0])")
            message = e.args[0]
            status_msg = "failed"
            status_code = status.HTTP_400_BAD_REQUEST

        return CustomAPIResponse(message, status_code, status_msg).send()


class DeleteAccountView(APIView):
    permission_classes = (IsAuthenticated,)
    http_method_names = ["delete"]

    def get_object(self, request, email=None):

        if user := UserModel.objects.filter(email=email).first():
            if request.user != user:
                raise PermissionDenied("Access Denied.")
            return user
        else:
            raise ValidationError("User account not found.")

    def delete(self, request, **kwargs):
        """
        Deactivate account
        """
        email = request.data.get("email")
        try:
            check_email_username(request.data)

            obj = self.get_object(request, email)
            obj.is_deleted = True
            obj.is_active = False
            obj.save()
            message = "Account deleted successfully. Data will be deleted after 30 days"
            status_msg = "success"
            status_code = status.HTTP_200_OK

            self.send_mail(obj)
        except (PermissionDenied, Exception) as e:
            logger.info(f"Exception in delete account: str(e.args[0])")
            message = e.args[0]
            status_msg = "failed"
            status_code = (
                status.HTTP_403_FORBIDDEN
                if isinstance(e, PermissionDenied)
                else status.HTTP_400_BAD_REQUEST
            )
        return CustomAPIResponse(message, status_code, status_msg).send()

    def send_mail(self, instance):
        email_content = {
            "subject": "Your Shortlink account has been deleted ✖",
            "sender": email_sender,
            "recipient": instance.email,
            "template": "delete-account.html",
        }
        context = {
            "username": instance.first_name,
            "email": instance.email,
            "admin_email": admin_support_sender,
        }
        logger.info(f"context for email called from delete account endpoint: {context}")

        # call celery
        send_notif_email.delay(email_content, context)


# customise JWT login payload to accept username or email
class CustomTokenView(jwt_views.TokenObtainPairView):
    serializer_class = CustomTokenSerializer
    token_obtain_pair = jwt_views.TokenObtainPairView.as_view()
    http_method_names = ["post"]

    def post(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(
                data=request.data,
                context={
                    "request": self.request,
                },
            )
            serializer.is_valid(raise_exception=True)
            return Response(serializer._validated_data, status=status.HTTP_200_OK)
        except TokenError as ex:
            raise InvalidToken(ex.args[0]) from ex
        except (ValidationError, AccountLocked, Exception) as exc:
            message = exc.args[0]
            status_msg = "failed"
            status_code = (
                status.HTTP_401_UNAUTHORIZED
                if isinstance(exc, ValidationError)
                else (
                    status.HTTP_423_LOCKED
                    if isinstance(exc, AccountLocked)
                    else status.HTTP_400_BAD_REQUEST
                )
            )

        return CustomAPIResponse(message, status_code, status_msg).send()


class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = LogoutSerializer
    http_method_names = ["post"]

    def post(self, request):
        try:
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            logout(request)
            message = "Logout successful"
            status_msg = "success"
            status_code = status.HTTP_205_RESET_CONTENT

        except Exception as e:
            message = e.args[0]
            status_msg = "failed"
            status_code = status.HTTP_400_BAD_REQUEST

        return CustomAPIResponse(message, status_code, status_msg).send()


class ResetPasswordView(UpdateAPIView):
    """
    Allow authenticated user to change password

    Accepts - password, confirm_password, old_password
    """

    permission_classes = (IsAuthenticated,)
    serializer_class = ResetPasswordSerializer
    http_method_names = ["patch"]

    def get_object(self):
        return self.request.user

    def patch(self, request, **kwargs):
        user = self.get_object()
        change_data = request.data
        change_serializer = self.serializer_class(user, data=change_data)
        try:
            change_serializer.is_valid(raise_exception=True)
            change_serializer.save()
            message = "Password reset completed."
            status_msg = "success"
            status_code = status.HTTP_200_OK
        except Exception as e:
            logger.error(f"Exception in resetPassword: {str(e.args[0])}")
            message = e.args[0]
            status_msg = "failed"
            status_code = status.HTTP_400_BAD_REQUEST

        return CustomAPIResponse(message, status_code, status_msg).send()
