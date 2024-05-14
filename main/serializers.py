import logging
from base64 import urlsafe_b64encode

from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.models import update_last_login
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.utils import timezone
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt import serializers as jwt_serializers

from main.models import CustomToken, UserAccount
from main.signals import user_created
from main.constants import admin_support_sender, email_sender
from main.tasks import send_notif_email
from common.exceptions import AccountLocked, AlreadyExists

logger = logging.getLogger("app")
UserModel = get_user_model()


token_validator = RegexValidator(
    regex=r"^[a-zA-Z0-9-]+$",
    message=(
        "Invalid token format. Only alphanumeric characters and hyphens are allowed."
    ),
)


class RegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        max_length=128,
        min_length=8,
        write_only=True,
        required=True,
        validators=[validate_password],
    )
    confirm_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = get_user_model()
        exclude = [
            "is_deleted",
            "is_active",
            "last_login",
            "date_joined",
        ]

    def validate(self, data):
        if not data.get("password") or not data.get("confirm_password"):
            raise serializers.ValidationError("Please enter a password and confirm it")
        if data.get("password") != data.get("confirm_password"):
            raise serializers.ValidationError("Your passwords do not match")

        return data

    def create(self, validated_data):
        password = validated_data.pop("password")
        email = validated_data.pop("email").lower()
        validated_data.pop("confirm_password", None)

        try:
            with transaction.atomic():
                user, created = UserModel.objects.get_or_create(
                    email__iexact=email, defaults=validated_data
                )
                if not created:
                    if user.is_active:
                        raise AlreadyExists("account already exists. Please login")
                    raise AlreadyExists(
                        "account already exists. Please request confirmation again"
                    )
                else:
                    user.set_password(password)
                    user.save()

        except Exception as e:
            raise serializers.ValidationError(str(e))

        user_created.send(
            sender=self.Meta.model,
            instance=user,
            created=True,
            request=self.context.get("request"),
        )

        return user


class ConfirmEmailSerializer(serializers.Serializer):
    def update(self, instance, validated_data):
        with transaction.atomic():
            try:
                CustomToken.objects.filter(user=instance.user, key=instance.key).update(
                    expiry_date=instance.created,
                    verified_on=timezone.localtime(),
                )
                UserAccount.objects.filter(id=instance.user.id).update(is_active=True)

                self.welcome_mail(instance)
            except Exception as e:
                transaction.set_rollback(True)
                logger.error(f"Error confirming email for {instance.user.email}: {e}")
                raise serializers.ValidationError(
                    "Error occurred confirming your email. Please try again later."
                ) from e
        return instance

    def welcome_mail(self, instance):
        request = self.context.get("request")
        email_content = {
            "subject": "Welcome to ShortLink! 🎉",
            "sender": email_sender,
            "recipient": instance.user.email,
            "template": "welcome-publisher.html",
        }
        url = f"{request.scheme}://{request.get_host()}/login"
        context = {
            "username": instance.user.first_name,
            "email": instance.user.email,
            "url": url,
        }
        logger.info(f"context for publisher welcome email to be sent: {context}")

        # call celery
        send_notif_email.delay(email_content, context)
        return True


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=False)
    username = serializers.CharField(required=False)

    def validate(self, data):
        try:
            user = UserModel.objects.get(email__iexact=data.get("email"))
        except (ValidationError, UserModel.DoesNotExist) as e:
            raise serializers.ValidationError("No account found with this email") from e

        return user

    def create_token_send_email(self, request, *args):
        user = self.validated_data
        token = default_token_generator.make_token(user)
        uid = urlsafe_b64encode(bytes(str(user.uid), "utf-8")).decode("utf-8")

        email_content = {
            "subject": "Reset password verification",
            "sender": email_sender,
            "recipient": user.email,
            "template": "forgot_password.html",
        }
        reset_url = request.build_absolute_uri(f"update/{uid}/{token}/")
        print(reset_url)
        context = {"username": user.username, "url": reset_url}
        logger.info(f"context for forgot email to be sent: {user.username}")

        # call celery
        send_notif_email.delay(email_content, context)
        return True


class ChangePasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(
        max_length=128,
        min_length=8,
        write_only=True,
        required=True,
        validators=[validate_password],
    )
    confirm_password = serializers.CharField(write_only=True, required=True)

    def validate(self, data):
        if not data.get("new_password") or not data.get("confirm_password"):
            raise serializers.ValidationError("Please enter a password and confirm it")
        if data.get("new_password") != data.get("confirm_password"):
            raise serializers.ValidationError("Your passwords do not match")

        return data

    def update(self, instance, validated_data):
        if not instance.check_password(validated_data["new_password"]):
            instance.set_password(validated_data["new_password"])
            instance.save()

            self.send_mail(instance)
            return instance
        else:
            raise serializers.ValidationError(
                "Your password is similar to one previously used. Change it!"
            )

    def send_mail(self, instance):
        email_content = {
            "subject": "Password successfully changed on ShortLink",
            "sender": email_sender,
            "recipient": instance.email,
            "template": "password_changed.html",
        }
        context = {
            "username": instance.first_name,
            "email": instance.email,
            "admin_email": admin_support_sender,
        }
        logger.info(f"context for password changed email to be sent: {context}")

        # call celery
        send_notif_email.delay(email_content, context)


class RegenerateEmailVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField(required=False)
    username = serializers.CharField(required=False)

    def validate(self, data):
        try:
            user = UserModel.objects.get(
                email=data.get("email"),
                is_deleted=False,
            )
        except (ValidationError, UserModel.DoesNotExist) as e:
            raise serializers.ValidationError("No account found with this email") from e

        if user and user.is_active is True and not user.is_deleted:
            raise serializers.ValidationError("Account validated already")

        user_created.send(
            sender=UserModel,
            instance=user,
            created=True,
            request=self.context.get("request"),
        )

        return user


class CustomTokenSerializer(jwt_serializers.TokenObtainPairSerializer):
    email = serializers.EmailField(required=False)
    password = serializers.CharField(required=True)

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        return token

    @property
    def fields(self):
        fields = super().fields
        return fields

    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")
        req = self.context["request"]

        if not (password or email):
            raise serializers.ValidationError("email and password are required")

        authenticate_kwargs = {
            self.username_field: email,
            "password": password,
        }

        try:
            user = authenticate(req, **authenticate_kwargs)
            if not user or user.is_deleted:
                raise AuthenticationFailed("No account found with this credential")

            # ToDo: This would never happen cos the model manager already removes user with not active flag.
            if not user.is_active:
                data = {"email": email}
                RegenerateEmailVerificationSerializer(
                    context={"request": req}
                ).validate(data)
                raise AuthenticationFailed(
                    "Account not verified yet. Check email to complete verification"
                )

        except Exception as e:
            logger.error(f"Authentication failed for **{email}** with error: {e}")

            if isinstance(e, AccountLocked):
                raise
            raise ValidationError(e) from e

        return self.return_token(user)

    def return_token(self, user):
        token = self.get_token(user)
        update_last_login(None, user)  # fix: simplejwt last_login attr not working
        return {
            "access": str(token.access_token),
            "refresh": str(token),
        }


class ResetPasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        max_length=128,
        min_length=8,
        write_only=True,
        required=True,
        validators=[validate_password],
    )
    confirm_password = serializers.CharField(write_only=True, required=True)
    old_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = UserAccount
        fields = ("old_password", "password", "confirm_password")

    def validate(self, data):
        error = {}
        user = self.instance

        if not data.get("password") or not data.get("confirm_password"):
            error["password"] = "Please enter a password and confirm it."
        if data.get("password") != data.get("confirm_password"):
            error["password"] = "Your passwords do not match"
        if not user.check_password(data.get("old_password")):
            error["password"] = "Old password not valid"
        if data.get("password") == data.get("old_password"):
            error["password"] = "New password cannot be same as old password"

        if error:
            raise serializers.ValidationError(error)

        data.pop("old_password")
        data.pop("confirm_password")
        return data

    def update(self, instance, validated_data):
        instance.set_password(validated_data["password"])
        instance.save()

        email_content = {
            "subject": "Your password was recently changed",
            "sender": email_sender,
            "recipient": instance.email,
            "template": "password_changed.html",
        }
        context = {"username": instance.first_name}
        logger.info(f"context for reset password email to be sent: {context}")

        send_notif_email.delay(email_content, context)

        return instance


class LogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()
