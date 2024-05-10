from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView

from main.views import (
    ChangePasswordView,
    ConfirmEmailView,
    CustomTokenView,
    DeleteAccountView,
    ForgotPasswordView,
    Home,
    LogoutView,
    RegenerateEmailVerificationView,
    RegisterAPIView,
    ResetPasswordView,
)

app_name = "main"

urlpatterns = [
    # auth
    path("", Home.as_view()),
    path("signup/", RegisterAPIView.as_view(), name="signup"),
    path(
        "confirm_email/<str:uid>/<str:token>",
        ConfirmEmailView.as_view(),
        name="confirm_email",
    ),
    path("regenerate_email/", RegenerateEmailVerificationView.as_view()),
    path("forgot_password/", ForgotPasswordView.as_view()),
    path(
        "forgot_password/update/<str:uid>/<str:token>/",
        ChangePasswordView.as_view(),
        name="change_password",
    ),
    path("delete_account", DeleteAccountView.as_view(), name="delete_account"),
    path("login/", CustomTokenView.as_view(), name="token_obtain_pair"),
    path("refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("validate_token/", TokenVerifyView.as_view(), name="validate"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("reset_password/", ResetPasswordView.as_view(), name="reset_password"),
]

