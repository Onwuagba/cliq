from datetime import datetime

from django.contrib import auth
from django.utils import timezone
from django.http import HttpResponseForbidden

from shortlink.settings import ALLOWED_ADMIN_IPS


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
                datetime_obj = datetime.strptime(date_string, date_format)

                inactive_duration = timezone.now() - datetime_obj
                if inactive_duration.total_seconds() > 300:
                    auth.logout(request)

            # timezone is set to str cos datetime is not serializable
            request.session["last_activity"] = str(timezone.now())

        return self.get_response(request)
