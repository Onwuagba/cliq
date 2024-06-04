from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import BasePermission

from shorty.utils import get_user_ip, is_ip_blacklisted


class IsAdmin(BasePermission):
    """
    Grant access to only admins (is_staff=True)
    """

    def has_permission(self, request, view):
        if bool(request.user and request.user.is_staff):
            return True
        raise PermissionDenied(
            {
                "message": "You do not have permission to perform this action.",
                "status": "failed",
            }
        )


class IsIPPermitted(BasePermission):
    """
    Checks if the user's IP is permitted to access the requested resource.
    """

    def has_permission(self, request, view):
        """
        Checks if the user has permission to access the requested resource.

        Returns:
            bool: True if the user has permission, False otherwise.

        Raises:
            PermissionDenied: If the user does not have permission and the request method is in the list
                {"POST", "PUT", "PATCH", "DELETE"}.

        """
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            ip_address = get_user_ip(request)

            if is_ip_blacklisted(ip_address):
                raise PermissionDenied(
                    {
                        "message": f"Access to this resource is restricted for IP {ip_address}",
                        "status": "failed",
                    }
                )

        return True
