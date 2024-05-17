from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import BasePermission


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
