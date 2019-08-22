from rest_framework import permissions


class UpdateOwnAccount(permissions.BasePermission):
    """Allow users to update their own account"""

    def has_object_permission(self, request, view, obj):
        """Check user is trying to edit their own account"""

        if request.method in permissions.SAFE_METHODS:
            return True

        return obj.uuid == request.user.uuid