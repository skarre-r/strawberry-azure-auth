from __future__ import annotations

__all__ = ["RoleBasedPermission"]

from typing import Any
from strawberry.permission import BasePermission

from .types import Info


class RoleBasedPermission(BasePermission):
    """
    Base class for creating Azure AD role based permissions.

    Example:

        >>> from strawberry_azure_auth.permissions import RoleBasedPermission
        ...
        >>> class ReadPermission(RoleBasedPermission):
        ...     roles = ["App.Read"]
    """

    message: str
    roles: list[str]

    async def has_permission(self, source: Any, info: Info, **kwargs: Any) -> bool:
        if not info.context.authorized:
            if not self.message:
                self.message = "Unauthorized"
            if hasattr(info.context, "response"):
                info.context.response.status_code = 401
            return False
        if not any(role in info.context.roles for role in self.roles):
            if not self.message:
                self.message = "Forbidden"
            if hasattr(info.context, "response"):
                info.context.response.status_code = 403
            return False
        return True
