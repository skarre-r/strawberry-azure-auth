__version__ = "2.0.0"

__all__ = ["AzureAuthExtension", "RoleBasedPermission"]

from .extension import AzureAuthExtension
from .permissions import RoleBasedPermission
