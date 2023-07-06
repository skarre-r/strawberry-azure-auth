__version__ = "2.1.0"

__all__ = ["AzureAuthExtension", "RoleBasedPermission"]

from .extension import AzureAuthExtension
from .permissions import RoleBasedPermission
