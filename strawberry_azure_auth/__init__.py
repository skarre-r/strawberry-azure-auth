__version__ = "1.2.0"

__all__ = ["AzureAuthExtension", "RoleBasedPermission"]

from .extension import AzureAuthExtension
from .permissions import RoleBasedPermission
