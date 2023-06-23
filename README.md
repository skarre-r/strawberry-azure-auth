# strawberry-azure-auth

Azure AD authentication for [Strawberry GraphQL](https://github.com/strawberry-graphql/strawberry),
inspired by [fastapi-azure-auth](https://github.com/Intility/fastapi-azure-auth).

## Limitations

* Single-tenant only
* V2 access tokens only
* Support is limited to django + channels

## Installation

```shell
pip install strawberry-azure-auth
# or
poetry add strawberry-azure-auth
```

## Usage

### Django

To enable authentication for Django, you just need to add the `AzureAuthExtension` to your strawberry schema config:

```python
# example/schema.py
import strawberry
from strawberry_azure_auth import AzureAuthExtension  # <--

schema = strawberry.Schema(
    query=...,
    extensions=[
        AzureAuthExtension(  # <--
            client_id=...,
            tenant_id=...
        )
    ]
)
```

### Channels

Currently, strawberry schema extensions don't apply to graphql subscriptions
(see [issue #2097](https://github.com/strawberry-graphql/strawberry/issues/2097)).

To make the authentication extension work with channels,
this package comes with custom http/ websocket "graphql consumer" classes
and a custom `Schema` class that provides extension support for subscriptions:

> :warning: The `Schema` class will be removed in the future when Strawberry adds extension support for subscriptions!

```python
# example/schema.py
from strawberry_azure_auth import AzureAuthExtension  # <--
from strawberry_azure_auth.channels import Schema  # <--

schema = Schema(  # <--
    query=...,
    subscription=...,
    extensions=[
        AzureAuthExtension(  # <--
            client_id=...,
            tenant_id=...
        )
    ]
)
```

```python
# example/asgi.py
import os
from django.urls import re_path
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from strawberry_azure_auth.channels import GraphQLHTTPConsumer, GraphQLWSConsumer  # <--

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "example.settings")
django_asgi_application = get_asgi_application()

# Import the schema after initializing Django
from .schema import schema

application = ProtocolTypeRouter(
    {
        "http": URLRouter([
            re_path(r"^graphql", GraphQLHTTPConsumer.as_asgi(schema=schema)),  # <--
            re_path("^", django_asgi_application)
        ]),
        "websocket": URLRouter([
            re_path(r"^graphql", GraphQLWSConsumer.as_asgi(schema=schema))  # <--
        ])
    }
)
```

### Permissions

The package includes a base permission class that can be used to set up *role-based access control* (RBAC).

To use RBAC, create new permission classes that extends `RoleBasedPermission` and customize the `roles` attribute:

```python
import strawberry
from strawberry_azure_auth import RoleBasedPermission  # <--


class ReadPermission(RoleBasedPermission):  # <--
    roles = ["Example.Read"]  # <--


@strawberry.type
class Query:
    @strawberry.field(permission_classes=[ReadPermission])  # <--
    def ping(self) -> str:
        return "pong"
```

You also have the option to lock **all** operations behind certain roles with the extension:

```python
# example/schema.py
import strawberry
from strawberry_azure_auth import AzureAuthExtension

schema = strawberry.Schema(
    query=...,
    extensions=[
        AzureAuthExtension(
            client_id=...,
            tenant_id=...,
            roles=["Example.Read"]  # <--
        )
    ]
)
```
