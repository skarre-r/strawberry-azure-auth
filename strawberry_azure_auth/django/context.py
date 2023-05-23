from __future__ import annotations

__all__ = ["DjangoContext", "DjangoExecutionContext"]


import dataclasses
from strawberry.django.context import StrawberryDjangoContext
from strawberry.types.execution import ExecutionContext


@dataclasses.dataclass
class DjangoContext(StrawberryDjangoContext):
    upn: str | None = None
    roles: list[str] = dataclasses.field(default_factory=list)
    authorized: bool = False

    _handle_authentication: bool = True
    _handle_authorization: bool = True

    @property
    def access_token(self) -> str | None:
        authorization_header: str | None = self.request.headers.get("Authorization")
        if authorization_header and authorization_header.lower().startswith("bearer "):
            _, access_token = authorization_header.split(" ")
            return access_token
        return None


class DjangoExecutionContext(ExecutionContext):
    context: DjangoContext
