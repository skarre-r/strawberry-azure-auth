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

    @property
    def access_token(self) -> str | None:
        for header in ["authorization", "Authorization"]:
            authorization_header: str | None = self.request.headers.get(header)
            if authorization_header and authorization_header.lower().startswith("bearer "):
                _, access_token = authorization_header.split(" ")
                return access_token
        return None


class DjangoExecutionContext(ExecutionContext):
    context: DjangoContext
