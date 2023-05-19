from __future__ import annotations

__all__ = ["DjangoContext", "DjangoExecutionContext"]


from dataclasses import dataclass
from strawberry.django.context import StrawberryDjangoContext
from strawberry.types.execution import ExecutionContext


@dataclass
class DjangoContext(StrawberryDjangoContext):
    upn: str | None = None
    roles: list[str] = list  # type: ignore[assignment]
    authorized: bool = False

    @property
    def access_token(self) -> str | None:
        authorization_header: str | None = self.request.headers.get("Authorization")
        if authorization_header and authorization_header.lower().startswith("bearer "):
            _, access_token = authorization_header.split(" ")
            return access_token
        return None


class DjangoExecutionContext(ExecutionContext):
    context: DjangoContext
