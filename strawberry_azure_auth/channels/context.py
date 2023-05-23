from __future__ import annotations

__all__ = ["ChannelsContext", "ChannelsExecutionContext"]

import dataclasses
from strawberry.channels.context import StrawberryChannelsContext
from strawberry.types.execution import ExecutionContext


@dataclasses.dataclass
class ChannelsContext(StrawberryChannelsContext):
    upn: str | None = None
    roles: list[str] = dataclasses.field(default_factory=list)
    authorized: bool = False

    _handle_authentication: bool = True
    _handle_authorization: bool = True

    @property
    def access_token(self) -> str | None:
        # check connection params
        authorization_param: str | None = (
            self.connection_params.get("Authorization") if self.connection_params else None
        )
        if authorization_param and authorization_param.lower().startswith("bearer "):
            _, access_token = authorization_param.split(" ")
            return access_token
        # check headers
        authorization_header: str | None = self.request.headers.get("Authorization")
        if authorization_header and authorization_header.lower().startswith("bearer "):
            _, access_token = authorization_header.split(" ")
            return access_token
        return None


class ChannelsExecutionContext(ExecutionContext):
    context: ChannelsContext
