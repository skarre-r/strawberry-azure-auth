from __future__ import annotations

__all__ = ["ChannelsWebsocketContext", "ChannelsHTTPContext", "ChannelsExecutionContext"]

import dataclasses
from typing import Any, TYPE_CHECKING
from strawberry.types.execution import ExecutionContext

if TYPE_CHECKING:
    from strawberry.channels.handlers.base import ChannelsConsumer
    from strawberry.channels.handlers.http_handler import ChannelsRequest
    from strawberry.http.temporal_response import TemporalResponse


@dataclasses.dataclass
class ChannelsHTTPContext:
    request: ChannelsRequest
    response: TemporalResponse

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


@dataclasses.dataclass
class ChannelsWebsocketContext:
    request: ChannelsConsumer
    connection_params: dict[str, Any] | None = None

    upn: str | None = None
    roles: list[str] = dataclasses.field(default_factory=list)
    authorized: bool = False

    @property
    def ws(self) -> ChannelsConsumer:
        return self.request

    @property
    def access_token(self) -> str | None:
        if self.connection_params:
            for param in ["authorization", "Authorization"]:
                authorization_param: str | None = self.connection_params.get(param)
                if authorization_param and authorization_param.lower().startswith("bearer "):
                    _, access_token = authorization_param.split(" ")
                    return access_token
        return None


class ChannelsExecutionContext(ExecutionContext):
    context: ChannelsHTTPContext | ChannelsWebsocketContext
