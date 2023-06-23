from __future__ import annotations

__all__ = ["Context", "ExecutionContext", "Info"]

from typing import TypeAlias, Union, Any
from strawberry.types.info import Info as StrawberryInfo

from .channels.context import ChannelsHTTPContext, ChannelsWebsocketContext, ChannelsExecutionContext
from .django.context import DjangoContext, DjangoExecutionContext


Context: TypeAlias = Union[ChannelsHTTPContext, ChannelsWebsocketContext, DjangoContext]
ExecutionContext: TypeAlias = Union[ChannelsExecutionContext, DjangoExecutionContext]

Info: TypeAlias = StrawberryInfo[Context, Any]
