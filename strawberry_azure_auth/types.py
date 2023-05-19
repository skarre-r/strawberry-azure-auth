from __future__ import annotations

__all__ = ["Context", "ExecutionContext", "Info"]

from typing import TypeVar, TypeAlias, Any
from strawberry.types.info import Info as StrawberryInfo

from .channels.context import ChannelsContext, ChannelsExecutionContext
from .django.context import DjangoContext, DjangoExecutionContext


Context = TypeVar("Context", ChannelsContext, DjangoContext)
ExecutionContext = TypeVar("ExecutionContext", ChannelsExecutionContext, DjangoExecutionContext)

Info: TypeAlias = StrawberryInfo[Context, Any]
