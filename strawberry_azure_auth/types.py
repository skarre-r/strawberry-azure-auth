from __future__ import annotations

__all__ = ["Context", "ExecutionContext", "Info"]

from typing import TypeVar, TypeAlias
from strawberry.types.info import Info as StrawberryInfo, RootValueType

from .channels.context import ChannelsContext, ChannelsExecutionContext
from .django.context import DjangoContext, DjangoExecutionContext


Context = TypeVar("Context", ChannelsContext, DjangoContext)
ExecutionContext = TypeVar("ExecutionContext", ChannelsExecutionContext, DjangoExecutionContext)

Info: TypeAlias = StrawberryInfo[Context, RootValueType]
