from __future__ import annotations

__all__ = ["GraphQLWSConsumer", "GraphQLHTTPConsumer"]

from typing import Any
from strawberry.channels import GraphQLWSConsumer as WSConsumer, GraphQLHTTPConsumer as HTTPConsumer
from strawberry.channels.handlers.base import ChannelsConsumer

from .context import ChannelsContext


class GraphQLWSConsumer(WSConsumer):
    """
    Custom :class:`strawberry.channels.GraphQLWSConsumer<strawberry.channels.GraphQLWSConsumer>` class
    that overrides the :method:`get_context<strawberry.channels.GraphQLWSConsumer.get_context>` method
    to make sure authentication attributes are included in the request contexts.

    Required to make the :class:`AzureAuthExtension<strawberry_azure_auth.extension.AzureAuthExtension>` extension
    work with GraphQL subscriptions.
    """

    async def get_context(
        self,
        request: ChannelsConsumer | None = None,
        connection_params: dict[str, Any] | None = None,
    ) -> ChannelsContext:
        return ChannelsContext(request=request or self, connection_params=connection_params)


class GraphQLHTTPConsumer(HTTPConsumer):
    """
    Custom :class:`strawberry.channels.GraphQLHTTPConsumer<strawberry.channels.GraphQLHTTPConsumer>` class
    that overrides the :method:`get_context<strawberry.channels.GraphQLHTTPConsumer.get_context>` method
    to make sure authentication attributes are included in the request contexts.

    Required to make the :class:`AzureAuthExtension<strawberry_azure_auth.extension.AzureAuthExtension>` extension
    work with GraphQL subscriptions.
    """

    async def get_context(
        self,
        request: ChannelsConsumer | None = None,
        connection_params: dict[str, Any] | None = None,
    ) -> ChannelsContext:
        return ChannelsContext(request=request or self, connection_params=connection_params)
