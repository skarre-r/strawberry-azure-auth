from __future__ import annotations

__all__ = ["GraphQLWSConsumer", "GraphQLHTTPConsumer"]

from typing import Any, TYPE_CHECKING
from strawberry.channels import (
    GraphQLWSConsumer as BaseGraphQLWSConsumer,
    GraphQLHTTPConsumer as BaseGraphQLHTTPConsumer,
)
from .context import ChannelsHTTPContext, ChannelsWebsocketContext

if TYPE_CHECKING:
    from strawberry.channels.handlers.base import ChannelsConsumer
    from strawberry.http.temporal_response import TemporalResponse
    from strawberry.channels.handlers.http_handler import ChannelsRequest


class GraphQLWSConsumer(BaseGraphQLWSConsumer):
    """
    Custom :class:`strawberry.channels.GraphQLWSConsumer<strawberry.channels.GraphQLWSConsumer>` class
    that overrides the :method:`get_context<strawberry.channels.GraphQLWSConsumer.get_context>` method
    to make sure authentication attributes are included in the request context.

    Required to make the :class:`AzureAuthExtension<strawberry_azure_auth.extension.AzureAuthExtension>` extension
    work with GraphQL subscriptions.
    """

    async def get_context(  # type: ignore[override]
        self, request: ChannelsConsumer, connection_params: dict[str, Any] | Any | None
    ) -> ChannelsWebsocketContext:
        return ChannelsWebsocketContext(request=request, connection_params=connection_params)


class GraphQLHTTPConsumer(BaseGraphQLHTTPConsumer):  # type: ignore[type-arg]
    """
    Custom :class:`strawberry.channels.GraphQLHTTPConsumer<strawberry.channels.GraphQLHTTPConsumer>` class
    that overrides the :method:`get_context<strawberry.channels.GraphQLHTTPConsumer.get_context>` method
    to make sure authentication attributes are included in the request context.

    Required to make the :class:`AzureAuthExtension<strawberry_azure_auth.extension.AzureAuthExtension>` extension
    work with GraphQL subscriptions.
    """

    async def get_context(self, request: ChannelsRequest, response: TemporalResponse) -> ChannelsHTTPContext:
        return ChannelsHTTPContext(request=request, response=response)
