# ruff: noqa: E501

from __future__ import annotations

__all__ = ["GraphQLWSConsumer", "GraphQLHTTPConsumer"]

import asyncio
import contextlib
from typing import Any, AsyncGenerator, TYPE_CHECKING
from strawberry.channels import GraphQLWSConsumer as WSConsumer, GraphQLHTTPConsumer as HTTPConsumer
from strawberry.channels.handlers.base import ChannelsConsumer
from strawberry.channels.handlers.graphql_transport_ws_handler import GraphQLTransportWSHandler as WSHandler
from strawberry.subscriptions.protocols.graphql_transport_ws.types import CompleteMessage

if TYPE_CHECKING:
    from strawberry.subscriptions.protocols.graphql_transport_ws.handlers import Operation

from .context import ChannelsContext


class GraphQLTransportWSHandler(WSHandler):
    """
    Custom :class:`GraphQLTransportWSHandler<strawberry.channels.handlers.graphql_transport_ws_handler.GraphQLTransportWSHandler>`
    class that moves 1 line in the `operation_task` method to get rid of unnecessary asyncio errors.
    """

    async def operation_task(self, result_source: AsyncGenerator, operation: Operation) -> None:  # type: ignore[type-arg]
        try:
            await self.handle_async_results(result_source=result_source, operation=operation)
        except BaseException:
            if operation.id in self.subscriptions:  # moved to here
                generator: AsyncGenerator = self.subscriptions[operation.id]  # type: ignore[type-arg]
                with contextlib.suppress(RuntimeError):
                    await generator.aclose()
                # moved from here
                del self.subscriptions[operation.id]
                del self.tasks[operation.id]
            raise
        else:
            await operation.send_message(CompleteMessage(id=operation.id))
        finally:
            task: asyncio.Task | None = asyncio.current_task()  # type: ignore[type-arg]
            assert task is not None
            self.completed_tasks.append(task)


class GraphQLWSConsumer(WSConsumer):
    """
    Custom :class:`strawberry.channels.GraphQLWSConsumer<strawberry.channels.GraphQLWSConsumer>` class
    that overrides the :method:`get_context<strawberry.channels.GraphQLWSConsumer.get_context>` method
    to make sure authentication attributes are included in the request contexts.

    Required to make the :class:`AzureAuthExtension<strawberry_azure_auth.extension.AzureAuthExtension>` extension
    work with GraphQL subscriptions.
    """

    graphql_transport_ws_handler_class = GraphQLTransportWSHandler

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
