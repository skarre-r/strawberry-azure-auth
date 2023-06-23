from __future__ import annotations

__all__ = ["Schema"]

import logging
import strawberry
from typing import Any, AsyncIterable, AsyncGenerator, Callable, Iterable, TYPE_CHECKING

from strawberry.types.graphql import OperationType
from strawberry.schema.execute import _run_validation, parse_document
from strawberry.extensions.runner import SchemaExtensionsRunner
from strawberry.exceptions import MissingQueryError
from strawberry.schema.exceptions import InvalidOperationTypeError
from graphql import (
    ExecutionResult,
    GraphQLError,
    parse,
    subscribe,
)

from .context import ChannelsExecutionContext

if TYPE_CHECKING:
    from strawberry.custom_scalar import ScalarWrapper, ScalarDefinition
    from strawberry.directive import StrawberryDirective
    from strawberry.schema.config import StrawberryConfig
    from strawberry.type import StrawberryType
    from strawberry.extensions import SchemaExtension
    from graphql import GraphQLFieldResolver, DocumentNode, GraphQLSchema, ExecutionContext


logger: logging.Logger = logging.getLogger(name="strawberry.execution")


async def _subscribe(
    schema: GraphQLSchema,
    document: DocumentNode,
    extensions: list[type[SchemaExtension] | SchemaExtension],  # !
    execution_context: ChannelsExecutionContext,  # !
    process_errors: Callable[[list[GraphQLError], ChannelsExecutionContext | None], None],  # !
    root_value: Any = None,
    context_value: Any = None,
    variable_values: dict[str, Any] | None = None,
    operation_name: str | None = None,
    field_resolver: GraphQLFieldResolver | None = None,
    subscribe_field_resolver: GraphQLFieldResolver | None = None,
) -> AsyncGenerator[ExecutionResult, None]:
    """
    Extends the :function:`graphql subscribe<graphql.execution.subscribe.subscribe>` function to provide
    extension support for subscriptions.

    The extension logic is adapted from the :function:`strawberry execute<strawberry.schema.execute.execute>` function
    which handles queries and mutations.

    """
    runner: SchemaExtensionsRunner = SchemaExtensionsRunner(execution_context=execution_context, extensions=extensions)

    async with runner.operation():  # extension > on_operation
        if not execution_context.query:
            raise MissingQueryError()  # type: ignore[no-untyped-call]

        async with runner.parsing():  # extension > on_parse
            try:
                if not execution_context.graphql_document:
                    execution_context.graphql_document = parse_document(
                        query=execution_context.query, **execution_context.parse_options
                    )
            except Exception as exc:
                error: GraphQLError = (
                    GraphQLError(message=str(exc), original_error=exc) if not isinstance(exc, GraphQLError) else exc
                )
                execution_context.errors = [error]
                process_errors([error], execution_context)
                yield ExecutionResult(data=None, errors=[error], extensions=await runner.get_extensions_results())
                return

        async with runner.validation():  # extension > on_validate
            if execution_context.operation_type != OperationType.SUBSCRIPTION:
                invalid_operation_type_error: InvalidOperationTypeError = InvalidOperationTypeError(
                    operation_type=execution_context.operation_type
                )
                execution_context.errors = [
                    GraphQLError(message=str(invalid_operation_type_error), original_error=invalid_operation_type_error)
                ]
                yield ExecutionResult(data=None, errors=execution_context.errors)
                return

            _run_validation(execution_context=execution_context)
            if execution_context.errors:
                process_errors(execution_context.errors, execution_context)
                yield ExecutionResult(
                    data=None, errors=execution_context.errors, extensions=await runner.get_extensions_results()
                )
                return

        async with runner.executing():  # extension > on_execute
            if execution_context.result:
                yield ExecutionResult(
                    data=execution_context.result.data,
                    errors=execution_context.result.errors,
                    extensions=await runner.get_extensions_results(),
                )
                return
            elif execution_context.errors:
                process_errors(execution_context.errors, execution_context)
                yield ExecutionResult(
                    data=None, errors=execution_context.errors, extensions=await runner.get_extensions_results()
                )
                return
            else:
                result: AsyncIterable[ExecutionResult] | ExecutionResult = await subscribe(
                    schema=schema,
                    document=document,
                    root_value=root_value,
                    context_value=context_value,
                    variable_values=variable_values,
                    operation_name=operation_name,
                    field_resolver=field_resolver,
                    subscribe_field_resolver=subscribe_field_resolver,
                )
                # TODO: include 'result.errors' in 'execution_context.errors'?
                if isinstance(result, ExecutionResult):
                    if result.errors:
                        process_errors(result.errors, execution_context)
                    yield result
                    return
                async for res in result:
                    if res.errors:
                        process_errors(res.errors, execution_context)
                    yield res


class Schema(strawberry.Schema):
    """
    Custom :class:`strawberry.Schema<strawberry.Schema>` class
    that overrides the :method:`subscribe<strawberry.Schema.subscribe>` method
    to make schema extensions also apply to GraphQL subscriptions.

    Inspired by: https://github.com/strawberry-graphql/strawberry/issues/2097#issuecomment-1314812575
    """

    def __init__(
        self,
        query: type,
        mutation: type | None = None,
        subscription: type | None = None,
        directives: Iterable[StrawberryDirective] = (),  # type: ignore[type-arg]
        types: Iterable[type | StrawberryType] = (),
        extensions: Iterable[type[SchemaExtension] | SchemaExtension] = (),
        execution_context_class: type[ExecutionContext] | None = None,
        config: StrawberryConfig | None = None,
        scalar_overrides: dict[object, type | ScalarWrapper | ScalarDefinition] | None = None,
        schema_directives: Iterable[object] = (),
        debug: bool = False,
    ) -> None:
        self.debug: bool = debug
        super().__init__(
            query=query,
            mutation=mutation,
            subscription=subscription,
            directives=directives,
            types=types,
            extensions=extensions,
            execution_context_class=execution_context_class,
            config=config,
            scalar_overrides=scalar_overrides,
            schema_directives=schema_directives,
        )

    async def subscribe(
        self,
        query: str,
        variable_values: dict[str, Any] | None = None,
        context_value: Any | None = None,
        root_value: Any | None = None,
        operation_name: str | None = None,
    ) -> AsyncGenerator[ExecutionResult, None]:
        execution_context: ChannelsExecutionContext = ChannelsExecutionContext(
            query=query,
            schema=self,
            context=context_value,
            root_value=root_value,
            variables=variable_values,
            provided_operation_name=operation_name,
        )
        return _subscribe(
            schema=self._schema,
            document=parse(query),
            extensions=self.get_extensions(),  # !
            execution_context=execution_context,  # !
            process_errors=self.process_errors,
            root_value=root_value,
            context_value=context_value,
            variable_values=variable_values,
            operation_name=operation_name,
        )

    def process_errors(
        self,
        errors: list[GraphQLError],
        execution_context: ChannelsExecutionContext | None = None,  # type: ignore[override]
    ) -> None:
        for error in errors:
            if self.debug:
                logger.error(error, exc_info=error.original_error)
            else:
                logger.error(error)
