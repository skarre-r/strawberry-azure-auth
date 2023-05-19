from __future__ import annotations

__all__ = ["is_introspection_query"]


from graphql.language.ast import DocumentNode, OperationDefinitionNode, SelectionNode, NameNode


def is_introspection_query(graphql_document: DocumentNode | None) -> bool:
    """
    Checks if the given graphql document is an introspection query.
    To be a valid introspection query, the document must:

    - Only include 'query' operations (no 'mutations' or 'subscriptions') named 'IntrospectionQuery'.
    - Only include fields prefixed with double underscores, fx '__schema'.

    (Fields prefixed with double underscores are reserved for schema introspection.)
    """
    if not graphql_document:
        return False
    operation_nodes: list[OperationDefinitionNode] = [
        node for node in graphql_document.definitions if isinstance(node, OperationDefinitionNode)
    ]
    if not all(
        node.operation.value == "query" and node.name and node.name.value == "IntrospectionQuery"
        for node in operation_nodes
    ):
        return False
    selection_nodes: list[SelectionNode] = [
        selection_node
        for operation_node in operation_nodes
        for selection_node in operation_node.selection_set.selections
    ]
    if not selection_nodes:
        return False
    selection_name_nodes: list[NameNode] = [
        name_node for selection_node in selection_nodes if (name_node := getattr(selection_node, "name", None))
    ]
    if not selection_name_nodes:
        return False
    return all(name_node.value.startswith("__") for name_node in selection_name_nodes)
