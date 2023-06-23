from __future__ import annotations

__all__ = ["AzureAuthExtension"]

import jwt
import asyncio
import logging
import contextlib
from uuid import UUID
from typing import Any
from graphql import GraphQLError, ExecutionResult
from strawberry.extensions.base_extension import SchemaExtension
from strawberry.utils.await_maybe import AsyncIteratorOrIterator
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from .openid import OpenIDConfig
from .types import ExecutionContext
from .utils import is_introspection_query

logger: logging.Logger = logging.getLogger(name="strawberry.auth")


class AzureAuthExtension(SchemaExtension):
    """
    Add Azure AD authentication to GraphQL requests.

    Example:

        >>> from strawberry import Schema
        >>> from strawberry_azure_auth import AzureAuthExtension
        ...
        >>> schema = Schema(
        ...     query=...,
        ...     extensions=[
        ...         AzureAuthExtension(
        ...             client_id=...,
        ...             tenant_id=...
        ...         )
        ...     ]
    """

    execution_context: ExecutionContext

    def __init__(
        self,
        *,
        client_id: str,
        tenant_id: str,
        scopes: str | list[str] | None = None,
        roles: list[str] | None = None,
        enable_caching: bool = False,
        allow_introspection: bool = True,
        allow_unauthorized: bool = False,
        execution_context: ExecutionContext | None = None,
    ) -> None:
        """
        :param client_id: Your Azure application's client ID.
        :param tenant_id: Your Azure tenant ID.
        :param scopes: Optional scope(s) defined by your Azure application.
            The provided scopes are used to validate the 'scp' claim
            which means that all access tokens must include at least one of them.
        :param roles: Optional role(s) defined by your Azure application.
            The provided roles are used to validate the 'roles' claim
            which means that all access tokens must include at least one of them.
        :param enable_caching: Whether to cache the OpenID configuration using Django's built-in cache framework or not.
            Useful during development to avoid re-fetching the OpenID document every time the application restarts.
            Off by default.
        :param allow_introspection: Whether to allow unauthenticated introspection queries or not.
            Enabled by default.
        :param allow_unauthorized: Whether to allow unauthorized requests or not.
            By default, the extension stops all unauthorized requests before they're executed.
            Set this to `True` to turn of this behavior.
            Useful if you have *any* operations that should not require authentication.
        """
        super().__init__(execution_context=execution_context)  # type: ignore[arg-type]
        self._client_id: str = client_id
        self._tenant_id: str = tenant_id
        self._scopes: list[str] = scopes.split(" ") if isinstance(scopes, str) else scopes if scopes else []
        self._roles: list[str] | None = roles
        self._allow_introspection: bool = allow_introspection
        self._allow_unauthorized: bool = allow_unauthorized
        self._openid: OpenIDConfig = OpenIDConfig(
            client_id=client_id, tenant_id=tenant_id, enable_caching=enable_caching
        )
        with contextlib.suppress(Exception):
            asyncio.run_coroutine_threadsafe(coro=self._openid.load_config(), loop=asyncio.get_event_loop())

    async def on_operation(self) -> AsyncIteratorOrIterator[None]:
        """
        Hook that runs at the start/ end of every request/ operation:
        Authenticate incoming requests by validating the provided access tokens.
        """
        if not self.execution_context.context.authorized and (
            access_token := self.execution_context.context.access_token
        ):
            header: dict[str, str] = jwt.get_unverified_header(jwt=access_token)
            if kid := header.get("kid"):
                await self._openid.load_config()
                if (issuer := self._openid.issuer) and (signing_key := self._openid.signing_keys.get(kid)):
                    with contextlib.suppress(Exception):
                        claims: dict[str, Any] = self._validate_token(
                            token=access_token, signing_key=signing_key, issuer=issuer
                        )
                        self.execution_context.context.authorized = True
                        self.execution_context.context.upn = claims.get("upn")
                        self.execution_context.context.roles = claims.get("roles", [])
        yield

    async def on_execute(self) -> AsyncIteratorOrIterator[None]:
        """
        Hook that runs before / after the 'GraphQL execution step':
        Stop the execution of unauthorized requests by manually setting the execution result.
        This behavior can be controlled with the 'allow_introspection' and 'allow_unauthorized' parameters.
        """
        if not bool(
            self._allow_introspection
            and is_introspection_query(graphql_document=self.execution_context.graphql_document)
        ):
            if not self._allow_unauthorized and not self.execution_context.context.authorized:
                self.execution_context.result = ExecutionResult(
                    data=None, errors=[GraphQLError(message="Unauthorized")]
                )
                if hasattr(self.execution_context.context, "response"):
                    self.execution_context.context.response.status_code = 401
        yield

    # region - Internal methods
    def _validate_token(self, token: str, signing_key: RSAPublicKey, issuer: str) -> dict[str, Any]:
        """
        Attempt to decode and validate the supplied access token:
        If the token is valid, its claims are returned.
        If it's not, an exception is raised.
        """
        try:
            claims: dict[str, Any] = jwt.decode(
                jwt=token,
                key=signing_key,
                algorithms=["RS256"],
                options={
                    "verify_signature": True,
                    "require": ["exp", "nbf", "iss", "aud", "iat", "sub", "scp", "tid", "uti", "oid", "azp"],
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iss": True,
                    "verify_aud": True,
                    "verify_iat": True,
                },
                audience=self._client_id,
                issuer=issuer,
                leeway=0,
            )
            self._verify_additional_claims(claims=claims)
        except Exception as exc:
            logger.warning("Failed to validate token!", exc_info=exc)
            raise
        return claims

    def _verify_additional_claims(self, claims: dict[str, Any]) -> None:
        """
        Verify additional, Azure AD specific claims that aren't covered by `jwt.decode`.

        Overview: https://learn.microsoft.com/en-us/azure/active-directory/develop/access-tokens#payload-claims
        """
        # sub: Subject (whom the token refers to), a unique string per user per application (ID).
        sub: str | None = claims.get("sub")
        if not sub or not isinstance(sub, str):
            raise jwt.InvalidTokenError("Invalid 'sub' claim")

        # tid: The tenant ID (GUID) that the user is signing in to.
        tid: str | None = claims.get("tid")
        if not tid or not isinstance(tid, str) or tid != self._tenant_id:
            raise jwt.InvalidTokenError("Invalid 'tid' claim")

        # uti: Token identifier claim (jti in JWT spec), a unique, per-token identifier.
        uti: str | None = claims.get("uti")
        if not uti or not isinstance(uti, str):
            raise jwt.InvalidTokenError("Invalid 'uti' claim")

        # oid: Similar to 'sub', a unique GUID per user across applications (versus per application).
        oid: str | None = claims.get("oid")
        if not oid or not isinstance(oid, str):
            raise jwt.InvalidTokenError("Invalid 'oid' claim")
        try:
            UUID(hex=oid, version=4)
        except Exception:
            raise jwt.InvalidTokenError("Invalid 'oid' claim")

        # azp: Authorized party, the application ID (GUID) of the client using the token.
        azp: str | None = claims.get("azp")
        if not azp or not isinstance(azp, str) or azp != self._client_id:
            raise jwt.InvalidTokenError("Invalid 'azp' claim")

        # scp: Scopes exposed by the application for which the client application has requested (and received) consent.
        if self._scopes:
            scp: str | None = claims.get("scp")
            if not scp or not isinstance(scp, str):
                raise jwt.InvalidTokenError("Invalid 'scp' claim")
            if scp not in self._scopes:
                raise jwt.InvalidTokenError("invalid 'scp' claim")

        # roles: Permissions exposed by the application that the requesting user has been given.
        if self._roles:
            roles: list[str] | None = claims.get("roles")
            if not roles:
                raise jwt.InvalidTokenError("Invalid 'roles' claim")
            if not any(role in roles for role in self._roles):
                raise jwt.InvalidTokenError("Invalid 'roles' claim")

    # endregion
