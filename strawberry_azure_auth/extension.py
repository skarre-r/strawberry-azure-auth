from __future__ import annotations

__all__ = ["AzureAuthExtension"]


import jwt
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
        ...             tenant_id=...,
        ...             scopes=...
        ...         )
        ...     ]
    """

    execution_context: ExecutionContext

    # TODO: rename the 'allow_unauthenticated' and 'allow_unauthorized' params
    def __init__(
        self,
        *,
        client_id: str,
        tenant_id: str,
        scopes: str | list[str],
        roles: list[str] | None = None,
        enable_caching: bool = False,
        allow_introspection: bool = True,
        allow_unauthenticated: bool = False,
        allow_unauthorized: bool = False,
        execution_context: ExecutionContext | None = None,
    ) -> None:
        """
        :param client_id: Your Azure application's client ID.
        :param tenant_id: Your Azure tenant ID.
        :param scopes: Scope(s) defined by your Azure application.
            The provided scopes are used to validate the 'scp' claim
            which means that all access tokens must include at least one of them.
        :param roles: Optional role(s) defined by your Azure application.
            If any are provided, they will be used to validate the 'roles' claim
            which means that all access tokens must include at least one of them.
            Does nothing if the `allow_unauthorized_operations` param is set to `True`.
        :param enable_caching: Whether to cache the OpenID configuration using Django's built-in cache framework or not.
            Useful during development to avoid re-fetching the OpenID document every time the application restarts.
            Off by default.
        :param allow_introspection: Whether to allow introspection queries or not.
            Enabled by default.
        :param allow_unauthenticated: Whether to allow unauthenticated requests or not.
            By default, all unauthenticated requests will be stopped before they're executed.
            Settings this to `True` will let those requests through, leaving it up to the permission classes to
            allow or block operations.
            Useful if you have *any* operations that should not require authentication.
            WARNING: Using this in conjunction with the 'allow_unauthorized' flag
            will disable the authentication completely!
        :param allow_unauthorized: Whether to allow unauthorized requests or not.
            By default, all unauthorized requests will be stopped by the extension (when using the 'roles' flag)
            or by any permission classes that inherit from
            the :class:`RoleBasedPermission<strawberry_azure_auth.permissions.RoleBasedPermission>` class.
            WARNING: Settings this to `True` will disable the permission handling, and
            using it in conjunction with the 'allow_unauthenticated' flag will disable the authentication completely!
        """
        super().__init__(execution_context=execution_context)  # type: ignore[arg-type]
        self._client_id: str = client_id
        self._tenant_id: str = tenant_id
        self._scopes: list[str] = scopes.split(" ") if isinstance(scopes, str) else scopes
        self._roles: list[str] | None = roles
        self._allow_introspection: bool = allow_introspection
        self._allow_unauthenticated: bool = allow_unauthenticated
        self._allow_unauthorized: bool = allow_unauthorized
        self._openid: OpenIDConfig = OpenIDConfig(
            client_id=client_id, tenant_id=tenant_id, enable_caching=enable_caching
        )

    async def on_operation(self) -> AsyncIteratorOrIterator[None]:
        """
        Hook that runs at the start/ end of every request/ operation:
        Authenticate incoming requests by validating the provided access tokens.
        """
        self.execution_context.context._handle_authentication = not self._allow_unauthenticated
        self.execution_context.context._handle_authorization = not self._allow_unauthorized

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
        This behaviour can be controlled using the 'roles', 'allow_introspection', 'allow_unauthenticated',
        and 'allow_unauthorized' parameters.
        """
        if not bool(
            self._allow_introspection
            and is_introspection_query(graphql_document=self.execution_context.graphql_document)
        ):
            if not self._allow_unauthenticated and not self.execution_context.context.authorized:
                self.execution_context.result = ExecutionResult(
                    data=None, errors=[GraphQLError(message="Unauthorized")]
                )
                if hasattr(self.execution_context.context, "response"):  # django http
                    self.execution_context.context.response.status_code = 401
            elif (
                not self._allow_unauthorized
                and self.execution_context.context.authorized
                and self._roles
                and not any(role in self._roles for role in self.execution_context.context.roles)
            ):
                self.execution_context.result = ExecutionResult(data=None, errors=[GraphQLError(message="Forbidden")])
                if hasattr(self.execution_context.context, "response"):  # django http
                    self.execution_context.context.response.status_code = 403
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

        # scp: Scopes exposed by the application for which the client application has requested (and received) consent.
        scp: str | None = claims.get("scp")
        if not scp or not isinstance(scp, str):
            raise jwt.InvalidTokenError("Invalid 'scp' claim")
        if self._scopes and scp not in self._scopes:
            raise jwt.InvalidTokenError("invalid 'scp' claim")

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

    # endregion
