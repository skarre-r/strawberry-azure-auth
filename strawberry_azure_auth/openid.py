from __future__ import annotations

__all__ = ["OpenIDConfig"]

import httpx
import logging
from typing import Final, TypedDict
from datetime import datetime, timedelta
from jwt.algorithms import RSAAlgorithm
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from django.core.cache import cache

logger: logging.Logger = logging.getLogger(name="strawberry.auth")

CACHE_KEY: Final[str] = "strawberry_azure_auth:openid"


class CacheValues(TypedDict):
    issuer: str
    keys: dict[str, str]
    dt: str


# region - Response types
class OpenIDDocument(TypedDict):
    token_endpoint: str
    token_endpoint_auth_methods_supported: list[str]
    jwks_uri: str  # !
    response_modes_supported: list[str]
    subject_types_supported: list[str]
    id_token_signing_alg_values_supported: list[str]
    response_types_supported: list[str]
    scopes_supported: list[str]
    issuer: str  # !
    request_uri_parameter_supported: bool
    userinfo_endpoint: str
    authorization_endpoint: str
    device_authorization_endpoint: str
    http_logout_supported: bool
    frontchannel_logout_supported: bool
    end_session_endpoint: str
    claims_supported: list[str]
    kerberos_endpoint: str
    tenant_region_scope: str
    cloud_instance_name: str
    cloud_graph_host_name: str
    msgraph_host: str
    rbac_url: str


class JWK(TypedDict):
    kty: str
    use: str
    kid: str
    x5t: str
    n: str
    e: str
    x5c: list[str]
    issuer: str


class JSONWebKeys(TypedDict):
    keys: list[JWK]


# endregion


class OpenIDConfig:
    def __init__(self, client_id: str, tenant_id: str, enable_caching: bool = False) -> None:
        """
        :param client_id: Your Azure application's client ID.
        :param tenant_id: Your Azure tenant ID.
        :param enable_caching: Whether to cache the configuration using Django's built-in cache framework or not.
            Useful during development to avoid re-fetching the OpenID document every time the application restarts.
            Off by default.
        """
        self._client_id: str = client_id
        self._tenant_id: str = tenant_id
        self._use_cache: bool = enable_caching
        self._last_update: datetime | None = None

        self.issuer: str = ""
        self.signing_keys: dict[str, RSAPublicKey] = {}

    @property
    def up_to_date(self) -> bool:
        if not self._last_update:
            return False
        expires: datetime = datetime.now() - timedelta(hours=24)
        return self._last_update > expires

    async def load_config(self) -> None:
        if bool(self.issuer and self.signing_keys and self.up_to_date):
            return
        try:
            await self._load_openid_configuration()
        except Exception as exc:
            logger.error("Failed to update the OpenID configuration!", exc_info=exc)

    async def _load_openid_configuration(self) -> None:
        if self._use_cache:
            try:
                cached_config: CacheValues
                if cached_config := await cache.aget(CACHE_KEY):
                    logger.debug("Using OpenID config from cache...")
                    self.issuer = cached_config["issuer"]
                    self.signing_keys = {
                        key: RSAAlgorithm.from_jwk(jwk=value) for key, value in cached_config["keys"].items()
                    }
                    self._last_update = datetime.fromisoformat(cached_config["dt"])
                    return
            except Exception as exc:
                logger.warning("Failed to use the cached OpenID config!", exc_info=exc)

        async with httpx.AsyncClient(timeout=10) as client:
            openid_url: str = (
                f"https://login.microsoftonline.com/{self._tenant_id}/v2.0/.well-known/openid-configuration"
            )
            logger.debug("Fetching the OpenID configuration document from '%s'...", openid_url)
            openid_response: httpx.Response = await client.get(
                url=openid_url,
                params={"appId": self._client_id},
            )
            openid_response.raise_for_status()
            openid_document: OpenIDDocument = openid_response.json()
            self.issuer = openid_document["issuer"]

            logger.debug("Fetching JSON web keys from '%s'...", openid_document["jwks_uri"])
            jwk_response: httpx.Response = await client.get(url=openid_document["jwks_uri"])
            jwk_response.raise_for_status()
            json_web_keys: JSONWebKeys = jwk_response.json()

        self.signing_keys = {}

        for jwk in json_web_keys["keys"]:
            if jwk["use"] == "sig":  # signing key
                public_key: RSAPublicKey = RSAAlgorithm.from_jwk(jwk=jwk)
                self.signing_keys.update({jwk["kid"]: public_key})

        self._last_update = datetime.now()

        if self._use_cache:
            logger.debug("Updating the OpenID cache...")
            try:
                value: CacheValues = {
                    "issuer": self.issuer,
                    "keys": {key: RSAAlgorithm.to_jwk(key_obj=value) for key, value in self.signing_keys.items()},
                    "dt": self._last_update.isoformat(),
                }
                await cache.aset(key=CACHE_KEY, value=value, timeout=60 * 60 * 24)
            except Exception as exc:
                logger.warning("Failed to update the OpenID cache!", exc_info=exc)

        logger.debug("OpenID config updated:")
        logger.debug("issuer: %s", self.issuer)
        logger.debug("keys: %s", len(self.signing_keys))
