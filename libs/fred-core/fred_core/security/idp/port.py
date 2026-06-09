# Copyright Thales 2026
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
IdpPort — provider-agnostic identity interface for Fred.

Why this file exists:
- Fred originally coupled authentication details (JWKS URL, claim shapes, token
  endpoints) directly to Keycloak conventions.  Adding a second provider (e.g.
  Azure Entra ID) would have required scattering ``if provider == "entra"``
  branches across oidc.py, outbound.py, and backend_to_backend_auth.py.
- Instead, each provider encapsulates its own conventions behind IdpPort.
  Fred's core only calls the port; the concrete adapter is chosen at startup
  from the ``OIDC_PROVIDER`` environment variable.

Supported providers (OIDC_PROVIDER env var):
- ``keycloak`` (default) — preserves all existing behaviour, zero regression.
- ``entra``              — Azure Entra ID / Microsoft identity platform v2.0.

Adding a new provider:
1. Subclass IdpPort (or implement the Protocol).
2. Add a case to build_idp().
3. No other files need to change.
"""

from __future__ import annotations

import logging
import os
from typing import Any, TypedDict

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared data type returned by every IdpPort.extract_identity()
# ---------------------------------------------------------------------------

class IdpUser(TypedDict):
    uid: str            # stable, tenant-wide user identifier (UUID string)
    username: str       # human-readable login / UPN / preferred_username
    email: str | None
    roles: list[str]    # app-level roles: ["admin"] / ["editor"] / ["viewer"]
    groups: list[str]   # raw group identifiers from the token (informational)


# ---------------------------------------------------------------------------
# Protocol (structural interface — no inheritance required)
# ---------------------------------------------------------------------------

class IdpPort:
    """
    Abstract base for identity provider adapters.

    Each concrete subclass answers three questions that differ between providers:
    1. Where are the public signing keys?  (jwks_url)
    2. How are roles and the user id encoded in the JWT?  (extract_identity)
    3. Where do we exchange a client secret for a service token?  (m2m_token_url / m2m_scope)
    """

    def jwks_url(self) -> str:
        raise NotImplementedError

    def extract_identity(self, payload: dict[str, Any]) -> IdpUser:
        raise NotImplementedError

    def m2m_token_url(self) -> str:
        raise NotImplementedError

    def m2m_scope(self) -> str | None:
        """OAuth2 scope for the client-credentials grant, or None if not required."""
        return None


# ---------------------------------------------------------------------------
# Keycloak adapter (preserves all existing claim conventions)
# ---------------------------------------------------------------------------

class KeycloakIdp(IdpPort):
    """
    Keycloak / generic OIDC adapter.

    Claim conventions:
    - stable user id  : ``sub`` claim
    - app roles       : ``resource_access[client_id].roles``
    - groups          : ``groups`` (human-readable path strings, e.g. "/thales")
    - JWKS            : ``{realm_url}/protocol/openid-connect/certs``
    - token endpoint  : ``{base}/realms/{realm}/protocol/openid-connect/token``
    """

    def __init__(self, realm_url: str, client_id: str) -> None:
        self._realm_url = realm_url.rstrip("/")
        self._client_id = client_id
        # Pre-compute base + realm for the token endpoint.
        self._base, self._realm = _split_realm_url(self._realm_url)

    def jwks_url(self) -> str:
        return f"{self._realm_url}/protocol/openid-connect/certs"

    def extract_identity(self, payload: dict[str, Any]) -> IdpUser:
        client_roles: list[str] = []
        resource_access = payload.get("resource_access", {})
        if isinstance(resource_access, dict):
            client_data = resource_access.get(self._client_id, {})
            client_roles = client_data.get("roles", []) if isinstance(client_data, dict) else []

        return IdpUser(
            uid=payload.get("sub", ""),
            username=payload.get("preferred_username", ""),
            email=payload.get("email"),
            roles=client_roles,
            groups=payload.get("groups", []) or [],
        )

    def m2m_token_url(self) -> str:
        return f"{self._base}/realms/{self._realm}/protocol/openid-connect/token"

    def m2m_scope(self) -> str | None:
        return None


# ---------------------------------------------------------------------------
# Azure Entra ID adapter
# ---------------------------------------------------------------------------

class EntraIdp(IdpPort):
    """
    Azure Entra ID (formerly Azure AD) adapter — Microsoft identity platform v2.0.

    Claim conventions:
    - stable user id  : ``oid`` claim (tenant-wide object id, a UUID — maps
                        directly to Fred's UUID-keyed user store). Falls back
                        to ``sub`` when ``oid`` is absent.
    - app roles       : top-level ``roles`` claim (populated when App Roles are
                        defined in the App Registration manifest and assigned to
                        users via Enterprise Applications → Users and groups).
    - groups          : ``groups`` claim (object-id GUIDs — informational only;
                        Fred uses OpenFGA as the authoritative membership store).
    - JWKS            : ``https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys``
    - token endpoint  : ``https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token``

    Groups overage:
    - When a user belongs to >200 groups Entra replaces the ``groups`` claim
      with ``_claim_names`` / ``_claim_sources``.  Fred deliberately ignores
      this because group membership is owned by OpenFGA, not the token.

    Required App Registration setup:
    - Define ``admin`` / ``editor`` / ``viewer`` App Roles in the manifest.
    - Assign users (or AD groups) to those roles in Enterprise Applications.
    - No Microsoft Graph permissions are needed for this adapter.
    """

    def __init__(self, authority_url: str, client_id: str) -> None:
        # authority_url is the v2.0 issuer, e.g.:
        #   https://login.microsoftonline.com/{tenant}/v2.0
        self._authority = authority_url.rstrip("/")
        self._client_id = client_id
        # Derive the tenant base (strip trailing /v2.0 if present)
        self._tenant_base = (
            self._authority[: -len("/v2.0")]
            if self._authority.endswith("/v2.0")
            else self._authority
        )

    def jwks_url(self) -> str:
        return f"{self._tenant_base}/discovery/v2.0/keys"

    def extract_identity(self, payload: dict[str, Any]) -> IdpUser:
        uid = payload.get("oid") or payload.get("sub") or ""
        roles: list[str] = payload.get("roles", []) or []
        username = (
            payload.get("preferred_username")
            or payload.get("upn")
            or payload.get("email")
            or payload.get("name")
            or ""
        )
        email = (
            payload.get("email")
            or payload.get("preferred_username")
            or payload.get("upn")
        )
        # groups holds GUIDs when present; may be absent on overage (ignored).
        groups: list[str] = payload.get("groups", []) or []

        return IdpUser(
            uid=str(uid),
            username=str(username),
            email=email,
            roles=list(roles),
            groups=list(groups),
        )

    def m2m_token_url(self) -> str:
        return f"{self._tenant_base}/oauth2/v2.0/token"

    def m2m_scope(self) -> str | None:
        # Entra requires an explicit scope for client-credentials grants.
        # The .default scope requests all statically configured permissions.
        return f"api://{self._client_id}/.default"


# ---------------------------------------------------------------------------
# Factory — reads OIDC_PROVIDER from the environment
# ---------------------------------------------------------------------------

def build_idp(realm_url: str, client_id: str) -> IdpPort:
    """
    Instantiate the right IdpPort implementation for the configured provider.

    Reads ``OIDC_PROVIDER`` from the environment (default: ``keycloak``).
    ``realm_url`` is the value already stored in ``UserSecurity.realm_url``
    — for Keycloak it is the realm URL; for Entra it is the authority URL
    (``https://login.microsoftonline.com/{tenant}/v2.0``).
    """
    provider = os.getenv("OIDC_PROVIDER", "keycloak").strip().lower()
    logger.info("[IDP] Building adapter for provider=%s", provider)
    match provider:
        case "entra":
            return EntraIdp(realm_url, client_id)
        case _:
            if provider != "keycloak":
                logger.warning(
                    "[IDP] Unknown OIDC_PROVIDER=%r, falling back to keycloak.", provider
                )
            return KeycloakIdp(realm_url, client_id)


# ---------------------------------------------------------------------------
# Module-level singleton (set once at application startup)
# ---------------------------------------------------------------------------

_IDP: IdpPort | None = None


def set_idp(idp: IdpPort) -> None:
    global _IDP
    _IDP = idp


def get_idp() -> IdpPort:
    if _IDP is None:
        raise RuntimeError(
            "IdpPort not initialized. Call set_idp() (via initialize_user_security) at startup."
        )
    return _IDP


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _split_realm_url(realm_url: str) -> tuple[str, str]:
    """Split ``http://host/realms/<realm>`` into ``(base, realm)``."""
    u = realm_url.rstrip("/")
    marker = "/realms/"
    idx = u.find(marker)
    if idx == -1:
        raise ValueError(
            f"Invalid Keycloak realm URL (expected .../realms/<realm>): {realm_url!r}"
        )
    base = u[:idx]
    realm = u[idx + len(marker):].split("/", 1)[0]
    return base, realm
