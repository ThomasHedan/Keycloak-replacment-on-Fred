# Copyright Thales 2025
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

import base64
import getpass
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, Tuple
from uuid import UUID

import jwt
from fastapi import Depends, HTTPException, Security
from fastapi.security import OAuth2PasswordBearer
from jwt import PyJWKClient

from fred_core.common import ThreadSafeLRUCache, get_config, read_env_bool
from fred_core.security.idp.port import build_idp, get_idp, set_idp
from fred_core.security.structure import KeycloakUser, UserSecurity
from fred_core.security.whitelist_access_control.access_control import (
    is_user_whitelisted,
    is_whitelist_active,
)

from ..users.store import BaseUserStore
from ..users.store.postgres_user_store import get_user_store

logger = logging.getLogger(__name__)

# --- runtime toggles ------------------
STRICT_ISSUER = read_env_bool("FRED_STRICT_ISSUER", default=False)
STRICT_AUDIENCE = read_env_bool("FRED_STRICT_AUDIENCE", default=False)
CLOCK_SKEW_SECONDS = int(os.getenv("FRED_JWT_CLOCK_SKEW", "0"))
JWT_CACHE_ENABLED = read_env_bool("FRED_JWT_CACHE_ENABLED", default=True)
JWT_CACHE_TTL_SECONDS = int(os.getenv("FRED_JWT_CACHE_TTL", "60"))
JWT_CACHE_MAX_SIZE = int(os.getenv("FRED_JWT_CACHE_SIZE", "512"))

# Global state — set by initialize_user_security() at startup.
# Public names are preserved for callers in fred-runtime and other apps.
KEYCLOAK_ENABLED = False
KEYCLOAK_URL = ""      # the authority/realm URL (provider-agnostic at this level)
KEYCLOAK_JWKS_URL = "" # derived via IdpPort.jwks_url()
KEYCLOAK_CLIENT_ID = ""
_JWKS_CLIENT: PyJWKClient | None = None
_JWT_CACHE: ThreadSafeLRUCache[str, tuple[float, KeycloakUser]] = ThreadSafeLRUCache(
    JWT_CACHE_MAX_SIZE
)


def _b64json(data: str) -> Dict[str, Any]:
    try:
        padded = data + "=" * (-len(data) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return {}


def _peek_header_and_claims(token: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    try:
        h, p, _ = token.split(".")
        return _b64json(h), _b64json(p)
    except Exception:
        return {}, {}


def _iso(ts: int | float | None) -> str | None:
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
    except Exception:
        return None


def get_keycloak_url() -> str:
    """Return the configured authority/realm URL (name kept for backward compatibility)."""
    if not KEYCLOAK_URL:
        logger.warning("[SECURITY] Authority URL requested but not initialized.")
        return ""
    return KEYCLOAK_URL


def get_keycloak_client_id() -> str:
    """Return the configured client ID (name kept for backward compatibility)."""
    if not KEYCLOAK_CLIENT_ID:
        logger.warning("[SECURITY] Client ID requested but not initialized.")
        return ""
    return KEYCLOAK_CLIENT_ID


def initialize_user_security(config: UserSecurity) -> None:
    """
    Initialize OIDC settings at application startup.

    Builds the right IdpPort implementation (Keycloak or Entra) from the
    ``OIDC_PROVIDER`` environment variable and caches the JWKS URL derived
    by the adapter.  All public symbols (KEYCLOAK_ENABLED, KEYCLOAK_URL, …)
    are preserved so callers in fred-runtime and other apps are unaffected.
    """
    global \
        KEYCLOAK_ENABLED, \
        KEYCLOAK_URL, \
        KEYCLOAK_JWKS_URL, \
        KEYCLOAK_CLIENT_ID, \
        _JWKS_CLIENT

    KEYCLOAK_ENABLED = config.enabled
    KEYCLOAK_URL = str(config.realm_url).rstrip("/")
    KEYCLOAK_CLIENT_ID = config.client_id

    # Build and register the provider adapter.
    idp = build_idp(KEYCLOAK_URL, KEYCLOAK_CLIENT_ID)
    set_idp(idp)

    KEYCLOAK_JWKS_URL = idp.jwks_url()
    _JWKS_CLIENT = None  # reset; lazy-created on first decode

    logger.info(
        "[SECURITY] OIDC initialized: provider=%s enabled=%s url=%s client_id=%s jwks=%s "
        "strict_issuer=%s strict_audience=%s skew=%ss",
        os.getenv("OIDC_PROVIDER", "keycloak"),
        KEYCLOAK_ENABLED,
        KEYCLOAK_URL,
        KEYCLOAK_CLIENT_ID,
        KEYCLOAK_JWKS_URL,
        STRICT_ISSUER,
        STRICT_AUDIENCE,
        CLOCK_SKEW_SECONDS,
    )


def split_realm_url(realm_url: str) -> tuple[str, str]:
    """
    Split ``http://host/realms/<realm>`` into ``(base, realm)``.

    Kept as a public helper for callers that still need it (e.g.
    keycloack_admin_client).  Raises ValueError for non-Keycloak URLs.
    """
    u = realm_url.rstrip("/")
    marker = "/realms/"
    idx = u.find(marker)
    if idx == -1:
        raise ValueError(
            f"Invalid keycloak_url (expected .../realms/<realm>): {realm_url}"
        )
    base = u[:idx]
    realm = u[idx + len(marker):].split("/", 1)[0]
    return base, realm


# OAuth2 Password Bearer
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)


def _get_jwks_client() -> PyJWKClient:
    global _JWKS_CLIENT
    if _JWKS_CLIENT is None:
        logger.debug("[SECURITY] Creating PyJWKClient for %s", KEYCLOAK_JWKS_URL)
        _JWKS_CLIENT = PyJWKClient(KEYCLOAK_JWKS_URL)
    return _JWKS_CLIENT


def _get_cached_user(token: str) -> KeycloakUser | None:
    if not JWT_CACHE_ENABLED or not token:
        return None
    entry = _JWT_CACHE.get(token)
    if entry is None:
        return None
    expires_at, user = entry
    now = time.time()
    if expires_at > now:
        logger.debug(
            "[SECURITY] JWT cache hit for subject=%s (expires_at=%s)",
            user.uid,
            _iso(expires_at),
        )
        return user
    _JWT_CACHE.delete(token)
    return None


def _cache_user(token: str, payload: Dict[str, Any], user: KeycloakUser) -> None:
    if not JWT_CACHE_ENABLED or JWT_CACHE_MAX_SIZE <= 0:
        return
    now = time.time()
    token_exp = payload.get("exp")
    ttl_exp = now + JWT_CACHE_TTL_SECONDS if JWT_CACHE_TTL_SECONDS > 0 else None
    expires_at_candidates: list[float] = []
    for candidate in (token_exp, ttl_exp):
        if candidate is None:
            continue
        try:
            expires_at_candidates.append(float(candidate))
        except (TypeError, ValueError) as exc:
            logger.debug("[SECURITY] Ignoring invalid expiry candidate %s (%s)", candidate, exc)
    if not expires_at_candidates:
        return
    expires_at = min(expires_at_candidates)
    if expires_at <= now:
        return
    _JWT_CACHE.set(token, (expires_at, user))


def _parse_user_uuid(user: KeycloakUser) -> UUID | None:
    try:
        return UUID(user.uid)
    except ValueError:
        return None


def decode_jwt(token: str) -> KeycloakUser:
    """Decode and validate a JWT, returning a KeycloakUser built via the active IdpPort."""
    if not KEYCLOAK_ENABLED:
        username = getpass.getuser()
        logger.debug("[SECURITY] Authentication is DISABLED. Returning mock user: %s", username)
        return KeycloakUser(
            uid=username,
            username=username,
            roles=["admin"],
            email=f"{username}@localhost",
            groups=["admins"],
        )

    cached_user = _get_cached_user(token)
    if cached_user:
        return cached_user

    header, payload_peek = _peek_header_and_claims(token)
    kid = header.get("kid")
    alg = header.get("alg")
    logger.debug(
        "JWT peek: kid=%s alg=%s iss=%s aud=%s azp=%s sub=%s exp=%s(%s) nbf=%s(%s)",
        kid, alg,
        payload_peek.get("iss"), payload_peek.get("aud"), payload_peek.get("azp"),
        payload_peek.get("sub"),
        payload_peek.get("exp"), _iso(payload_peek.get("exp")),
        payload_peek.get("nbf"), _iso(payload_peek.get("nbf")),
    )

    iss = payload_peek.get("iss")
    aud = payload_peek.get("aud")
    if iss and KEYCLOAK_URL and not str(iss).startswith(KEYCLOAK_URL):
        logger.warning(
            "[SECURITY] JWT issuer mismatch (soft): iss=%s expected_prefix=%s",
            iss, KEYCLOAK_URL,
        )
        if STRICT_ISSUER:
            raise HTTPException(status_code=401, detail="Invalid token issuer")

    if KEYCLOAK_CLIENT_ID:
        aud_list = aud if isinstance(aud, list) else [aud] if aud else []
        if KEYCLOAK_CLIENT_ID not in aud_list:
            logger.debug(
                "[SECURITY] JWT audience does not include client_id (soft): aud=%s client_id=%s",
                aud_list, KEYCLOAK_CLIENT_ID,
            )
            if STRICT_AUDIENCE:
                raise HTTPException(status_code=401, detail="Invalid token audience")

    try:
        t0 = time.perf_counter()
        jwks_client = _get_jwks_client()
        signing_key = jwks_client.get_signing_key_from_jwt(token).key
        logger.debug("[SECURITY] JWKS resolved key in %.1f ms (kid=%s)", (time.perf_counter() - t0) * 1000, kid)
    except Exception as e:
        logger.warning("[SECURITY] Could not retrieve signing key from JWKS: %s", e)
        raise HTTPException(
            status_code=401,
            detail="Invalid token signature",
            headers={"WWW-Authenticate": "Bearer error='invalid_token'"},
        )

    try:
        payload = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            options={"verify_exp": True, "verify_aud": False},
            leeway=CLOCK_SKEW_SECONDS,
        )
        logger.debug("[SECURITY] JWT token successfully decoded")
    except jwt.ExpiredSignatureError:
        logger.warning("[SECURITY] Access token expired")
        raise HTTPException(
            status_code=401,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer error='invalid_token', error_description='token expired'"},
        )
    except jwt.InvalidTokenError as e:
        logger.error("[SECURITY] Invalid JWT token: %s", e)
        raise HTTPException(
            status_code=401,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer error='invalid_token'"},
        )

    # Delegate claim extraction to the active IdpPort adapter.
    idp_user = get_idp().extract_identity(payload)

    if not idp_user["uid"]:
        logger.warning("[SECURITY] JWT missing a usable subject claim (provider=%s)",
                       os.getenv("OIDC_PROVIDER", "keycloak"))
        raise HTTPException(
            status_code=401,
            detail="Invalid token claims",
            headers={"WWW-Authenticate": "Bearer error='invalid_token'"},
        )

    logger.debug(
        "[SECURITY] JWT decoded: uid=%s username=%s email=%s roles=%s",
        idp_user["uid"], idp_user["username"], idp_user["email"], idp_user["roles"],
    )

    user = KeycloakUser(
        uid=idp_user["uid"],
        username=idp_user["username"],
        roles=idp_user["roles"],
        email=idp_user["email"],
        groups=idp_user["groups"],
    )
    _cache_user(token, payload, user)
    return user


async def get_current_user(
    token: str = Security(oauth2_scheme),
    user_store: BaseUserStore = Depends(get_user_store),
    configuration=Depends(get_config),
) -> KeycloakUser:
    """
    Return the authenticated user, run JIT provisioning, and enforce GCU when enabled.
    """
    user = await get_current_user_without_gcu(token)
    if not KEYCLOAK_ENABLED:
        return user

    user_uuid = _parse_user_uuid(user)

    # JIT provisioning: persist a row on first authenticated request so GCU
    # acceptance, storage quotas and the user picker have a stable anchor.
    # The mock no-security user (uid="admin") is not UUID-backed — skip it.
    if user_uuid is not None:
        await user_store.ensure_user(user_uuid)

    if configuration.app.gcu_version is None:
        return user

    if user_uuid is None:
        logger.warning(
            "[SECURITY] Authenticated subject %r is not UUID-backed; rejecting GCU lookup.",
            user.uid,
        )
        raise HTTPException(status_code=403, detail="user_not_accept_gcu")

    user_details = await user_store.find_user_by_id(user_uuid)
    accepted_gcu_version = (
        user_details.gcuVersionAccepted.value
        if user_details is not None and user_details.gcuVersionAccepted is not None
        else None
    )
    if accepted_gcu_version != configuration.app.gcu_version:
        raise HTTPException(status_code=403, detail="user_not_accept_gcu")
    return user


async def get_current_user_without_gcu(
    token: str = Security(oauth2_scheme),
) -> KeycloakUser:
    """Validate the Bearer token and return the authenticated user."""
    if not KEYCLOAK_ENABLED:
        logger.debug("[SECURITY] Authentication is DISABLED. Returning a mock user.")
        return KeycloakUser(
            uid="admin",
            username="admin",
            roles=["admin"],
            email="admin@mail.com",
            groups=["admins"],
        )

    if not token:
        logger.warning("No Bearer token provided on secured endpoint")
        raise HTTPException(
            status_code=401,
            detail="No authentication token provided",
            headers={"WWW-Authenticate": "Bearer"},
        )

    logger.debug("[SECURITY] Received token prefix: %s...", token[:10])
    user = decode_jwt(token)
    if is_whitelist_active() and not is_user_whitelisted(user):
        logger.warning(
            "[SECURITY] User not in whitelist: uid=%s email=%s", user.uid, user.email,
        )
        raise HTTPException(status_code=403, detail="user_not_whitelisted")
    return user
