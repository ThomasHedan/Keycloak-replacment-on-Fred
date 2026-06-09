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

# fred_core/security/service_auth.py

from __future__ import annotations

import asyncio
import os
import time
import typing as t

import httpx
from fastapi import FastAPI
from httpx import Request, Response
from pydantic import BaseModel

# ──────────────────────────────────────────────────────────────────────────────
# Fred rationale:
# - When a tool calls our own API (self-call), there might be no user bearer.
#   We need a *service* token (client_credentials) so calls don’t 401.
# - We keep this generic in fred_core so any app can reuse it.
# - We don’t wire it into FastAPI yet; that comes later.
# ──────────────────────────────────────────────────────────────────────────────

# ──────────────────────────────────────────────────────────────────────────────
# Fred rationale:
# - When a tool calls our own API (self-call), there might be no user bearer.
#   We need a *service* token (client_credentials) so calls don’t 401.
# - We keep this generic in fred_core so any app can reuse it.
# - We don’t wire it into FastAPI yet; that comes later.
# ──────────────────────────────────────────────────────────────────────────────


class M2MAuthConfig(BaseModel):
    """
    Minimal config for client-credentials flow.

    Pass ``token_url`` directly (provider-agnostic).
    For backward compatibility ``keycloak_realm_url`` is still accepted and
    the Keycloak token endpoint is derived from it automatically.

    Preferred (any provider):
        token_url  — full token endpoint URL returned by ``IdpPort.m2m_token_url()``
        scope      — optional scope (required for Entra: ``api://<id>/.default``)

    Legacy (Keycloak only):
        keycloak_realm_url — realm URL; ``token_url`` is derived from it
    """

    token_url: str = ""
    client_id: str
    secret_env: str
    scope: str | None = None
    # Deprecated — kept for callers that haven't migrated yet.
    keycloak_realm_url: str = ""

    def model_post_init(self, __context: object) -> None:
        # If only the legacy field is supplied, derive token_url from it.
        if not self.token_url and self.keycloak_realm_url:
            object.__setattr__(
                self,
                "token_url",
                f"{self.keycloak_realm_url}/protocol/openid-connect/token",
            )


class M2MTokenProvider:
    """
    Caches and refreshes a Keycloak client-credentials token.
    Thread-safe (async) and cheap to reuse across calls.
    """

    def __init__(self, cfg: M2MAuthConfig):
        self.cfg = cfg
        self._secret = os.getenv(cfg.secret_env, "")
        self._lock = asyncio.Lock()
        self._token: str | None = None
        self._exp: int = 0  # epoch seconds

    async def get_token(self) -> str:
        now = int(time.time())
        if self._token and now < self._exp - 30:
            return self._token

        async with self._lock:
            # double-check inside lock
            now = int(time.time())
            if self._token and now < self._exp - 30:
                return self._token

            if not self._secret:
                raise RuntimeError(
                    f"Missing OIDC client secret in env: {self.cfg.secret_env}"
                )

            form = {
                "grant_type": "client_credentials",
                "client_id": self.cfg.client_id,
                "client_secret": self._secret,
            }
            if self.cfg.scope:
                form["scope"] = self.cfg.scope

            async with httpx.AsyncClient(timeout=10.0) as c:
                r = await c.post(self.cfg.token_url, data=form)
                r.raise_for_status()
                payload = r.json()

            token = payload.get("access_token")
            expires_in = int(payload.get("expires_in", 60))

            if not isinstance(token, str) or not token:
                raise RuntimeError("Auth server did not return a valid access_token")

            self._token = token
            self._exp = now + expires_in

            # Guarantee to the outside world that we return str
            assert self._token is not None
            return self._token


class M2MBearerAuth(httpx.Auth):
    """
    httpx.Auth that injects 'Authorization: Bearer <service_token>'.

    Important: httpx expects an *async generator* here. We yield the request
    after mutating headers, which avoids the common type errors.
    """

    requires_request_body = True
    requires_response_body = False

    def __init__(self, provider: M2MTokenProvider):
        self._provider = provider

    async def async_auth_flow(
        self, request: Request
    ) -> t.AsyncGenerator[Request, Response]:
        token = await self._provider.get_token()
        request.headers["Authorization"] = f"Bearer {token}"
        yield request  # httpx performs the request; we don't need the response hook here.


def make_m2m_asgi_client(app: FastAPI, auth: httpx.Auth) -> httpx.AsyncClient:
    """
    In-process client for self-calls via ASGITransport (no network).
    """
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://apiserver",
        timeout=15.0,
        auth=auth,
    )
