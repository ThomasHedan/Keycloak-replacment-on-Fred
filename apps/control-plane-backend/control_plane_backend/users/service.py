from __future__ import annotations

import logging
from collections.abc import Iterable
from uuid import UUID

from fred_core import (
    Action,
    BaseUserStore,
    KeycloakUser,
    Resource,
    authorize,
)
from fred_core.users import GcuVersionsType, UserRow

from control_plane_backend.users.dependencies import UserServiceDependencies
from control_plane_backend.users.schemas import (
    UserSummary,
)

logger = logging.getLogger(__name__)


@authorize(Action.READ, Resource.USER)
async def list_users(
    _current_user: KeycloakUser,
    deps: UserServiceDependencies,
) -> list[UserSummary]:
    """Return an empty list — user listing is no longer backed by a user directory."""
    logger.info("list_users: no directory backend configured; returning empty list.")
    return []


async def get_users_by_ids(
    user_ids: Iterable[str],
    deps: UserServiceDependencies,
) -> dict[str, UserSummary]:
    """Return minimal user summaries (id only) for each requested id.

    Without a user directory the display names are unavailable, so callers
    receive stubs that at least carry the stable id.
    """
    unique_ids = {user_id for user_id in user_ids if user_id}
    return {user_id: UserSummary(id=user_id) for user_id in unique_ids}


async def find_user_details_by_id(
    user_id: UUID,
    user_store: BaseUserStore,
) -> UserRow | None:
    return await user_store.find_user_by_id(user_id)


async def update_gcu_validation(
    user_id: UUID,
    user_store: BaseUserStore,
    deps: UserServiceDependencies,
) -> None:
    cfg = deps.configuration
    if cfg.app.gcu_version is None:
        return

    await user_store.update_gcu_version(user_id, GcuVersionsType(cfg.app.gcu_version))
