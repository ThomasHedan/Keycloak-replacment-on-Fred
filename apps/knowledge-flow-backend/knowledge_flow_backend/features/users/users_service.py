import logging
from collections.abc import Iterable

from fred_core import Action, KeycloakUser, Resource, authorize

from knowledge_flow_backend.features.users.users_structures import UserSummary

logger = logging.getLogger(__name__)


@authorize(Action.READ, Resource.USER)
async def list_users(_curent_user: KeycloakUser) -> list[UserSummary]:
    """Return an empty list — user listing is no longer backed by a directory."""
    return []


async def get_users_by_ids(user_ids: Iterable[str]) -> dict[str, UserSummary]:
    """Return id-only stubs for each requested user id."""
    unique_ids = {user_id for user_id in user_ids if user_id}
    return {user_id: UserSummary(id=user_id) for user_id in unique_ids}
