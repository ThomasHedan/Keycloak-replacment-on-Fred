from __future__ import annotations

from pydantic import BaseModel


class UserNotFoundError(Exception):
    def __init__(self, user_id: str) -> None:
        super().__init__(f"User with id '{user_id}' was not found.")


class UserSummary(BaseModel):
    """Normalized user projection returned by Control Plane APIs."""

    id: str
    first_name: str | None = None
    last_name: str | None = None
    username: str | None = None
    email: str | None = None
