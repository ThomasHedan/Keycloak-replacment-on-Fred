from __future__ import annotations

from dataclasses import dataclass

from fastapi import Request

from control_plane_backend.app.container import ControlPlaneContainer
from control_plane_backend.app.dependencies import get_application_container
from control_plane_backend.config.models import Configuration


@dataclass(slots=True)
class UserServiceDependencies:
    configuration: Configuration


def build_user_service_dependencies(
    container: ControlPlaneContainer,
) -> UserServiceDependencies:
    return UserServiceDependencies(
        configuration=container.configuration,
    )


def get_user_service_dependencies(request: Request) -> UserServiceDependencies:
    return build_user_service_dependencies(get_application_container(request))
