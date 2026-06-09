from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from uuid import uuid4

from fastapi import UploadFile
from fred_core import (
    KeycloakUser,
    RebacDisabledResult,
    RebacEngine,
    RebacReference,
    Relation,
    RelationType,
    Resource,
    SessionSchema,
    TeamPermission,
)
from fred_core.common import TeamId
from fred_core.scheduler import SchedulerBackend
from fred_core.teams.metadata_store import TeamMetadataPatch

from control_plane_backend.scheduler.policies.policy_engine import (
    evaluate_policy_for_request,
)
from control_plane_backend.scheduler.policies.policy_models import (
    LifecycleTrigger,
    PolicyResolutionRequest,
)
from control_plane_backend.scheduler.temporal.structures import LifecycleManagerInput
from control_plane_backend.teams.dependencies import TeamServiceDependencies
from control_plane_backend.teams.schemas import (
    AddTeamMemberRequest,
    BannerUploadError,
    RemoveTeamMemberResponse,
    Team,
    TeamMember,
    TeamNotFoundError,
    TeamOwnerConstraintError,
    TeamWithPermissions,
    UpdateTeamMemberRequest,
    UpdateTeamRequest,
    UserTeamRelation,
)
from control_plane_backend.teams.system import (
    get_system_team,
    list_system_teams,
    to_team_summary,
)
from control_plane_backend.users.schemas import UserSummary

logger = logging.getLogger(__name__)

_MAX_BANNER_FILE_SIZE_BYTES = 5 * 1024 * 1024
_ALLOWED_BANNER_MIME_TYPES = {"image/jpeg", "image/png", "image/webp"}
_BANNER_EXTENSION_BY_MIME = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/webp": ".webp",
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


async def list_teams(
    user: KeycloakUser,
    deps: TeamServiceDependencies,
) -> list[Team]:
    personal_limit = deps.configuration.app.personal_max_resources_storage_size
    selectable_teams: dict[str, Team] = {
        str(team.id): to_team_summary(team)
        for team in await list_system_teams(user, personal_limit)
    }

    rebac = deps.rebac

    authorized_teams_refs = await rebac.lookup_user_resources(
        user,
        TeamPermission.CAN_READ,
    )
    if isinstance(authorized_teams_refs, RebacDisabledResult):
        return list(selectable_teams.values())

    authorized_team_ids: list[TeamId] = [TeamId(ref.id) for ref in authorized_teams_refs]
    await rebac.ensure_team_organization_relations(authorized_team_ids)

    collaborative_teams = await _enrich_teams_with_data(
        rebac,
        user,
        authorized_team_ids,
        deps,
    )
    for team in collaborative_teams:
        selectable_teams[str(team.id)] = team
    return list(selectable_teams.values())


async def get_team_by_id(
    user: KeycloakUser,
    team_id: TeamId,
    deps: TeamServiceDependencies,
) -> TeamWithPermissions:
    personal_limit = deps.configuration.app.personal_max_resources_storage_size
    system_team = await get_system_team(user, team_id, personal_limit)
    if system_team is not None:
        return system_team

    rebac = deps.rebac

    consistency_token = await _validate_team_and_check_permission(
        user,
        team_id,
        rebac,
        [TeamPermission.CAN_READ],
        deps,
    )

    teams = await _enrich_teams_with_data(
        rebac,
        user,
        [team_id],
        deps,
    )
    if not teams:
        raise TeamNotFoundError(team_id)

    permissions = await _get_team_permissions_for_user(
        rebac,
        user,
        team_id,
        consistency_token,
    )
    return TeamWithPermissions(**teams[0].model_dump(), permissions=permissions)


async def update_team(
    user: KeycloakUser,
    team_id: TeamId,
    request: UpdateTeamRequest,
    deps: TeamServiceDependencies,
) -> TeamWithPermissions:
    rebac = deps.rebac

    consistency_token = await _validate_team_and_check_permission(
        user,
        team_id,
        rebac,
        [TeamPermission.CAN_UPDATE_INFO],
        deps,
    )

    if request.model_fields_set:
        patch = TeamMetadataPatch.model_validate(request.model_dump(exclude_unset=True))
        await deps.get_team_metadata_store().upsert(team_id, patch)

        if "is_private" in request.model_fields_set:
            public_relation = Relation(
                subject=RebacReference(Resource.USER, "*"),
                relation=RelationType.PUBLIC,
                resource=RebacReference(Resource.TEAM, team_id),
            )
            if request.is_private:
                await rebac.delete_relations([public_relation])
            else:
                await rebac.add_relation(public_relation)

    teams = await _enrich_teams_with_data(
        rebac,
        user,
        [team_id],
        deps,
    )
    if not teams:
        raise TeamNotFoundError(team_id)

    permissions = await _get_team_permissions_for_user(
        rebac,
        user,
        team_id,
        consistency_token,
    )
    return TeamWithPermissions(**teams[0].model_dump(), permissions=permissions)


async def upload_team_banner(
    user: KeycloakUser,
    team_id: TeamId,
    file: UploadFile,
    deps: TeamServiceDependencies,
) -> None:
    rebac = deps.rebac

    await _validate_team_and_check_permission(
        user,
        team_id,
        rebac,
        [TeamPermission.CAN_UPDATE_INFO],
        deps,
    )

    try:
        payload = await file.read(_MAX_BANNER_FILE_SIZE_BYTES + 1)
        if len(payload) > _MAX_BANNER_FILE_SIZE_BYTES:
            raise BannerUploadError(
                f"File too large: {len(payload)} bytes (max: {_MAX_BANNER_FILE_SIZE_BYTES})"
            )
        if not payload:
            raise BannerUploadError("Empty file upload is not allowed")

        declared_content_type = (
            file.content_type or "application/octet-stream"
        ).lower()
        if declared_content_type not in _ALLOWED_BANNER_MIME_TYPES:
            raise BannerUploadError(f"Invalid content type: {declared_content_type}")

        detected_content_type = _detect_image_content_type(payload)
        if detected_content_type not in _ALLOWED_BANNER_MIME_TYPES:
            raise BannerUploadError(
                f"File content doesn't match allowed image formats: {detected_content_type or 'unknown'}"
            )
        if detected_content_type != declared_content_type:
            raise BannerUploadError(
                f"File content doesn't match declared content type: {detected_content_type}"
            )

        file_ext = Path(file.filename or "").suffix.lower()
        if not file_ext:
            file_ext = _BANNER_EXTENSION_BY_MIME[detected_content_type]

        object_storage_key = f"teams/{team_id}/banner-{uuid4().hex}{file_ext}"
        deps.get_content_store().put_object(
            object_storage_key,
            BytesIO(payload),
            content_type=detected_content_type,
        )

        await deps.get_team_metadata_store().upsert(
            team_id,
            TeamMetadataPatch(banner_object_storage_key=object_storage_key),
        )
        logger.info("Uploaded banner for team %s: %s", team_id, object_storage_key)
    finally:
        await file.close()


async def list_team_members(
    user: KeycloakUser,
    team_id: TeamId,
    deps: TeamServiceDependencies,
) -> list[TeamMember]:
    rebac = deps.rebac

    await _validate_team_and_check_permission(
        user,
        team_id,
        rebac,
        [TeamPermission.CAN_READ_MEMEBERS],
        deps,
    )
    owner_ids, manager_ids, member_ids = await asyncio.gather(
        _get_team_users_by_relation(rebac, team_id, RelationType.OWNER),
        _get_team_users_by_relation(rebac, team_id, RelationType.MANAGER),
        _get_team_users_by_relation(rebac, team_id, RelationType.MEMBER),
    )
    user_summaries = await deps.get_users_by_ids(member_ids)

    team_members: list[TeamMember] = []
    for member_id in member_ids:
        user_summary = user_summaries.get(member_id) or UserSummary(id=member_id)
        if member_id in owner_ids:
            relation = UserTeamRelation.OWNER
        elif member_id in manager_ids:
            relation = UserTeamRelation.MANAGER
        else:
            relation = UserTeamRelation.MEMBER
        team_members.append(TeamMember(user=user_summary, relation=relation))

    return team_members


async def add_team_member(
    user: KeycloakUser,
    team_id: TeamId,
    request: AddTeamMemberRequest,
    deps: TeamServiceDependencies,
) -> None:
    rebac = deps.rebac

    permission_to_check = _get_administer_permission_for_team_role_relation(
        request.relation
    )
    await _validate_team_and_check_permission(
        user,
        team_id,
        rebac,
        [permission_to_check],
        deps,
    )
    await _add_team_member_relation(rebac, team_id, request.user_id, request.relation)

    logger.info(
        "Added user %s as %s to team %s",
        request.user_id,
        request.relation.value,
        team_id,
    )


async def remove_team_member(
    user: KeycloakUser,
    team_id: TeamId,
    user_id: str,
    deps: TeamServiceDependencies,
) -> RemoveTeamMemberResponse:
    rebac = deps.rebac

    target_role = await _get_user_role_in_team(rebac, team_id, user_id)
    await _ensure_team_keeps_at_least_one_owner(
        rebac=rebac,
        team_id=team_id,
        user_id=user_id,
        current_role=target_role,
        wanted_role=None,
    )
    permission_to_check = _get_administer_permission_for_team_role_relation(target_role)

    await _validate_team_and_check_permission(
        user,
        team_id,
        rebac,
        [permission_to_check],
        deps,
    )
    await _remove_all_team_member_relations(rebac, team_id, user_id)

    policy = evaluate_policy_for_request(
        PolicyResolutionRequest(
            team_id=team_id,
            trigger=LifecycleTrigger.MEMBER_REMOVED,
        ),
        deps.get_policy_catalog(),
    )
    scheduled_delete_at = _utcnow() + timedelta(seconds=policy.retention_seconds)

    session_store = deps.get_session_store()
    queue_store = deps.get_purge_queue_store()
    sessions: list[SessionSchema] = await session_store.get_for_user(user_id, team_id)

    sessions_enqueued = 0
    for session in sessions:
        await queue_store.enqueue(
            session_id=session.id,
            team_id=team_id,
            user_id=user_id,
            due_at=scheduled_delete_at,
        )
        sessions_enqueued += 1

    logger.info(
        "Removed user %s from team %s and enqueued %d sessions for purge",
        user_id,
        team_id,
        sessions_enqueued,
    )
    if sessions_enqueued > 0:
        await _run_lifecycle_if_in_memory_scheduler(deps)

    return RemoveTeamMemberResponse(
        team_id=team_id,
        user_id=user_id,
        sessions_enqueued=sessions_enqueued,
        scheduled_delete_at=scheduled_delete_at,
        policy_mode=policy.mode.value,
        retention_seconds=policy.retention_seconds,
        matched_rule_id=policy.matched_rule_id,
    )


async def _run_lifecycle_if_in_memory_scheduler(
    deps: TeamServiceDependencies,
) -> None:
    if not deps.configuration.scheduler.enabled:
        return
    if deps.scheduler_backend != SchedulerBackend.MEMORY:
        return

    result = await deps.run_lifecycle_manager_once_in_memory(LifecycleManagerInput())
    logger.info(
        "[LIFECYCLE][IN_MEMORY] post-member-removal pass scanned=%s deleted=%s dry_run_actions=%s",
        result.scanned,
        result.deleted,
        result.dry_run_actions,
    )


async def update_team_member(
    user: KeycloakUser,
    team_id: TeamId,
    user_id: str,
    request: UpdateTeamMemberRequest,
    deps: TeamServiceDependencies,
) -> None:
    rebac = deps.rebac

    target_current_role = await _get_user_role_in_team(rebac, team_id, user_id)
    target_wanted_role = request.relation
    await _ensure_team_keeps_at_least_one_owner(
        rebac=rebac,
        team_id=team_id,
        user_id=user_id,
        current_role=target_current_role,
        wanted_role=target_wanted_role,
    )
    permissions_to_check = [
        _get_administer_permission_for_team_role_relation(target_current_role),
        _get_administer_permission_for_team_role_relation(target_wanted_role),
    ]

    await _validate_team_and_check_permission(
        user,
        team_id,
        rebac,
        permissions_to_check,
        deps,
    )
    await _remove_all_team_member_relations(rebac, team_id, user_id)
    await _add_team_member_relation(rebac, team_id, user_id, request.relation)

    logger.info(
        "Updated user %s relation to %s in team %s",
        user_id,
        request.relation.value,
        team_id,
    )


async def _enrich_teams_with_data(
    rebac: RebacEngine,
    user: KeycloakUser,
    team_ids: list[TeamId],
    deps: TeamServiceDependencies,
) -> list[Team]:
    if not team_ids:
        return []

    content_store = deps.get_content_store()
    team_metadata_by_id = await deps.get_team_metadata_store().get_by_team_ids(team_ids)
    owner_ids_list, member_ids_list = await asyncio.gather(
        asyncio.gather(
            *[
                _get_team_users_by_relation(rebac, team_id, RelationType.OWNER)
                for team_id in team_ids
            ]
        ),
        asyncio.gather(
            *[
                _get_team_users_by_relation(rebac, team_id, RelationType.MEMBER)
                for team_id in team_ids
            ]
        ),
    )

    team_owner_ids_map = {
        team_id: owner_ids for team_id, owner_ids in zip(team_ids, owner_ids_list)
    }
    team_member_ids_map = {
        team_id: member_ids for team_id, member_ids in zip(team_ids, member_ids_list)
    }
    all_owner_ids: set[str] = set().union(*owner_ids_list)
    user_summaries = await deps.get_users_by_ids(all_owner_ids)

    teams: list[Team] = []
    for team_id in team_ids:
        member_ids = team_member_ids_map.get(team_id, set())
        metadata = team_metadata_by_id.get(team_id)
        banner_image_url: str | None = None
        if metadata and metadata.banner_object_storage_key:
            if _is_absolute_url(metadata.banner_object_storage_key):
                banner_image_url = metadata.banner_object_storage_key
            else:
                try:
                    banner_image_url = content_store.get_presigned_url(
                        metadata.banner_object_storage_key,
                        expires=timedelta(hours=1),
                    )
                except Exception as exc:
                    logger.warning(
                        "Failed to generate presigned URL for team %s banner: %s",
                        team_id,
                        exc,
                    )

        owners = _dedupe_user_summaries_by_display_key(
            [
                user_summaries.get(owner_id) or UserSummary(id=owner_id)
                for owner_id in team_owner_ids_map.get(team_id, set())
            ]
        )
        max_storage = (
            metadata.max_resources_storage_size
            if metadata and metadata.max_resources_storage_size is not None
            else deps.configuration.app.default_team_max_resources_storage_size
        )
        # TeamMetadata has no name field; fall back to team_id string
        name = str(team_id)
        teams.append(
            Team(
                id=team_id,
                name=name,
                member_count=len(member_ids),
                owners=owners,
                is_member=user.uid in member_ids,
                description=metadata.description if metadata else None,
                is_private=metadata.is_private if metadata else True,
                banner_image_url=banner_image_url,
                max_resources_storage_size=max_storage,
                current_resources_storage_size=metadata.current_resources_storage_size
                if metadata
                else None,
            )
        )

    return teams


def _dedupe_user_summaries_by_display_key(
    users: list[UserSummary],
) -> list[UserSummary]:
    deduped_users: list[UserSummary] = []
    seen_display_keys: set[str] = set()

    for user in users:
        display_key = (user.username or user.id).strip().casefold()
        if display_key in seen_display_keys:
            continue
        seen_display_keys.add(display_key)
        deduped_users.append(user)

    return deduped_users


async def _get_team_permissions_for_user(
    rebac: RebacEngine,
    user: KeycloakUser,
    team_id: TeamId,
    consistency_token: str | None = None,
) -> list[TeamPermission]:
    permissions_to_check = list(TeamPermission)
    group_relations, org_relations = await asyncio.gather(
        rebac.groups_list_to_relations(user),
        rebac.user_role_to_organization_relation(user),
    )
    contextual_relations = group_relations | org_relations

    checks = await asyncio.gather(
        *[
            rebac.has_permission(
                RebacReference(Resource.USER, user.uid),
                permission,
                RebacReference(Resource.TEAM, team_id),
                contextual_relations=contextual_relations,
                consistency_token=consistency_token,
            )
            for permission in permissions_to_check
        ]
    )
    return [
        permission
        for permission, has_permission in zip(permissions_to_check, checks)
        if has_permission
    ]


async def _get_team_users_by_relation(
    rebac: RebacEngine,
    team_id: TeamId,
    relation: RelationType,
) -> set[str]:
    subjects = await rebac.lookup_subjects(
        RebacReference(type=Resource.TEAM, id=team_id),
        relation,
        Resource.USER,
    )
    if isinstance(subjects, RebacDisabledResult):
        return set()
    return {subject.id for subject in subjects}


def _sanitize_name(value: object, fallback: str) -> str:
    name = str(value or "").strip()
    return name or fallback


def _detect_image_content_type(payload: bytes) -> str | None:
    if payload.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if payload.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if len(payload) >= 12 and payload[0:4] == b"RIFF" and payload[8:12] == b"WEBP":
        return "image/webp"
    return None


def _is_absolute_url(value: str) -> bool:
    candidate = value.lower()
    return candidate.startswith("http://") or candidate.startswith("https://")


async def _validate_team_and_check_permission(
    user: KeycloakUser,
    team_id: TeamId,
    rebac: RebacEngine,
    permissions: list[TeamPermission],
    deps: TeamServiceDependencies,
) -> str | None:
    metadata = await deps.get_team_metadata_store().get_by_team_id(team_id)
    if metadata is None:
        raise TeamNotFoundError(team_id)

    consistency_token = await rebac.check_user_team_permissions_or_raise(
        user=user,
        team_id=team_id,
        permissions=permissions,
    )

    return consistency_token


async def _add_team_member_relation(
    rebac: RebacEngine,
    team_id: TeamId,
    user_id: str,
    relation: UserTeamRelation,
) -> None:
    await rebac.add_relation(
        Relation(
            subject=RebacReference(Resource.USER, user_id),
            relation=relation.to_relation(),
            resource=RebacReference(Resource.TEAM, team_id),
        )
    )


def _get_administer_permission_for_team_role_relation(
    target: UserTeamRelation,
) -> TeamPermission:
    if target == UserTeamRelation.MANAGER:
        return TeamPermission.CAN_ADMINISTER_MANAGERS
    if target == UserTeamRelation.OWNER:
        return TeamPermission.CAN_ADMINISTER_OWNERS
    return TeamPermission.CAN_ADMINISTER_MEMBERS


async def _get_user_role_in_team(
    rebac: RebacEngine,
    team_id: TeamId,
    user_id: str,
) -> UserTeamRelation:
    owner_ids, manager_ids = await asyncio.gather(
        _get_team_users_by_relation(rebac, team_id, RelationType.OWNER),
        _get_team_users_by_relation(rebac, team_id, RelationType.MANAGER),
    )
    if user_id in owner_ids:
        return UserTeamRelation.OWNER
    if user_id in manager_ids:
        return UserTeamRelation.MANAGER
    return UserTeamRelation.MEMBER


async def _remove_all_team_member_relations(
    rebac: RebacEngine,
    team_id: TeamId,
    user_id: str,
) -> None:
    await rebac.delete_relations(
        [
            Relation(
                subject=RebacReference(Resource.USER, user_id),
                relation=RelationType.OWNER,
                resource=RebacReference(Resource.TEAM, team_id),
            ),
            Relation(
                subject=RebacReference(Resource.USER, user_id),
                relation=RelationType.MANAGER,
                resource=RebacReference(Resource.TEAM, team_id),
            ),
            Relation(
                subject=RebacReference(Resource.USER, user_id),
                relation=RelationType.MEMBER,
                resource=RebacReference(Resource.TEAM, team_id),
            ),
        ]
    )


async def _ensure_team_keeps_at_least_one_owner(
    *,
    rebac: RebacEngine,
    team_id: TeamId,
    user_id: str,
    current_role: UserTeamRelation,
    wanted_role: UserTeamRelation | None,
) -> None:
    is_owner_demotion_or_removal = current_role == UserTeamRelation.OWNER and (
        wanted_role is None or wanted_role != UserTeamRelation.OWNER
    )
    if not is_owner_demotion_or_removal:
        return

    owner_ids = await _get_team_users_by_relation(rebac, team_id, RelationType.OWNER)
    if user_id in owner_ids and len(owner_ids) <= 1:
        raise TeamOwnerConstraintError(
            "Operation denied: a team must keep at least one owner."
        )
