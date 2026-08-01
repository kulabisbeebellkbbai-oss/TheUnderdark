from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from theunderdark.adapter import (
    Authorization as CoreAuthorization,
    RootRegistration as CoreRootRegistration,
    StorageAdapter,
)

from .models import Authorization, ProjectRegistration


class StorageService(StorageAdapter):
    """Public service API, initialized only with explicit fixture registrations."""

    def __init__(
        self,
        projects: Iterable[ProjectRegistration] = (),
        authorizations: Iterable[Authorization] = (),
    ) -> None:
        super().__init__()
        for project in projects:
            self.register_project(project)
        for authorization in authorizations:
            self.authorize(authorization)

    def register_project(self, project: ProjectRegistration) -> None:
        for root in project.roots:
            self.register_root(CoreRootRegistration(
                project_id=project.project_id,
                root_id=root.root_id,
                host_path=__import__("pathlib").Path(root.host_path),
                alias=root.alias,
                policy_revision=project.policy_revision,
                status=root.status if project.status == "active" else project.status,
                allowed_actions=root.allowed_actions,
                max_content_bytes=min(project.limits.max_content_bytes, root.limits.max_content_bytes),
            ))

    def authorize(self, authorization: Authorization) -> None:
        self.add_authorization(CoreAuthorization(
            authorization_ref=authorization.authorization_ref,
            request_id=authorization.request_id,
            project_id=authorization.project_id,
            action=authorization.action,
            root_id=authorization.root_id,
            relative_path=authorization.relative_path,
            source_root_id=authorization.source_root_id,
            source_relative_path=authorization.source_relative_path,
            status=authorization.status,
            claimed_by=authorization.claimed_by,
            expires_at=authorization.expires_at,
            max_bytes=authorization.limits.max_content_bytes,
        ))

    # Contract names use *_get, while the implementation's clearer names remain aliases.
    def underdark_project_get(self, **kwargs: Any) -> dict[str, Any]: return self.project_get(**kwargs)
    def underdark_root_get(self, **kwargs: Any) -> dict[str, Any]: return self.root_get(**kwargs)
