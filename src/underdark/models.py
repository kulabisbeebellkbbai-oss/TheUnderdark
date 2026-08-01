from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Literal

from theunderdark.adapter import MAX_CONTENT_BYTES


@dataclass(frozen=True)
class Limits:
    max_content_bytes: int = MAX_CONTENT_BYTES
    max_request_bytes: int = 1_398_102
    max_page_size: int = 200
    max_items: int = 200


@dataclass(frozen=True)
class RootRegistration:
    root_id: str
    host_path: Path | str
    alias: str
    status: Literal["active", "suspended", "retired"] = "active"
    allowed_actions: frozenset[str] = frozenset(
        {"directory.create", "file.write", "path.copy", "path.move", "path.delete"}
    )
    limits: Limits = field(default_factory=Limits)


@dataclass(frozen=True)
class ProjectRegistration:
    project_id: str
    roots: tuple[RootRegistration, ...] | list[RootRegistration]
    label: str = "fixture project"
    policy_revision: str = "1"
    status: Literal["active", "suspended", "retired"] = "active"
    limits: Limits = field(default_factory=Limits)


@dataclass(frozen=True)
class Authorization:
    authorization_ref: str
    request_id: str
    project_id: str
    action: str
    root_id: str
    relative_path: str
    source_root_id: str | None = None
    source_relative_path: str | None = None
    status: Literal["approved", "pending", "revoked"] = "approved"
    claimed_by: str = "storage-adapter.theunderdark"
    expires_at: datetime | None = None
    limits: Limits = field(default_factory=Limits)
