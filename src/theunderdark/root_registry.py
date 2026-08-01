"""Durable, local-only registered-root control plane and composition."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Mapping, Protocol, Sequence

from .mutation_executor import ResolvedRoot


@dataclass(frozen=True)
class ControlPlaneApproval:
    approval_id: str
    action: str
    project_id: str
    root_id: str
    policy_revision: str
    target_digest: str
    status: str
    expires_at: str


class ControlPlaneVerifier(Protocol):
    def verify(self, action: str, payload: Mapping[str, object], target_digest: str) -> ControlPlaneApproval: ...


class RegistryFailure(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message); self.code = code; self.message = message


class SQLiteRootRegistry:
    """Append-only policy revisions; registration is never exposed as an MCP tool."""

    def __init__(self, state_path: str | Path, *, verifier: ControlPlaneVerifier, protected_paths: Sequence[str | Path] = ()) -> None:
        if verifier is None: raise TypeError("an approved control-plane verifier is required")
        self.path = Path(state_path)
        if not self.path.is_absolute(): raise ValueError("registry state path must be absolute")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._verifier = verifier
        source_root = Path(__file__).resolve().parents[2]
        overseer_root = source_root.parent / "Overseer"
        sensitive_defaults = (
            Path.home() / ".ssh",
            Path.home() / ".gnupg",
            Path.home() / ".config",
            Path.home() / ".local" / "share" / "overseer",
        )
        self._protected = (
            source_root,
            overseer_root.resolve(strict=False),
            *(path.resolve(strict=True) for path in sensitive_defaults if path.exists()),
            *(Path(value).resolve(strict=True) for value in protected_paths),
        )
        self._identity = self._prepare_file()
        self._connection = sqlite3.connect(self.path, isolation_level=None, timeout=30)
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.executescript("""
        CREATE TABLE IF NOT EXISTS root_revisions (
          project_id TEXT NOT NULL, root_id TEXT NOT NULL, policy_revision TEXT NOT NULL,
          host_path TEXT NOT NULL, alias TEXT NOT NULL, status TEXT NOT NULL, max_bytes INTEGER NOT NULL,
          device INTEGER NOT NULL, inode INTEGER NOT NULL, approval_id TEXT NOT NULL,
          target_digest TEXT NOT NULL, created_at TEXT NOT NULL,
          PRIMARY KEY(project_id, root_id, policy_revision)
        );
        CREATE TABLE IF NOT EXISTS root_heads (
          project_id TEXT NOT NULL, root_id TEXT NOT NULL, policy_revision TEXT NOT NULL,
          PRIMARY KEY(project_id, root_id)
        );
        """)
        self._harden()

    def register(self, *, project_id: str, root_id: str, policy_revision: str, host_path: str | Path, alias: str, max_bytes: int) -> None:
        self._validate_text(project_id, "project_id"); self._validate_text(root_id, "root_id")
        self._validate_text(policy_revision, "policy_revision"); self._validate_text(alias, "alias")
        if max_bytes < 1: raise RegistryFailure("INVALID_ARGUMENT", "max_bytes must be positive")
        root, info = self._validate_root(host_path)
        payload = self._payload(project_id, root_id, policy_revision, root, alias, "active", max_bytes)
        approval_payload = self._approval_payload(payload, info)
        digest, approval = self._approve("root.register", approval_payload)
        with self._transaction():
            if self._head(project_id, root_id) is not None: raise RegistryFailure("ROOT_EXISTS", "root is already registered")
            self._reject_overlap(root)
            self._insert(payload, info, approval.approval_id, digest)

    def transition(self, *, project_id: str, root_id: str, current_revision: str, policy_revision: str, status: str, max_bytes: int | None = None) -> None:
        if status not in {"active", "suspended", "retired"}: raise RegistryFailure("INVALID_ARGUMENT", "status is invalid")
        with self._transaction():
            current = self._current(project_id, root_id)
            if str(current["policy_revision"]) != current_revision: raise RegistryFailure("POLICY_REVISION_MISMATCH", "current revision changed")
            if policy_revision == current_revision: raise RegistryFailure("REVISION_CONFLICT", "new revision must be immutable and distinct")
            allowed = {"active": {"suspended", "retired"}, "suspended": {"active", "retired"}, "retired": set()}
            if status not in allowed[str(current["status"])]: raise RegistryFailure("TRANSITION_INVALID", "root status transition is invalid")
            limit = int(current["max_bytes"]) if max_bytes is None else max_bytes
            if limit < 1: raise RegistryFailure("INVALID_ARGUMENT", "max_bytes must be positive")
            root = Path(str(current["host_path"]))
            validated, info = self._validate_root(root)
            if (info.st_dev, info.st_ino) != (int(current["device"]), int(current["inode"])):
                raise RegistryFailure("ROOT_IDENTITY_CHANGED", "registered root identity changed")
            payload = self._payload(project_id, root_id, policy_revision, validated, str(current["alias"]), status, limit)
            digest, approval = self._approve("root.transition", self._approval_payload(payload, info))
            self._insert(payload, info, approval.approval_id, digest)

    def project_roots(self, project_id: str) -> tuple[Mapping[str, object], ...]:
        rows = self._connection.execute("""
          SELECT r.project_id,r.root_id,r.policy_revision,r.alias,r.status,r.max_bytes
          FROM root_heads h JOIN root_revisions r USING(project_id,root_id,policy_revision)
          WHERE r.project_id=? ORDER BY r.root_id
        """, (project_id,)).fetchall()
        return tuple({key: row[key] for key in ("project_id", "root_id", "policy_revision", "alias", "status", "max_bytes")} for row in rows)

    def root_ids(self, project_id: str) -> tuple[str, ...]:
        """Return the sorted active namespace keys for read-backend composition."""
        return tuple(str(row["root_id"]) for row in self.project_roots(project_id) if row["status"] == "active")

    def resolve(self, project_id: str, root_id: str, policy_revision: str) -> ResolvedRoot:
        row = self._current(project_id, root_id)
        if str(row["policy_revision"]) != policy_revision: raise RegistryFailure("POLICY_REVISION_MISMATCH", "exact active revision is required")
        if str(row["status"]) != "active": raise RegistryFailure("ROOT_INACTIVE", "root is not active")
        root, info = self._validate_root(Path(str(row["host_path"])))
        if (info.st_dev, info.st_ino) != (int(row["device"]), int(row["inode"])):
            raise RegistryFailure("ROOT_IDENTITY_CHANGED", "registered root identity changed")
        return ResolvedRoot(root, str(row["alias"]), int(row["max_bytes"]), str(row["policy_revision"]))

    def resolve_current(self, project_id: str, root_id: str) -> ResolvedRoot:
        row = self._current(project_id, root_id)
        return self.resolve(project_id, root_id, str(row["policy_revision"]))

    def resolver_for_revision(self, policy_revision: str):
        return lambda project_id, root_id: self.resolve(project_id, root_id, policy_revision)

    def close(self) -> None: self._connection.close(); self._harden()
    def __enter__(self): return self
    def __exit__(self, *_): self.close()

    def _validate_root(self, value: str | Path) -> tuple[Path, os.stat_result]:
        supplied = Path(value)
        if not supplied.is_absolute(): raise RegistryFailure("ROOT_INVALID", "registered root must be absolute")
        try:
            raw = supplied.lstat()
            if stat.S_ISLNK(raw.st_mode): raise RegistryFailure("ROOT_INVALID", "registered root cannot be a symlink")
            root = supplied.resolve(strict=True); info = root.stat(follow_symlinks=False)
        except OSError as exc: raise RegistryFailure("ROOT_INVALID", "registered root is unavailable") from exc
        if not stat.S_ISDIR(info.st_mode): raise RegistryFailure("ROOT_INVALID", "registered root must be a directory")
        parent_info = root.parent.stat(follow_symlinks=False)
        if info.st_dev != parent_info.st_dev: raise RegistryFailure("CROSS_DEVICE_DENIED", "mount roots are not registrable")
        if root in {Path("/"), Path.home().resolve()}:
            raise RegistryFailure("PROTECTED_PATH", "filesystem or home root is protected")
        forbidden = [Path("/proc"), Path("/sys"), Path("/dev"), Path("/run"), self.path.resolve(), *self._protected]
        for protected in forbidden:
            if root == protected or root in protected.parents or protected in root.parents:
                raise RegistryFailure("PROTECTED_PATH", "root overlaps protected local state")
        return root, info

    def _reject_overlap(self, root: Path) -> None:
        for row in self._connection.execute("SELECT host_path FROM root_revisions JOIN root_heads USING(project_id,root_id,policy_revision)").fetchall():
            existing = Path(str(row["host_path"]))
            if root == existing or root in existing.parents or existing in root.parents:
                raise RegistryFailure("ROOT_OVERLAP", "registered roots cannot overlap")

    def _approve(self, action: str, payload: Mapping[str, object]) -> tuple[str, ControlPlaneApproval]:
        digest = "sha256:" + hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        try: approval = self._verifier.verify(action, payload, digest)
        except Exception as exc: raise RegistryFailure("APPROVAL_UNAVAILABLE", "control-plane approval verification failed") from exc
        try:
            expected = (action, payload["project_id"], payload["root_id"], payload["policy_revision"], digest, "approved")
            actual = (approval.action, approval.project_id, approval.root_id, approval.policy_revision, approval.target_digest, approval.status)
            expires = datetime.fromisoformat(approval.expires_at.replace("Z", "+00:00")).astimezone(UTC)
        except (AttributeError, TypeError, ValueError) as exc:
            raise RegistryFailure("APPROVAL_MISMATCH", "control-plane approval record is invalid") from exc
        if actual != expected or expires <= datetime.now(UTC):
            raise RegistryFailure("APPROVAL_MISMATCH", "control-plane approval does not match registration")
        return digest, approval

    @staticmethod
    def _payload(project: str, root_id: str, revision: str, root: Path, alias: str, status: str, max_bytes: int) -> dict[str, object]:
        return {"project_id": project, "root_id": root_id, "policy_revision": revision, "host_path": str(root), "alias": alias, "status": status, "max_bytes": max_bytes}

    @staticmethod
    def _approval_payload(payload: Mapping[str, object], info: os.stat_result) -> dict[str, object]:
        return {
            "project_id": payload["project_id"],
            "root_id": payload["root_id"],
            "policy_revision": payload["policy_revision"],
            "alias": payload["alias"],
            "status": payload["status"],
            "max_bytes": payload["max_bytes"],
            "root_identity": "sha256:" + hashlib.sha256(f"{info.st_dev}:{info.st_ino}".encode()).hexdigest(),
        }

    def _insert(self, payload, info, approval_id, digest) -> None:
        now = datetime.now(UTC).isoformat()
        self._connection.execute("INSERT INTO root_revisions VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (*payload.values(), info.st_dev, info.st_ino, approval_id, digest, now))
        self._connection.execute("INSERT INTO root_heads VALUES (?,?,?) ON CONFLICT(project_id,root_id) DO UPDATE SET policy_revision=excluded.policy_revision", (payload["project_id"], payload["root_id"], payload["policy_revision"]))

    def _head(self, project, root): return self._connection.execute("SELECT policy_revision FROM root_heads WHERE project_id=? AND root_id=?", (project,root)).fetchone()
    def _current(self, project, root):
        row=self._connection.execute("SELECT r.* FROM root_heads h JOIN root_revisions r USING(project_id,root_id,policy_revision) WHERE r.project_id=? AND r.root_id=?",(project,root)).fetchone()
        if not row: raise RegistryFailure("ROOT_NOT_REGISTERED", "root is not registered")
        return row

    @staticmethod
    def _validate_text(value, name):
        if not isinstance(value,str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value):
            raise RegistryFailure("INVALID_ARGUMENT", f"{name} is invalid")

    def _prepare_file(self):
        flags=os.O_CREAT|os.O_EXCL|os.O_WRONLY|getattr(os,"O_NOFOLLOW",0)
        try: fd=os.open(self.path,flags,0o600)
        except FileExistsError:
            status=self.path.lstat(); self._validate_db(status); os.chmod(self.path,0o600,follow_symlinks=False); return status.st_dev,status.st_ino
        try: status=os.fstat(fd); self._validate_db(status); os.fchmod(fd,0o600); return status.st_dev,status.st_ino
        finally: os.close(fd)
    def _validate_db(self,status):
        if not stat.S_ISREG(status.st_mode): raise ValueError("registry must be a regular file")
        if hasattr(os,"geteuid") and status.st_uid != os.geteuid(): raise PermissionError("registry must be process-owned")
    def _harden(self):
        status=self.path.lstat(); self._validate_db(status)
        if (status.st_dev,status.st_ino)!=self._identity: raise ValueError("registry identity changed")
        os.chmod(self.path,0o600,follow_symlinks=False)
        for suffix in ("-wal","-shm"):
            side=Path(f"{self.path}{suffix}")
            if side.exists(): self._validate_db(side.lstat()); os.chmod(side,0o600,follow_symlinks=False)
    class _Tx:
        def __init__(self,owner): self.owner=owner
        def __enter__(self): self.owner._lock.acquire(); self.owner._connection.execute("BEGIN IMMEDIATE")
        def __exit__(self,t,v,b): self.owner._connection.execute("ROLLBACK" if t else "COMMIT"); self.owner._lock.release(); self.owner._harden()
    def _transaction(self): return self._Tx(self)


__all__=["ControlPlaneApproval","ControlPlaneVerifier","RegistryFailure","SQLiteRootRegistry"]
