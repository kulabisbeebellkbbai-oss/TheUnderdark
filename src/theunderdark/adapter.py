from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import threading
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Literal

CONTRACT_VERSION = "1.0"
ID_RE = re.compile(r"^[!-~]{1,128}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_CONTENT_BYTES = 1_048_576
MAX_REQUEST_BYTES = 1_398_102
MAX_PAGE_SIZE = 200
MAX_REASON_LENGTH = 512


@dataclass(frozen=True)
class RootRegistration:
    project_id: str
    root_id: str
    host_path: Path
    alias: str
    policy_revision: str = "1"
    status: Literal["active", "suspended", "retired"] = "active"
    allowed_actions: frozenset[str] = frozenset(
        {"directory.create", "file.write", "path.copy", "path.move", "path.delete"}
    )
    max_content_bytes: int = MAX_CONTENT_BYTES


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
    max_bytes: int = MAX_CONTENT_BYTES


@dataclass
class Operation:
    operation_id: str
    request_id: str
    project_id: str
    action: str
    request_digest: str
    state: str = "accepted"
    host_state_changed: bool | str = False
    result: dict[str, Any] = field(default_factory=dict)
    error: dict[str, Any] | None = None
    evidence_id: str = field(default_factory=lambda: f"evidence-{uuid.uuid4().hex}")
    transitions: list[str] = field(default_factory=lambda: ["accepted"])


class ContractFailure(Exception):
    def __init__(self, code: str, message: str, *, retryable: bool = False):
        super().__init__(message)
        self.code, self.message, self.retryable = code, message, retryable


class StorageAdapter:
    """In-memory policy/journal with filesystem effects limited to registered roots."""

    def __init__(self) -> None:
        self._roots: dict[tuple[str, str], RootRegistration] = {}
        self._authorizations: dict[str, Authorization] = {}
        self._operations: dict[str, Operation] = {}
        self._idempotency: dict[tuple[str, str], str] = {}
        self._lock = threading.RLock()

    # Fixture-only control plane. These methods are intentionally not MCP tools.
    def register_root(self, registration: RootRegistration) -> None:
        self._identifier(registration.project_id, "project_id")
        self._identifier(registration.root_id, "root_id")
        supplied_root = registration.host_path
        if supplied_root.is_symlink():
            raise ValueError("fixture root must be an existing non-symlink directory")
        root = supplied_root.resolve(strict=True)
        fixture_base = Path(tempfile.gettempdir()).resolve(strict=True)
        if not root.is_dir() or root == fixture_base or fixture_base not in root.parents:
            raise ValueError("fixture root must be an existing non-symlink directory")
        normalized = RootRegistration(**{**registration.__dict__, "host_path": root})
        with self._lock:
            self._roots[(registration.project_id, registration.root_id)] = normalized

    def add_authorization(self, authorization: Authorization) -> None:
        for value, name in ((authorization.authorization_ref, "authorization_ref"), (authorization.request_id, "request_id")):
            self._identifier(value, name)
        self._relative(authorization.relative_path)
        if authorization.source_relative_path is not None:
            self._relative(authorization.source_relative_path)
        with self._lock:
            self._authorizations[authorization.authorization_ref] = authorization

    def health_get(self, request_id: str = "health") -> dict[str, Any]:
        return self._success(request_id, {"status": "healthy", "contract_version": CONTRACT_VERSION, "dependencies": {"registration_store": "ready", "operation_journal": "ready", "overseer_verifier": "fixture"}})

    def project_get(self, project_id: str, request_id: str = "read") -> dict[str, Any]:
        try:
            self._identifier(project_id, "project_id")
            roots = [r for (p, _), r in self._roots.items() if p == project_id]
            if not roots:
                raise ContractFailure("PROJECT_NOT_REGISTERED", "The project is not registered.")
            return self._success(request_id, {"project_id": project_id, "status": "active" if any(r.status == "active" for r in roots) else "suspended", "policy_revision": roots[0].policy_revision, "quota_profile": {"max_content_bytes": min(r.max_content_bytes for r in roots), "directory_page_size": MAX_PAGE_SIZE}, "roots": [{"root_id": r.root_id, "alias": r.alias, "status": r.status} for r in sorted(roots, key=lambda x: x.root_id)]})
        except ContractFailure as exc:
            return self._failure(request_id, exc)

    def root_get(self, project_id: str, root_id: str, request_id: str = "read") -> dict[str, Any]:
        try:
            root = self._root(project_id, root_id, active=False)
            return self._success(request_id, {"project_id": project_id, "root_id": root_id, "alias": root.alias, "status": root.status, "policy_revision": root.policy_revision, "symlink_policy": "deny", "allowed_actions": sorted(root.allowed_actions), "limits": {"max_content_bytes": root.max_content_bytes, "directory_page_size": MAX_PAGE_SIZE}})
        except ContractFailure as exc:
            return self._failure(request_id, exc)

    def path_stat(self, project_id: str, root_id: str, relative_path: str, include_digest: bool = False, request_id: str = "read") -> dict[str, Any]:
        try:
            root = self._root(project_id, root_id)
            path = self._safe_existing(root, relative_path)
            info = self._metadata(path, include_digest)
            return self._success(request_id, {"path": self._alias(project_id, root_id, relative_path), **info})
        except FileNotFoundError:
            return self._failure(request_id, ContractFailure("SOURCE_NOT_FOUND", "The requested path does not exist."))
        except ContractFailure as exc:
            return self._failure(request_id, exc)

    def directory_list(self, project_id: str, root_id: str, relative_path: str, cursor: str | None = None, limit: int = 100, request_id: str = "read") -> dict[str, Any]:
        try:
            root = self._root(project_id, root_id)
            directory = self._safe_existing(root, relative_path)
            if not directory.is_dir():
                raise ContractFailure("PATH_CONFLICT", "The requested path is not a directory.")
            if not 1 <= limit <= MAX_PAGE_SIZE:
                raise ContractFailure("INVALID_ARGUMENT", "limit is outside the supported range.")
            context = hashlib.sha256(f"{project_id}\0{root_id}\0{relative_path}\0{root.policy_revision}".encode()).hexdigest()[:16]
            offset = 0
            if cursor:
                try:
                    raw = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
                    if raw["c"] != context or not isinstance(raw["o"], int) or raw["o"] < 0:
                        raise ValueError
                    offset = raw["o"]
                except Exception:
                    raise ContractFailure("INVALID_ARGUMENT", "The directory cursor is invalid for this request.")
            entries = []
            for child in sorted(directory.iterdir(), key=lambda p: p.name):
                if child.is_symlink():
                    kind, size = "symlink_denied", 0
                else:
                    st = child.stat(follow_symlinks=False)
                    kind = "directory" if stat.S_ISDIR(st.st_mode) else "file" if stat.S_ISREG(st.st_mode) else "special_denied"
                    size = st.st_size
                entries.append({"name": child.name, "type": kind, "size": size})
            page = entries[offset:offset + limit]
            next_cursor = None
            if offset + limit < len(entries):
                next_cursor = base64.urlsafe_b64encode(json.dumps({"c": context, "o": offset + limit}, separators=(",", ":")).encode()).decode().rstrip("=")
            return self._success(request_id, {"path": self._alias(project_id, root_id, relative_path), "entries": page, "next_cursor": next_cursor})
        except FileNotFoundError:
            return self._failure(request_id, ContractFailure("SOURCE_NOT_FOUND", "The requested directory does not exist."))
        except ContractFailure as exc:
            return self._failure(request_id, exc)

    def operation_get(self, project_id: str, operation_id: str, request_id: str = "read") -> dict[str, Any]:
        try:
            op = self._operations.get(operation_id)
            if op is None or op.project_id != project_id:
                raise ContractFailure("SOURCE_NOT_FOUND", "The operation was not found.")
            result = {"state": op.state, "action": op.action, "transitions": list(op.transitions), "result": op.result}
            if op.error:
                result["error"] = op.error
            return self._success(op.request_id, result, op)
        except ContractFailure as exc:
            return self._failure(request_id, exc)

    def directory_create(self, *, relative_path: str, parents: bool = False, **common: Any) -> dict[str, Any]:
        return self._mutate("directory.create", common, {"relative_path": relative_path, "parents": parents}, lambda root, auth: self._mkdir(root, relative_path, parents))

    def file_write(self, *, relative_path: str, content: str, content_digest: dict[str, str], write_mode: str, content_encoding: str = "utf8", expected_prior_digest: dict[str, str] | None = None, **common: Any) -> dict[str, Any]:
        action = {"relative_path": relative_path, "content": content, "content_digest": content_digest, "write_mode": write_mode, "content_encoding": content_encoding, "expected_prior_digest": expected_prior_digest}
        return self._mutate("file.write", common, action, lambda root, auth: self._write(root, action, auth))

    def path_copy(self, *, source_root_id: str, source_relative_path: str, relative_path: str, destination_mode: str = "create_only", **common: Any) -> dict[str, Any]:
        action = {"source_root_id": source_root_id, "source_relative_path": source_relative_path, "relative_path": relative_path, "destination_mode": destination_mode}
        return self._mutate("path.copy", common, action, lambda root, auth: self._copy(root, action, auth))

    def path_move(self, *, source_relative_path: str, relative_path: str, expected_source_digest: dict[str, str] | None = None, expected_source_type: str | None = None, destination_mode: str = "create_only", **common: Any) -> dict[str, Any]:
        action = {"source_relative_path": source_relative_path, "relative_path": relative_path, "expected_source_digest": expected_source_digest, "expected_source_type": expected_source_type, "destination_mode": destination_mode}
        return self._mutate("path.move", common, action, lambda root, auth: self._move(root, action))

    def path_delete(self, *, relative_path: str, expected_type: str, expected_digest: dict[str, str] | None = None, recursive: bool = False, **common: Any) -> dict[str, Any]:
        action = {"relative_path": relative_path, "expected_type": expected_type, "expected_digest": expected_digest, "recursive": recursive}
        return self._mutate("path.delete", common, action, lambda root, auth: self._delete(root, action))

    def _mutate(self, action_name: str, common: dict[str, Any], action: dict[str, Any], execute: Any) -> dict[str, Any]:
        request_id = str(common.get("request_id", ""))
        op: Operation | None = None
        try:
            required = ("project_id", "root_id", "request_id", "idempotency_key", "authorization_ref", "policy_revision", "reason")
            if any(k not in common for k in required):
                raise ContractFailure("INVALID_ARGUMENT", "Required mutation fields are missing.")
            for name in required[:-1]:
                self._identifier(str(common[name]), name)
            if not isinstance(common["reason"], str) or not 1 <= len(common["reason"]) <= MAX_REASON_LENGTH:
                raise ContractFailure("INVALID_ARGUMENT", "reason is outside the supported range.")
            if len(json.dumps({"common": common, "action": action}, sort_keys=True, default=str).encode()) > MAX_REQUEST_BYTES:
                raise ContractFailure("REQUEST_TOO_LARGE", "The request exceeds the service limit.")
            # Schema/path syntax validation is deliberately completed before
            # registration, authorization, journal reservation, or filesystem
            # access. Authority can never make a malformed path acceptable.
            self._relative(action["relative_path"])
            if "source_relative_path" in action:
                self._relative(action["source_relative_path"])
            root = self._root(common["project_id"], common["root_id"])
            if common["policy_revision"] != root.policy_revision:
                raise ContractFailure("POLICY_REVISION_MISMATCH", "The policy revision does not match the registration.")
            if action_name not in root.allowed_actions:
                raise ContractFailure("UNSUPPORTED_ACTION", "The action is not allowed for this root.")
            digest = hashlib.sha256(json.dumps({"action": action_name, "common": common, "input": action}, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
            key = (common["project_id"], common["idempotency_key"])
            with self._lock:
                previous_id = self._idempotency.get(key)
                if previous_id:
                    previous = self._operations[previous_id]
                    if previous.request_digest != digest:
                        raise ContractFailure("IDEMPOTENCY_CONFLICT", "The idempotency key is bound to another request.")
                    return self._envelope_for(previous)
                op = Operation(f"op-{uuid.uuid4().hex}", request_id, common["project_id"], action_name, digest)
                self._operations[op.operation_id] = op
                self._idempotency[key] = op.operation_id
                auth = self._authorize(common, action_name, action)
                self._transition(op, "authorized")
                self._transition(op, "executing")
                op.result = execute(root, auth)
                op.host_state_changed = True
                self._transition(op, "succeeded")
                return self._envelope_for(op)
        except ContractFailure as exc:
            if op:
                op.error = {"code": exc.code, "message": exc.message, "retryable": exc.retryable, "details": {}}
                self._transition(op, "failed")
                return self._envelope_for(op)
            return self._failure(request_id, exc)
        except OSError:
            failure = ContractFailure("EXECUTION_FAILED", "The bounded filesystem operation failed.")
            if op:
                if op.state == "executing":
                    op.host_state_changed = "unknown"
                op.error = {"code": failure.code, "message": failure.message, "retryable": False, "details": {}}
                self._transition(op, "failed")
                return self._envelope_for(op)
            return self._failure(request_id, failure)
        except (ValueError, binascii.Error):
            failure = ContractFailure("EXECUTION_FAILED", "The bounded filesystem operation failed.")
            if op:
                op.error = {"code": failure.code, "message": failure.message, "retryable": False, "details": {}}
                self._transition(op, "failed")
                return self._envelope_for(op)
            return self._failure(request_id, failure)

    def _authorize(self, common: dict[str, Any], action_name: str, action: dict[str, Any]) -> Authorization:
        auth = self._authorizations.get(common["authorization_ref"])
        if auth is None:
            raise ContractFailure("AUTHORIZATION_REQUIRED", "An exact fixture authorization is required.")
        if auth.status != "approved":
            raise ContractFailure("AUTHORIZATION_NOT_APPROVED", "The authorization is not approved.")
        if auth.expires_at and auth.expires_at.astimezone(UTC) <= datetime.now(UTC):
            raise ContractFailure("AUTHORIZATION_EXPIRED", "The authorization has expired.")
        if auth.claimed_by != "storage-adapter.theunderdark":
            raise ContractFailure("CLAIM_MISMATCH", "The request is not claimed by this adapter.")
        expected = (auth.request_id, auth.project_id, auth.root_id, auth.action, auth.relative_path)
        actual = (common["request_id"], common["project_id"], common["root_id"], action_name, action["relative_path"])
        if expected != actual:
            raise ContractFailure("AUTHORIZATION_MISMATCH", "The approval does not match the requested action.")
        if action_name == "path.copy" and (auth.source_root_id, auth.source_relative_path) != (action["source_root_id"], action["source_relative_path"]):
            raise ContractFailure("AUTHORIZATION_MISMATCH", "The approval does not match the requested source.")
        if action_name == "path.move" and (auth.source_root_id, auth.source_relative_path) != (auth.root_id, action["source_relative_path"]):
            raise ContractFailure("AUTHORIZATION_MISMATCH", "The approval does not match the requested source.")
        return auth

    def _mkdir(self, root: RootRegistration, relative: str, parents: bool) -> dict[str, Any]:
        target = self._safe_new(root, relative)
        if target.exists():
            raise ContractFailure("DESTINATION_EXISTS", "The destination already exists.")
        if parents:
            # Validate every existing prefix first; mkdir never follows an existing symlink.
            self._validate_prefixes(root, relative)
            target.mkdir(parents=True)
        else:
            target.mkdir()
        return {"path": self._alias(root.project_id, root.root_id, relative), "type": "directory"}

    def _write(self, root: RootRegistration, action: dict[str, Any], auth: Authorization) -> dict[str, Any]:
        if action["content_encoding"] == "utf8":
            data = action["content"].encode("utf-8")
        elif action["content_encoding"] == "base64":
            data = base64.b64decode(action["content"], validate=True)
        else:
            raise ContractFailure("INVALID_ARGUMENT", "content_encoding must be utf8 or base64.")
        if len(data) > min(root.max_content_bytes, auth.max_bytes, MAX_CONTENT_BYTES):
            raise ContractFailure("QUOTA_EXCEEDED", "The decoded content exceeds the authorized limit.")
        self._digest_matches(data, action["content_digest"])
        target = self._safe_new(root, action["relative_path"])
        exists = target.exists()
        if action["write_mode"] == "create_only" and exists:
            raise ContractFailure("DESTINATION_EXISTS", "The destination already exists.")
        if action["write_mode"] == "replace_exact":
            if not exists:
                raise ContractFailure("SOURCE_NOT_FOUND", "The replacement target does not exist.")
            current = self._safe_existing(root, action["relative_path"])
            if not current.is_file() or not action["expected_prior_digest"]:
                raise ContractFailure("PRECONDITION_FAILED", "Replacement requires an exact regular-file digest.")
            self._digest_matches(current.read_bytes(), action["expected_prior_digest"])
        elif action["write_mode"] != "create_only":
            raise ContractFailure("INVALID_ARGUMENT", "write_mode is unsupported.")
        target.parent.mkdir(parents=False, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix=".underdark-", dir=target.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_name, target)
        finally:
            try: os.unlink(temp_name)
            except FileNotFoundError: pass
        return {"path": self._alias(root.project_id, root.root_id, action["relative_path"]), "bytes": len(data), "digest": action["content_digest"]}

    def _copy(self, destination_root: RootRegistration, action: dict[str, Any], auth: Authorization) -> dict[str, Any]:
        if action["destination_mode"] != "create_only":
            raise ContractFailure("INVALID_ARGUMENT", "Only create_only copy is supported.")
        source_root = self._root(destination_root.project_id, action["source_root_id"])
        source = self._safe_existing(source_root, action["source_relative_path"])
        destination = self._safe_new(destination_root, action["relative_path"])
        if destination.exists():
            raise ContractFailure("DESTINATION_EXISTS", "The destination already exists.")
        if source.is_file():
            if source.stat().st_size > min(destination_root.max_content_bytes, auth.max_bytes):
                raise ContractFailure("QUOTA_EXCEEDED", "The source exceeds the authorized byte limit.")
            shutil.copyfile(source, destination, follow_symlinks=False)
            size = destination.stat().st_size
        else:
            raise ContractFailure("UNSUPPORTED_ACTION", "Version 1 fixture copy supports regular files only.")
        return {"source": self._alias(source_root.project_id, source_root.root_id, action["source_relative_path"]), "path": self._alias(destination_root.project_id, destination_root.root_id, action["relative_path"]), "bytes": size}

    def _move(self, root: RootRegistration, action: dict[str, Any]) -> dict[str, Any]:
        if action["destination_mode"] != "create_only":
            raise ContractFailure("INVALID_ARGUMENT", "Only create_only move is supported.")
        source = self._safe_existing(root, action["source_relative_path"])
        destination = self._safe_new(root, action["relative_path"])
        if destination.exists():
            raise ContractFailure("DESTINATION_EXISTS", "The destination already exists.")
        actual_type = "file" if source.is_file() else "directory"
        if action["expected_source_type"] and action["expected_source_type"] != actual_type:
            raise ContractFailure("PRECONDITION_FAILED", "The source type changed.")
        if action["expected_source_digest"]:
            if not source.is_file():
                raise ContractFailure("PRECONDITION_FAILED", "Only regular files have content digests.")
            self._digest_matches(source.read_bytes(), action["expected_source_digest"])
        os.rename(source, destination)
        return {"source": self._alias(root.project_id, root.root_id, action["source_relative_path"]), "path": self._alias(root.project_id, root.root_id, action["relative_path"]), "type": actual_type}

    def _delete(self, root: RootRegistration, action: dict[str, Any]) -> dict[str, Any]:
        if action["recursive"]:
            raise ContractFailure("UNSUPPORTED_ACTION", "Recursive deletion is not supported.")
        target = self._safe_existing(root, action["relative_path"])
        actual_type = "file" if target.is_file() else "directory"
        if actual_type != action["expected_type"]:
            raise ContractFailure("PRECONDITION_FAILED", "The target type changed.")
        if action["expected_digest"]:
            if not target.is_file():
                raise ContractFailure("PRECONDITION_FAILED", "Only regular files have content digests.")
            self._digest_matches(target.read_bytes(), action["expected_digest"])
        try:
            target.unlink() if actual_type == "file" else target.rmdir()
        except OSError as exc:
            if actual_type == "directory":
                raise ContractFailure("NOT_EMPTY", "The directory is not empty.") from exc
            raise
        return {"path": self._alias(root.project_id, root.root_id, action["relative_path"]), "deleted_type": actual_type}

    def _root(self, project_id: str, root_id: str, active: bool = True) -> RootRegistration:
        self._identifier(project_id, "project_id"); self._identifier(root_id, "root_id")
        root = self._roots.get((project_id, root_id))
        if root is None:
            if not any(p == project_id for p, _ in self._roots):
                raise ContractFailure("PROJECT_NOT_REGISTERED", "The project is not registered.")
            raise ContractFailure("ROOT_NOT_REGISTERED", "The root is not registered.")
        if active and root.status != "active":
            raise ContractFailure("REGISTRATION_INACTIVE", "The registration is not active.")
        return root

    @staticmethod
    def _identifier(value: str, name: str) -> None:
        if not isinstance(value, str) or not ID_RE.fullmatch(value) or any(c in value for c in "\\/"):
            raise ContractFailure("INVALID_ARGUMENT", f"{name} is invalid.")

    @staticmethod
    def _relative(value: str) -> PurePosixPath:
        if not isinstance(value, str) or not value or "\\" in value or "://" in value or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ContractFailure("PATH_INVALID", "The relative path is invalid.")
        path = PurePosixPath(value)
        if path.is_absolute() or any(part in ("", ".", "..") for part in value.split("/")) or re.match(r"^[A-Za-z]:", value):
            raise ContractFailure("PATH_INVALID", "The relative path is invalid.")
        return path

    def _validate_prefixes(self, root: RootRegistration, relative: str) -> None:
        current = root.host_path
        for part in self._relative(relative).parts[:-1]:
            current /= part
            if current.exists() or current.is_symlink():
                st = current.lstat()
                if stat.S_ISLNK(st.st_mode): raise ContractFailure("SYMLINK_DENIED", "Symbolic links are denied.")
                if not stat.S_ISDIR(st.st_mode): raise ContractFailure("PATH_CONFLICT", "A parent component is not a directory.")
                if current.stat().st_dev != root.host_path.stat().st_dev: raise ContractFailure("PATH_OUTSIDE_ROOT", "Mount traversal is denied.")

    def _safe_new(self, root: RootRegistration, relative: str) -> Path:
        self._validate_prefixes(root, relative)
        target = root.host_path.joinpath(*self._relative(relative).parts)
        if target.is_symlink(): raise ContractFailure("SYMLINK_DENIED", "Symbolic links are denied.")
        if target.exists(): self._check_type(root, target)
        return target

    def _safe_existing(self, root: RootRegistration, relative: str) -> Path:
        target = self._safe_new(root, relative)
        if not target.exists(): raise FileNotFoundError
        return target

    @staticmethod
    def _check_type(root: RootRegistration, path: Path) -> None:
        st = path.lstat()
        if stat.S_ISLNK(st.st_mode): raise ContractFailure("SYMLINK_DENIED", "Symbolic links are denied.")
        if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)): raise ContractFailure("SPECIAL_FILE_DENIED", "Special files are denied.")
        if st.st_dev != root.host_path.stat().st_dev: raise ContractFailure("PATH_OUTSIDE_ROOT", "Mount traversal is denied.")
        if stat.S_ISREG(st.st_mode) and st.st_nlink != 1: raise ContractFailure("SPECIAL_FILE_DENIED", "Hard-linked files are denied.")

    def _metadata(self, path: Path, digest: bool) -> dict[str, Any]:
        st = path.stat(follow_symlinks=False)
        result = {"type": "file" if stat.S_ISREG(st.st_mode) else "directory", "size": st.st_size, "modified_at": datetime.fromtimestamp(st.st_mtime, UTC).isoformat()}
        if digest and stat.S_ISREG(st.st_mode): result["digest"] = {"algorithm": "sha256", "value": hashlib.sha256(path.read_bytes()).hexdigest()}
        return result

    @staticmethod
    def _digest_matches(data: bytes, digest: dict[str, str]) -> None:
        if not isinstance(digest, dict) or digest.get("algorithm") != "sha256" or not HEX64_RE.fullmatch(str(digest.get("value", ""))):
            raise ContractFailure("INVALID_ARGUMENT", "A lowercase SHA-256 digest is required.")
        if hashlib.sha256(data).hexdigest() != digest["value"]:
            raise ContractFailure("PRECONDITION_FAILED", "The content digest does not match.")

    @staticmethod
    def _alias(project: str, root: str, relative: str) -> str: return f"{project}/{root}/{relative}"
    @staticmethod
    def _transition(op: Operation, state: str) -> None: op.state = state; op.transitions.append(state)
    def _success(self, request_id: str, result: dict[str, Any], op: Operation | None = None) -> dict[str, Any]:
        return {"ok": True, "contract_version": CONTRACT_VERSION, "request_id": request_id, **({"operation_id": op.operation_id} if op else {}), "result": result, "evidence": {"evidence_ids": [op.evidence_id] if op else [], "host_state_changed": op.host_state_changed if op else False, "redactions_applied": False}}
    def _failure(self, request_id: str, exc: ContractFailure, op: Operation | None = None) -> dict[str, Any]:
        return {"ok": False, "contract_version": CONTRACT_VERSION, "request_id": request_id, **({"operation_id": op.operation_id} if op else {}), "error": {"code": exc.code, "message": exc.message, "retryable": exc.retryable, "details": {}}, "evidence": {"evidence_ids": [op.evidence_id] if op else [], "host_state_changed": op.host_state_changed if op else False, "redactions_applied": True}}
    def _envelope_for(self, op: Operation) -> dict[str, Any]:
        if op.error:
            result = {"ok": False, "contract_version": CONTRACT_VERSION, "request_id": op.request_id, "operation_id": op.operation_id, "error": op.error, "evidence": {"evidence_ids": [op.evidence_id], "host_state_changed": op.host_state_changed, "redactions_applied": True}}
            return result
        return self._success(op.request_id, {"state": op.state, **op.result}, op)
