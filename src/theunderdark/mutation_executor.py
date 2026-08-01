"""Injected, bounded mutation executor backed by descriptor-relative primitives."""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import threading
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, Mapping

from .fscontain import ContainmentError, FileIdentity, RootHandle


@dataclass(frozen=True)
class ResolvedRoot:
    """Protected resolver output; host location is never returned in evidence."""

    root: Path | RootHandle
    alias: str
    max_bytes: int = 1_048_576
    policy_revision: str = "1"


class ExecutorFailure(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


RootResolver = Callable[[str, str], ResolvedRoot]


class FsContainMutationExecutor:
    """Map v1 storage actions onto injected, registered ``RootHandle`` roots."""

    def __init__(
        self,
        resolver: RootResolver,
        *,
        max_content_bytes: int = 1_048_576,
        max_concurrent_per_project: int = 4,
    ) -> None:
        if not callable(resolver):
            raise TypeError("a protected root resolver is required")
        if max_content_bytes < 1 or max_concurrent_per_project < 1:
            raise ValueError("executor bounds must be positive")
        self._resolver = resolver
        self._max_content_bytes = max_content_bytes
        self._max_concurrent = max_concurrent_per_project
        self._guard = threading.Lock()
        self._locks: dict[tuple[str, str, str], threading.RLock] = {}
        self._admission: dict[str, threading.BoundedSemaphore] = {}

    def execute(self, action: str, request: Mapping[str, object]) -> Mapping[str, object]:
        project = self._string(request, "project_id")
        admission = self._project_admission(project)
        if not admission.acquire(blocking=False):
            raise ExecutorFailure("RATE_LIMITED", "project mutation concurrency is exhausted")
        try:
            return self._execute_admitted(action, project, request)
        except ExecutorFailure:
            raise
        except ContainmentError as exc:
            raise ExecutorFailure(exc.code, "bounded filesystem execution was denied") from exc
        finally:
            admission.release()

    def _execute_admitted(self, action: str, project: str, request: Mapping[str, object]) -> Mapping[str, object]:
        root_id = self._string(request, "root_id")
        target = self._string(request, "relative_path")
        paths = [(root_id, target)]
        if action in {"path.copy", "path.move"}:
            source_root_id = self._string(request, "source_root_id") if action == "path.copy" else root_id
            paths.append((source_root_id, self._string(request, "source_relative_path")))
        with self._path_locks(project, paths), ExitStack() as stack:
            destination_binding = self._resolve(project, root_id)
            if destination_binding.policy_revision != self._string(request, "policy_revision"):
                raise ExecutorFailure("POLICY_REVISION_MISMATCH", "registered root policy revision does not match")
            destination = stack.enter_context(self._root_context(destination_binding.root))
            limit = min(self._max_content_bytes, destination_binding.max_bytes)

            if action == "directory.create":
                if request.get("parents", False) is not False:
                    raise ExecutorFailure("UNSUPPORTED_ACTION", "recursive parent creation is not supported")
                identity = destination.create_directory(target)
                return self._result(destination_binding.alias, target, identity, "directory")

            if action == "file.write":
                data = self._decode_content(request, limit)
                supplied = self._digest(request.get("content_digest"), "content_digest")
                self._require_digest(data, supplied)
                mode = request.get("write_mode")
                if mode == "create_only":
                    identity = destination.atomic_write(target, data)
                elif mode == "replace_exact":
                    expected = self._digest(request.get("expected_prior_digest"), "expected_prior_digest")
                    identity = self._regular_identity_and_digest(destination, target, expected, limit)
                    identity = destination.atomic_write(target, data, replace=True, expected_identity=identity)
                else:
                    raise ExecutorFailure("INVALID_ARGUMENT", "unsupported write mode")
                return self._result(destination_binding.alias, target, identity, "file", supplied)

            if action == "path.copy":
                if request.get("destination_mode", "create_only") != "create_only":
                    raise ExecutorFailure("UNSUPPORTED_ACTION", "copy must be create-only")
                source_root_id = self._string(request, "source_root_id")
                source_path = self._string(request, "source_relative_path")
                source_binding = self._resolve(project, source_root_id)
                if source_binding.policy_revision != self._string(request, "policy_revision"):
                    raise ExecutorFailure("POLICY_REVISION_MISMATCH", "source root policy revision does not match")
                source = stack.enter_context(self._root_context(source_binding.root))
                copy_limit = min(limit, source_binding.max_bytes)
                data, digest = self._read_bounded(source, source_path, copy_limit)
                identity = destination.atomic_write(target, data)
                return self._result(destination_binding.alias, target, identity, "file", digest)

            if action == "path.move":
                if request.get("destination_mode", "create_only") != "create_only":
                    raise ExecutorFailure("UNSUPPORTED_ACTION", "move must be create-only")
                source_path = self._string(request, "source_relative_path")
                expected_type = request.get("expected_source_type")
                if expected_type not in {"file", "directory"}:
                    raise ExecutorFailure("PRECONDITION_REQUIRED", "exact source type is required")
                if expected_type == "file":
                    expected = self._digest(request.get("expected_source_digest"), "expected_source_digest")
                    identity = self._regular_identity_and_digest(destination, source_path, expected, limit)
                else:
                    if request.get("expected_source_digest") is not None:
                        raise ExecutorFailure("INVALID_ARGUMENT", "directory move cannot use a content digest")
                    with destination.open_directory(source_path) as opened:
                        identity = opened.identity
                moved = destination.rename(source_path, target, expected_identity=identity)
                return self._result(destination_binding.alias, target, moved, expected_type)

            if action == "path.delete":
                if request.get("recursive", False) is not False:
                    raise ExecutorFailure("UNSUPPORTED_ACTION", "recursive delete is not supported")
                expected_type = request.get("expected_type")
                if expected_type == "file":
                    expected = self._digest(request.get("expected_digest"), "expected_digest")
                    identity = self._regular_identity_and_digest(destination, target, expected, limit)
                    destination.unlink(target, expected_identity=identity)
                elif expected_type == "directory":
                    if request.get("expected_digest") is not None:
                        raise ExecutorFailure("INVALID_ARGUMENT", "directory delete cannot use a content digest")
                    with destination.open_directory(target) as opened:
                        identity = opened.identity
                    destination.unlink(target, expected_identity=identity, directory=True)
                else:
                    raise ExecutorFailure("PRECONDITION_REQUIRED", "exact delete type is required")
                return {
                    "verified": True,
                    "host_state_changed": True,
                    "path": self._alias(destination_binding.alias, target),
                    "deleted_type": expected_type,
                    "redactions_applied": True,
                }
            raise ExecutorFailure("UNSUPPORTED_ACTION", "action is not supported")

    def _resolve(self, project: str, root_id: str) -> ResolvedRoot:
        try:
            binding = self._resolver(project, root_id)
        except Exception as exc:
            raise ExecutorFailure("ROOT_UNAVAILABLE", "registered root resolution failed") from exc
        if not isinstance(binding, ResolvedRoot) or not binding.alias or binding.max_bytes < 1:
            raise ExecutorFailure("ROOT_UNAVAILABLE", "registered root resolution was invalid")
        return binding

    @staticmethod
    @contextmanager
    def _root_context(root: Path | RootHandle) -> Iterator[RootHandle]:
        if isinstance(root, RootHandle):
            if root.descriptor < 0:
                raise ExecutorFailure("ROOT_UNAVAILABLE", "registered root handle is closed")
            yield root
        else:
            with RootHandle.open(root) as opened:
                yield opened

    def _decode_content(self, request: Mapping[str, object], limit: int) -> bytes:
        content = request.get("content")
        if not isinstance(content, str):
            raise ExecutorFailure("INVALID_ARGUMENT", "content must be a string")
        encoding = request.get("content_encoding", "utf8")
        try:
            data = content.encode("utf-8") if encoding == "utf8" else base64.b64decode(content, validate=True) if encoding == "base64" else None
        except (UnicodeError, binascii.Error) as exc:
            raise ExecutorFailure("INVALID_ARGUMENT", "content encoding is invalid") from exc
        if data is None:
            raise ExecutorFailure("INVALID_ARGUMENT", "content encoding is unsupported")
        if len(data) > limit:
            raise ExecutorFailure("QUOTA_EXCEEDED", "content exceeds the bounded byte limit")
        return data

    @staticmethod
    def _digest(value: object, field: str) -> str:
        if not isinstance(value, Mapping) or value.get("algorithm") != "sha256":
            raise ExecutorFailure("PRECONDITION_REQUIRED", f"{field} must be a sha256 digest")
        digest = value.get("value")
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ExecutorFailure("INVALID_ARGUMENT", f"{field} is invalid")
        return digest

    @staticmethod
    def _require_digest(data: bytes, expected: str) -> None:
        if not hashlib.sha256(data).hexdigest() == expected:
            raise ExecutorFailure("PRECONDITION_FAILED", "content digest does not match")

    def _regular_identity_and_digest(self, root: RootHandle, path: str, expected: str, limit: int) -> FileIdentity:
        with root.open_regular(path) as opened:
            actual = self._hash_descriptor(opened.descriptor, limit)
            if actual != expected:
                raise ExecutorFailure("PRECONDITION_FAILED", "existing file digest does not match")
            return opened.identity

    def _read_bounded(self, root: RootHandle, path: str, limit: int) -> tuple[bytes, str]:
        with root.open_regular(path) as opened:
            chunks: list[bytes] = []
            total = 0
            digest = hashlib.sha256()
            while True:
                chunk = os.read(opened.descriptor, min(1024 * 1024, limit + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise ExecutorFailure("QUOTA_EXCEEDED", "copy source exceeds the bounded byte limit")
                chunks.append(chunk)
                digest.update(chunk)
            return b"".join(chunks), digest.hexdigest()

    @staticmethod
    def _hash_descriptor(descriptor: int, limit: int) -> str:
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                return digest.hexdigest()
            total += len(chunk)
            if total > limit:
                raise ExecutorFailure("QUOTA_EXCEEDED", "existing file exceeds the bounded byte limit")
            digest.update(chunk)

    @staticmethod
    def _string(request: Mapping[str, object], field: str) -> str:
        value = request.get(field)
        if not isinstance(value, str) or not value:
            raise ExecutorFailure("INVALID_ARGUMENT", f"{field} is required")
        return value

    @staticmethod
    def _alias(alias: str, relative_path: str) -> str:
        return f"{alias}:{relative_path}"

    def _result(self, alias: str, path: str, identity: FileIdentity, kind: str, digest: str | None = None) -> dict[str, object]:
        result: dict[str, object] = {
            "verified": True,
            "host_state_changed": True,
            "path": self._alias(alias, path),
            "type": kind,
            "bytes": identity.size,
            "redactions_applied": True,
        }
        if digest is not None:
            result["digest"] = {"algorithm": "sha256", "value": digest}
        return result

    def _project_admission(self, project: str) -> threading.BoundedSemaphore:
        with self._guard:
            return self._admission.setdefault(project, threading.BoundedSemaphore(self._max_concurrent))

    @contextmanager
    def _path_locks(self, project: str, paths: list[tuple[str, str]]) -> Iterator[None]:
        keys = sorted({(project, root, path) for root, path in paths})
        with self._guard:
            locks = [self._locks.setdefault(key, threading.RLock()) for key in keys]
        for lock in locks:
            lock.acquire()
        try:
            yield
        finally:
            for lock in reversed(locks):
                lock.release()


__all__ = ["ExecutorFailure", "FsContainMutationExecutor", "ResolvedRoot", "RootResolver"]
