"""Descriptor-relative, metadata-only read backend for registered roots."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator, Mapping, Sequence

from .fscontain import ContainmentError, FileIdentity, RootHandle
from .mutation_executor import ResolvedRoot


class ReadFailure(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


ReadRootResolver = Callable[[str, str], ResolvedRoot]
ProjectRoots = Callable[[str], Sequence[str]]


class FsContainReadBackend:
    """Return redacted metadata without file content or host-root disclosure."""

    def __init__(self, resolver: ReadRootResolver, project_roots: ProjectRoots, *, max_digest_bytes: int = 1_048_576) -> None:
        if not callable(resolver) or not callable(project_roots):
            raise TypeError("protected root and project resolvers are required")
        if max_digest_bytes < 1:
            raise ValueError("max_digest_bytes must be positive")
        self._resolver = resolver
        self._project_roots = project_roots
        self._max_digest_bytes = max_digest_bytes

    def project_get(self, project_id: str) -> Mapping[str, object]:
        roots = []
        for root_id in sorted(set(self._project_roots(project_id))):
            binding = self._resolve(project_id, root_id)
            roots.append({"root_id": root_id, "alias": binding.alias, "status": "active"})
        if not roots:
            raise ReadFailure("PROJECT_NOT_REGISTERED", "project has no resolved roots")
        revisions = {self._resolve(project_id, str(root["root_id"])).policy_revision for root in roots}
        return {"project_id": project_id, "status": "active", "policy_revision": next(iter(revisions)) if len(revisions)==1 else "mixed", "roots": roots, "redactions_applied": True}

    def root_get(self, project_id: str, root_id: str) -> Mapping[str, object]:
        binding = self._resolve(project_id, root_id)
        with self._root_context(binding.root) as root:
            identity = root.identity
            return {
                "project_id": project_id,
                "root_id": root_id,
                "alias": binding.alias,
                "status": "active",
                "policy_revision": binding.policy_revision,
                "limits": {"max_digest_bytes": min(binding.max_bytes, self._max_digest_bytes)},
                "namespace_identity": self._identity_token(identity),
                "symlink_policy": "deny",
                "redactions_applied": True,
            }

    def path_stat(
        self,
        project_id: str,
        root_id: str,
        relative_path: str,
        include_digest: bool = False,
    ) -> tuple[str, tuple[Mapping[str, object], ...]]:
        binding = self._resolve(project_id, root_id)
        with self._root_context(binding.root) as root:
            try:
                with root.open_regular(relative_path) as opened:
                    info = os.fstat(opened.descriptor)
                    result: dict[str, object] = self._metadata(binding.alias, relative_path, "file", info)
                    if include_digest:
                        limit = min(binding.max_bytes, self._max_digest_bytes)
                        result["digest"] = {
                            "algorithm": "sha256",
                            "value": self._hash_descriptor(opened.descriptor, limit),
                        }
                    return result
            except ContainmentError as regular_error:
                if regular_error.code not in {"SPECIAL_FILE_DENIED", "OPEN_FAILED"}:
                    try:
                        with root.open_directory(relative_path) as opened:
                            if include_digest:
                                raise ReadFailure("UNSUPPORTED_ACTION", "directory content digest is not supported")
                            return self._metadata(
                                binding.alias, relative_path, "directory", os.fstat(opened.descriptor)
                            )
                    except ContainmentError:
                        raise self._read_failure(regular_error) from regular_error
                try:
                    with root.open_directory(relative_path) as opened:
                        if include_digest:
                            raise ReadFailure("UNSUPPORTED_ACTION", "directory content digest is not supported")
                        return self._metadata(binding.alias, relative_path, "directory", os.fstat(opened.descriptor))
                except ContainmentError as directory_error:
                    raise self._read_failure(directory_error) from directory_error

    def directory_snapshot(
        self,
        project_id: str,
        root_id: str,
        relative_path: str,
    ) -> Mapping[str, object]:
        binding = self._resolve(project_id, root_id)
        with self._root_context(binding.root) as root, root.open_directory(relative_path) as directory:
            before_info = os.fstat(directory.descriptor)
            entries = [
                self._inspect_child(root, binding.alias, relative_path, name)
                for name in sorted(os.listdir(directory.descriptor))
            ]
            after_info = os.fstat(directory.descriptor)
            after = FileIdentity.from_stat(after_info)
            if not self._same_namespace(before_info, after_info):
                raise ReadFailure("SNAPSHOT_CHANGED", "directory changed during snapshot")
            namespace_payload = {
                "directory": self._identity_token(after),
                "entries": [
                    {key: entry[key] for key in ("name", "type", "size", "modified_ns", "identity")}
                    for entry in entries
                ],
            }
            namespace_id = hashlib.sha256(
                json.dumps(namespace_payload, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            return f"sha256:{namespace_id}", tuple(entries)

    def _inspect_child(self, root: RootHandle, alias: str, parent: str, name: str) -> dict[str, object]:
        relative = f"{parent}/{name}"
        try:
            with root.open_regular(relative) as opened:
                info = os.fstat(opened.descriptor)
                return self._entry(name, "file", info)
        except ContainmentError as regular_error:
            try:
                with root.open_directory(relative) as opened:
                    return self._entry(name, "directory", os.fstat(opened.descriptor))
            except ContainmentError as directory_error:
                raise self._read_failure(regular_error) from directory_error

    @staticmethod
    def _entry(name: str, kind: str, info: os.stat_result) -> dict[str, object]:
        identity = FileIdentity.from_stat(info)
        return {
            "name": name,
            "type": kind,
            "size": info.st_size,
            "modified_ns": info.st_mtime_ns,
            "identity": FsContainReadBackend._identity_token(identity),
        }

    @staticmethod
    def _metadata(alias: str, path: str, kind: str, info: os.stat_result) -> dict[str, object]:
        return {
            "path": FsContainReadBackend._alias(alias, path),
            "type": kind,
            "size": info.st_size,
            "modified_ns": info.st_mtime_ns,
            "identity": FsContainReadBackend._identity_token(FileIdentity.from_stat(info)),
            "redactions_applied": True,
        }

    @staticmethod
    def _identity_token(identity: FileIdentity) -> str:
        payload = f"{identity.device}:{identity.inode}:{stat.S_IFMT(identity.mode)}:{identity.links}"
        return f"sha256:{hashlib.sha256(payload.encode()).hexdigest()}"

    @staticmethod
    def _same_namespace(first: os.stat_result, second: os.stat_result) -> bool:
        return (first.st_dev, first.st_ino, stat.S_IFMT(first.st_mode), first.st_size, first.st_mtime_ns, first.st_ctime_ns) == (
            second.st_dev,
            second.st_ino,
            stat.S_IFMT(second.st_mode),
            second.st_size,
            second.st_mtime_ns,
            second.st_ctime_ns,
        )

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
                raise ReadFailure("QUOTA_EXCEEDED", "file exceeds the bounded digest limit")
            digest.update(chunk)

    def _resolve(self, project_id: str, root_id: str) -> ResolvedRoot:
        try:
            binding = self._resolver(project_id, root_id)
        except Exception as exc:
            raise ReadFailure("ROOT_UNAVAILABLE", "registered root resolution failed") from exc
        if not isinstance(binding, ResolvedRoot) or not binding.alias or binding.max_bytes < 1:
            raise ReadFailure("ROOT_UNAVAILABLE", "registered root resolution was invalid")
        return binding

    @staticmethod
    @contextmanager
    def _root_context(root: Path | RootHandle) -> Iterator[RootHandle]:
        if isinstance(root, RootHandle):
            if root.descriptor < 0:
                raise ReadFailure("ROOT_UNAVAILABLE", "registered root handle is closed")
            yield root
        else:
            with RootHandle.open(root) as opened:
                yield opened

    @staticmethod
    def _read_failure(error: ContainmentError) -> ReadFailure:
        return ReadFailure(error.code, "descriptor-relative metadata read was denied")

    @staticmethod
    def _alias(alias: str, relative_path: str) -> str:
        return f"{alias}:{relative_path}"


__all__ = ["FsContainReadBackend", "ProjectRoots", "ReadFailure", "ReadRootResolver"]
