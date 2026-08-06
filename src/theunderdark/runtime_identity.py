"""Bounded, descriptor-based identity for the active TheUnderdark runtime."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time


RUNTIME_EXCLUDED = frozenset({
    ".git", ".venv", ".codex", ".agents", "__pycache__", ".pytest_cache", "tests", "docs",
})
_COMMIT = re.compile(r"[0-9a-f]{40}")
_CHUNK = 1024 * 1024


@dataclass(frozen=True)
class RuntimeCaptureLimits:
    max_entries: int = 10_000
    max_depth: int = 32
    max_file_bytes: int = 8 * 1024 * 1024
    max_total_bytes: int = 64 * 1024 * 1024
    max_config_bytes: int = 1 * 1024 * 1024

    def __post_init__(self) -> None:
        if any(value < 0 for value in self.__dict__.values()):
            raise ValueError("capture limits must be non-negative")


DEFAULT_LIMITS = RuntimeCaptureLimits()


class RuntimeIdentityError(ValueError):
    """A runtime or configuration identity did not match its expectation."""


def validate_production_runtime_root(
    runtime_root: str | Path,
    *,
    limits: RuntimeCaptureLimits = DEFAULT_LIMITS,
) -> Path:
    """Validate the immutable source tree used by the production process.

    The production invariant requires deployment integration to execute the
    package from the root-owned attested source tree; Task 5 updates
    installation and unit composition accordingly.
    """
    root = Path(runtime_root)
    if not root.is_absolute() or root.name in ("", ".", ".."):
        raise RuntimeIdentityError("RUNTIME_PROVENANCE_MISMATCH")
    try:
        root_fd = _open_directory_tree(root, "RUNTIME_PROVENANCE_MISMATCH")
    except RuntimeIdentityError:
        raise
    try:
        root_info = os.fstat(root_fd)
        _require_immutable_entry(root_info)
    except (OSError, RuntimeIdentityError) as error:
        if isinstance(error, RuntimeIdentityError):
            raise RuntimeIdentityError("RUNTIME_IMMUTABILITY_INVALID") from error
        raise RuntimeIdentityError("RUNTIME_IMMUTABILITY_INVALID") from error
    finally:
        os.close(root_fd)

    try:
        canonical_root = root.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise RuntimeIdentityError("RUNTIME_PROVENANCE_MISMATCH") from error
    _validate_loaded_module_root(canonical_root)
    _validate_immutable_tree(canonical_root, limits)
    return canonical_root


def _validate_loaded_module_root(root: Path) -> None:
    source_root = root / "src" / "theunderdark"
    loaded_paths: list[Path] = []
    for name, module in sys.modules.items():
        if name == "theunderdark" or name.startswith("theunderdark."):
            loaded = getattr(module, "__file__", None)
            if loaded is not None:
                loaded_paths.append(Path(loaded))
    try:
        canonical_source = source_root.resolve(strict=True)
        canonical_root = root.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise RuntimeIdentityError("RUNTIME_PROVENANCE_MISMATCH") from error
    if canonical_root != root or not canonical_source.is_dir():
        raise RuntimeIdentityError("RUNTIME_PROVENANCE_MISMATCH")
    for loaded in loaded_paths:
        try:
            resolved = loaded.resolve(strict=True)
            resolved.relative_to(canonical_source)
        except (OSError, ValueError):
            raise RuntimeIdentityError("RUNTIME_PROVENANCE_MISMATCH")
    for module_name in ("theunderdark", "theunderdark.production_cli"):
        loaded = getattr(sys.modules.get(module_name), "__file__", None)
        if loaded is None:
            raise RuntimeIdentityError("RUNTIME_PROVENANCE_MISMATCH")
        try:
            Path(loaded).resolve(strict=True).relative_to(canonical_source)
        except (OSError, ValueError):
            raise RuntimeIdentityError("RUNTIME_PROVENANCE_MISMATCH")


def _validate_immutable_tree(root: Path, limits: RuntimeCaptureLimits) -> None:
    try:
        root_fd = _open_directory_tree(root, "RUNTIME_IMMUTABILITY_INVALID")
    except RuntimeIdentityError as error:
        raise RuntimeIdentityError("RUNTIME_IMMUTABILITY_INVALID") from error
    try:
        root_before = os.fstat(root_fd)
        _require_immutable_entry(root_before)
        if not stat.S_ISDIR(root_before.st_mode):
            raise RuntimeIdentityError("RUNTIME_IMMUTABILITY_INVALID")
        entries = [0]
        _walk_immutable_directory(root_fd, (), limits, entries)
        _same_file(root_before, os.fstat(root_fd), "RUNTIME_IMMUTABILITY_INVALID")
    except (OSError, RuntimeIdentityError) as error:
        if isinstance(error, RuntimeIdentityError) and str(error) == "RUNTIME_IMMUTABILITY_INVALID":
            raise
        raise RuntimeIdentityError("RUNTIME_IMMUTABILITY_INVALID") from error
    finally:
        os.close(root_fd)


def _walk_immutable_directory(
    directory_fd: int,
    relative: tuple[str, ...],
    limits: RuntimeCaptureLimits,
    entries: list[int],
) -> None:
    try:
        with os.scandir(directory_fd) as iterator:
            for entry in iterator:
                child = relative + (entry.name,)
                if len(child) > limits.max_depth:
                    raise RuntimeIdentityError("RUNTIME_IMMUTABILITY_INVALID")
                _count_entry(entries, limits)
                info = os.stat(entry.name, dir_fd=directory_fd, follow_symlinks=False)
                _require_immutable_entry(info)
                if stat.S_ISDIR(info.st_mode):
                    child_fd = _open_at(directory_fd, entry.name, os.O_DIRECTORY, "RUNTIME_IMMUTABILITY_INVALID")
                    try:
                        opened = os.fstat(child_fd)
                        _same_file(info, opened, "RUNTIME_IMMUTABILITY_INVALID")
                        _walk_immutable_directory(child_fd, child, limits, entries)
                        _same_file(opened, os.fstat(child_fd), "RUNTIME_IMMUTABILITY_INVALID")
                    finally:
                        os.close(child_fd)
                else:
                    child_fd = _open_at(directory_fd, entry.name, os.O_RDONLY, "RUNTIME_IMMUTABILITY_INVALID")
                    try:
                        _same_file(info, os.fstat(child_fd), "RUNTIME_IMMUTABILITY_INVALID")
                    finally:
                        os.close(child_fd)
    except (OSError, RuntimeIdentityError) as error:
        if isinstance(error, RuntimeIdentityError) and str(error) == "RUNTIME_IMMUTABILITY_INVALID":
            raise
        raise RuntimeIdentityError("RUNTIME_IMMUTABILITY_INVALID") from error


def _require_immutable_entry(info: os.stat_result) -> None:
    if (
        info.st_uid != 0
        or stat.S_IMODE(info.st_mode) & 0o022
        or stat.S_ISLNK(info.st_mode)
        or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))
        or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1)
    ):
        raise RuntimeIdentityError("RUNTIME_IMMUTABILITY_INVALID")


def compute_runtime_digest(
    path: str | Path,
    commit: str,
    *,
    limits: RuntimeCaptureLimits = DEFAULT_LIMITS,
) -> str:
    """Hash Capability A's canonical records without an unbounded pathname walk."""

    _validate_commit(commit)
    root_fd = _open_directory_tree(Path(path), "RUNTIME_CAPTURE_FAILED")
    try:
        try:
            root_before = os.fstat(root_fd)
        except OSError as error:
            raise RuntimeIdentityError("RUNTIME_CAPTURE_FAILED") from error
        files: list[dict[str, object]] = []
        _walk_directory(root_fd, (), files, limits, [0], [0])
        _same_file(root_before, os.fstat(root_fd), "RUNTIME_CAPTURE_CHANGED")
    finally:
        os.close(root_fd)
    files.sort(key=lambda item: tuple(str(item["path"]).split("/")))
    return _object_digest({"version": 1, "commit": commit, "files": files})


def compute_config_digest(path: str | Path, *, limits: RuntimeCaptureLimits = DEFAULT_LIMITS) -> str:
    """Hash the exact, bounded private configuration bytes."""

    _bytes, digest = snapshot_config(path, limits=limits)
    return digest


def snapshot_config(
    path: str | Path,
    *,
    limits: RuntimeCaptureLimits = DEFAULT_LIMITS,
) -> tuple[bytes, str]:
    """Read and hash a config through one stable descriptor."""

    target = Path(path)
    parent_fd, name = _open_parent(target, "CONFIG_CAPTURE_FAILED")
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(name, flags, dir_fd=parent_fd)
        except OSError as error:
            raise RuntimeIdentityError("CONFIG_CAPTURE_FAILED") from error
        try:
            before = os.fstat(fd)
            _require_regular(before, "CONFIG_UNSUPPORTED_ENTRY")
            if before.st_nlink != 1:
                raise RuntimeIdentityError("CONFIG_HARDLINK_REJECTED")
            if before.st_size > limits.max_config_bytes:
                raise RuntimeIdentityError("CONFIG_SIZE_LIMIT")
            data = _read_bounded(fd, before.st_size, limits.max_config_bytes, "CONFIG_SIZE_LIMIT")
            after = os.fstat(fd)
            _same_file(before, after, "CONFIG_CAPTURE_CHANGED")
            return data, "sha256:" + hashlib.sha256(data).hexdigest()
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


@dataclass(frozen=True)
class RuntimeIdentity:
    runtime_digest: str
    config_digest: str
    process_start_id: str

    @classmethod
    def capture(
        cls,
        runtime_path: str | Path,
        commit: str,
        expected_runtime: str,
        config_path: str | Path,
        expected_config: str,
        *,
        limits: RuntimeCaptureLimits = DEFAULT_LIMITS,
    ) -> "RuntimeIdentity":
        identity, _config = cls.capture_with_config(
            runtime_path, commit, expected_runtime, config_path, expected_config, limits=limits,
        )
        return identity

    @classmethod
    def capture_with_config(
        cls,
        runtime_path: str | Path,
        commit: str,
        expected_runtime: str,
        config_path: str | Path,
        expected_config: str,
        *,
        limits: RuntimeCaptureLimits = DEFAULT_LIMITS,
    ) -> tuple["RuntimeIdentity", bytes]:
        runtime = compute_runtime_digest(runtime_path, commit, limits=limits)
        config_bytes, config = snapshot_config(config_path, limits=limits)
        if runtime != expected_runtime:
            raise RuntimeIdentityError("RUNTIME_IDENTITY_MISMATCH")
        if config != expected_config:
            raise RuntimeIdentityError("CONFIG_IDENTITY_MISMATCH")
        process_start_id = "sha256:" + hashlib.sha256(
            f"{os.getpid()}:{time.monotonic_ns()}".encode()
        ).hexdigest()
        return cls(runtime, config, process_start_id), config_bytes


def _walk_directory(
    directory_fd: int,
    relative: tuple[str, ...],
    files: list[dict[str, object]],
    limits: RuntimeCaptureLimits,
    entry_ref: list[int],
    bytes_ref: list[int],
) -> int:
    try:
        with os.scandir(directory_fd) as iterator:
            for entry in iterator:
                child = relative + (entry.name,)
                if any(part in RUNTIME_EXCLUDED for part in child):
                    continue
                if len(child) > limits.max_depth:
                    raise RuntimeIdentityError("RUNTIME_DEPTH_LIMIT")
                _count_entry(entry_ref, limits)
                try:
                    info = os.stat(entry.name, dir_fd=directory_fd, follow_symlinks=False)
                except OSError as error:
                    raise RuntimeIdentityError("RUNTIME_CAPTURE_FAILED") from error
                if stat.S_ISLNK(info.st_mode) or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                    raise RuntimeIdentityError("RUNTIME_UNSUPPORTED_ENTRY")
                if stat.S_ISDIR(info.st_mode):
                    child_fd = _open_at(directory_fd, entry.name, os.O_DIRECTORY, "RUNTIME_CAPTURE_FAILED")
                    try:
                        opened = os.fstat(child_fd)
                        _same_file(info, opened, "RUNTIME_CAPTURE_CHANGED")
                        _walk_directory(child_fd, child, files, limits, entry_ref, bytes_ref)
                        _same_file(opened, os.fstat(child_fd), "RUNTIME_CAPTURE_CHANGED")
                    finally:
                        os.close(child_fd)
                    continue
                if info.st_nlink != 1:
                    raise RuntimeIdentityError("RUNTIME_HARDLINK_REJECTED")
                fd = _open_at(directory_fd, entry.name, os.O_RDONLY, "RUNTIME_CAPTURE_FAILED")
                try:
                    before = os.fstat(fd)
                    _same_file(info, before, "RUNTIME_CAPTURE_CHANGED")
                    if before.st_size > limits.max_file_bytes:
                        raise RuntimeIdentityError("RUNTIME_FILE_SIZE_LIMIT")
                    data_digest = _digest_fd(fd, before.st_size, limits.max_file_bytes, bytes_ref, limits.max_total_bytes)
                    _same_file(before, os.fstat(fd), "RUNTIME_CAPTURE_CHANGED")
                finally:
                    os.close(fd)
                files.append({
                    "path": "/".join(child),
                    "mode": stat.S_IMODE(info.st_mode),
                    "sha256": "sha256:" + data_digest,
                })
    except OSError as error:
        raise RuntimeIdentityError("RUNTIME_CAPTURE_FAILED") from error
    return bytes_ref[0]


def _digest_fd(fd: int, size: int, per_file: int, total_ref: list[int], total_limit: int) -> str:
    digest = hashlib.sha256()
    read = 0
    while True:
        chunk = os.read(fd, _CHUNK)
        if not chunk:
            break
        read += len(chunk)
        total_ref[0] += len(chunk)
        if read > per_file:
            raise RuntimeIdentityError("RUNTIME_FILE_SIZE_LIMIT")
        if total_ref[0] > total_limit:
            raise RuntimeIdentityError("RUNTIME_TOTAL_SIZE_LIMIT")
        digest.update(chunk)
    if read != size:
        raise RuntimeIdentityError("RUNTIME_CAPTURE_CHANGED")
    return digest.hexdigest()


def _read_bounded(fd: int, size: int, limit: int, code: str) -> bytes:
    data = bytearray()
    while True:
        chunk = os.read(fd, min(_CHUNK, limit - len(data) + 1))
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > limit:
            raise RuntimeIdentityError(code)
    if len(data) != size:
        raise RuntimeIdentityError("CONFIG_CAPTURE_CHANGED")
    return bytes(data)


def _open_directory_tree(path: Path, code: str) -> int:
    fd, _name = _open_parent(path, code)
    try:
        return _open_at(fd, path.name, os.O_DIRECTORY, code)
    finally:
        os.close(fd)


def _open_parent(path: Path, code: str) -> tuple[int, str]:
    if not path.is_absolute() or path.name in ("", ".", ".."):
        raise RuntimeIdentityError(code)
    fd = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))
    try:
        for component in path.parts[1:-1]:
            if component in ("", ".", ".."):
                raise RuntimeIdentityError(code)
            next_fd = _open_at(fd, component, os.O_DIRECTORY, code)
            os.close(fd)
            fd = next_fd
        return fd, path.name
    except Exception:
        os.close(fd)
        raise


def _open_at(directory_fd: int, name: str, kind: int, code: str) -> int:
    flags = os.O_RDONLY | kind | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        return os.open(name, flags, dir_fd=directory_fd)
    except OSError as error:
        raise RuntimeIdentityError(code) from error


def _require_regular(info: os.stat_result, code: str) -> None:
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeIdentityError(code)


def _same_file(before: os.stat_result, after: os.stat_result, code: str) -> None:
    fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in fields):
        raise RuntimeIdentityError(code)


def _count_entry(entry_ref: list[int], limits: RuntimeCaptureLimits) -> None:
    entry_ref[0] += 1
    if entry_ref[0] > limits.max_entries:
        raise RuntimeIdentityError("RUNTIME_ENTRY_COUNT_LIMIT")


def _validate_commit(commit: str) -> None:
    if not isinstance(commit, str) or _COMMIT.fullmatch(commit) is None:
        raise ValueError("runtime commit must be a 40-character lowercase hexadecimal revision")


def _object_digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


__all__ = [
    "DEFAULT_LIMITS", "RUNTIME_EXCLUDED", "RuntimeCaptureLimits", "RuntimeIdentity",
    "RuntimeIdentityError", "compute_config_digest", "compute_runtime_digest", "snapshot_config",
    "validate_production_runtime_root",
]
