"""Descriptor-relative filesystem containment for registered Linux roots.

The primitives in this module never concatenate an untrusted path with a host
root.  Linux ``openat2(2)`` resolves the complete relative path in one kernel
operation beneath a trusted root descriptor, denying symlinks, magic links,
and mount traversal.  Callers retain responsibility for policy, authorization,
locking, quotas, journaling, and durable evidence.
"""

from __future__ import annotations

import ctypes
import errno
import os
import platform
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import TracebackType
from typing import Final


RESOLVE_NO_XDEV: Final = 0x01
RESOLVE_NO_MAGICLINKS: Final = 0x02
RESOLVE_NO_SYMLINKS: Final = 0x04
RESOLVE_BENEATH: Final = 0x08
RESOLVE_POLICY: Final = (
    RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH
)

_SYS_OPENAT2: Final = {
    "x86_64": 437,
    "amd64": 437,
    "aarch64": 437,
    "arm64": 437,
    "riscv64": 437,
}.get(platform.machine().lower())
_SYS_RENAMEAT2: Final = {
    "x86_64": 316,
    "amd64": 316,
    "aarch64": 276,
    "arm64": 276,
    "riscv64": 276,
}.get(platform.machine().lower())
_RENAME_NOREPLACE: Final = 1

_LIBC = ctypes.CDLL(None, use_errno=True)


class _OpenHow(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("mode", ctypes.c_uint64),
        ("resolve", ctypes.c_uint64),
    ]


class ContainmentError(OSError):
    """A path could not be used without weakening the containment contract."""

    def __init__(self, code: str, message: str, *, cause_errno: int | None = None):
        super().__init__(cause_errno or 0, message)
        self.code = code
        self.cause_errno = cause_errno


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int
    mode: int
    size: int
    links: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> "FileIdentity":
        return cls(value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_nlink)


class OpenedFile:
    """Owned descriptor with identity captured after the atomic open."""

    def __init__(self, descriptor: int, identity: FileIdentity):
        self.descriptor = descriptor
        self.identity = identity

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1

    def __enter__(self) -> "OpenedFile":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def _relative_bytes(relative_path: str) -> bytes:
    if not isinstance(relative_path, str) or not relative_path:
        raise ContainmentError("PATH_INVALID", "path must be a non-empty relative string")
    if "\x00" in relative_path or "\\" in relative_path or "\n" in relative_path or "\r" in relative_path:
        raise ContainmentError("PATH_INVALID", "path contains a forbidden character")
    path = PurePosixPath(relative_path)
    parts = path.parts
    if path.is_absolute() or not parts or any(part in {"", ".", ".."} for part in parts):
        raise ContainmentError("PATH_INVALID", "path must be normalized and relative")
    # PurePosixPath normalizes duplicate slashes and dot components, so compare
    # the spelling to prevent aliases from reaching the kernel.
    if str(path) != relative_path or ":" in parts[0]:
        raise ContainmentError("PATH_INVALID", "path must be normalized and relative")
    return os.fsencode(relative_path)


def _openat2(directory_fd: int, path: bytes, flags: int, mode: int = 0) -> int:
    if _SYS_OPENAT2 is None:
        raise ContainmentError("UNSUPPORTED_PLATFORM", "openat2 is unavailable on this architecture")
    how = _OpenHow(flags=flags, mode=mode, resolve=RESOLVE_POLICY)
    descriptor = _LIBC.syscall(
        _SYS_OPENAT2,
        directory_fd,
        ctypes.c_char_p(path),
        ctypes.byref(how),
        ctypes.sizeof(how),
    )
    if descriptor < 0:
        number = ctypes.get_errno()
        if number == errno.ENOSYS:
            code = "UNSUPPORTED_PLATFORM"
        elif number in {errno.ELOOP, errno.EXDEV, errno.ENOTDIR}:
            code = "CONTAINMENT_DENIED"
        elif number in {errno.ENXIO, errno.ENODEV}:
            code = "SPECIAL_FILE_DENIED"
        elif number == errno.ENOENT:
            code = "SOURCE_NOT_FOUND"
        elif number == errno.EEXIST:
            code = "DESTINATION_EXISTS"
        else:
            code = "OPEN_FAILED"
        raise ContainmentError(code, "descriptor-relative open was denied", cause_errno=number)
    return int(descriptor)


def _rename_noreplace(source_fd: int, source: str, destination_fd: int, destination: str) -> None:
    if _SYS_RENAMEAT2 is None:
        raise ContainmentError("UNSUPPORTED_PLATFORM", "renameat2 is unavailable on this architecture")
    result = _LIBC.syscall(
        _SYS_RENAMEAT2,
        source_fd,
        ctypes.c_char_p(os.fsencode(source)),
        destination_fd,
        ctypes.c_char_p(os.fsencode(destination)),
        _RENAME_NOREPLACE,
    )
    if result < 0:
        number = ctypes.get_errno()
        code = "DESTINATION_EXISTS" if number == errno.EEXIST else "MUTATION_FAILED"
        raise ContainmentError(code, "descriptor-relative rename was denied", cause_errno=number)


class RootHandle:
    """Trusted registered-root descriptor used for atomic relative opens."""

    def __init__(self, descriptor: int, identity: FileIdentity):
        self.descriptor = descriptor
        self.identity = identity

    @classmethod
    def open(cls, host_path: Path | str) -> "RootHandle":
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            descriptor = os.open(os.fspath(host_path), flags)
        except OSError as exc:
            raise ContainmentError(
                "ROOT_INVALID", "registered root must be a non-symlink directory", cause_errno=exc.errno
            ) from exc
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode):
            os.close(descriptor)
            raise ContainmentError("ROOT_INVALID", "registered root must be a directory")
        return cls(descriptor, FileIdentity.from_stat(info))

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1

    def __enter__(self) -> "RootHandle":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def _ensure_open(self) -> None:
        if self.descriptor < 0:
            raise ValueError("root handle is closed")

    def open_regular(
        self,
        relative_path: str,
        *,
        writable: bool = False,
        allow_hard_links: bool = False,
    ) -> OpenedFile:
        """Atomically open an existing regular file beneath the root."""

        self._ensure_open()
        flags = (
            (os.O_RDWR if writable else os.O_RDONLY)
            | os.O_CLOEXEC
            | os.O_NOFOLLOW
            | os.O_NONBLOCK
        )
        descriptor = _openat2(self.descriptor, _relative_bytes(relative_path), flags)
        return self._validate_regular(descriptor, allow_hard_links=allow_hard_links)

    def create_regular(
        self,
        relative_path: str,
        *,
        mode: int = 0o600,
    ) -> OpenedFile:
        """Atomically create a new, exclusive regular file beneath the root."""

        self._ensure_open()
        if mode & ~0o777:
            raise ContainmentError("MODE_INVALID", "file mode contains unsupported bits")
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
        descriptor = _openat2(self.descriptor, _relative_bytes(relative_path), flags, mode)
        return self._validate_regular(descriptor, allow_hard_links=False)

    def open_directory(self, relative_path: str) -> OpenedFile:
        """Atomically open an existing directory beneath the root."""

        self._ensure_open()
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        descriptor = _openat2(self.descriptor, _relative_bytes(relative_path), flags)
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode):
            os.close(descriptor)
            raise ContainmentError("SPECIAL_FILE_DENIED", "path is not a directory")
        return OpenedFile(descriptor, FileIdentity.from_stat(info))

    def create_directory(self, relative_path: str, *, mode: int = 0o700) -> FileIdentity:
        """Create one directory beneath an existing, descriptor-opened parent."""

        self._ensure_open()
        if mode & ~0o777:
            raise ContainmentError("MODE_INVALID", "directory mode contains unsupported bits")
        parent_path, leaf = self._split_parent(relative_path)
        with self._open_parent(parent_path) as parent:
            self._verify_parent(parent_path, parent.identity)
            try:
                os.mkdir(leaf, mode=mode, dir_fd=parent.descriptor)
            except FileExistsError as exc:
                raise ContainmentError("DESTINATION_EXISTS", "destination already exists") from exc
            except OSError as exc:
                raise ContainmentError("MUTATION_FAILED", "directory creation failed", cause_errno=exc.errno) from exc
            os.fsync(parent.descriptor)
            info = os.stat(leaf, dir_fd=parent.descriptor, follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode):
                raise ContainmentError("SPECIAL_FILE_DENIED", "created path is not a directory")
            return FileIdentity.from_stat(info)

    def atomic_write(
        self,
        relative_path: str,
        data: bytes,
        *,
        replace: bool = False,
        expected_identity: FileIdentity | None = None,
        mode: int = 0o600,
    ) -> FileIdentity:
        """Publish a fsynced regular file through an in-directory temporary."""

        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")
        if replace and expected_identity is None:
            raise ContainmentError("PRECONDITION_REQUIRED", "replacement requires exact identity")
        parent_path, leaf = self._split_parent(relative_path)
        with self._open_parent(parent_path) as parent:
            if replace:
                self._require_identity(relative_path, expected_identity)
            temporary = f".underdark-{secrets.token_hex(16)}"
            descriptor = -1
            try:
                descriptor = os.open(
                    temporary,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                    mode,
                    dir_fd=parent.descriptor,
                )
                view = memoryview(data)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError(errno.EIO, "short write")
                    view = view[written:]
                os.fsync(descriptor)
                os.close(descriptor)
                descriptor = -1
                self._verify_parent(parent_path, parent.identity)
                if replace:
                    self._require_identity(relative_path, expected_identity)
                    os.replace(temporary, leaf, src_dir_fd=parent.descriptor, dst_dir_fd=parent.descriptor)
                else:
                    _rename_noreplace(parent.descriptor, temporary, parent.descriptor, leaf)
                os.fsync(parent.descriptor)
                with self.open_regular(relative_path) as published:
                    return published.identity
            except ContainmentError:
                raise
            except OSError as exc:
                raise ContainmentError("MUTATION_FAILED", "atomic file publication failed", cause_errno=exc.errno) from exc
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                try:
                    os.unlink(temporary, dir_fd=parent.descriptor)
                except FileNotFoundError:
                    pass

    def copy_regular(self, source_path: str, destination_path: str, *, mode: int = 0o600) -> FileIdentity:
        """Copy a regular file through open descriptors and publish no-replace."""

        with self.open_regular(source_path) as source:
            chunks: list[bytes] = []
            while True:
                chunk = os.read(source.descriptor, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            return self.atomic_write(destination_path, b"".join(chunks), mode=mode)

    def rename(self, source_path: str, destination_path: str, *, expected_identity: FileIdentity) -> FileIdentity:
        """Move a regular file or empty directory within this root, no-replace."""

        source_parent_path, source_leaf = self._split_parent(source_path)
        destination_parent_path, destination_leaf = self._split_parent(destination_path)
        with self._open_parent(source_parent_path) as source_parent, self._open_parent(destination_parent_path) as destination_parent:
            self._require_identity(source_path, expected_identity, allow_directory=True)
            self._verify_parent(source_parent_path, source_parent.identity)
            self._verify_parent(destination_parent_path, destination_parent.identity)
            _rename_noreplace(source_parent.descriptor, source_leaf, destination_parent.descriptor, destination_leaf)
            os.fsync(source_parent.descriptor)
            if destination_parent.identity != source_parent.identity:
                os.fsync(destination_parent.descriptor)
            return self._node_identity(destination_path, allow_directory=True)

    def unlink(self, relative_path: str, *, expected_identity: FileIdentity, directory: bool = False) -> None:
        """Unlink an exact regular file or an exact empty directory."""

        parent_path, leaf = self._split_parent(relative_path)
        with self._open_parent(parent_path) as parent:
            actual = self._node_identity(relative_path, allow_directory=directory)
            self._match_identity(actual, expected_identity)
            if directory != stat.S_ISDIR(actual.mode):
                raise ContainmentError("TYPE_MISMATCH", "path type does not match unlink request")
            self._verify_parent(parent_path, parent.identity)
            try:
                if directory:
                    os.rmdir(leaf, dir_fd=parent.descriptor)
                else:
                    os.unlink(leaf, dir_fd=parent.descriptor)
            except OSError as exc:
                raise ContainmentError("MUTATION_FAILED", "descriptor-relative unlink failed", cause_errno=exc.errno) from exc
            os.fsync(parent.descriptor)

    @staticmethod
    def _split_parent(relative_path: str) -> tuple[str | None, str]:
        decoded = os.fsdecode(_relative_bytes(relative_path))
        path = PurePosixPath(decoded)
        return (None if len(path.parts) == 1 else str(path.parent), path.name)

    def _open_parent(self, parent_path: str | None) -> OpenedFile:
        if parent_path is None:
            descriptor = os.dup(self.descriptor)
            return OpenedFile(descriptor, FileIdentity.from_stat(os.fstat(descriptor)))
        return self.open_directory(parent_path)

    def _verify_parent(self, parent_path: str | None, expected: FileIdentity) -> None:
        with self._open_parent(parent_path) as current:
            if (
                current.identity.device != expected.device
                or current.identity.inode != expected.inode
                or stat.S_IFMT(current.identity.mode) != stat.S_IFMT(expected.mode)
            ):
                raise ContainmentError("PRECONDITION_FAILED", "parent directory identity changed")

    def _node_identity(self, relative_path: str, *, allow_directory: bool = False) -> FileIdentity:
        descriptor = _openat2(
            self.descriptor,
            _relative_bytes(relative_path),
            os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        try:
            info = os.fstat(descriptor)
            if stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1:
                    raise ContainmentError("HARD_LINK_DENIED", "regular file link count must equal one")
            elif not (allow_directory and stat.S_ISDIR(info.st_mode)):
                raise ContainmentError("SPECIAL_FILE_DENIED", "path type is not allowed")
            return FileIdentity.from_stat(info)
        finally:
            os.close(descriptor)

    def _require_identity(
        self,
        relative_path: str,
        expected: FileIdentity | None,
        *,
        allow_directory: bool = False,
    ) -> None:
        if expected is None:
            raise ContainmentError("PRECONDITION_REQUIRED", "exact identity is required")
        self._match_identity(self._node_identity(relative_path, allow_directory=allow_directory), expected)

    @staticmethod
    def _match_identity(actual: FileIdentity, expected: FileIdentity) -> None:
        if actual != expected:
            raise ContainmentError("PRECONDITION_FAILED", "filesystem identity changed")

    @staticmethod
    def _validate_regular(descriptor: int, *, allow_hard_links: bool) -> OpenedFile:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            os.close(descriptor)
            raise ContainmentError("SPECIAL_FILE_DENIED", "path is not a regular file")
        if info.st_nlink != 1 and not allow_hard_links:
            os.close(descriptor)
            raise ContainmentError("HARD_LINK_DENIED", "regular file link count must equal one")
        return OpenedFile(descriptor, FileIdentity.from_stat(info))


__all__ = ["ContainmentError", "FileIdentity", "OpenedFile", "RootHandle"]
