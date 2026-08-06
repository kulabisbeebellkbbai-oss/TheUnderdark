from __future__ import annotations

import hashlib
import json
import os
import stat
from types import SimpleNamespace
from pathlib import Path

import pytest

from theunderdark.production_app import create_production_http_app, create_production_mcp
from theunderdark.production import ProductionStorageService
from theunderdark.journal import SQLiteOperationJournal
from theunderdark.runtime_identity import (
    RuntimeIdentity,
    RuntimeIdentityError,
    RuntimeCaptureLimits,
    compute_config_digest,
    compute_runtime_digest,
    validate_production_runtime_root,
)
import theunderdark.runtime_identity as runtime_identity_module


def _runtime_digest(path: Path, commit: str) -> str:
    files = []
    excluded = {".git", ".venv", ".codex", ".agents", "__pycache__", ".pytest_cache", "tests", "docs"}
    for item in sorted(path.rglob("*")):
        relative = item.relative_to(path)
        if any(part in excluded for part in relative.parts) or not item.is_file():
            continue
        files.append({
            "path": relative.as_posix(),
            "mode": stat.S_IMODE(item.stat().st_mode),
            "sha256": "sha256:" + hashlib.sha256(item.read_bytes()).hexdigest(),
        })
    payload = {"version": 1, "commit": commit, "files": files}
    return "sha256:" + hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _service(tmp_path: Path) -> ProductionStorageService:
    return ProductionStorageService(journal=SQLiteOperationJournal(tmp_path / "operations.sqlite3"), verifier=object(), executor=object())


def test_runtime_digest_is_capability_a_canonical_and_excludes_non_runtime_entries(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("print('ok')\n")
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "z").write_text("nested\n")
    (tmp_path / "a.py").write_text("prefix collision\n")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "secret.txt").write_text("excluded\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_app.py").write_text("excluded\n")
    commit = "a" * 40

    assert compute_runtime_digest(tmp_path, commit) == _runtime_digest(tmp_path, commit)
    assert compute_runtime_digest(tmp_path, commit) == compute_runtime_digest(tmp_path, commit)


def test_runtime_digest_matches_capability_a_oracle_for_prefix_collisions(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "z").write_text("nested\n")
    (tmp_path / "a.py").write_text("sibling\n")
    assert compute_runtime_digest(tmp_path, "a" * 40) == _runtime_digest(tmp_path, "a" * 40)


def test_runtime_digest_masks_special_mode_bits_like_capability_a(tmp_path: Path) -> None:
    target = tmp_path / "setuid.py"
    target.write_text("print('ok')\n")
    target.chmod(0o4755)
    payload = {
        "version": 1,
        "commit": "a" * 40,
        "files": [{
            "path": "setuid.py",
            "mode": stat.S_IMODE(target.stat().st_mode),
            "sha256": "sha256:" + hashlib.sha256(target.read_bytes()).hexdigest(),
        }],
    }
    expected = "sha256:" + hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert stat.S_IMODE(target.stat().st_mode) == 0o4755
    assert compute_runtime_digest(tmp_path, "a" * 40) == expected


@pytest.mark.parametrize(
    ("setup", "limit", "code"),
    [
        (lambda root: (root / "a").write_text("x"), "max_entries", "RUNTIME_ENTRY_COUNT_LIMIT"),
        (lambda root: (root / "a").write_bytes(b"123"), "max_file_bytes", "RUNTIME_FILE_SIZE_LIMIT"),
    ],
)
def test_runtime_limits_reject_limit_plus_one(tmp_path: Path, setup, limit: str, code: str) -> None:
    setup(tmp_path)
    limits = RuntimeCaptureLimits(**{limit: 0 if limit == "max_entries" else 2})
    with pytest.raises(RuntimeIdentityError, match=code):
        compute_runtime_digest(tmp_path, "a" * 40, limits=limits)


def test_runtime_total_and_depth_limits_reject_limit_plus_one(tmp_path: Path) -> None:
    (tmp_path / "a").write_bytes(b"12")
    (tmp_path / "b").write_bytes(b"34")
    with pytest.raises(RuntimeIdentityError, match="RUNTIME_TOTAL_SIZE_LIMIT"):
        compute_runtime_digest(tmp_path, "a" * 40, limits=RuntimeCaptureLimits(max_total_bytes=3))
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "file").write_text("x")
    with pytest.raises(RuntimeIdentityError, match="RUNTIME_DEPTH_LIMIT"):
        compute_runtime_digest(tmp_path, "a" * 40, limits=RuntimeCaptureLimits(max_depth=1))


@pytest.mark.parametrize(
    ("setup", "limit", "code"),
    [
        (lambda root: (root / "a").write_bytes(b"x"), "max_entries", "RUNTIME_ENTRY_COUNT_LIMIT"),
        (lambda root: ((root / "a").mkdir(), (root / "a" / "f").write_bytes(b"x")), "max_depth", "RUNTIME_DEPTH_LIMIT"),
        (lambda root: (root / "a").write_bytes(b"xy"), "max_file_bytes", "RUNTIME_FILE_SIZE_LIMIT"),
        (lambda root: ((root / "a").write_bytes(b"x"), (root / "b").write_bytes(b"y")), "max_total_bytes", "RUNTIME_TOTAL_SIZE_LIMIT"),
    ],
)
def test_runtime_limits_accept_exact_boundary(tmp_path: Path, setup, limit: str, code: str) -> None:
    setup(tmp_path)
    values = {"max_entries": 1, "max_depth": 2, "max_file_bytes": 2, "max_total_bytes": 2}
    assert compute_runtime_digest(tmp_path, "a" * 40, limits=RuntimeCaptureLimits(**{limit: values[limit]}))


def test_config_limit_accepts_exact_boundary(tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    config.write_bytes(b"12345")
    assert compute_config_digest(config, limits=RuntimeCaptureLimits(max_config_bytes=5)).startswith("sha256:")


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "special"])
def test_runtime_traversal_rejects_unsafe_entries(tmp_path: Path, kind: str) -> None:
    target = tmp_path / "target"
    target.write_text("safe")
    if kind == "symlink":
        (tmp_path / "entry").symlink_to(target)
    elif kind == "hardlink":
        os.link(target, tmp_path / "entry")
    else:
        os.mkfifo(tmp_path / "entry")
    with pytest.raises(RuntimeIdentityError) as failure:
        compute_runtime_digest(tmp_path, "a" * 40)
    assert failure.value.args[0] in {"RUNTIME_UNSUPPORTED_ENTRY", "RUNTIME_HARDLINK_REJECTED"}


def test_runtime_rejects_regular_to_symlink_swap_between_stat_and_open(tmp_path: Path, monkeypatch) -> None:
    entry = tmp_path / "entry"
    outside = tmp_path / "outside"
    entry.write_text("safe")
    outside.write_text("external secret")
    original_open = runtime_identity_module.os.open
    swapped = False

    def swap_before_open(name, flags, *args, **kwargs):
        nonlocal swapped
        if not swapped and kwargs.get("dir_fd") is not None and name == "entry" and not (flags & os.O_DIRECTORY):
            entry.unlink()
            entry.symlink_to(outside)
            swapped = True
        return original_open(name, flags, *args, **kwargs)

    monkeypatch.setattr(runtime_identity_module.os, "open", swap_before_open)
    with pytest.raises(RuntimeIdentityError, match="RUNTIME_CAPTURE_(FAILED|CHANGED)"):
        compute_runtime_digest(tmp_path, "a" * 40)
    assert swapped and entry.is_symlink()


def test_runtime_rejects_directory_swap_between_stat_and_open(tmp_path: Path, monkeypatch) -> None:
    entry = tmp_path / "entry"
    outside = tmp_path / "outside"
    entry.mkdir()
    outside.mkdir()
    original_open = runtime_identity_module.os.open
    swapped = False

    def swap_before_open(name, flags, *args, **kwargs):
        nonlocal swapped
        if not swapped and kwargs.get("dir_fd") is not None and name == "entry" and flags & os.O_DIRECTORY:
            entry.rmdir()
            entry.symlink_to(outside, target_is_directory=True)
            swapped = True
        return original_open(name, flags, *args, **kwargs)

    monkeypatch.setattr(runtime_identity_module.os, "open", swap_before_open)
    with pytest.raises(RuntimeIdentityError, match="RUNTIME_CAPTURE_(FAILED|CHANGED)"):
        compute_runtime_digest(tmp_path, "a" * 40)
    assert swapped and entry.is_symlink()


def test_runtime_root_metadata_change_is_rejected(tmp_path: Path, monkeypatch) -> None:
    original_scandir = runtime_identity_module.os.scandir
    changed = False

    def change_root_once(directory_fd):
        nonlocal changed
        if not changed:
            tmp_path.chmod(0o755)
            changed = True
        return original_scandir(directory_fd)

    monkeypatch.setattr(runtime_identity_module.os, "scandir", change_root_once)
    with pytest.raises(RuntimeIdentityError, match="RUNTIME_CAPTURE_CHANGED"):
        compute_runtime_digest(tmp_path, "a" * 40)


def test_config_snapshot_rejects_symlink_hardlink_and_size_limit(tmp_path: Path) -> None:
    real = tmp_path / "real-config"
    real.write_bytes(b"config")
    link = tmp_path / "config-link"
    link.symlink_to(real)
    with pytest.raises(RuntimeIdentityError, match="CONFIG_CAPTURE_FAILED"):
        compute_config_digest(link)
    hardlink = tmp_path / "config-hardlink"
    os.link(real, hardlink)
    with pytest.raises(RuntimeIdentityError, match="CONFIG_HARDLINK_REJECTED"):
        compute_config_digest(hardlink)
    hardlink.unlink()
    with pytest.raises(RuntimeIdentityError, match="CONFIG_SIZE_LIMIT"):
        compute_config_digest(real, limits=RuntimeCaptureLimits(max_config_bytes=5))


def test_config_digest_is_digest_of_exact_bytes(tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    config.write_bytes(b'{"b":2,"a":1}\n')

    assert compute_config_digest(config) == "sha256:" + hashlib.sha256(config.read_bytes()).hexdigest()


def test_runtime_identity_rejects_wrong_expected_digest(tmp_path: Path) -> None:
    expected = "sha256:" + "a" * 64
    config = tmp_path / "config.json"
    config.write_bytes(b"config\n")
    with pytest.raises(RuntimeIdentityError, match="RUNTIME_IDENTITY_MISMATCH"):
        RuntimeIdentity.capture(tmp_path, "b" * 40, expected, config, compute_config_digest(config))


def test_runtime_identity_rejects_wrong_expected_config_digest(tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    config.write_bytes(b"config\n")
    runtime = compute_runtime_digest(tmp_path, "b" * 40)
    with pytest.raises(RuntimeIdentityError, match="CONFIG_IDENTITY_MISMATCH"):
        RuntimeIdentity.capture(tmp_path, "b" * 40, runtime, config, "sha256:" + "a" * 64)


def test_production_provenance_rejects_loaded_package_outside_root(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "src" / "theunderdark"
    source.mkdir(parents=True)
    (source / "__init__.py").write_text("\n")
    monkeypatch.setattr(runtime_identity_module, "_require_immutable_entry", lambda _info: None)
    monkeypatch.setattr(runtime_identity_module, "_validate_immutable_tree", lambda *_args: None)
    with pytest.raises(RuntimeIdentityError, match="RUNTIME_PROVENANCE_MISMATCH"):
        validate_production_runtime_root(tmp_path)


@pytest.mark.parametrize("field", ["st_uid", "st_mode", "st_nlink"])
def test_production_immutability_rejects_nonroot_writable_or_hardlinked_file(tmp_path: Path, monkeypatch, field: str) -> None:
    entry = tmp_path / "entry"
    entry.write_text("x")
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    base = entry.stat()
    values = {
        "st_uid": 1000,
        "st_mode": stat.S_IFREG | 0o664,
        "st_nlink": 2,
    }
    fake = os.stat_result(tuple(values[field] if name == field else getattr(base, name) for name in (
        "st_mode", "st_ino", "st_dev", "st_nlink", "st_uid", "st_gid", "st_size", "st_atime", "st_mtime", "st_ctime"
    )))
    monkeypatch.setattr(runtime_identity_module, "_open_directory_tree", lambda *_args: os.dup(fd))
    monkeypatch.setattr(runtime_identity_module.os, "stat", lambda *_args, **_kwargs: fake)
    try:
        with pytest.raises(RuntimeIdentityError, match="RUNTIME_IMMUTABILITY_INVALID"):
            runtime_identity_module._validate_immutable_tree(tmp_path, RuntimeCaptureLimits())
    finally:
        os.close(fd)


def test_production_immutability_rejects_invalid_root_metadata(tmp_path: Path, monkeypatch) -> None:
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    root_info = SimpleNamespace(
        st_uid=1000,
        st_mode=stat.S_IFDIR | 0o755,
        st_nlink=1,
        st_dev=1,
        st_ino=1,
        st_size=0,
        st_mtime_ns=1,
        st_ctime_ns=1,
    )
    monkeypatch.setattr(runtime_identity_module, "_open_directory_tree", lambda *_args: os.dup(fd))
    monkeypatch.setattr(runtime_identity_module.os, "fstat", lambda _fd: root_info)
    try:
        with pytest.raises(RuntimeIdentityError, match="RUNTIME_IMMUTABILITY_INVALID"):
            runtime_identity_module._validate_immutable_tree(tmp_path, RuntimeCaptureLimits())
    finally:
        os.close(fd)


def test_production_immutability_rejects_root_descriptor_mutation(tmp_path: Path, monkeypatch) -> None:
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    root_info = SimpleNamespace(
        st_uid=0,
        st_mode=stat.S_IFDIR | 0o755,
        st_nlink=1,
        st_dev=1,
        st_ino=1,
        st_size=0,
        st_mtime_ns=1,
        st_ctime_ns=1,
    )
    mutated_info = SimpleNamespace(**{**vars(root_info), "st_ino": 2})
    descriptors = iter((root_info, mutated_info))
    monkeypatch.setattr(runtime_identity_module, "_open_directory_tree", lambda *_args: os.dup(fd))
    monkeypatch.setattr(runtime_identity_module.os, "fstat", lambda _fd: next(descriptors))
    try:
        with pytest.raises(RuntimeIdentityError, match="RUNTIME_IMMUTABILITY_INVALID"):
            runtime_identity_module._validate_immutable_tree(tmp_path, RuntimeCaptureLimits())
    finally:
        os.close(fd)


def test_runtime_identity_exposes_only_safe_opaque_fields(tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    config.write_bytes(b"config\n")
    identity = RuntimeIdentity.capture(
        tmp_path, "b" * 40, compute_runtime_digest(tmp_path, "b" * 40), config, compute_config_digest(config)
    )

    assert set(identity.__dataclass_fields__) == {"runtime_digest", "config_digest", "process_start_id"}
    assert identity.process_start_id.startswith("sha256:")
    assert str(tmp_path) not in repr(identity)


def test_health_exposes_only_safe_attestation(tmp_path: Path) -> None:
    service = _service(tmp_path)
    config = tmp_path / "config.json"
    config.write_bytes(b"config\n")
    identity = RuntimeIdentity.capture(
        tmp_path, "b" * 40, compute_runtime_digest(tmp_path, "b" * 40), config, compute_config_digest(config)
    )
    app = create_production_http_app(service, runtime_identity=identity)

    import asyncio
    import httpx

    async def request_health():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            return await client.get("/health")

    health = asyncio.run(request_health()).json()
    assert health["runtime"] == {
        "runtime_digest": identity.runtime_digest,
        "config_digest": identity.config_digest,
        "process_start_id": identity.process_start_id,
    }
    assert "path" not in repr(health)
    service.journal.close()


def test_mcp_health_exposes_same_safe_attestation(tmp_path: Path) -> None:
    service = _service(tmp_path)
    config = tmp_path / "config.json"
    config.write_bytes(b"config\n")
    identity = RuntimeIdentity.capture(
        tmp_path, "b" * 40, compute_runtime_digest(tmp_path, "b" * 40), config, compute_config_digest(config)
    )
    mcp = create_production_mcp(service, runtime_identity=identity)

    async def call_health():
        from mcp.shared.memory import create_connected_server_and_client_session
        async with create_connected_server_and_client_session(mcp) as client:
            return await client.call_tool("underdark_health_get", {})

    import asyncio
    result = asyncio.run(call_health())
    payload = json.loads(result.content[0].text)
    assert payload["result"]["runtime"] == {
        "runtime_digest": identity.runtime_digest,
        "config_digest": identity.config_digest,
        "process_start_id": identity.process_start_id,
    }
    assert "path" not in repr(payload)
    service.journal.close()
