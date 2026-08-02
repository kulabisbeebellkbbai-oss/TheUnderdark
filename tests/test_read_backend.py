from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from theunderdark.mutation_executor import ResolvedRoot
from theunderdark.read_backend import FsContainReadBackend, ReadFailure


@pytest.fixture
def configured(tmp_path: Path):
    root = tmp_path / "registered"
    root.mkdir()
    roots = {("roadex", "work"): ResolvedRoot(root, "workspace", max_bytes=16)}
    backend = FsContainReadBackend(lambda project, root_id: roots[(project, root_id)], lambda project: [root for (owner, root) in roots if owner == project], max_digest_bytes=16)
    return backend, root


def assert_failure(code: str, action) -> None:
    with pytest.raises(ReadFailure) as raised:
        action()
    assert raised.value.code == code


def test_project_and_root_metadata_are_redacted(configured) -> None:
    backend, root = configured
    project = backend.project_get("roadex")
    registration = backend.root_get("roadex", "work")
    rendered = repr((project, registration))
    assert project["roots"] == [{"root_id": "work", "alias": "workspace", "status": "active"}]
    assert registration["alias"] == "workspace"
    assert str(root) not in rendered and "host_path" not in rendered


def test_descriptor_relative_stat_and_digest_return_no_content(configured) -> None:
    backend, root = configured
    (root / "payload").write_bytes(b"secret")
    result = backend.path_stat("roadex", "work", "payload", include_digest=True)
    assert result["path"] == "workspace:payload"
    assert result["digest"] == {"algorithm": "sha256", "value": hashlib.sha256(b"secret").hexdigest()}
    assert "secret" not in repr(result) and str(root) not in repr(result)


def test_directory_snapshot_is_sorted_and_stable(configured) -> None:
    backend, root = configured
    directory = root / "page"
    directory.mkdir()
    (directory / "b").write_text("b")
    (directory / "a").mkdir()
    first = backend.directory_snapshot("roadex", "work", "page")
    second = backend.directory_snapshot("roadex", "work", "page")
    assert [entry["name"] for entry in first[1]] == ["a", "b"]
    assert first[0] == second[0]
    (directory / "c").write_text("c")
    third = backend.directory_snapshot("roadex", "work", "page")
    assert third[0] != first[0]


def test_directory_snapshot_allows_root_path_and_preserves_child_names(configured) -> None:
    backend, root = configured
    (root / "child-dir").mkdir()
    (root / "alpha").write_text("a")
    (root / "zeta").write_text("z")
    _, entries = backend.directory_snapshot("roadex", "work", "")
    assert [entry["name"] for entry in entries] == ["alpha", "child-dir", "zeta"]
    assert all("/" not in entry["name"] for entry in entries)


def test_directory_snapshot_root_path_closes_directory_duplicate_once(configured, monkeypatch) -> None:
    backend, _ = configured
    duplicates: list[int] = []
    close_calls: list[int] = []
    real_dup = os.dup
    real_close = os.close

    def tracked_dup(fd: int) -> int:
        descriptor = real_dup(fd)
        duplicates.append(descriptor)
        return descriptor

    def tracked_close(fd: int) -> None:
        if fd in duplicates:
            close_calls.append(fd)
        return real_close(fd)

    monkeypatch.setattr(os, "dup", tracked_dup)
    monkeypatch.setattr(os, "close", tracked_close)
    backend.directory_snapshot("roadex", "work", "")

    assert len(duplicates) == 1
    assert len(close_calls) == 1
    assert close_calls[0] == duplicates[0]


def test_snapshot_denies_symlink_special_and_hardlink_entries(configured, tmp_path: Path) -> None:
    backend, root = configured
    for name, create in (
        ("link", lambda path: path.symlink_to(tmp_path / "outside")),
        ("fifo", lambda path: os.mkfifo(path)),
    ):
        directory = root / name
        directory.mkdir()
        create(directory / "denied")
        assert_failure("CONTAINMENT_DENIED" if name == "link" else "SPECIAL_FILE_DENIED", lambda d=name: backend.directory_snapshot("roadex", "work", d))

    directory = root / "hardlinks"
    directory.mkdir()
    original = directory / "original"
    original.write_text("shared")
    (directory / "linked").hardlink_to(original)
    assert_failure("HARD_LINK_DENIED", lambda: backend.directory_snapshot("roadex", "work", "hardlinks"))


def test_stat_denies_symlink_and_cross_root_escape(configured, tmp_path: Path) -> None:
    backend, root = configured
    outside = tmp_path / "outside"
    outside.write_text("outside")
    (root / "link").symlink_to(outside)
    assert_failure("CONTAINMENT_DENIED", lambda: backend.path_stat("roadex", "work", "link"))
    assert_failure("PATH_INVALID", lambda: backend.path_stat("roadex", "work", "../outside"))


def test_snapshot_fails_if_entry_is_swapped_before_descriptor_open(
    configured, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend, root = configured
    directory = root / "race"
    directory.mkdir()
    victim = directory / "victim"
    victim.write_text("inside")
    outside = tmp_path / "outside"
    outside.write_text("outside")
    original = backend._inspect_child
    swapped = False

    def swap_then_inspect(*args):
        nonlocal swapped
        if not swapped:
            victim.unlink()
            victim.symlink_to(outside)
            swapped = True
        return original(*args)

    monkeypatch.setattr(backend, "_inspect_child", swap_then_inspect)
    assert_failure("CONTAINMENT_DENIED", lambda: backend.directory_snapshot("roadex", "work", "race"))


def test_digest_limit_fails_closed(configured) -> None:
    backend, root = configured
    (root / "large").write_bytes(b"x" * 17)
    assert_failure("QUOTA_EXCEEDED", lambda: backend.path_stat("roadex", "work", "large", include_digest=True))
