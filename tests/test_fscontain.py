from __future__ import annotations

import os
from pathlib import Path

import pytest

from theunderdark.fscontain import ContainmentError, RootHandle


@pytest.fixture
def registered(tmp_path: Path) -> Path:
    root = tmp_path / "registered"
    root.mkdir()
    return root


def assert_denied(code: str, action) -> None:
    with pytest.raises(ContainmentError) as raised:
        action()
    assert raised.value.code == code


@pytest.mark.parametrize(
    "relative",
    ["", "/etc/passwd", "../outside", "a/../outside", "a//b", "./a", "C:/boot.ini", "a\\b", "bad\x00name", "bad\nname"],
)
def test_rejects_non_normalized_paths_before_open(registered: Path, relative: str) -> None:
    with RootHandle.open(registered) as root:
        assert_denied("PATH_INVALID", lambda: root.open_regular(relative))


def test_opens_regular_file_and_captures_identity(registered: Path) -> None:
    target = registered / "payload"
    target.write_bytes(b"safe")
    with RootHandle.open(registered) as root, root.open_regular("payload") as opened:
        assert os.read(opened.descriptor, 4) == b"safe"
        assert opened.identity.inode == target.stat().st_ino
        assert opened.identity.links == 1


def test_denies_intermediate_and_leaf_symlinks(registered: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_text("outside")
    (registered / "middle").symlink_to(outside, target_is_directory=True)
    (registered / "leaf").symlink_to(outside / "secret")
    with RootHandle.open(registered) as root:
        assert_denied("CONTAINMENT_DENIED", lambda: root.open_regular("middle/secret"))
        assert_denied("CONTAINMENT_DENIED", lambda: root.open_regular("leaf"))


def test_atomic_resolution_denies_component_swapped_to_symlink(
    registered: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    safe = registered / "safe"
    safe.mkdir()
    (safe / "payload").write_text("inside")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "payload").write_text("outside")

    import theunderdark.fscontain as containment

    real_openat2 = containment._openat2
    swapped = False

    def swap_then_open(directory_fd: int, path: bytes, flags: int, mode: int = 0) -> int:
        nonlocal swapped
        if not swapped:
            safe.rename(registered / "former-safe")
            (registered / "safe").symlink_to(outside, target_is_directory=True)
            swapped = True
        return real_openat2(directory_fd, path, flags, mode)

    monkeypatch.setattr(containment, "_openat2", swap_then_open)
    with RootHandle.open(registered) as root:
        assert_denied("CONTAINMENT_DENIED", lambda: root.open_regular("safe/payload"))


def test_denies_fifo_and_directory_as_regular_file(registered: Path) -> None:
    os.mkfifo(registered / "pipe")
    (registered / "directory").mkdir()
    with RootHandle.open(registered) as root:
        assert_denied("SPECIAL_FILE_DENIED", lambda: root.open_regular("pipe"))
        assert_denied("SPECIAL_FILE_DENIED", lambda: root.open_regular("directory"))


def test_denies_unix_socket_as_regular_file(registered: Path) -> None:
    import socket

    endpoint = socket.socket(socket.AF_UNIX)
    try:
        endpoint.bind(str(registered / "socket"))
        with RootHandle.open(registered) as root:
            assert_denied("SPECIAL_FILE_DENIED", lambda: root.open_regular("socket"))
    finally:
        endpoint.close()


def test_denies_hard_link_unless_policy_explicitly_allows_it(registered: Path) -> None:
    original = registered / "original"
    original.write_text("shared")
    os.link(original, registered / "linked")
    with RootHandle.open(registered) as root:
        assert_denied("HARD_LINK_DENIED", lambda: root.open_regular("linked"))
        with root.open_regular("linked", allow_hard_links=True) as opened:
            assert opened.identity.links == 2


def test_exclusive_create_does_not_follow_leaf_symlink(registered: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.write_text("unchanged")
    (registered / "new").symlink_to(outside)
    with RootHandle.open(registered) as root:
        assert_denied("DESTINATION_EXISTS", lambda: root.create_regular("new"))
    assert outside.read_text() == "unchanged"


def test_exclusive_create_returns_open_descriptor(registered: Path) -> None:
    with RootHandle.open(registered) as root, root.create_regular("created") as opened:
        os.write(opened.descriptor, b"payload")
        assert opened.identity.links == 1
    assert (registered / "created").read_bytes() == b"payload"


def test_root_must_not_be_a_symlink(registered: Path, tmp_path: Path) -> None:
    linked = tmp_path / "linked"
    linked.symlink_to(registered, target_is_directory=True)
    assert_denied("ROOT_INVALID", lambda: RootHandle.open(linked))


def test_create_directory_uses_existing_descriptor_parent(registered: Path) -> None:
    (registered / "parent").mkdir()
    with RootHandle.open(registered) as root:
        identity = root.create_directory("parent/child")
    assert (registered / "parent/child").is_dir()
    assert identity.inode == (registered / "parent/child").stat().st_ino


def test_create_directory_denies_symlink_parent(registered: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (registered / "parent").symlink_to(outside, target_is_directory=True)
    with RootHandle.open(registered) as root:
        assert_denied("CONTAINMENT_DENIED", lambda: root.create_directory("parent/child"))
    assert not (outside / "child").exists()


def test_atomic_write_create_and_exact_replace(registered: Path) -> None:
    with RootHandle.open(registered) as root:
        created = root.atomic_write("payload", b"first")
        replaced = root.atomic_write("payload", b"second", replace=True, expected_identity=created)
    assert (registered / "payload").read_bytes() == b"second"
    assert replaced.inode != created.inode
    assert not list(registered.glob(".underdark-*"))


def test_atomic_write_refuses_existing_destination_and_stale_replace(registered: Path) -> None:
    (registered / "payload").write_bytes(b"original")
    with RootHandle.open(registered) as root, root.open_regular("payload") as opened:
        identity = opened.identity
        assert_denied("DESTINATION_EXISTS", lambda: root.atomic_write("payload", b"new"))
        (registered / "payload").write_bytes(b"changed")
        assert_denied(
            "PRECONDITION_FAILED",
            lambda: root.atomic_write("payload", b"new", replace=True, expected_identity=identity),
        )
    assert (registered / "payload").read_bytes() == b"changed"


def test_copy_regular_uses_open_source_and_no_replace(registered: Path) -> None:
    (registered / "source").write_bytes(b"copied")
    with RootHandle.open(registered) as root:
        copied = root.copy_regular("source", "destination")
        assert_denied("DESTINATION_EXISTS", lambda: root.copy_regular("source", "destination"))
    assert (registered / "destination").read_bytes() == b"copied"
    assert copied.links == 1


def test_same_root_rename_is_no_replace_and_identity_bound(registered: Path) -> None:
    (registered / "source").write_bytes(b"move")
    (registered / "occupied").write_bytes(b"keep")
    with RootHandle.open(registered) as root, root.open_regular("source") as source:
        identity = source.identity
        assert_denied("DESTINATION_EXISTS", lambda: root.rename("source", "occupied", expected_identity=identity))
        moved = root.rename("source", "destination", expected_identity=identity)
    assert not (registered / "source").exists()
    assert (registered / "destination").read_bytes() == b"move"
    assert moved.inode == identity.inode


def test_unlink_regular_and_empty_directory_require_exact_identity(registered: Path) -> None:
    (registered / "file").write_bytes(b"remove")
    (registered / "empty").mkdir()
    with RootHandle.open(registered) as root, root.open_regular("file") as opened, root.open_directory("empty") as directory:
        root.unlink("file", expected_identity=opened.identity)
        root.unlink("empty", expected_identity=directory.identity, directory=True)
    assert not (registered / "file").exists()
    assert not (registered / "empty").exists()


def test_unlink_denies_hard_link_and_nonempty_directory(registered: Path) -> None:
    original = registered / "original"
    original.write_bytes(b"shared")
    os.link(original, registered / "linked")
    directory = registered / "full"
    directory.mkdir()
    (directory / "child").write_bytes(b"safe")
    with RootHandle.open(registered) as root, root.open_directory("full") as opened:
        assert_denied("HARD_LINK_DENIED", lambda: root.unlink("linked", expected_identity=opened.identity))
        assert_denied("MUTATION_FAILED", lambda: root.unlink("full", expected_identity=opened.identity, directory=True))
    assert (directory / "child").read_bytes() == b"safe"
