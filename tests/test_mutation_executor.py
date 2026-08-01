from __future__ import annotations

import base64
import hashlib
import threading
from pathlib import Path

import pytest

from theunderdark.mutation_executor import ExecutorFailure, FsContainMutationExecutor, ResolvedRoot


def digest(data: bytes | str) -> dict[str, str]:
    if isinstance(data, str):
        data = data.encode()
    return {"algorithm": "sha256", "value": hashlib.sha256(data).hexdigest()}


@pytest.fixture
def roots(tmp_path: Path) -> dict[tuple[str, str], ResolvedRoot]:
    work = tmp_path / "work"
    other = tmp_path / "other"
    work.mkdir()
    other.mkdir()
    return {
        ("roadex", "work"): ResolvedRoot(work, "workspace", max_bytes=16),
        ("roadex", "other"): ResolvedRoot(other, "artifacts", max_bytes=16),
    }


@pytest.fixture
def executor(roots) -> FsContainMutationExecutor:
    return FsContainMutationExecutor(lambda project, root: roots[(project, root)], max_content_bytes=16)


def request(**values) -> dict[str, object]:
    base: dict[str, object] = {"project_id": "roadex", "root_id": "work", "policy_revision": "1", "relative_path": "target"}
    base.update(values)
    return base


def assert_failure(code: str, action) -> None:
    with pytest.raises(ExecutorFailure) as raised:
        action()
    assert raised.value.code == code


def test_maps_directory_create_and_redacts_host_path(executor, roots) -> None:
    result = executor.execute("directory.create", request(parents=False))
    assert (roots[("roadex", "work")].root / "target").is_dir()
    assert result["path"] == "workspace:target"
    assert result["verified"] is True and result["redactions_applied"] is True
    assert str(roots[("roadex", "work")].root) not in repr(result)
    assert_failure("UNSUPPORTED_ACTION", lambda: executor.execute("directory.create", request(relative_path="a/b", parents=True)))


def test_maps_utf8_create_and_exact_replace(executor, roots) -> None:
    created = executor.execute(
        "file.write",
        request(content="first", content_encoding="utf8", content_digest=digest("first"), write_mode="create_only"),
    )
    replaced = executor.execute(
        "file.write",
        request(content="second", content_encoding="utf8", content_digest=digest("second"), write_mode="replace_exact", expected_prior_digest=digest("first")),
    )
    assert (roots[("roadex", "work")].root / "target").read_text() == "second"
    assert created["digest"] == digest("first") and replaced["digest"] == digest("second")


def test_base64_digest_and_size_fail_closed(executor, roots) -> None:
    encoded = base64.b64encode(b"binary").decode()
    executor.execute("file.write", request(content=encoded, content_encoding="base64", content_digest=digest(b"binary"), write_mode="create_only"))
    assert (roots[("roadex", "work")].root / "target").read_bytes() == b"binary"
    assert_failure("PRECONDITION_FAILED", lambda: executor.execute("file.write", request(relative_path="bad", content="x", content_digest=digest("y"), write_mode="create_only")))
    assert_failure("QUOTA_EXCEEDED", lambda: executor.execute("file.write", request(relative_path="large", content="x" * 17, content_digest=digest("x" * 17), write_mode="create_only")))


def test_cross_root_copy_is_bounded_and_descriptor_backed(executor, roots) -> None:
    source = roots[("roadex", "other")].root / "source"
    source.write_bytes(b"copy")
    result = executor.execute(
        "path.copy",
        request(source_root_id="other", source_relative_path="source", destination_mode="create_only"),
    )
    assert (roots[("roadex", "work")].root / "target").read_bytes() == b"copy"
    assert result["digest"] == digest("copy")
    source.write_bytes(b"x" * 17)
    assert_failure("QUOTA_EXCEEDED", lambda: executor.execute("path.copy", request(relative_path="large", source_root_id="other", source_relative_path="source", destination_mode="create_only")))


def test_move_requires_exact_type_and_digest(executor, roots) -> None:
    root = roots[("roadex", "work")].root
    (root / "source").write_bytes(b"move")
    result = executor.execute(
        "path.move",
        request(source_relative_path="source", expected_source_type="file", expected_source_digest=digest("move"), destination_mode="create_only"),
    )
    assert not (root / "source").exists() and (root / "target").read_bytes() == b"move"
    assert result["type"] == "file"


def test_delete_is_nonrecursive_and_exact(executor, roots) -> None:
    root = roots[("roadex", "work")].root
    (root / "target").write_bytes(b"delete")
    result = executor.execute("path.delete", request(expected_type="file", expected_digest=digest("delete"), recursive=False))
    assert not (root / "target").exists() and result["deleted_type"] == "file"
    full = root / "full"
    full.mkdir()
    (full / "child").write_text("safe")
    assert_failure("UNSUPPORTED_ACTION", lambda: executor.execute("path.delete", request(relative_path="full", expected_type="directory", recursive=True)))
    assert (full / "child").read_text() == "safe"


def test_symlink_and_hard_link_inputs_fail_closed(executor, roots, tmp_path: Path) -> None:
    root = roots[("roadex", "work")].root
    outside = tmp_path / "outside"
    outside.write_text("safe")
    (root / "link").symlink_to(outside)
    assert_failure("CONTAINMENT_DENIED", lambda: executor.execute("path.delete", request(relative_path="link", expected_type="file", expected_digest=digest("safe"), recursive=False)))
    original = root / "original"
    original.write_text("shared")
    (root / "hard").hardlink_to(original)
    assert_failure("HARD_LINK_DENIED", lambda: executor.execute("path.delete", request(relative_path="hard", expected_type="file", expected_digest=digest("shared"), recursive=False)))


def test_concurrent_admission_fails_without_queueing(roots, monkeypatch: pytest.MonkeyPatch) -> None:
    entered = threading.Event()
    release = threading.Event()
    executor = FsContainMutationExecutor(lambda project, root: roots[(project, root)], max_concurrent_per_project=1)
    original = executor._execute_admitted

    def blocked(*args):
        entered.set()
        release.wait(timeout=2)
        return original(*args)

    monkeypatch.setattr(executor, "_execute_admitted", blocked)
    failure: list[str] = []
    thread = threading.Thread(target=lambda: executor.execute("directory.create", request(relative_path="one", parents=False)))
    thread.start()
    assert entered.wait(timeout=1)
    try:
        try:
            executor.execute("directory.create", request(relative_path="two", parents=False))
        except ExecutorFailure as exc:
            failure.append(exc.code)
    finally:
        release.set()
        thread.join(timeout=2)
    assert failure == ["RATE_LIMITED"]
