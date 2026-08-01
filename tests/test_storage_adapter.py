from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from theunderdark.adapter import Authorization, RootRegistration, StorageAdapter


def digest(data: bytes | str) -> dict[str, str]:
    if isinstance(data, str):
        data = data.encode()
    return {"algorithm": "sha256", "value": hashlib.sha256(data).hexdigest()}


@pytest.fixture
def root(tmp_path: Path) -> Path:
    path = tmp_path / "registered"
    path.mkdir()
    return path


@pytest.fixture
def adapter(root: Path) -> StorageAdapter:
    service = StorageAdapter()
    service.register_root(RootRegistration("roadex", "work", root, "workspace", max_content_bytes=16))
    return service


def authorize(adapter: StorageAdapter, action_name: str, target: str, *, request: str = "req-1", ref: str = "auth-1", **changes) -> Authorization:
    auth = Authorization(ref, request, "roadex", action_name, "work", target)
    auth = replace(auth, **changes)
    adapter.add_authorization(auth)
    return auth


def common(auth: Authorization, *, key: str = "idem-1", **changes) -> dict:
    values = {
        "project_id": auth.project_id,
        "root_id": auth.root_id,
        "request_id": auth.request_id,
        "idempotency_key": key,
        "authorization_ref": auth.authorization_ref,
        "policy_revision": "1",
        "reason": "fixture verification",
    }
    values.update(changes)
    return values


def assert_error(result: dict, code: str) -> None:
    assert result["ok"] is False
    assert result["error"]["code"] == code
    assert result["evidence"]["host_state_changed"] is False


def test_project_and_root_views_are_redacted(adapter: StorageAdapter, root: Path) -> None:
    project = adapter.project_get("roadex")
    registration = adapter.root_get("roadex", "work")
    serialized = repr((project, registration))
    assert project["ok"] and registration["ok"]
    assert registration["result"]["alias"] == "workspace"
    assert str(root) not in serialized
    assert "host_path" not in serialized


@pytest.mark.parametrize("path", ["/etc/passwd", "../escape", "a/../escape", "a//b", "./a", "C:/boot.ini", "file://host/x", "a\\b", "bad\x00name", "bad\nname"])
def test_invalid_paths_fail_without_touching_outside(adapter: StorageAdapter, root: Path, tmp_path: Path, path: str) -> None:
    sentinel = tmp_path / "escape"
    sentinel.write_text("safe")
    auth = Authorization("auth-path", "req-path", "roadex", "directory.create", "work", path)
    adapter._authorizations[auth.authorization_ref] = auth  # malformed path must fail before authority can widen it
    result = adapter.directory_create(relative_path=path, **common(auth, key=f"key-{hash(path)}"))
    assert_error(result, "PATH_INVALID")
    assert sentinel.read_text() == "safe"


@pytest.mark.parametrize("link_at", ["middle", "leaf"])
def test_symlink_escape_is_denied(adapter: StorageAdapter, root: Path, tmp_path: Path, link_at: str) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_text("unchanged")
    relative = "link/new" if link_at == "middle" else "link"
    (root / "link").symlink_to(outside if link_at == "middle" else sentinel)
    auth = authorize(adapter, "directory.create", relative)
    result = adapter.directory_create(relative_path=relative, **common(auth))
    assert_error(result, "SYMLINK_DENIED")
    assert sentinel.read_text() == "unchanged"


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"status": "pending"}, "AUTHORIZATION_NOT_APPROVED"),
        ({"status": "revoked"}, "AUTHORIZATION_NOT_APPROVED"),
        ({"claimed_by": "other-adapter"}, "CLAIM_MISMATCH"),
        ({"expires_at": datetime.now(UTC) - timedelta(seconds=1)}, "AUTHORIZATION_EXPIRED"),
        ({"project_id": "another-project"}, "AUTHORIZATION_MISMATCH"),
        ({"root_id": "another-root"}, "AUTHORIZATION_MISMATCH"),
        ({"action": "path.delete"}, "AUTHORIZATION_MISMATCH"),
        ({"relative_path": "other"}, "AUTHORIZATION_MISMATCH"),
    ],
)
def test_authority_must_match_exact_claim(adapter: StorageAdapter, root: Path, changes: dict, code: str) -> None:
    auth = authorize(adapter, "directory.create", "new", **changes)
    result = adapter.directory_create(relative_path="new", **common(auth, project_id="roadex", root_id="work"))
    assert_error(result, code)
    assert not (root / "new").exists()


def test_missing_authorization_fails_closed(adapter: StorageAdapter, root: Path) -> None:
    auth = Authorization("missing", "req", "roadex", "directory.create", "work", "new")
    result = adapter.directory_create(relative_path="new", **common(auth))
    assert_error(result, "AUTHORIZATION_REQUIRED")
    assert not (root / "new").exists()


def test_directory_create_and_identical_retry_are_at_most_once(adapter: StorageAdapter, root: Path) -> None:
    auth = authorize(adapter, "directory.create", "one/two")
    kwargs = common(auth)
    first = adapter.directory_create(relative_path="one/two", parents=True, **kwargs)
    second = adapter.directory_create(relative_path="one/two", parents=True, **kwargs)
    assert first == second
    assert first["result"]["state"] == "succeeded"
    assert first["evidence"]["host_state_changed"] is True
    assert (root / "one/two").is_dir()
    operation = adapter.operation_get("roadex", first["operation_id"])
    assert operation["result"]["transitions"] == ["accepted", "authorized", "executing", "succeeded"]


def test_idempotency_key_rejects_changed_payload(adapter: StorageAdapter, root: Path) -> None:
    first_auth = authorize(adapter, "directory.create", "one")
    assert adapter.directory_create(relative_path="one", **common(first_auth))["ok"]
    second_auth = authorize(adapter, "directory.create", "two", request="req-2", ref="auth-2")
    result = adapter.directory_create(relative_path="two", **common(second_auth))
    assert_error(result, "IDEMPOTENCY_CONFLICT")
    assert not (root / "two").exists()


def test_file_create_replace_stat_and_quota(adapter: StorageAdapter, root: Path) -> None:
    auth = authorize(adapter, "file.write", "note.txt")
    created = adapter.file_write(relative_path="note.txt", content="hello", content_digest=digest("hello"), write_mode="create_only", **common(auth))
    assert created["ok"] and (root / "note.txt").read_text() == "hello"
    stat = adapter.path_stat("roadex", "work", "note.txt", include_digest=True)
    assert stat["result"]["digest"] == digest("hello")

    replacement = authorize(adapter, "file.write", "note.txt", request="req-2", ref="auth-2")
    result = adapter.file_write(relative_path="note.txt", content="world", content_digest=digest("world"), write_mode="replace_exact", expected_prior_digest=digest("hello"), **common(replacement, key="idem-2"))
    assert result["ok"] and (root / "note.txt").read_text() == "world"

    oversized = authorize(adapter, "file.write", "large", request="req-3", ref="auth-3")
    result = adapter.file_write(relative_path="large", content="x" * 17, content_digest=digest("x" * 17), write_mode="create_only", **common(oversized, key="idem-3"))
    assert_error(result, "QUOTA_EXCEEDED")
    assert not (root / "large").exists()


def test_copy_move_and_delete(adapter: StorageAdapter, root: Path) -> None:
    (root / "source").write_text("payload")
    copy_auth = authorize(adapter, "path.copy", "copy", source_root_id="work", source_relative_path="source")
    copied = adapter.path_copy(source_root_id="work", source_relative_path="source", relative_path="copy", **common(copy_auth))
    assert copied["ok"] and (root / "copy").read_text() == "payload"

    move_auth = authorize(adapter, "path.move", "moved", request="req-2", ref="auth-2", source_root_id="work", source_relative_path="copy")
    moved = adapter.path_move(source_relative_path="copy", relative_path="moved", expected_source_type="file", expected_source_digest=digest("payload"), **common(move_auth, key="idem-2"))
    assert moved["ok"] and not (root / "copy").exists() and (root / "moved").exists()

    delete_auth = authorize(adapter, "path.delete", "moved", request="req-3", ref="auth-3")
    deleted = adapter.path_delete(relative_path="moved", expected_type="file", expected_digest=digest("payload"), **common(delete_auth, key="idem-3"))
    assert deleted["ok"] and not (root / "moved").exists()


def test_delete_is_non_recursive(adapter: StorageAdapter, root: Path) -> None:
    directory = root / "full"
    directory.mkdir()
    (directory / "child").write_text("safe")
    auth = authorize(adapter, "path.delete", "full")
    recursive = adapter.path_delete(relative_path="full", expected_type="directory", recursive=True, **common(auth))
    assert_error(recursive, "UNSUPPORTED_ACTION")
    assert (directory / "child").read_text() == "safe"


def test_failure_and_success_evidence_never_leak_host_path_or_content(adapter: StorageAdapter, root: Path) -> None:
    secret = "TOKEN_super_secret_value"
    auth = authorize(adapter, "file.write", "secret.txt")
    result = adapter.file_write(relative_path="secret.txt", content=secret, content_digest=digest(secret), write_mode="create_only", **common(auth))
    operation = adapter.operation_get("roadex", result["operation_id"])
    rendered = repr((result, operation))
    assert str(root) not in rendered
    assert secret not in rendered
    assert result["evidence"]["evidence_ids"]


def test_public_service_api_accepts_fixture_models(root: Path) -> None:
    from underdark.models import Limits, ProjectRegistration, RootRegistration as PublicRoot
    from underdark.service import StorageService

    service = StorageService([
        ProjectRegistration("public-project", [PublicRoot("fixture", root, "safe-alias", limits=Limits(max_content_bytes=8))])
    ])
    result = service.project_get("public-project")
    assert result["ok"] is True
    assert result["result"]["roots"] == [{"root_id": "fixture", "alias": "safe-alias", "status": "active"}]


def test_registration_rejects_non_temporary_and_symlink_roots(tmp_path: Path) -> None:
    service = StorageAdapter()
    with pytest.raises(ValueError):
        service.register_root(RootRegistration("roadex", "work", Path.cwd(), "workspace"))

    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    with pytest.raises(ValueError):
        service.register_root(RootRegistration("roadex", "work", linked, "workspace"))


def test_execution_oserror_reports_unknown_host_state(
    adapter: StorageAdapter, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    auth = authorize(adapter, "directory.create", "partial")

    def partial_failure(_root, relative, _parents):
        (_root.host_path / relative).mkdir()
        raise OSError("simulated post-mutation failure")

    monkeypatch.setattr(adapter, "_mkdir", partial_failure)
    result = adapter.directory_create(relative_path="partial", **common(auth))
    assert result["ok"] is False
    assert result["error"]["code"] == "EXECUTION_FAILED"
    assert result["evidence"]["host_state_changed"] == "unknown"
