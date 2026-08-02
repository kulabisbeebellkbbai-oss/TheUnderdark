from __future__ import annotations

import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from theunderdark.root_registry import ControlPlaneApproval, RegistryFailure, SQLiteRootRegistry


class Approver:
    def __init__(self): self.override = {}; self.payloads = []
    def verify(self, action, payload, target_digest):
        self.payloads.append(dict(payload))
        approval = ControlPlaneApproval(
            "approval-1", action, str(payload["project_id"]), str(payload["root_id"]),
            str(payload["policy_revision"]), target_digest, "approved",
            (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
        )
        return replace(approval, **self.override)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    path = tmp_path / "registered"; path.mkdir(); return path


@pytest.fixture
def registry(tmp_path: Path):
    value = SQLiteRootRegistry((tmp_path / "state" / "roots.sqlite3").resolve(), verifier=Approver())
    yield value
    value.close()


def register(registry, root, **changes):
    values = dict(project_id="roadex", root_id="work", policy_revision="1", host_path=root, alias="workspace", max_bytes=32)
    values.update(changes); registry.register(**values)


def assert_failure(code, action):
    with pytest.raises(RegistryFailure) as raised: action()
    assert raised.value.code == code


def test_registration_is_durable_redacted_and_owner_only(registry, root: Path) -> None:
    register(registry, root)
    rows = registry.project_roots("roadex")
    assert rows == ({"project_id":"roadex","root_id":"work","policy_revision":"1","alias":"workspace","status":"active","max_bytes":32},)
    assert str(root) not in repr(rows)
    assert registry.path.stat().st_mode & 0o777 == 0o600
    resolved = registry.resolve("roadex", "work", "1")
    assert resolved.root == root.resolve() and resolved.alias == "workspace" and resolved.max_bytes == 32
    assert resolved.policy_revision == "1"
    assert registry.resolve_current("roadex", "work") == resolved
    assert registry.root_ids("roadex") == ("work",)


def test_exact_approval_is_required_before_write(tmp_path: Path, root: Path) -> None:
    approver = Approver(); approver.override = {"status":"pending"}
    with SQLiteRootRegistry((tmp_path/"roots.sqlite3").resolve(), verifier=approver) as registry:
        assert_failure("APPROVAL_MISMATCH", lambda: register(registry, root))
        assert registry.project_roots("roadex") == ()


def test_exact_registration_retry_revalidates_approval_without_write(tmp_path: Path, root: Path) -> None:
    approver=Approver()
    with SQLiteRootRegistry((tmp_path/"roots.sqlite3").resolve(),verifier=approver) as registry:
        register(registry,root)
        before=registry._connection.execute("SELECT * FROM root_revisions").fetchall()
        changes=registry._connection.total_changes
        register(registry,root)
        after=registry._connection.execute("SELECT * FROM root_revisions").fetchall()
        assert len(approver.payloads)==2
        assert after==before and registry._connection.total_changes==changes


@pytest.mark.parametrize("changes",[
    {"policy_revision":"2"},
    {"alias":"another"},
    {"max_bytes":64},
])
def test_conflicting_registration_retry_revalidates_then_rejects_without_write(tmp_path: Path, root: Path, changes) -> None:
    approver=Approver()
    with SQLiteRootRegistry((tmp_path/"roots.sqlite3").resolve(),verifier=approver) as registry:
        register(registry,root)
        before=registry._connection.execute("SELECT * FROM root_revisions").fetchall()
        total=registry._connection.total_changes
        assert_failure("ROOT_EXISTS",lambda:register(registry,root,**changes))
        assert len(approver.payloads)==2
        assert registry._connection.execute("SELECT * FROM root_revisions").fetchall()==before
        assert registry._connection.total_changes==total


def test_registration_retry_rejects_replaced_root_identity_after_reapproval(tmp_path: Path, root: Path) -> None:
    approver=Approver()
    with SQLiteRootRegistry((tmp_path/"roots.sqlite3").resolve(),verifier=approver) as registry:
        register(registry,root)
        before=registry._connection.execute("SELECT * FROM root_revisions").fetchall(); total=registry._connection.total_changes
        moved=root.with_name("original"); root.rename(moved); root.mkdir()
        assert_failure("ROOT_EXISTS",lambda:register(registry,root))
        assert len(approver.payloads)==2
        assert registry._connection.execute("SELECT * FROM root_revisions").fetchall()==before
        assert registry._connection.total_changes==total


def test_approval_payload_never_contains_host_path(tmp_path: Path, root: Path) -> None:
    approver = Approver()
    with SQLiteRootRegistry((tmp_path/"roots.sqlite3").resolve(), verifier=approver) as registry:
        register(registry, root)
    assert approver.payloads and "host_path" not in approver.payloads[0]
    assert str(root) not in repr(approver.payloads)
    assert str(approver.payloads[0]["root_identity"]).startswith("sha256:")


def test_revisions_are_append_only_and_exact(tmp_path: Path, root: Path) -> None:
    with SQLiteRootRegistry((tmp_path/"roots.sqlite3").resolve(), verifier=Approver()) as registry:
        register(registry, root)
        registry.transition(project_id="roadex",root_id="work",current_revision="1",policy_revision="2",status="suspended",max_bytes=16)
        assert_failure("ROOT_INACTIVE", lambda: registry.resolve("roadex","work","2"))
        assert_failure("POLICY_REVISION_MISMATCH", lambda: registry.resolve("roadex","work","1"))
        count=registry._connection.execute("SELECT count(*) FROM root_revisions").fetchone()[0]
        assert count == 2
        registry.transition(project_id="roadex",root_id="work",current_revision="2",policy_revision="3",status="active")
        assert registry.resolve("roadex","work","3").max_bytes == 16
        assert registry.resolve("roadex","work","3").policy_revision == "3"


def test_rejects_symlink_file_and_protected_roots(tmp_path: Path, root: Path) -> None:
    state=(tmp_path/"state"/"roots.sqlite3").resolve(); protected=tmp_path/"protected"; protected.mkdir()
    with SQLiteRootRegistry(state,verifier=Approver(),protected_paths=[protected]) as registry:
        link=tmp_path/"link"; link.symlink_to(root,target_is_directory=True)
        plain=tmp_path/"plain"; plain.write_text("x")
        assert_failure("ROOT_INVALID",lambda: register(registry,link))
        assert_failure("ROOT_INVALID",lambda: register(registry,plain))
        assert_failure("PROTECTED_PATH",lambda: register(registry,protected))
        assert_failure("PROTECTED_PATH",lambda: register(registry,Path.home(),root_id="home"))
        source_root = Path(__file__).resolve().parents[1]
        assert_failure("PROTECTED_PATH",lambda: register(registry,source_root,root_id="underdark"))


def test_dedicated_operator_approved_home_subdirectory_can_be_registered(tmp_path: Path) -> None:
    dedicated = tmp_path / "roadex-storage"; dedicated.mkdir()
    with SQLiteRootRegistry((tmp_path/"state"/"roots.sqlite3").resolve(), verifier=Approver()) as registry:
        register(registry, dedicated)
        assert registry.resolve("roadex", "work", "1").root == dedicated.resolve()


def test_rejects_overlapping_roots(tmp_path: Path, registry) -> None:
    parent=tmp_path/"parent"; child=parent/"child"; child.mkdir(parents=True)
    register(registry,parent)
    assert_failure("ROOT_OVERLAP",lambda: register(registry,child,root_id="child"))


def test_rejects_registry_symlink(tmp_path: Path) -> None:
    target=tmp_path/"target"; target.write_text("")
    link=tmp_path/"registry.sqlite3"; link.symlink_to(target)
    with pytest.raises(ValueError): SQLiteRootRegistry(link,verifier=Approver())


def test_identity_change_blocks_resolver(registry, root: Path) -> None:
    register(registry,root)
    moved=root.with_name("moved"); root.rename(moved); root.mkdir()
    assert_failure("ROOT_IDENTITY_CHANGED",lambda: registry.resolve("roadex","work","1"))


@pytest.mark.parametrize("field,value", [("alias","../escape"),("alias","bad/name"),("alias","bad\nname"),("project_id","bad/path"),("root_id","bad:root"),("policy_revision","bad revision")])
def test_identifiers_and_aliases_reject_controls_and_path_values(registry, root: Path, field: str, value: str) -> None:
    assert_failure("INVALID_ARGUMENT", lambda: register(registry, root, **{field:value}))


def test_malformed_approval_record_fails_closed(tmp_path: Path, root: Path) -> None:
    class Malformed:
        def verify(self, *_): return object()
    with SQLiteRootRegistry((tmp_path/"roots.sqlite3").resolve(), verifier=Malformed()) as registry:
        assert_failure("APPROVAL_MISMATCH", lambda: register(registry, root))
