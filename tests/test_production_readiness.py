"""Cross-component proofs for production readiness without service activation."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from theunderdark.admission import AdmissionDenied, AdmissionLimits, SQLiteAdmissionController
from theunderdark.fscontain import ContainmentError, RootHandle
from theunderdark.journal import AuthorizationSnapshot, OperationState, SQLiteOperationJournal
from theunderdark.mutation_executor import ExecutorFailure, FsContainMutationExecutor
from theunderdark.pagination import CursorInvalid, SQLiteSnapshotPaginator
from theunderdark.production import ProductionStorageService, _request_digest
from theunderdark.production_app import create_production_http_app, create_production_mcp


class ExactVerifier:
    def __init__(self) -> None:
        self.calls = 0

    def verify(self, action, request, request_digest):
        self.calls += 1
        now = datetime.now(UTC)
        return AuthorizationSnapshot(
            str(request["authorization_ref"]), str(request["request_id"]),
            str(request["project_id"]), str(request["root_id"]), action,
            request_digest, str(request["policy_revision"]), "claim", "approval",
            now.isoformat(), (now + timedelta(minutes=5)).isoformat(), {"max_bytes": 32},
        )


class VerifiedExecutor:
    def __init__(self) -> None:
        self.calls = 0

    def execute(self, action, request):
        self.calls += 1
        return {"verified": True, "host_state_changed": True, "bytes": 0, "path": "safe:result"}


def mutation_request(**changes) -> dict[str, object]:
    request: dict[str, object] = {
        "project_id": "roadex", "root_id": "work", "request_id": "req-1",
        "idempotency_key": "idem-1", "authorization_ref": "auth-1",
        "policy_revision": "1", "reason": "readiness proof",
        "relative_path": "result", "parents": False,
    }
    request.update(changes)
    return request


def test_durable_restart_idempotency_and_reconciliation(tmp_path: Path) -> None:
    state = (tmp_path / "journal.sqlite3").resolve()
    verifier, executor = ExactVerifier(), VerifiedExecutor()
    request = mutation_request()
    with SQLiteOperationJournal(state) as journal:
        first = ProductionStorageService(journal=journal, verifier=verifier, executor=executor).directory_create(**request)
        assert first["ok"] and verifier.calls == executor.calls == 1
    with SQLiteOperationJournal(state) as journal:
        retry = ProductionStorageService(journal=journal, verifier=verifier, executor=executor).directory_create(**request)
        assert retry == first and verifier.calls == executor.calls == 1

    interrupted_state = (tmp_path / "interrupted.sqlite3").resolve()
    with SQLiteOperationJournal(interrupted_state) as journal:
        request_digest = _request_digest("directory.create", request)
        journal.store_authorization(verifier.verify("directory.create", request, request_digest))
        operation, _ = journal.reserve(
            project_id="roadex", request_id="req-1", idempotency_key="idem-1",
            request_digest=request_digest, authorization_ref="auth-1", action="directory.create",
        )
        journal.transition(operation.operation_id, OperationState.AUTHORIZED)
        journal.transition(operation.operation_id, OperationState.EXECUTING)
    with SQLiteOperationJournal(interrupted_state) as journal:
        service = ProductionStorageService(journal=journal, verifier=verifier, executor=executor)
        assert service.recovered_operations[0].state is OperationState.INDETERMINATE
        recovered = service.directory_create(**request)
        assert recovered["error"]["code"] == "RESULT_INDETERMINATE"
        reconciled = service.reconcile(
            "roadex", operation.operation_id,
            lambda _: (OperationState.SUCCEEDED, True, {"digest": "sha256:verified"}),
            evidence_id="evidence-reconcile",
        )
        assert reconciled["ok"] and reconciled["result"]["state"] == "succeeded"


def test_descriptor_relative_containment_denies_symlink_swap(tmp_path: Path) -> None:
    root_path = tmp_path / "root"
    outside = tmp_path / "outside"
    root_path.mkdir(); outside.mkdir()
    (outside / "sentinel").write_text("unchanged")
    (root_path / "escape").symlink_to(outside, target_is_directory=True)
    with RootHandle.open(root_path) as root:
        with pytest.raises(ContainmentError) as denied:
            root.open_regular("escape/sentinel")
    assert denied.value.code == "CONTAINMENT_DENIED"
    assert (outside / "sentinel").read_text() == "unchanged"


def test_durable_quota_concurrency_and_rate_limits(tmp_path: Path) -> None:
    limits = AdmissionLimits(
        max_storage_bytes=10, max_concurrent_operations=1,
        max_requests_per_window=2, rate_window_seconds=60, lease_seconds=1,
    )
    now = datetime.now(UTC)
    state = (tmp_path / "admission.sqlite3").resolve()
    with SQLiteAdmissionController(state) as admission:
        admission.set_committed_usage("roadex", 4)
        held = admission.reserve("roadex", "op-1", 5, limits, now=now)
        with pytest.raises(AdmissionDenied) as concurrent:
            admission.reserve("roadex", "op-2", 1, limits, now=now)
        assert concurrent.value.code == "RATE_LIMITED"
        admission.commit(held.reservation_id, 5)
    with SQLiteAdmissionController(state) as admission:
        with pytest.raises(AdmissionDenied) as quota:
            admission.reserve("roadex", "op-2", 2, limits, now=now)
        assert quota.value.code == "QUOTA_EXCEEDED"

    rate_state = (tmp_path / "rate.sqlite3").resolve()
    rate_limits = AdmissionLimits(100, 2, 1, 60, 1)
    with SQLiteAdmissionController(rate_state) as admission:
        admission.reserve("roadex", "one", 0, rate_limits, now=now)
        with pytest.raises(AdmissionDenied) as rate:
            admission.reserve("roadex", "two", 0, rate_limits, now=now + timedelta(seconds=2))
        assert rate.value.code == "RATE_LIMITED"


def test_snapshot_pagination_is_stable_and_context_bound(tmp_path: Path) -> None:
    with SQLiteSnapshotPaginator(
        (tmp_path / "pages.sqlite3").resolve(), cursor_key=b"p" * 32, max_page_size=2,
    ) as paginator:
        entries = [{"name": name, "type": "file", "size": 1} for name in ("b", "c", "d")]
        first = paginator.first_page(
            project_id="roadex", root_id="work", relative_path="dir", policy_revision="1",
            namespace_identity="inode:1", entries=entries, limit=2,
        )
        # Caller namespace changes cannot alter the durable snapshot.
        entries.insert(0, {"name": "a", "type": "file", "size": 1})
        second = paginator.next_page(
            first.next_cursor, project_id="roadex", root_id="work", relative_path="dir",
            policy_revision="1", namespace_identity="inode:1", limit=2,
        )
        assert [item["name"] for item in first.entries + second.entries] == ["b", "c", "d"]
        with pytest.raises(CursorInvalid):
            paginator.next_page(
                first.next_cursor, project_id="roadex", root_id="other", relative_path="dir",
                policy_revision="1", namespace_identity="inode:1", limit=2,
            )


def test_strict_transport_and_minimal_http_health(tmp_path: Path) -> None:
    journal = SQLiteOperationJournal((tmp_path / "transport.sqlite3").resolve())
    service = ProductionStorageService(journal=journal, verifier=ExactVerifier(), executor=VerifiedExecutor())
    mcp = create_production_mcp(service)

    async def exercise():
        async with create_connected_server_and_client_session(mcp) as client:
            invalid = await client.call_tool("underdark_health_get", {"unexpected": True})
        app = create_production_http_app(service)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            health = await client.get("/health")
            method = await client.post("/health")
        return invalid, health, method, app

    invalid, health, method, app = asyncio.run(exercise())
    assert invalid.isError is True
    assert health.status_code == 200 and method.status_code == 405
    assert set(health.json()) == {"status", "contract_version", "dependencies"}
    assert "transport.sqlite3" not in health.text
    assert any(getattr(route, "path", None) == "/mcp" for route in app.routes)
    journal.close()


def test_activation_requires_authoritative_verifier_and_registered_root_composition(tmp_path: Path) -> None:
    journal = SQLiteOperationJournal((tmp_path / "activation.sqlite3").resolve())
    with pytest.raises(TypeError):
        ProductionStorageService(journal=journal, verifier=None, executor=VerifiedExecutor())

    executor = FsContainMutationExecutor(lambda _project, _root: (_ for _ in ()).throw(KeyError("unregistered")))
    with pytest.raises(ExecutorFailure) as denied:
        executor.execute("directory.create", {"project_id": "roadex", "root_id": "work", "relative_path": "new", "parents": False})
    assert denied.value.code == "ROOT_UNAVAILABLE"
    assert not (tmp_path / "new").exists()
    journal.close()
