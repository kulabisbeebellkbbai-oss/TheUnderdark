from datetime import UTC, datetime, timedelta

from theunderdark.admission import AdmissionLimits, SQLiteAdmissionController
from theunderdark.composition import compose_production_runtime
from theunderdark.journal import AuthorizationSnapshot, SQLiteOperationJournal
from theunderdark.pagination import SQLiteSnapshotPaginator
from theunderdark.root_registry import ControlPlaneApproval, SQLiteRootRegistry
from theunderdark.runtime_identity import RuntimeIdentity


IDENTITY = RuntimeIdentity("sha256:" + "a" * 64, "sha256:" + "b" * 64, "sha256:" + "c" * 64)


class RegistrationApprover:
    def verify(self, action, payload, target_digest):
        return ControlPlaneApproval(
            "approval-root", action, payload["project_id"], payload["root_id"],
            payload["policy_revision"], target_digest, "approved",
            (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
        )


class OperationVerifier:
    def verify(self, action, request, request_digest):
        now = datetime.now(UTC)
        return AuthorizationSnapshot(
            request["authorization_ref"], request["request_id"], request["project_id"],
            request["root_id"], action, request_digest, request["policy_revision"],
            "claim", "approval-operation", now.isoformat(),
            (now + timedelta(minutes=5)).isoformat(), {"max_bytes": 32},
        )


def test_explicit_composition_executes_only_registered_exact_revision(tmp_path):
    root = tmp_path / "storage"; root.mkdir()
    with (
        SQLiteRootRegistry((tmp_path / "roots.sqlite3").resolve(), verifier=RegistrationApprover()) as registry,
        SQLiteOperationJournal((tmp_path / "journal.sqlite3").resolve()) as journal,
        SQLiteAdmissionController((tmp_path / "admission.sqlite3").resolve()) as admission,
        SQLiteSnapshotPaginator((tmp_path / "pages.sqlite3").resolve(), cursor_key=b"c" * 32) as paginator,
    ):
        registry.register(project_id="roadex", root_id="work", policy_revision="1", host_path=root, alias="workspace", max_bytes=32)
        runtime = compose_production_runtime(
            registry=registry, journal=journal, admission=admission, paginator=paginator,
                verifier=OperationVerifier(), limits_provider=lambda _project: AdmissionLimits(32, 1, 10, 60),
                max_content_bytes=32, max_concurrent_per_project=1,
                runtime_identity=IDENTITY,
            )
        result = runtime.service.directory_create(
            project_id="roadex", root_id="work", request_id="request-1",
            idempotency_key="idempotency-1", authorization_ref="authorization-1",
            policy_revision="1", reason="bounded composition test",
            relative_path="created", parents=False,
        )
        assert result["ok"] is True and (root / "created").is_dir()
        mismatch = runtime.service.directory_create(
            project_id="roadex", root_id="work", request_id="request-2",
            idempotency_key="idempotency-2", authorization_ref="authorization-2",
            policy_revision="2", reason="wrong revision",
            relative_path="denied", parents=False,
        )
        assert mismatch["ok"] is False and not (root / "denied").exists()
