from datetime import UTC, datetime, timedelta

import pytest

from theunderdark.journal import AuthorizationSnapshot, JournalConflict, JournalTransitionError, OperationState, SQLiteOperationJournal


def authorization(now):
    return AuthorizationSnapshot("auth-1", "req-1", "project", "root", "file.write", "sha256:target", "1", "claim-1", "approval-1", now.isoformat(), (now + timedelta(minutes=5)).isoformat(), {"max_bytes": 10})


def test_reservation_is_durable_and_idempotent_across_restart(tmp_path):
    path = (tmp_path / "journal.sqlite3").resolve(); now = datetime.now(UTC)
    with SQLiteOperationJournal(path) as journal:
        journal.store_authorization(authorization(now))
        first, created = journal.reserve(project_id="project", request_id="req-1", idempotency_key="idem", request_digest="sha256:req", authorization_ref="auth-1", action="file.write")
        assert created
    with SQLiteOperationJournal(path) as journal:
        second, created = journal.reserve(project_id="project", request_id="req-1", idempotency_key="idem", request_digest="sha256:req", authorization_ref="auth-1", action="file.write")
        assert not created and second.operation_id == first.operation_id
        with pytest.raises(JournalConflict): journal.reserve(project_id="project", request_id="req-1", idempotency_key="idem", request_digest="sha256:changed", authorization_ref="auth-1", action="file.write")


def test_restart_marks_executing_indeterminate_then_reconciles(tmp_path):
    path=(tmp_path/"journal.sqlite3").resolve(); now=datetime.now(UTC)
    with SQLiteOperationJournal(path) as journal:
        journal.store_authorization(authorization(now)); op,_=journal.reserve(project_id="project",request_id="req-1",idempotency_key="idem",request_digest="sha256:req",authorization_ref="auth-1",action="file.write")
        journal.transition(op.operation_id, OperationState.AUTHORIZED); journal.transition(op.operation_id, OperationState.EXECUTING)
    with SQLiteOperationJournal(path) as journal:
        recovered=journal.recover_interrupted(); assert recovered[0].state == OperationState.INDETERMINATE and recovered[0].host_state_changed == "unknown"
        final=journal.reconcile(op.operation_id, lambda _: (OperationState.SUCCEEDED, True, {"digest":"sha256:verified"}), evidence_id="reconcile-1")
        assert final.state == OperationState.SUCCEEDED and len(journal.transitions(op.operation_id)) == 5


def test_illegal_success_before_execution_is_rejected(tmp_path):
    now=datetime.now(UTC)
    with SQLiteOperationJournal((tmp_path/"journal.sqlite3").resolve()) as journal:
        journal.store_authorization(authorization(now)); op,_=journal.reserve(project_id="project",request_id="req-1",idempotency_key="idem",request_digest="sha256:req",authorization_ref="auth-1",action="file.write")
        with pytest.raises(JournalTransitionError): journal.transition(op.operation_id, OperationState.SUCCEEDED, host_state_changed=True)
