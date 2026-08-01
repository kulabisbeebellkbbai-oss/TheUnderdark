"""Durable operation journal for the bounded storage adapter.

Construction requires an explicit path. This module contains no global journal,
service activation, transport, or filesystem mutation implementation.
"""
from __future__ import annotations

import json
import os
import sqlite3
import stat
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Callable, Mapping


class OperationState(StrEnum):
    ACCEPTED = "accepted"
    AUTHORIZED = "authorized"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    INDETERMINATE = "indeterminate"
    CANCELLED = "cancelled"


TERMINAL_STATES = frozenset({OperationState.SUCCEEDED, OperationState.FAILED, OperationState.INDETERMINATE, OperationState.CANCELLED})
TRANSITIONS = {
    OperationState.ACCEPTED: frozenset({OperationState.AUTHORIZED, OperationState.FAILED, OperationState.CANCELLED}),
    OperationState.AUTHORIZED: frozenset({OperationState.EXECUTING, OperationState.FAILED, OperationState.CANCELLED}),
    OperationState.EXECUTING: frozenset({OperationState.SUCCEEDED, OperationState.FAILED, OperationState.INDETERMINATE}),
    OperationState.INDETERMINATE: frozenset({OperationState.SUCCEEDED, OperationState.FAILED, OperationState.INDETERMINATE}),
    OperationState.SUCCEEDED: frozenset(), OperationState.FAILED: frozenset(), OperationState.CANCELLED: frozenset(),
}


@dataclass(frozen=True)
class AuthorizationSnapshot:
    authorization_ref: str
    request_id: str
    project_id: str
    root_id: str
    action: str
    target_digest: str
    policy_revision: str
    claim_id: str
    approval_id: str
    approved_at: str
    expires_at: str
    limits: Mapping[str, int]


@dataclass(frozen=True)
class JournalOperation:
    operation_id: str
    project_id: str
    request_id: str
    idempotency_key: str
    request_digest: str
    authorization_ref: str
    action: str
    state: OperationState
    host_state_changed: bool | str
    created_at: str
    updated_at: str
    result: Mapping[str, object] | None
    error_code: str | None


class JournalConflict(RuntimeError): pass
class JournalTransitionError(RuntimeError): pass


class SQLiteOperationJournal:
    def __init__(self, state_path: str | Path) -> None:
        self.path = Path(state_path)
        if not self.path.is_absolute():
            raise ValueError("journal state path must be absolute")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._identity = self._prepare_file()
        self._connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._initialize()
        self._harden()

    def _prepare_file(self) -> tuple[int, int]:
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"): flags |= os.O_NOFOLLOW
        try:
            fd = os.open(self.path, flags, 0o600)
        except FileExistsError:
            status = self.path.lstat()
            self._validate_file(status)
            os.chmod(self.path, 0o600, follow_symlinks=False)
            return status.st_dev, status.st_ino
        try:
            status = os.fstat(fd); self._validate_file(status); os.fchmod(fd, 0o600)
            return status.st_dev, status.st_ino
        finally: os.close(fd)

    def _validate_file(self, status: os.stat_result) -> None:
        if not stat.S_ISREG(status.st_mode): raise ValueError("journal must be a regular file")
        if hasattr(os, "geteuid") and status.st_uid != os.geteuid(): raise PermissionError("journal must be process-owned")

    def _harden(self) -> None:
        status = self.path.lstat(); self._validate_file(status)
        if (status.st_dev, status.st_ino) != self._identity: raise ValueError("journal identity changed")
        os.chmod(self.path, 0o600, follow_symlinks=False)
        for suffix in ("-wal", "-shm"):
            sidecar = Path(f"{self.path}{suffix}")
            if sidecar.exists():
                side_status = sidecar.lstat(); self._validate_file(side_status); os.chmod(sidecar, 0o600, follow_symlinks=False)

    def _initialize(self) -> None:
        self._connection.executescript("""
        CREATE TABLE IF NOT EXISTS authorizations (
          authorization_ref TEXT PRIMARY KEY, request_id TEXT NOT NULL, project_id TEXT NOT NULL,
          payload TEXT NOT NULL, consumed_by TEXT
        );
        CREATE TABLE IF NOT EXISTS operations (
          operation_id TEXT PRIMARY KEY, project_id TEXT NOT NULL, request_id TEXT NOT NULL,
          idempotency_key TEXT NOT NULL, request_digest TEXT NOT NULL, authorization_ref TEXT NOT NULL,
          action TEXT NOT NULL, state TEXT NOT NULL, host_state_changed TEXT NOT NULL,
          result TEXT, error_code TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
          UNIQUE(project_id, idempotency_key), UNIQUE(request_id)
        );
        CREATE TABLE IF NOT EXISTS transitions (
          sequence INTEGER PRIMARY KEY AUTOINCREMENT, operation_id TEXT NOT NULL, from_state TEXT,
          to_state TEXT NOT NULL, occurred_at TEXT NOT NULL, evidence_id TEXT NOT NULL,
          summary TEXT NOT NULL, UNIQUE(operation_id, evidence_id)
        );
        CREATE TABLE IF NOT EXISTS reconciliation (
          sequence INTEGER PRIMARY KEY AUTOINCREMENT, operation_id TEXT NOT NULL, evidence_id TEXT NOT NULL,
          observed_state TEXT NOT NULL, conclusion TEXT NOT NULL, occurred_at TEXT NOT NULL,
          metadata TEXT NOT NULL, UNIQUE(operation_id, evidence_id)
        );
        """)

    def close(self) -> None:
        self._connection.close(); self._harden()

    def __enter__(self): return self
    def __exit__(self, *args): self.close()

    def store_authorization(self, authorization: AuthorizationSnapshot) -> None:
        payload = _json(authorization.__dict__)
        with self._transaction():
            existing = self._connection.execute("SELECT payload FROM authorizations WHERE authorization_ref = ?", (authorization.authorization_ref,)).fetchone()
            if existing and str(existing["payload"]) != payload: raise JournalConflict("authorization reference is immutable")
            self._connection.execute("INSERT OR IGNORE INTO authorizations (authorization_ref, request_id, project_id, payload) VALUES (?, ?, ?, ?)", (authorization.authorization_ref, authorization.request_id, authorization.project_id, payload))

    def reserve(self, *, project_id: str, request_id: str, idempotency_key: str, request_digest: str, authorization_ref: str, action: str, now: str | None = None) -> tuple[JournalOperation, bool]:
        timestamp = now or _now()
        with self._transaction():
            existing = self._connection.execute("SELECT * FROM operations WHERE project_id = ? AND idempotency_key = ?", (project_id, idempotency_key)).fetchone()
            if existing:
                operation = _operation(existing)
                if operation.request_digest != request_digest or operation.request_id != request_id or operation.authorization_ref != authorization_ref:
                    raise JournalConflict("idempotency key is bound to another canonical request")
                return operation, False
            authorization = self._connection.execute("SELECT payload, consumed_by FROM authorizations WHERE authorization_ref = ?", (authorization_ref,)).fetchone()
            if not authorization: raise JournalConflict("authorization snapshot is missing")
            snapshot = json.loads(str(authorization["payload"]))
            if snapshot["project_id"] != project_id or snapshot["request_id"] != request_id or snapshot["action"] != action: raise JournalConflict("authorization snapshot does not match request")
            if _parse(snapshot["expires_at"]) <= _parse(timestamp): raise JournalConflict("authorization snapshot expired before reservation")
            if authorization["consumed_by"]: raise JournalConflict("authorization snapshot is already consumed")
            operation_id = f"op-{uuid.uuid4().hex}"
            self._connection.execute("INSERT INTO operations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)", (operation_id, project_id, request_id, idempotency_key, request_digest, authorization_ref, action, OperationState.ACCEPTED.value, "false", timestamp, timestamp))
            self._connection.execute("UPDATE authorizations SET consumed_by = ? WHERE authorization_ref = ?", (operation_id, authorization_ref))
            self._append_transition(operation_id, None, OperationState.ACCEPTED, timestamp, "operation intent durably reserved")
            return self.get(operation_id), True

    def transition(self, operation_id: str, state: OperationState, *, host_state_changed: bool | str | None = None, result: Mapping[str, object] | None = None, error_code: str | None = None, summary: str = "state transition", now: str | None = None) -> JournalOperation:
        timestamp = now or _now()
        with self._transaction():
            current = self.get(operation_id)
            if state not in TRANSITIONS[current.state]: raise JournalTransitionError(f"illegal transition {current.state.value} -> {state.value}")
            changed = current.host_state_changed if host_state_changed is None else host_state_changed
            if state == OperationState.SUCCEEDED and changed is not True and not (current.action.startswith("backup.") and changed is False): raise JournalTransitionError("success requires verified host-state evidence")
            if state in {OperationState.ACCEPTED, OperationState.AUTHORIZED, OperationState.CANCELLED} and changed not in {False, "false"}: raise JournalTransitionError("pre-execution state cannot report host mutation")
            self._connection.execute("UPDATE operations SET state=?, host_state_changed=?, result=?, error_code=?, updated_at=? WHERE operation_id=?", (state.value, _changed(changed), _json(result) if result is not None else None, error_code, timestamp, operation_id))
            self._append_transition(operation_id, current.state, state, timestamp, summary)
            return self.get(operation_id)

    def get(self, operation_id: str) -> JournalOperation:
        row = self._connection.execute("SELECT * FROM operations WHERE operation_id = ?", (operation_id,)).fetchone()
        if not row: raise KeyError(operation_id)
        return _operation(row)

    def lookup_idempotency(self, project_id: str, idempotency_key: str) -> JournalOperation | None:
        row = self._connection.execute(
            "SELECT * FROM operations WHERE project_id = ? AND idempotency_key = ?",
            (project_id, idempotency_key),
        ).fetchone()
        return _operation(row) if row else None

    def recover_interrupted(self, now: str | None = None) -> tuple[JournalOperation, ...]:
        timestamp = now or _now(); recovered = []
        with self._transaction():
            rows = self._connection.execute("SELECT operation_id FROM operations WHERE state = ?", (OperationState.EXECUTING.value,)).fetchall()
            for row in rows:
                op_id = str(row["operation_id"])
                self._connection.execute("UPDATE operations SET state=?, host_state_changed=?, error_code=?, updated_at=? WHERE operation_id=?", (OperationState.INDETERMINATE.value, "unknown", "RESULT_INDETERMINATE", timestamp, op_id))
                self._append_transition(op_id, OperationState.EXECUTING, OperationState.INDETERMINATE, timestamp, "restart found operation interrupted after execution began")
                recovered.append(self.get(op_id))
        return tuple(recovered)

    def reconcile(self, operation_id: str, inspect: Callable[[JournalOperation], tuple[OperationState, bool | str, Mapping[str, object]]], *, evidence_id: str, now: str | None = None) -> JournalOperation:
        timestamp = now or _now()
        with self._transaction():
            current = self.get(operation_id)
            if current.state != OperationState.INDETERMINATE: raise JournalTransitionError("only indeterminate operations can be reconciled")
            conclusion, changed, metadata = inspect(current)
            if conclusion not in {OperationState.SUCCEEDED, OperationState.FAILED, OperationState.INDETERMINATE}: raise JournalTransitionError("reconciliation conclusion is invalid")
            self._connection.execute("INSERT INTO reconciliation (operation_id,evidence_id,observed_state,conclusion,occurred_at,metadata) VALUES (?,?,?,?,?,?)", (operation_id, evidence_id, current.state.value, conclusion.value, timestamp, _json(metadata)))
            if conclusion == OperationState.INDETERMINATE: return current
            if conclusion == OperationState.SUCCEEDED and changed is not True:
                raise JournalTransitionError("successful reconciliation requires verified host mutation")
            self._connection.execute(
                "UPDATE operations SET state=?, host_state_changed=?, result=?, error_code=?, updated_at=? WHERE operation_id=?",
                (conclusion.value, _changed(changed), _json(metadata), None if conclusion == OperationState.SUCCEEDED else "EXECUTION_FAILED", timestamp, operation_id),
            )
            self._append_transition(operation_id, current.state, conclusion, timestamp, "reconciliation concluded operation")
            return self.get(operation_id)

    def transitions(self, operation_id: str) -> tuple[Mapping[str, object], ...]:
        rows = self._connection.execute("SELECT * FROM transitions WHERE operation_id=? ORDER BY sequence", (operation_id,)).fetchall()
        return tuple(dict(row) for row in rows)

    def _append_transition(self, operation_id: str, from_state: OperationState | None, to_state: OperationState, timestamp: str, summary: str) -> None:
        evidence_id = f"evidence-{uuid.uuid4().hex}"
        self._connection.execute("INSERT INTO transitions (operation_id,from_state,to_state,occurred_at,evidence_id,summary) VALUES (?,?,?,?,?,?)", (operation_id, from_state.value if from_state else None, to_state.value, timestamp, evidence_id, summary[:512]))

    class _Transaction:
        def __init__(self, owner): self.owner=owner
        def __enter__(self): self.owner._lock.acquire(); self.owner._connection.execute("BEGIN IMMEDIATE")
        def __exit__(self, typ, value, tb): self.owner._connection.execute("ROLLBACK" if typ else "COMMIT"); self.owner._lock.release(); self.owner._harden()
    def _transaction(self): return self._Transaction(self)


def _operation(row: sqlite3.Row) -> JournalOperation:
    changed = {"true": True, "false": False}.get(str(row["host_state_changed"]), "unknown")
    return JournalOperation(str(row["operation_id"]), str(row["project_id"]), str(row["request_id"]), str(row["idempotency_key"]), str(row["request_digest"]), str(row["authorization_ref"]), str(row["action"]), OperationState(str(row["state"])), changed, str(row["created_at"]), str(row["updated_at"]), json.loads(row["result"]) if row["result"] else None, str(row["error_code"]) if row["error_code"] else None)
def _json(value: object) -> str: return json.dumps(value, sort_keys=True, separators=(",", ":"))
def _now() -> str: return datetime.now(UTC).isoformat()
def _parse(value: str) -> datetime: return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
def _changed(value: bool | str) -> str: return "true" if value is True else "false" if value is False else "unknown"
