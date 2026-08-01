"""Journal-backed production orchestration without a filesystem executor.

The service has no defaults for authority or execution. Callers must inject an
authoritative verifier and a bounded executor (eventually backed by fscontain).
This module itself cannot activate a service or choose a host path.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Callable, Mapping, Protocol

from .journal import (
    AuthorizationSnapshot,
    JournalConflict,
    JournalOperation,
    OperationState,
    SQLiteOperationJournal,
)
from .admission import AdmissionDenied, AdmissionLimits, SQLiteAdmissionController
from .pagination import CursorInvalid, SQLiteSnapshotPaginator

CONTRACT_VERSION = "1.0"
COMMON_FIELDS = frozenset({"project_id", "root_id", "request_id", "idempotency_key", "authorization_ref", "policy_revision", "reason"})
ACTION_FIELDS = {
    "directory.create": frozenset({"relative_path", "parents"}),
    "file.write": frozenset({"relative_path", "content", "content_digest", "write_mode", "content_encoding", "expected_prior_digest"}),
    "path.copy": frozenset({"source_root_id", "source_relative_path", "relative_path", "destination_mode"}),
    "path.move": frozenset({"source_relative_path", "relative_path", "expected_source_digest", "expected_source_type", "destination_mode"}),
    "path.delete": frozenset({"relative_path", "expected_type", "expected_digest", "recursive"}),
    "backup.create": frozenset({"source_root_id", "retention_count", "encryption_profile"}),
    "backup.verify_restore": frozenset({"artifact_id", "expected_manifest_digest", "expected_artifact_digest"}),
}


class AuthorizationVerifier(Protocol):
    def verify(self, action: str, request: Mapping[str, object], request_digest: str) -> AuthorizationSnapshot: ...


class BoundedMutationExecutor(Protocol):
    """Execution boundary expected to use RootHandle/fscontain primitives."""
    def execute(self, action: str, request: Mapping[str, object]) -> Mapping[str, object]: ...

class BackupExecutor(Protocol):
    def execute(self) -> Mapping[str, object]: ...
    def verify_restore(self, *, artifact_id: str, expected_manifest_digest: str, expected_artifact_digest: str) -> Mapping[str, object]: ...


class ReadBackend(Protocol):
    def project_get(self, project_id: str) -> Mapping[str, object]: ...
    def root_get(self, project_id: str, root_id: str) -> Mapping[str, object]: ...
    def path_stat(self, project_id: str, root_id: str, relative_path: str, include_digest: bool = False) -> Mapping[str, object]: ...
    def directory_snapshot(self, project_id: str, root_id: str, relative_path: str) -> tuple[str, tuple[Mapping[str, object], ...]]: ...


class ProductionStorageService:
    def __init__(self, *, journal: SQLiteOperationJournal, verifier: AuthorizationVerifier, executor: BoundedMutationExecutor, admission: SQLiteAdmissionController | None = None, admission_limits: Callable[[str], AdmissionLimits] | None = None, read_backend: ReadBackend | None = None, paginator: SQLiteSnapshotPaginator | None = None, backup_executor_provider: Callable[[str,str,str],BackupExecutor] | None = None) -> None:
        if journal is None or verifier is None or executor is None:
            raise TypeError("journal, verifier, and bounded executor are required")
        self.journal, self.verifier, self.executor = journal, verifier, executor
        self.admission, self.admission_limits = admission, admission_limits
        self.read_backend, self.paginator = read_backend, paginator
        self.backup_executor_provider = backup_executor_provider
        self.recovered_operations = journal.recover_interrupted()

    def directory_create(self, **request: object) -> dict[str, Any]: return self._submit("directory.create", request)
    def file_write(self, **request: object) -> dict[str, Any]: return self._submit("file.write", request)
    def path_copy(self, **request: object) -> dict[str, Any]: return self._submit("path.copy", request)
    def path_move(self, **request: object) -> dict[str, Any]: return self._submit("path.move", request)
    def path_delete(self, **request: object) -> dict[str, Any]: return self._submit("path.delete", request)
    def backup_create(self, **request: object) -> dict[str, Any]: return self._submit("backup.create", request)
    def backup_verify_restore(self, **request: object) -> dict[str, Any]: return self._submit("backup.verify_restore", request)

    def project_get(self, project_id: str, request_id: str = "read") -> dict[str, Any]:
        return self._read(request_id, lambda: self.read_backend.project_get(project_id) if self.read_backend else _missing_read())

    def root_get(self, project_id: str, root_id: str, request_id: str = "read") -> dict[str, Any]:
        return self._read(request_id, lambda: self.read_backend.root_get(project_id, root_id) if self.read_backend else _missing_read())

    def path_stat(self, project_id: str, root_id: str, relative_path: str, include_digest: bool = False, request_id: str = "read") -> dict[str, Any]:
        return self._read(request_id, lambda: self.read_backend.path_stat(project_id, root_id, relative_path, include_digest) if self.read_backend else _missing_read())

    def directory_list(self, project_id: str, root_id: str, relative_path: str, policy_revision: str = "", cursor: str | None = None, limit: int = 100, request_id: str = "read") -> dict[str, Any]:
        try:
            if not self.read_backend or not self.paginator: raise ProductionFailure("DEPENDENCY_UNAVAILABLE", "The bounded read dependencies are unavailable.")
            if not policy_revision:
                root = self.read_backend.root_get(project_id, root_id)
                policy_revision = str(root.get("policy_revision") or "")
                if not policy_revision: raise ProductionFailure("DEPENDENCY_UNAVAILABLE", "The root policy revision is unavailable.")
            if cursor is None:
                identity, entries = self.read_backend.directory_snapshot(project_id, root_id, relative_path)
                page = self.paginator.first_page(project_id=project_id, root_id=root_id, relative_path=relative_path, policy_revision=policy_revision, namespace_identity=identity, entries=entries, limit=limit)
            else:
                identity, _ = self.read_backend.directory_snapshot(project_id, root_id, relative_path)
                page = self.paginator.next_page(cursor, project_id=project_id, root_id=root_id, relative_path=relative_path, policy_revision=policy_revision, namespace_identity=identity, limit=limit)
            return self._read_success(request_id, {"entries": list(page.entries), "next_cursor": page.next_cursor})
        except CursorInvalid:
            return self._failure(request_id, "INVALID_ARGUMENT", "The cursor is invalid for the current namespace.")
        except ProductionFailure as error: return self._failure(request_id, error.code, error.message)
        except Exception: return self._failure(request_id, "DEPENDENCY_UNAVAILABLE", "The bounded read backend is unavailable.")

    def operation_get(self, project_id: str, operation_id: str, request_id: str = "read") -> dict[str, Any]:
        try:
            operation = self.journal.get(operation_id)
            if operation.project_id != project_id:
                raise KeyError(operation_id)
            return self._envelope(operation)
        except KeyError:
            return self._failure(request_id, "SOURCE_NOT_FOUND", "The operation was not found.")

    def reconcile(
        self,
        project_id: str,
        operation_id: str,
        inspect: Callable[[JournalOperation], tuple[OperationState, bool | str, Mapping[str, object]]],
        *,
        evidence_id: str,
    ) -> dict[str, Any]:
        operation = self.journal.get(operation_id)
        if operation.project_id != project_id:
            return self._failure(operation.request_id, "SOURCE_NOT_FOUND", "The operation was not found.")
        reconciled = self.journal.reconcile(operation_id, inspect, evidence_id=evidence_id)
        if self.admission is not None:
            reservation = self.admission.lookup_operation(operation.request_id)
            if reservation is not None:
                if reconciled.state == OperationState.SUCCEEDED:
                    actual = min(reservation.growth_bytes, max(0, int((reconciled.result or {}).get("bytes", reservation.growth_bytes))))
                    self.admission.commit(reservation.reservation_id, actual)
                elif reconciled.state == OperationState.FAILED:
                    self.admission.release(reservation.reservation_id)
        return self._envelope(reconciled)

    def _submit(self, action: str, request: Mapping[str, object]) -> dict[str, Any]:
        request_id = str(request.get("request_id", ""))
        reservation = None
        try:
            self._validate(action, request)
            digest = _request_digest(action, request)
            project_id, key = str(request["project_id"]), str(request["idempotency_key"])
            prior = self.journal.lookup_idempotency(project_id, key)
            if prior is not None:
                if prior.request_digest != digest or prior.request_id != request_id or prior.authorization_ref != request["authorization_ref"]:
                    raise ProductionFailure("IDEMPOTENCY_CONFLICT", "The idempotency key is bound to another request.")
                return self._envelope(prior)
            try:
                authorization = self.verifier.verify(action, request, digest)
                self._validate_authorization(authorization, action, request, digest)
            except ProductionFailure:
                raise
            except Exception:
                return self._failure(
                    request_id,
                    "DEPENDENCY_UNAVAILABLE",
                    "The authoritative approval verifier is unavailable.",
                )
            self.journal.store_authorization(authorization)
            if self.admission is not None:
                if self.admission_limits is None: raise ProductionFailure("DEPENDENCY_UNAVAILABLE", "Admission limits are not configured.")
                reservation = self.admission.reserve(project_id, request_id, self._growth(action, request, authorization), self.admission_limits(project_id))
            operation, _ = self.journal.reserve(
                project_id=project_id, request_id=request_id, idempotency_key=key,
                request_digest=digest, authorization_ref=str(request["authorization_ref"]), action=action,
            )
            operation = self.journal.transition(operation.operation_id, OperationState.AUTHORIZED, summary="authoritative approval snapshot verified")
            operation = self.journal.transition(operation.operation_id, OperationState.EXECUTING, summary="bounded executor entered")
            try:
                if action.startswith("backup."):
                    if self.backup_executor_provider is None: raise ProductionFailure("DEPENDENCY_UNAVAILABLE","The bounded backup provider is unavailable.")
                    backup=self.backup_executor_provider(project_id,str(request["root_id"]),str(request["policy_revision"]))
                    if action=="backup.create":
                        outcome=dict(backup.execute()); result=dict(outcome.get("result",{})); result["manifest_digest"]="sha256:"+str(result["manifest_digest"]); result["artifact_digest"]="sha256:"+str(result["artifact_digest"]); result.update({"verified":True,"host_state_changed":bool(outcome.get("evidence",{}).get("host_state_changed"))})
                    else:
                        result=dict(backup.verify_restore(artifact_id=str(request["artifact_id"]),expected_manifest_digest=str(request["expected_manifest_digest"]),expected_artifact_digest=str(request["expected_artifact_digest"])))
                else: result = dict(self.executor.execute(action, request))
            except Exception:
                # Executor exceptions are deliberately minimized; once entered,
                # the service cannot prove whether host state changed.
                operation = self.journal.transition(operation.operation_id, OperationState.INDETERMINATE, host_state_changed="unknown", error_code="RESULT_INDETERMINATE", summary="executor outcome could not be verified")
                if reservation: self.admission.hold_for_recovery(reservation.reservation_id)
                return self._envelope(operation)
            verified = result.pop("verified", None)
            changed = result.pop("host_state_changed", None)
            valid_changed = isinstance(changed,bool) and (action.startswith("backup.") or changed is True)
            if verified is not True or not valid_changed:
                operation = self.journal.transition(operation.operation_id, OperationState.INDETERMINATE, host_state_changed="unknown", result=result, error_code="VERIFY_FAILED", summary="executor postcondition evidence was incomplete")
                if reservation: self.admission.hold_for_recovery(reservation.reservation_id)
            else:
                operation = self.journal.transition(operation.operation_id, OperationState.SUCCEEDED, host_state_changed=changed, result=result, summary="postconditions verified")
                if reservation: self.admission.commit(reservation.reservation_id, min(reservation.growth_bytes, max(0, int(result.get("bytes", 0)))))
            return self._envelope(operation)
        except ProductionFailure as error:
            return self._failure(request_id, error.code, error.message)
        except JournalConflict as error:
            if reservation and self.admission: self.admission.release(reservation.reservation_id)
            code = "IDEMPOTENCY_CONFLICT" if "idempotency" in str(error) else "AUTHORIZATION_MISMATCH"
            return self._failure(request_id, code, "The durable request reservation was rejected.")
        except AdmissionDenied as error:
            return self._failure(request_id, error.code, "The bounded project admission limit rejected the operation.")

    @staticmethod
    def _validate(action: str, request: Mapping[str, object]) -> None:
        allowed = COMMON_FIELDS | ACTION_FIELDS.get(action, frozenset())
        if action not in ACTION_FIELDS: raise ProductionFailure("UNSUPPORTED_ACTION", "The action is unsupported.")
        if set(request) - allowed: raise ProductionFailure("INVALID_ARGUMENT", "Unknown request fields are not allowed.")
        if not COMMON_FIELDS <= set(request): raise ProductionFailure("INVALID_ARGUMENT", "Required mutation fields are missing.")
        for name in ("project_id", "root_id", "request_id", "idempotency_key", "authorization_ref", "policy_revision", "reason"):
            value = request[name]
            if not isinstance(value, str) or not value or len(value) > (512 if name == "reason" else 128):
                raise ProductionFailure("INVALID_ARGUMENT", f"{name} is invalid.")
        if action not in {"backup.create","backup.verify_restore"} and "relative_path" not in request: raise ProductionFailure("INVALID_ARGUMENT", "relative_path is required.")
        required=ACTION_FIELDS[action] if action.startswith("backup.") else frozenset()
        if not required <= set(request): raise ProductionFailure("INVALID_ARGUMENT","Required action fields are missing.")
        for name in required:
            value=request[name]
            if name=="retention_count":
                if isinstance(value,bool) or value!=3: raise ProductionFailure("INVALID_ARGUMENT","retention_count is invalid.")
            elif not isinstance(value,str) or not value or len(value)>128: raise ProductionFailure("INVALID_ARGUMENT",f"{name} is invalid.")
        if action=="backup.create" and (request["source_root_id"]!=request["root_id"] or request["encryption_profile"]!="gpg-symmetric-aes256-iterated-s2k"):
            raise ProductionFailure("INVALID_ARGUMENT","backup creation parameters are invalid.")
        if action=="backup.verify_restore":
            if not str(request["artifact_id"]).startswith("backup-") or any(not _sha256(value) for value in (request["expected_manifest_digest"],request["expected_artifact_digest"])):
                raise ProductionFailure("INVALID_ARGUMENT","backup verification parameters are invalid.")

    @staticmethod
    def _validate_authorization(snapshot: AuthorizationSnapshot, action: str, request: Mapping[str, object], digest: str) -> None:
        exact = (snapshot.authorization_ref, snapshot.request_id, snapshot.project_id, snapshot.root_id, snapshot.action, snapshot.policy_revision, snapshot.target_digest)
        actual = (request["authorization_ref"], request["request_id"], request["project_id"], request["root_id"], action, request["policy_revision"], digest)
        if exact != actual:
            raise ProductionFailure("AUTHORIZATION_MISMATCH", "The authoritative approval does not match the canonical request.")

    def _envelope(self, operation: JournalOperation) -> dict[str, Any]:
        evidence = [str(row["evidence_id"]) for row in self.journal.transitions(operation.operation_id)]
        base = {"contract_version": CONTRACT_VERSION, "request_id": operation.request_id, "operation_id": operation.operation_id, "evidence": {"evidence_ids": evidence, "host_state_changed": operation.host_state_changed, "redactions_applied": operation.action.startswith("backup.")}}
        if operation.state in {OperationState.FAILED, OperationState.INDETERMINATE, OperationState.CANCELLED}:
            return {"ok": False, **base, "error": {"code": operation.error_code or "EXECUTION_FAILED", "message": "The durable operation did not reach verified success.", "retryable": False, "details": {}}, "result": {"state": operation.state.value}}
        return {"ok": True, **base, "result": {"state": operation.state.value, **dict(operation.result or {})}}

    def _read(self, request_id: str, load: Callable[[], Mapping[str, object]]) -> dict[str, Any]:
        try: return self._read_success(request_id, dict(load()))
        except ProductionFailure as error: return self._failure(request_id, error.code, error.message)
        except KeyError: return self._failure(request_id, "SOURCE_NOT_FOUND", "The requested record was not found.")
        except Exception: return self._failure(request_id, "DEPENDENCY_UNAVAILABLE", "The bounded read backend is unavailable.")

    @staticmethod
    def _read_success(request_id: str, result: Mapping[str, object]) -> dict[str, Any]:
        return {"ok": True, "contract_version": CONTRACT_VERSION, "request_id": request_id, "result": dict(result), "evidence": {"evidence_ids": [], "host_state_changed": False, "redactions_applied": True}}

    @staticmethod
    def _growth(action: str, request: Mapping[str, object], authorization: AuthorizationSnapshot) -> int:
        if action == "file.write":
            content = request.get("content", ""); encoding = request.get("content_encoding", "utf8")
            try: return len(str(content).encode()) if encoding == "utf8" else len(base64.b64decode(str(content), validate=True))
            except Exception: raise ProductionFailure("INVALID_ARGUMENT", "The content encoding is invalid.")
        if action == "path.copy": return int(authorization.limits.get("max_bytes", 0))
        return 0

    @staticmethod
    def _failure(request_id: str, code: str, message: str) -> dict[str, Any]:
        return {"ok": False, "contract_version": CONTRACT_VERSION, "request_id": request_id, "error": {"code": code, "message": message, "retryable": False, "details": {}}, "evidence": {"evidence_ids": [], "host_state_changed": False, "redactions_applied": True}}


class ProductionFailure(RuntimeError):
    def __init__(self, code: str, message: str): super().__init__(message); self.code=code; self.message=message


def _request_digest(action: str, request: Mapping[str, object]) -> str:
    payload = json.dumps({"action": action, "request": request}, sort_keys=True, separators=(",", ":"), default=str).encode()
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"

def _sha256(value:object)->bool:
    text=str(value); return len(text)==71 and text.startswith("sha256:") and all(character in "0123456789abcdef" for character in text[7:])

def _missing_read(): raise ProductionFailure("DEPENDENCY_UNAVAILABLE", "The bounded read backend is unavailable.")


__all__ = ["AuthorizationVerifier", "BoundedMutationExecutor", "ReadBackend", "ProductionStorageService"]
