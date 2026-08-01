from datetime import UTC, datetime, timedelta

from theunderdark.journal import AuthorizationSnapshot, OperationState, SQLiteOperationJournal
from theunderdark.production import ProductionStorageService, _request_digest
from theunderdark.admission import AdmissionLimits, SQLiteAdmissionController
from theunderdark.pagination import SQLiteSnapshotPaginator


class Verifier:
    def __init__(self): self.calls=0
    def verify(self, action, request, request_digest):
        self.calls += 1; now=datetime.now(UTC)
        return AuthorizationSnapshot(str(request["authorization_ref"]),str(request["request_id"]),str(request["project_id"]),str(request["root_id"]),action,request_digest,str(request["policy_revision"]),"claim","approval",now.isoformat(),(now+timedelta(minutes=5)).isoformat(),{"max_bytes":10})


class Executor:
    def __init__(self): self.calls=0
    def execute(self, action, request): self.calls += 1; return {"verified":True,"host_state_changed":True,"path":"project/root/result"}

class Reads:
    def project_get(self,p): return {"project_id":p,"status":"active"}
    def root_get(self,p,r): return {"project_id":p,"root_id":r,"alias":"safe"}
    def path_stat(self,p,r,path,include_digest=False): return {"path":f"{p}/{r}/{path}","type":"file","size":1}
    def directory_snapshot(self,p,r,path): return "device:1/inode:2",tuple({"name":n,"type":"file","size":1} for n in ("b","c","d"))


def request():
    return dict(project_id="project",root_id="root",request_id="req",idempotency_key="key",authorization_ref="auth",policy_revision="1",reason="bounded test",relative_path="result",parents=False)


def test_terminal_retry_survives_service_restart(tmp_path):
    path=(tmp_path/"state.sqlite3").resolve(); verifier=Verifier(); executor=Executor()
    with SQLiteOperationJournal(path) as journal:
        original=ProductionStorageService(journal=journal,verifier=verifier,executor=executor).directory_create(**request())
        assert original["ok"] and executor.calls == verifier.calls == 1
    with SQLiteOperationJournal(path) as journal:
        retried=ProductionStorageService(journal=journal,verifier=verifier,executor=executor).directory_create(**request())
        assert retried == original and executor.calls == verifier.calls == 1


def test_restart_recovers_executing_before_accepting_retry(tmp_path):
    path=(tmp_path/"state.sqlite3").resolve(); verifier=Verifier(); executor=Executor(); payload=request()
    with SQLiteOperationJournal(path) as journal:
        digest=_request_digest("directory.create",payload); auth=verifier.verify("directory.create",payload,digest); journal.store_authorization(auth)
        op,_=journal.reserve(project_id="project",request_id="req",idempotency_key="key",request_digest=digest,authorization_ref="auth",action="directory.create")
        journal.transition(op.operation_id,OperationState.AUTHORIZED); journal.transition(op.operation_id,OperationState.EXECUTING)
    with SQLiteOperationJournal(path) as journal:
        service=ProductionStorageService(journal=journal,verifier=verifier,executor=executor)
        assert service.recovered_operations[0].state == OperationState.INDETERMINATE
        result=service.directory_create(**payload)
        assert not result["ok"] and result["error"]["code"] == "RESULT_INDETERMINATE" and executor.calls == 0


def test_unknown_fields_fail_before_verifier_or_journal(tmp_path):
    verifier=Verifier(); executor=Executor()
    with SQLiteOperationJournal((tmp_path/"state.sqlite3").resolve()) as journal:
        result=ProductionStorageService(journal=journal,verifier=verifier,executor=executor).directory_create(**request(), unexpected=True)
        assert result["error"]["code"] == "INVALID_ARGUMENT" and verifier.calls == executor.calls == 0


def test_verifier_failure_is_redacted_and_fails_closed(tmp_path):
    class FailingVerifier:
        def verify(self, action, request, request_digest):
            raise RuntimeError("private verifier detail")

    executor = Executor()
    with SQLiteOperationJournal((tmp_path / "state.sqlite3").resolve()) as journal:
        result = ProductionStorageService(
            journal=journal,
            verifier=FailingVerifier(),
            executor=executor,
        ).directory_create(**request())
        assert result["error"]["code"] == "DEPENDENCY_UNAVAILABLE"
        assert "private verifier detail" not in str(result)
        assert executor.calls == 0


def test_service_reconciliation_is_append_only_and_project_bound(tmp_path):
    path=(tmp_path/"state.sqlite3").resolve(); verifier=Verifier(); executor=Executor(); payload=request()
    with SQLiteOperationJournal(path) as journal:
        digest=_request_digest("directory.create",payload); journal.store_authorization(verifier.verify("directory.create",payload,digest))
        op,_=journal.reserve(project_id="project",request_id="req",idempotency_key="key",request_digest=digest,authorization_ref="auth",action="directory.create")
        journal.transition(op.operation_id,OperationState.AUTHORIZED); journal.transition(op.operation_id,OperationState.EXECUTING); journal.recover_interrupted()
        service=ProductionStorageService(journal=journal,verifier=verifier,executor=executor)
        result=service.reconcile("project",op.operation_id,lambda _: (OperationState.SUCCEEDED,True,{"digest":"verified"}),evidence_id="evidence-reconcile")
        assert result["ok"] and result["result"]["state"] == "succeeded" and len(result["evidence"]["evidence_ids"]) == 5

def test_admission_is_committed_and_read_pages_are_stable(tmp_path):
    verifier=Verifier(); executor=Executor()
    with SQLiteOperationJournal((tmp_path/"journal.sqlite3").resolve()) as journal, SQLiteAdmissionController((tmp_path/"admission.sqlite3").resolve()) as admission, SQLiteSnapshotPaginator((tmp_path/"pages.sqlite3").resolve(),cursor_key=b"x"*32,max_page_size=2) as paginator:
        service=ProductionStorageService(journal=journal,verifier=verifier,executor=executor,admission=admission,admission_limits=lambda _:AdmissionLimits(10,1,10,60),read_backend=Reads(),paginator=paginator)
        result=service.directory_create(**request()); assert result["ok"]
        project=service.project_get("project"); assert project["result"]["project_id"]=="project" and project["evidence"]["host_state_changed"] is False
        first=service.directory_list("project","root","dir","1",limit=2); second=service.directory_list("project","root","dir","1",cursor=first["result"]["next_cursor"],limit=2)
        assert [e["name"] for e in first["result"]["entries"]+second["result"]["entries"]]==["b","c","d"]
