from datetime import UTC, datetime, timedelta

from theunderdark.backup_executor import EncryptedBackupExecutor
from theunderdark.journal import AuthorizationSnapshot, SQLiteOperationJournal
from theunderdark.production import ProductionStorageService, _request_digest
from theunderdark.composition import BackupBinding, build_backup_executor_provider
from theunderdark.mutation_executor import ResolvedRoot


class Verifier:
    def __init__(self): self.requests=[]
    def verify(self, action, request, request_digest):
        self.requests.append((action,dict(request),request_digest))
        now=datetime.now(UTC)
        return AuthorizationSnapshot(request["authorization_ref"],request["request_id"],request["project_id"],request["root_id"],action,request_digest,request["policy_revision"],"claim","approval",now.isoformat(),(now+timedelta(minutes=5)).isoformat(),{})

class Mutations:
    def execute(self,*_): raise AssertionError("backup actions must not reach mutation executor")

def common(number):
    return {"project_id":"roadex","root_id":"work","request_id":f"request-{number}","idempotency_key":f"key-{number}","authorization_ref":f"auth-{number}","policy_revision":"7","reason":"approved encrypted backup"}

def test_backup_actions_use_exact_overseer_payload_and_preserve_host_state(tmp_path):
    source=tmp_path/"source"; artifacts=tmp_path/"artifacts"; source.mkdir(); artifacts.mkdir(mode=0o700)
    phrase=tmp_path/"phrase"; phrase.write_text("fixture-passphrase"); phrase.chmod(0o600); (source/"data.txt").write_text("data")
    executor=EncryptedBackupExecutor(source_root=source,artifact_dir=artifacts,passphrase_file=phrase)
    verifier=Verifier(); journal=SQLiteOperationJournal((tmp_path/"journal.sqlite3").resolve())
    service=ProductionStorageService(journal=journal,verifier=verifier,executor=Mutations(),backup_executor_provider=lambda project,root,revision: executor if (project,root,revision)==("roadex","work","7") else (_ for _ in ()).throw(PermissionError()))
    create={**common(1),"source_root_id":"work","retention_count":3,"encryption_profile":"gpg-symmetric-aes256-iterated-s2k"}
    first=service.backup_create(**create)
    assert first["ok"] and first["evidence"]["host_state_changed"] is True and first["evidence"]["redactions_applied"] is True
    assert verifier.requests[-1][2]==_request_digest("backup.create",create)
    reused=service.backup_create(**{**common(2),**{key:create[key] for key in ("source_root_id","retention_count","encryption_profile")}})
    assert reused["ok"] and reused["evidence"]["host_state_changed"] is False
    verify={**common(3),"artifact_id":first["result"]["artifact_id"],"expected_artifact_digest":first["result"]["artifact_digest"],"expected_manifest_digest":first["result"]["manifest_digest"]}
    before={path.name for path in artifacts.glob("backup-*.tar.gpg")}; checked=service.backup_verify_restore(**verify)
    assert checked["ok"] and checked["evidence"]["host_state_changed"] is False
    assert {path.name for path in artifacts.glob("backup-*.tar.gpg")}==before
    journal.close()

def test_backup_provider_and_source_root_mismatch_fail_closed(tmp_path):
    verifier=Verifier(); journal=SQLiteOperationJournal((tmp_path/"journal.sqlite3").resolve()); calls=[]
    service=ProductionStorageService(journal=journal,verifier=verifier,executor=Mutations(),backup_executor_provider=lambda *identity: calls.append(identity))
    request={**common(1),"source_root_id":"another-project","retention_count":3,"encryption_profile":"gpg-symmetric-aes256-iterated-s2k"}
    result=service.backup_create(**request)
    assert not result["ok"] and result["error"]["code"]=="INVALID_ARGUMENT" and calls==[]
    journal.close()

def test_private_backup_bindings_require_exact_registered_identity(tmp_path):
    source=tmp_path/"source"; artifacts=tmp_path/"artifacts"; source.mkdir(); artifacts.mkdir(mode=0o700)
    phrase=tmp_path/"phrase"; phrase.write_text("fixture-passphrase"); phrase.chmod(0o600)
    class Registry:
        def resolve(self,project,root,revision):
            if (project,root,revision)!=("roadex","work","7"): raise KeyError
            return ResolvedRoot(source,"workspace",policy_revision="7")
    binding=BackupBinding("roadex","work","7",source,artifacts,phrase)
    provider=build_backup_executor_provider(Registry(),[binding])
    assert isinstance(provider("roadex","work","7"),EncryptedBackupExecutor)
    import pytest
    with pytest.raises(PermissionError): provider("other-project","work","7")
    with pytest.raises(ValueError): build_backup_executor_provider(Registry(),[binding,binding])
