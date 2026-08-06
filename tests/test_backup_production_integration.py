from datetime import UTC, datetime, timedelta
import hashlib
import json
import os
from pathlib import Path

from theunderdark.admission import AdmissionLimits, SQLiteAdmissionController
from theunderdark.backup_executor import EncryptedBackupExecutor
from theunderdark.composition import compose_production_runtime
from theunderdark.journal import AuthorizationSnapshot, SQLiteOperationJournal
from theunderdark.pagination import SQLiteSnapshotPaginator
from theunderdark.production import ProductionStorageService, _request_digest
from theunderdark.composition import BackupBinding, build_backup_executor_provider
from theunderdark.mutation_executor import ResolvedRoot
from theunderdark.overseer_verifier import OverseerAuthorizationVerifier
from theunderdark.root_registry import ControlPlaneApproval, SQLiteRootRegistry
from theunderdark.runtime_identity import RuntimeIdentity


IDENTITY = RuntimeIdentity("sha256:" + "a" * 64, "sha256:" + "b" * 64, "sha256:" + "c" * 64)


class _DisposableRootVerifier:
    """Deterministic approval transport for disposable component composition."""

    def verify(self, action, payload, target_digest):
        return ControlPlaneApproval(
            "disposable-root-approval",
            action,
            str(payload["project_id"]),
            str(payload["root_id"]),
            str(payload["policy_revision"]),
            target_digest,
            "approved",
            "2099-01-01T00:00:00+00:00",
        )


class _ReadOnlyVerificationTransport:
    """The read-only acceptance path must never contact its verifier transport."""

    def __init__(self) -> None:
        self.calls = 0

    def post(self, *_args, **_kwargs):
        self.calls += 1
        raise AssertionError("Task 4 read-only composition must not verify a mutation")


def test_disposable_read_composition_uses_real_overseer_verifier(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    authority = tmp_path / "authority.json"
    authority.write_text(json.dumps({
        "project_id": "project.donuthole",
        "root_id": "backup-root",
        "policy_revision": "1",
        "alias": "donuthole-source",
        "max_bytes": 1024,
        "root_path": str(root),
    }, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    authority.chmod(0o400)

    service = build_real_service(tmp_path, authority)

    assert isinstance(service.verifier, OverseerAuthorizationVerifier)
    assert service.verifier._http_client.calls == 0


def build_real_service(workspace: Path, authority_path: Path) -> ProductionStorageService:
    """Compose the real read-path components from a sealed disposable authority file.

    This is test support only.  It never opens a listener, calls a live
    authority provider, or configures backup/restore execution.
    """

    workspace = workspace.resolve()
    supplied_authority = Path(authority_path)
    if supplied_authority.is_symlink():
        raise ValueError("disposable authority must be a sealed regular file")
    authority_path = supplied_authority.resolve(strict=True)
    if not authority_path.is_file() or os.stat(authority_path).st_mode & 0o222:
        raise ValueError("disposable authority must be a sealed regular file")
    raw_bytes = authority_path.read_bytes()
    try:
        authority = json.loads(raw_bytes)
    except json.JSONDecodeError as error:
        raise ValueError("disposable authority must be JSON") from error
    required = {"project_id", "root_id", "policy_revision", "alias", "max_bytes", "root_path"}
    if not isinstance(authority, dict) or set(authority) != required:
        raise ValueError("disposable authority fields are invalid")
    root_path = Path(str(authority["root_path"])).resolve(strict=True)
    workspace.mkdir(mode=0o700, parents=True, exist_ok=True)
    state = workspace / "state"
    state.mkdir(mode=0o700, exist_ok=True)
    registry = SQLiteRootRegistry((state / "roots.sqlite3").resolve(), verifier=_DisposableRootVerifier())
    registry.register(
        project_id=str(authority["project_id"]),
        root_id=str(authority["root_id"]),
        policy_revision=str(authority["policy_revision"]),
        host_path=root_path,
        alias=str(authority["alias"]),
        max_bytes=int(authority["max_bytes"]),
    )
    journal = SQLiteOperationJournal((state / "journal.sqlite3").resolve())
    admission = SQLiteAdmissionController((state / "admission.sqlite3").resolve())
    paginator = SQLiteSnapshotPaginator(
        (state / "pagination.sqlite3").resolve(),
        cursor_key=hashlib.sha256(raw_bytes).digest(),
        max_page_size=2,
    )
    verifier = OverseerAuthorizationVerifier(
        endpoint="http://127.0.0.1:8766/storage/authorizations/verify",
        token_provider=lambda: "disposable-read-only-token",
        http_client=_ReadOnlyVerificationTransport(),
    )
    composition = compose_production_runtime(
        registry=registry,
        journal=journal,
        admission=admission,
        paginator=paginator,
        verifier=verifier,
        limits_provider=lambda _project_id: AdmissionLimits(1_048_576, 4, 16, 60, 60),
        runtime_identity=IDENTITY,
    )
    if authority_path.read_bytes() != raw_bytes:
        raise AssertionError("disposable authority changed during composition")
    registry.close()
    journal.close()
    admission.close()
    paginator.close()
    return composition.service


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
    assert first["request_digest"]==_request_digest("backup.create",create)
    assert verifier.requests[-1][2]==_request_digest("backup.create",create)
    reused=service.backup_create(**{**common(2),**{key:create[key] for key in ("source_root_id","retention_count","encryption_profile")}})
    assert reused["ok"] and reused["evidence"]["host_state_changed"] is False
    verify={**common(3),"artifact_id":first["result"]["artifact_id"],"expected_artifact_digest":first["result"]["artifact_digest"],"expected_manifest_digest":first["result"]["manifest_digest"]}
    before={path.name for path in artifacts.glob("backup-*.tar.gpg")}; checked=service.backup_verify_restore(**verify)
    assert checked["ok"] and checked["evidence"]["host_state_changed"] is False
    assert checked["request_digest"]==_request_digest("backup.verify_restore",verify)
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
