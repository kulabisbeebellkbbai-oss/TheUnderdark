import importlib, json, os, socket
from pathlib import Path
import pytest

def test_production_runtime_dependency_is_declared():
    import tomllib
    project=tomllib.loads((Path(__file__).parents[1]/"pyproject.toml").read_text())["project"]
    assert any(value.startswith("uvicorn>=") for value in project["dependencies"])

def private(path:Path,data:bytes): path.write_bytes(data); path.chmod(0o600)
def config(tmp_path:Path):
    state=tmp_path/"state"; state.mkdir(); state.chmod(0o700); token=tmp_path/"token"; key=tmp_path/"key"; cfg=tmp_path/"config.json"
    private(token,b"test-token\n"); private(key,b"k"*32)
    value={"host":"127.0.0.1","port":8799,"state_dir":str(state),"journal_path":str(state/"journal.sqlite3"),"admission_path":str(state/"admission.sqlite3"),"pagination_path":str(state/"pages.sqlite3"),"registry_path":str(state/"roots.sqlite3"),"overseer_authorization_endpoint":"http://127.0.0.1:8766/storage/authorizations/verify","overseer_root_endpoint":"http://127.0.0.1:8766/storage/roots/verify","overseer_token_file":str(token),"cursor_key_file":str(key),"root_authorization_refs":{},"backup_bindings":[],"limits":{"max_storage_bytes":1024,"max_concurrent_operations":1,"max_requests_per_window":10,"rate_window_seconds":60}}
    private(cfg,json.dumps(value).encode()); return cfg,value

def test_import_has_no_socket_or_file_side_effect(tmp_path,monkeypatch):
    opened=[]; monkeypatch.setattr(socket,"socket",lambda *a,**k: opened.append((a,k)))
    module=importlib.import_module("theunderdark.production_cli"); importlib.reload(module)
    assert opened==[] and list(tmp_path.iterdir())==[]

def test_check_composes_without_binding(tmp_path,monkeypatch):
    cfg,_=config(tmp_path); bound=[]; monkeypatch.setattr(socket.socket,"bind",lambda self,address:bound.append(address))
    from theunderdark.production_cli import main
    assert main(["check","--config",str(cfg)])==0 and bound==[]
    assert all((Path(value).stat().st_mode&0o777)==0o600 for value in json.loads(cfg.read_text()).values() if isinstance(value,str) and value.endswith(".sqlite3"))

def test_rejects_non_loopback_and_permissive_secret(tmp_path):
    cfg,value=config(tmp_path); value["host"]="0.0.0.0"; private(cfg,json.dumps(value).encode())
    from theunderdark.production_cli import build_runtime
    with pytest.raises(ValueError): build_runtime(cfg)
    value["host"]="127.0.0.1"; Path(value["overseer_token_file"]).chmod(0o644); private(cfg,json.dumps(value).encode())
    with pytest.raises(PermissionError): build_runtime(cfg)

def test_check_rejects_empty_token_before_live_call(tmp_path):
    cfg,value=config(tmp_path); private(Path(value["overseer_token_file"]),b"\n")
    from theunderdark.production_cli import build_runtime
    with pytest.raises(ValueError,match="token file is empty"): build_runtime(cfg)


def test_serve_requires_explicit_runtime_attestation_arguments(tmp_path):
    from theunderdark.production_cli import main

    cfg, _ = config(tmp_path)
    with pytest.raises(SystemExit) as error:
        main(["serve", "--config", str(cfg)])
    assert error.value.code == 2


def test_serve_uses_explicit_deployed_runtime_root_and_attested_config_bytes(tmp_path, monkeypatch):
    cfg, _ = config(tmp_path)
    deployed = tmp_path / "installed-runtime"
    deployed.mkdir()
    captured = {}
    import theunderdark.production_cli as launcher
    from theunderdark.runtime_identity import RuntimeIdentity

    identity = RuntimeIdentity("sha256:" + "a" * 64, "sha256:" + "b" * 64, "sha256:" + "c" * 64)

    def capture(runtime_root, commit, expected_runtime, config_path, expected_config):
        captured.update(runtime_root=runtime_root, config_path=config_path)
        return identity, b"captured-config"

    class Runtime:
        service = object()
        bind = type("Bind", (), {"host": "127.0.0.1", "port": 8799})()

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            captured["closed"] = True

    def build(config_path, *, config_bytes=None):
        captured["build_config_path"] = config_path
        captured["config_bytes"] = config_bytes
        return Runtime()

    monkeypatch.setattr(launcher.RuntimeIdentity, "capture_with_config", capture)
    monkeypatch.setattr(launcher, "validate_production_runtime_root", lambda runtime_root: deployed)
    monkeypatch.setattr(launcher, "build_runtime", build)
    import uvicorn
    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: captured.update(served=True))
    import theunderdark.production_app as production_app
    monkeypatch.setattr(production_app, "create_production_http_app", lambda *_args, **_kwargs: object())
    result = launcher.main([
        "serve", "--config", str(cfg), "--runtime-root", str(deployed),
        "--expected-runtime-digest", identity.runtime_digest,
        "--expected-config-digest", identity.config_digest, "--source-commit", "a" * 40,
    ])
    assert result == 0
    assert captured["runtime_root"] == deployed
    assert captured["config_bytes"] == b"captured-config"
    assert captured["closed"] and captured["served"]


def test_serve_refuses_an_unrelated_valid_digest_before_capture_build_or_uvicorn(tmp_path, monkeypatch, capsys):
    cfg, _ = config(tmp_path)
    unrelated = tmp_path / "unrelated-runtime"
    (unrelated / "src" / "theunderdark").mkdir(parents=True)
    (unrelated / "src" / "theunderdark" / "__init__.py").write_text("\n")
    from theunderdark.runtime_identity import compute_runtime_digest
    import theunderdark.production_cli as launcher

    monkeypatch.setattr(launcher, "validate_production_runtime_root", lambda _root: (_ for _ in ()).throw(
        launcher.RuntimeIdentityError("RUNTIME_PROVENANCE_MISMATCH")
    ))
    calls = []
    monkeypatch.setattr(launcher.RuntimeIdentity, "capture_with_config", lambda *_args, **_kwargs: calls.append("capture"))
    monkeypatch.setattr(launcher, "build_runtime", lambda *_args, **_kwargs: calls.append("build"))
    import uvicorn
    monkeypatch.setattr(uvicorn, "run", lambda *_args, **_kwargs: calls.append("uvicorn"))
    result = launcher.main([
        "serve", "--config", str(cfg), "--runtime-root", str(unrelated),
        "--expected-runtime-digest", compute_runtime_digest(unrelated, "a" * 40),
        "--expected-config-digest", "sha256:" + "b" * 64, "--source-commit", "a" * 40,
    ])
    output = capsys.readouterr()
    assert result == 2 and calls == []
    assert json.loads(output.err)["error"]["code"] == "RUNTIME_PROVENANCE_MISMATCH"


def test_build_runtime_uses_captured_config_snapshot_after_path_mutation(tmp_path):
    cfg, _ = config(tmp_path)
    captured = cfg.read_bytes()
    private(cfg, b"this is no longer the captured JSON")
    import theunderdark.production_cli as launcher

    with launcher.build_runtime(cfg, compose_backup_bindings=False, config_bytes=captured) as runtime:
        assert runtime.bind.host == "127.0.0.1"


def test_build_runtime_fails_closed_when_config_path_is_replaced(tmp_path):
    cfg, _ = config(tmp_path)
    captured = cfg.read_bytes()
    replacement = tmp_path / "replacement.json"
    private(replacement, captured)
    cfg.unlink()
    cfg.symlink_to(replacement)
    import theunderdark.production_cli as launcher

    with pytest.raises(PermissionError):
        launcher.build_runtime(cfg, compose_backup_bindings=False, config_bytes=captured)


def test_serve_mismatch_is_redacted_and_does_not_leave_runtime_open(tmp_path, monkeypatch, capsys):
    cfg, _ = config(tmp_path)
    import theunderdark.production_cli as launcher

    monkeypatch.setattr(
        launcher, "validate_production_runtime_root", lambda runtime_root: Path(runtime_root)
    )
    monkeypatch.setattr(
        launcher.RuntimeIdentity, "capture_with_config",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(launcher.RuntimeIdentityError("CONFIG_IDENTITY_MISMATCH")),
    )
    result = launcher.main([
        "serve", "--config", str(cfg), "--runtime-root", str(tmp_path),
        "--expected-runtime-digest", "sha256:" + "a" * 64,
        "--expected-config-digest", "sha256:" + "b" * 64, "--source-commit", "a" * 40,
    ])
    output = capsys.readouterr()
    assert result == 2
    assert json.loads(output.err) == {"ok": False, "error": {"code": "CONFIG_IDENTITY_MISMATCH"}, "redactions_applied": True}
    assert str(tmp_path) not in output.err

def test_partial_construction_closes_prior_resources(tmp_path,monkeypatch):
    cfg,_=config(tmp_path); closed=[]
    import theunderdark.production_cli as launcher
    real=launcher.SQLiteOperationJournal
    class TrackedJournal(real):
        def close(self): closed.append("journal"); super().close()
    class BrokenAdmission:
        def __init__(self,*a,**k): raise RuntimeError("later dependency failed")
    monkeypatch.setattr(launcher,"SQLiteOperationJournal",TrackedJournal); monkeypatch.setattr(launcher,"SQLiteAdmissionController",BrokenAdmission)
    with pytest.raises(RuntimeError,match="later dependency failed"): launcher.build_runtime(cfg)
    assert closed==["journal"]

def test_register_root_failure_emits_only_redacted_stable_code(tmp_path,monkeypatch,capsys):
    cfg,_=config(tmp_path)
    import theunderdark.production_cli as launcher
    def fail(*_args,**_kwargs): raise PermissionError("private /path token=must-not-leak")
    monkeypatch.setattr(launcher,"register_approved_root",fail)
    result=launcher.main(["register-root","--config",str(cfg),"--project-id","project","--root-id","root","--policy-revision","1","--host-path",str(tmp_path),"--alias","workspace","--max-bytes","1","--authorization-ref","auth"])
    output=capsys.readouterr()
    assert result==2 and output.out==""
    assert json.loads(output.err)=={"ok":False,"error":{"code":"PRIVATE_STATE_INVALID"},"redactions_applied":True}
    assert "path" not in output.err and "token" not in output.err and "Traceback" not in output.err

def test_register_root_composes_registry_before_backup_bindings_and_exact_retry_preserves_config(tmp_path,monkeypatch):
    cfg,value=config(tmp_path)
    source=tmp_path/"source"; source.mkdir()
    artifact=tmp_path/"artifacts"; artifact.mkdir(); artifact.chmod(0o700)
    phrase=tmp_path/"passphrase"; private(phrase,b"test-passphrase")
    value["backup_bindings"]=[{"project_id":"project","root_id":"root","policy_revision":"1","source_root":str(source),"artifact_dir":str(artifact),"passphrase_file":str(phrase),"gpg_executable":"/usr/bin/gpg"}]
    private(cfg,json.dumps(value).encode())
    import theunderdark.production_cli as launcher
    from theunderdark.root_registry import ControlPlaneApproval
    with launcher.build_runtime(cfg,compose_backup_bindings=False) as runtime:
        digest=runtime.registry.registration_target_digest(project_id="project",root_id="root",policy_revision="1",host_path=source,alias="workspace",max_bytes=1)
    value["root_authorization_refs"]={digest:"auth"}; private(cfg,json.dumps(value).encode())
    original=cfg.read_bytes(); identity=(cfg.stat().st_dev,cfg.stat().st_ino); mode=cfg.stat().st_mode&0o777; approvals=[]
    def approve(_self,action,payload,target):
        approvals.append(target)
        return ControlPlaneApproval("approval",action,payload["project_id"],payload["root_id"],payload["policy_revision"],target,"approved","2099-01-01T00:00:00+00:00")
    monkeypatch.setattr(launcher.OverseerRootControlVerifier,"verify",approve)
    arguments=dict(project_id="project",root_id="root",policy_revision="1",host_path=source,alias="workspace",max_bytes=1,authorization_ref="auth")
    first=launcher.register_approved_root(cfg,**arguments)
    second=launcher.register_approved_root(cfg,**arguments)
    assert first==second==digest and approvals==[digest,digest]
    assert cfg.read_bytes()==original and (cfg.stat().st_dev,cfg.stat().st_ino)==identity and cfg.stat().st_mode&0o777==mode==0o600
    with launcher.build_runtime(cfg) as runtime:
        assert runtime.registry.root_ids("project")== ("root",)

@pytest.mark.parametrize(("references","authorization_ref","code"),[
    ({},"auth","AUTHORIZATION_REQUIRED"),
    ("mismatch","auth","AUTHORIZATION_MISMATCH"),
])
def test_register_root_requires_exact_prebound_authorization_without_rewriting_config(tmp_path,references,authorization_ref,code):
    cfg,value=config(tmp_path); source=tmp_path/"source"; source.mkdir()
    import theunderdark.production_cli as launcher
    with launcher.build_runtime(cfg,compose_backup_bindings=False) as runtime:
        digest=runtime.registry.registration_target_digest(project_id="project",root_id="root",policy_revision="1",host_path=source,alias="workspace",max_bytes=1)
    value["root_authorization_refs"]={} if references=={} else {digest:"other-auth"}; private(cfg,json.dumps(value).encode())
    original=cfg.read_bytes(); identity=(cfg.stat().st_dev,cfg.stat().st_ino)
    with pytest.raises(launcher.RootVerificationError) as failure:
        launcher.register_approved_root(cfg,project_id="project",root_id="root",policy_revision="1",host_path=source,alias="workspace",max_bytes=1,authorization_ref=authorization_ref)
    assert failure.value.code==code
    assert cfg.read_bytes()==original and (cfg.stat().st_dev,cfg.stat().st_ino)==identity
