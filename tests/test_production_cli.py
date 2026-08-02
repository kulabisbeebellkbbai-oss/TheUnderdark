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

def test_register_root_composes_registry_before_backup_bindings(tmp_path,monkeypatch):
    cfg,value=config(tmp_path)
    source=tmp_path/"source"; source.mkdir()
    artifact=tmp_path/"artifacts"; artifact.mkdir(); artifact.chmod(0o700)
    phrase=tmp_path/"passphrase"; private(phrase,b"test-passphrase")
    value["backup_bindings"]=[{"project_id":"project","root_id":"root","policy_revision":"1","source_root":str(source),"artifact_dir":str(artifact),"passphrase_file":str(phrase),"gpg_executable":"/usr/bin/gpg"}]
    private(cfg,json.dumps(value).encode())
    import theunderdark.production_cli as launcher
    from theunderdark.root_registry import ControlPlaneApproval
    monkeypatch.setattr(launcher.OverseerRootControlVerifier,"verify",lambda _self,action,payload,target:ControlPlaneApproval("approval",action,payload["project_id"],payload["root_id"],payload["policy_revision"],target,"approved","2099-01-01T00:00:00+00:00"))
    digest=launcher.register_approved_root(cfg,project_id="project",root_id="root",policy_revision="1",host_path=source,alias="workspace",max_bytes=1,authorization_ref="auth")
    assert digest.startswith("sha256:")
    with launcher.build_runtime(cfg) as runtime:
        assert runtime.registry.root_ids("project")== ("root",)
