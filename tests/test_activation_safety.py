"""Production launcher refusal tests; none invoke the serving path."""

from __future__ import annotations

import importlib
import json
import socket
import sys
from datetime import UTC,datetime,timedelta
from pathlib import Path

import pytest


def owner_file(path: Path, value: bytes) -> None:
    path.write_bytes(value)
    path.chmod(0o600)


def launcher_config(tmp_path: Path) -> tuple[Path, dict[str, object]]:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    token = tmp_path / "overseer.token"
    cursor = tmp_path / "cursor.key"
    config = tmp_path / "production.json"
    owner_file(token, b"fixture-token\n")
    owner_file(cursor, b"c" * 32)
    value: dict[str, object] = {
        "host": "127.0.0.1",
        "port": 8799,
        "state_dir": str(state),
        "journal_path": str(state / "journal.sqlite3"),
        "admission_path": str(state / "admission.sqlite3"),
        "pagination_path": str(state / "pagination.sqlite3"),
        "registry_path": str(state / "registry.sqlite3"),
        "overseer_authorization_endpoint": "http://127.0.0.1:8766/storage/authorizations/verify",
        "overseer_root_endpoint": "http://127.0.0.1:8766/storage/roots/verify",
        "overseer_token_file": str(token),
        "cursor_key_file": str(cursor),
        "root_authorization_refs": {},
        "backup_bindings": [],
        "limits": {
            "max_storage_bytes": 1024,
            "max_concurrent_operations": 1,
            "max_requests_per_window": 10,
            "rate_window_seconds": 60,
        },
    }
    owner_file(config, json.dumps(value).encode())
    return config, value


def rewrite(config: Path, value: dict[str, object]) -> None:
    owner_file(config, json.dumps(value).encode())


def test_import_never_constructs_socket_or_reads_launcher_config(monkeypatch: pytest.MonkeyPatch) -> None:
    sockets: list[tuple] = []
    real_socket = socket.socket
    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: sockets.append((args, kwargs)))
    sys.modules.pop("theunderdark.production_cli", None)
    imported = importlib.import_module("theunderdark.production_cli")
    assert imported.__name__ == "theunderdark.production_cli"
    assert sockets == []
    monkeypatch.setattr(socket, "socket", real_socket)


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "::1", "localhost", "127.0.0.2"])
def test_build_rejects_every_non_exact_loopback_host(tmp_path: Path, host: str) -> None:
    from theunderdark.production_cli import build_runtime

    config, value = launcher_config(tmp_path)
    value["host"] = host
    rewrite(config, value)
    with pytest.raises(ValueError, match="loopback"):
        build_runtime(config)


@pytest.mark.parametrize(("target", "mode"), [("config", 0o644), ("token", 0o640), ("cursor", 0o644), ("state", 0o755)])
def test_permissions_must_be_owner_only(tmp_path: Path, target: str, mode: int) -> None:
    from theunderdark.production_cli import build_runtime

    config, value = launcher_config(tmp_path)
    paths = {
        "config": config,
        "token": Path(str(value["overseer_token_file"])),
        "cursor": Path(str(value["cursor_key_file"])),
        "state": Path(str(value["state_dir"])),
    }
    paths[target].chmod(mode)
    with pytest.raises(PermissionError, match="owner-only"):
        build_runtime(config)


def test_missing_or_symlinked_token_fails_before_runtime_composition(tmp_path: Path) -> None:
    from theunderdark.production_cli import build_runtime

    config, value = launcher_config(tmp_path)
    token = Path(str(value["overseer_token_file"]))
    token.unlink()
    with pytest.raises(FileNotFoundError):
        build_runtime(config)

    real = tmp_path / "real-token"
    owner_file(real, b"fixture-token")
    token.symlink_to(real)
    with pytest.raises(PermissionError, match="owner-only regular file"):
        build_runtime(config)


def test_empty_token_fails_during_check_composition(tmp_path: Path) -> None:
    from theunderdark.production_cli import build_runtime

    config, value = launcher_config(tmp_path)
    owner_file(Path(str(value["overseer_token_file"])), b" \n")
    with pytest.raises(ValueError, match="token file is empty"):
        build_runtime(config)


def test_partial_constructor_failure_closes_every_opened_resource(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import theunderdark.production_cli as launcher

    config, _ = launcher_config(tmp_path)
    opened: list[object] = []

    class Resource:
        closed = False

        def __init__(self, *args, **kwargs):
            opened.append(self)

        def close(self):
            self.closed = True

    monkeypatch.setattr(launcher, "SQLiteRootRegistry", Resource)
    monkeypatch.setattr(launcher, "SQLiteOperationJournal", Resource)
    monkeypatch.setattr(launcher, "SQLiteAdmissionController", Resource)
    monkeypatch.setattr(
        launcher,
        "SQLiteSnapshotPaginator",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("constructor failed")),
    )
    with pytest.raises(RuntimeError, match="constructor failed"):
        launcher.build_runtime(config)
    assert len(opened) == 3
    assert all(resource.closed for resource in opened)


def test_all_state_databases_must_be_direct_children_of_private_state(tmp_path: Path) -> None:
    from theunderdark.production_cli import build_runtime

    config, value = launcher_config(tmp_path)
    value["journal_path"] = str(tmp_path / "journal.sqlite3")
    rewrite(config, value)
    with pytest.raises(ValueError, match="direct children"):
        build_runtime(config)
    assert not (tmp_path / "journal.sqlite3").exists()


def test_check_path_composes_and_closes_without_importing_uvicorn_or_binding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from theunderdark.production_cli import main

    config, _ = launcher_config(tmp_path)
    bound: list[object] = []
    monkeypatch.setattr(socket.socket, "bind", lambda _socket, address: bound.append(address))
    before = "uvicorn" in sys.modules
    assert main(["check", "--config", str(config)]) == 0
    assert bound == []
    assert ("uvicorn" in sys.modules) is before
    state = tmp_path / "state"
    assert all(path.stat().st_mode & 0o077 == 0 for path in state.iterdir())

def test_backup_bindings_are_required_exact_private_and_non_wildcard(tmp_path: Path) -> None:
    from theunderdark.production_cli import build_runtime
    config,value=launcher_config(tmp_path)
    del value["backup_bindings"]; rewrite(config,value)
    with pytest.raises(ValueError,match="exact supported fields"): build_runtime(config)

    source=tmp_path/"source"; artifacts=tmp_path/"artifacts"; source.mkdir(); artifacts.mkdir(mode=0o700)
    phrase=tmp_path/"backup.passphrase"; owner_file(phrase,b"fixture")
    value["backup_bindings"]=[{"project_id":"*","root_id":"work","policy_revision":"1","source_root":str(source),"artifact_dir":str(artifacts),"passphrase_file":str(phrase),"gpg_executable":"/usr/bin/gpg"}]
    rewrite(config,value)
    with pytest.raises(ValueError,match="opaque IDs"): build_runtime(config)

    for invalid in ("with space","with\nnewline","control\x00byte"):
        value["backup_bindings"][0]["project_id"]=invalid; rewrite(config,value)
        with pytest.raises(ValueError,match="opaque IDs"): build_runtime(config)

    value["backup_bindings"][0]["project_id"]="roadex"; artifacts.chmod(0o755); rewrite(config,value)
    with pytest.raises(PermissionError,match="owner-only"): build_runtime(config)

def test_operator_registers_only_exact_overseer_approved_root_and_binds_config(tmp_path: Path,monkeypatch:pytest.MonkeyPatch)->None:
    import theunderdark.production_cli as launcher
    config,value=launcher_config(tmp_path); root=tmp_path/"approved-root"; root.mkdir(); observed=[]
    def approve(_self,_url,*,headers,json,timeout):
        observed.append(dict(json)); now=datetime.now(UTC)
        record={key:json[key] for key in ("action","project_id","root_id","policy_revision","root_identity","alias","status","max_bytes","target_digest")}
        return {"ok":True,"contract_version":"1.0","authorization":{"approval_id":"approval-root-1",**record,"approved_at":now.isoformat(),"expires_at":(now+timedelta(minutes=5)).isoformat(),"redactions_applied":True}}
    monkeypatch.setattr(launcher.UrllibJSONTransport,"post",approve)
    digest=launcher.register_approved_root(config,project_id="roadex",root_id="work",policy_revision="7",host_path=root,alias="workspace",max_bytes=1024,authorization_ref="root-auth-1")
    updated=json.loads(config.read_text()); assert updated["root_authorization_refs"]=={digest:"root-auth-1"}
    assert observed[0]["authorization_ref"]=="root-auth-1" and observed[0]["project_id"]=="roadex" and "host_path" not in observed[0]
    with launcher.build_runtime(config) as runtime: assert runtime.registry.resolve("roadex","work","7").root==root

@pytest.mark.parametrize("field,value",[("project_id","*"),("root_id","with space"),("policy_revision","bad\nrevision")])
def test_operator_rejects_non_exact_root_identity_without_config_mutation(tmp_path:Path,field:str,value:str)->None:
    from theunderdark.production_cli import register_approved_root
    config,_=launcher_config(tmp_path); root=tmp_path/"root"; root.mkdir(); before=config.read_bytes()
    arguments={"project_id":"roadex","root_id":"work","policy_revision":"7","host_path":root,"alias":"workspace","max_bytes":1024,"authorization_ref":"root-auth-1"}; arguments[field]=value
    with pytest.raises(Exception): register_approved_root(config,**arguments)
    assert config.read_bytes()==before

def test_operator_rolls_back_authorization_binding_when_overseer_denies(tmp_path:Path,monkeypatch:pytest.MonkeyPatch)->None:
    import theunderdark.production_cli as launcher
    config,_=launcher_config(tmp_path); root=tmp_path/"root"; root.mkdir(); before=config.read_bytes()
    monkeypatch.setattr(launcher.UrllibJSONTransport,"post",lambda *_a,**_k:{"ok":False,"error":{"code":"AUTHORIZATION_MISMATCH"}})
    with pytest.raises(Exception): launcher.register_approved_root(config,project_id="roadex",root_id="work",policy_revision="7",host_path=root,alias="workspace",max_bytes=1024,authorization_ref="root-auth-1")
    assert config.read_bytes()==before
    with launcher.build_runtime(config) as runtime: assert runtime.registry.project_roots("roadex")==()
