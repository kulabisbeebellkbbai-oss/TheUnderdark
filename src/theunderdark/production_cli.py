"""Explicit production composition and loopback-only launcher."""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping
from urllib.request import Request,urlopen

from .admission import AdmissionLimits,SQLiteAdmissionController
from .composition import BackupBinding,build_backup_executor_provider
from .journal import SQLiteOperationJournal
from .mutation_executor import FsContainMutationExecutor
from .overseer_verifier import OverseerAuthorizationVerifier
from .pagination import SQLiteSnapshotPaginator
from .production import ProductionStorageService
from .read_backend import FsContainReadBackend
from .root_registry import RegistryFailure,SQLiteRootRegistry
from .root_verifier import OverseerRootControlVerifier,RootVerificationError


class UrllibJSONTransport:
    def post(self,url:str,*,headers:Mapping[str,str],json:Mapping[str,object],timeout:float)->Mapping[str,object]:
        request=Request(url,data=__import__("json").dumps(json,separators=(",",":")).encode(),headers=dict(headers),method="POST")
        with urlopen(request,timeout=timeout) as response:
            if response.status!=200: raise RuntimeError("authoritative endpoint rejected request")
            value=__import__("json").loads(response.read(1_048_577))
        if not isinstance(value,dict): raise RuntimeError("authoritative endpoint returned invalid JSON")
        return value


@dataclass(frozen=True)
class _Bind:
    host:str
    port:int
    def __post_init__(self):
        if self.host!="127.0.0.1" or not 1<=self.port<=65535: raise ValueError("production bind must be explicit IPv4 loopback and a valid port")

class ProductionRuntime:
    def __init__(self,*resources,service:ProductionStorageService,bind:_Bind,registry:SQLiteRootRegistry,root_authorization_refs:dict[str,str]): self._resources=resources; self.service=service; self.bind=bind; self.registry=registry; self.root_authorization_refs=root_authorization_refs
    def close(self):
        for resource in reversed(self._resources):
            close=getattr(resource,"close",None)
            if callable(close): close()
    def __enter__(self): return self
    def __exit__(self,*_): self.close()


def build_runtime(config_path:str|Path,*,compose_backup_bindings:bool=True)->ProductionRuntime:
    config_file=_private_file(Path(config_path),"config",exact_mode=0o600); config=json.loads(config_file.read_text())
    required={"host","port","state_dir","journal_path","admission_path","pagination_path","registry_path","overseer_authorization_endpoint","overseer_root_endpoint","overseer_token_file","cursor_key_file","root_authorization_refs","limits","backup_bindings"}
    if set(config)!=required: raise ValueError("production config must contain the exact supported fields")
    bind=_Bind(str(config["host"]),int(config["port"])); state_dir=_private_directory(Path(str(config["state_dir"])))
    paths=[Path(str(config[name])) for name in ("journal_path","admission_path","pagination_path","registry_path")]
    if any(not path.is_absolute() or path.parent.resolve()!=state_dir.resolve() for path in paths): raise ValueError("all state databases must be direct children of the private state directory")
    for path in paths:
        if path.exists(): _private_file(path,"state database",exact_mode=0o600)
    token_file=_private_file(Path(str(config["overseer_token_file"])),"token",exact_mode=0o600); cursor_file=_private_file(Path(str(config["cursor_key_file"])),"cursor key",exact_mode=0o600)
    cursor_key=cursor_file.read_bytes(); transport=UrllibJSONTransport()
    def token_provider():
        current=_private_file(token_file,"token",exact_mode=0o600).read_text().strip()
        if not current: raise ValueError("token file is empty")
        return current
    # Check readiness now rather than deferring an empty credential failure to
    # the first live authorization request. Do not retain the returned value.
    initial_token=token_provider(); initial_token=""
    references=config["root_authorization_refs"]
    if not isinstance(references,dict) or any(not isinstance(k,str) or not isinstance(v,str) or not v for k,v in references.items()): raise ValueError("root authorization reference map is invalid")
    root_verifier=OverseerRootControlVerifier(endpoint=str(config["overseer_root_endpoint"]),token_provider=token_provider,authorization_ref_provider=lambda _a,_p,d: references[d],http_client=transport)
    backup_bindings=_backup_bindings(config["backup_bindings"])
    resources=[]; prior_umask=os.umask(0o077)
    try:
        registry=SQLiteRootRegistry(paths[3],verifier=root_verifier,protected_paths=(state_dir,config_file,token_file,cursor_file)); resources.append(registry)
        journal=SQLiteOperationJournal(paths[0]); resources.append(journal)
        admission=SQLiteAdmissionController(paths[1]); resources.append(admission)
        paginator=SQLiteSnapshotPaginator(paths[2],cursor_key=cursor_key); resources.append(paginator)
    except Exception:
        for resource in reversed(resources):
            try: resource.close()
            except Exception: pass
        raise
    finally: os.umask(prior_umask)
    try:
        for path in paths: _private_file(path,"state database",exact_mode=0o600)
        verifier=OverseerAuthorizationVerifier(endpoint=str(config["overseer_authorization_endpoint"]),token_provider=token_provider,http_client=transport)
        executor=FsContainMutationExecutor(registry.resolve_current); reads=FsContainReadBackend(registry.resolve_current,registry.root_ids)
        limits_data=config["limits"]
        if not isinstance(limits_data,dict): raise ValueError("limits must be an object")
        limits=AdmissionLimits(**limits_data)
        backup_provider=build_backup_executor_provider(registry,backup_bindings) if compose_backup_bindings and backup_bindings else None
        service=ProductionStorageService(journal=journal,verifier=verifier,executor=executor,admission=admission,admission_limits=lambda _project:limits,read_backend=reads,paginator=paginator,backup_executor_provider=backup_provider)
    except Exception:
        for resource in reversed(resources):
            try: resource.close()
            except Exception: pass
        raise
    return ProductionRuntime(*resources,service=service,bind=bind,registry=registry,root_authorization_refs=references)

def register_approved_root(config_path:str|Path,*,project_id:str,root_id:str,policy_revision:str,host_path:str|Path,alias:str,max_bytes:int,authorization_ref:str)->str:
    """Register one exact root using its prebound Overseer authorization."""
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}",authorization_ref) is None: raise ValueError("authorization_ref must be an opaque ID")
    config_file=_private_file(Path(config_path),"config",exact_mode=0o600)
    # Root registration must compose the registry before resolving backup
    # bindings. Resolving the binding here would require the root that this
    # operation is responsible for registering, creating a circular startup
    # dependency. Normal check/serve startup still resolves every binding.
    with build_runtime(config_file,compose_backup_bindings=False) as runtime:
        arguments={"project_id":project_id,"root_id":root_id,"policy_revision":policy_revision,"host_path":host_path,"alias":alias,"max_bytes":max_bytes}
        digest=runtime.registry.registration_target_digest(**arguments)
        prebound=runtime.root_authorization_refs.get(digest)
        if prebound is None: raise RootVerificationError("AUTHORIZATION_REQUIRED","approval target is not prebound in the protected configuration")
        if prebound!=authorization_ref: raise RootVerificationError("AUTHORIZATION_MISMATCH","approval target is prebound to another authorization reference")
        runtime.registry.register(**arguments)
        return digest


def main(argv:list[str]|None=None)->int:
    parser=argparse.ArgumentParser(prog="theunderdark-production"); parser.add_argument("command",choices=("check","serve","register-root")); parser.add_argument("--config",required=True)
    parser.add_argument("--project-id"); parser.add_argument("--root-id"); parser.add_argument("--policy-revision"); parser.add_argument("--host-path"); parser.add_argument("--alias"); parser.add_argument("--max-bytes",type=int); parser.add_argument("--authorization-ref")
    args=parser.parse_args(argv)
    if args.command=="register-root":
        names=("project_id","root_id","policy_revision","host_path","alias","max_bytes","authorization_ref")
        if any(getattr(args,name) is None for name in names): parser.error("register-root requires exact root identity, path, limit, alias, and authorization reference")
        try:
            register_approved_root(args.config,**{name:getattr(args,name) for name in names})
        except Exception as error:
            # Emit only a stable error class/code. Paths, tokens, HTTP bodies,
            # tracebacks, and exception messages are intentionally excluded.
            print(json.dumps({"ok":False,"error":{"code":_startup_error_code(error)},"redactions_applied":True},sort_keys=True),file=sys.stderr)
            return 2
        return 0
    with build_runtime(args.config) as runtime:
        if args.command=="check": return 0
        import uvicorn
        from .production_app import create_production_http_app
        uvicorn.run(create_production_http_app(runtime.service),host=runtime.bind.host,port=runtime.bind.port,log_config=None)
    return 0


def _startup_error_code(error:Exception)->str:
    if isinstance(error,(RegistryFailure,RootVerificationError)): return error.code
    if isinstance(error,PermissionError): return "PRIVATE_STATE_INVALID"
    if isinstance(error,KeyError): return "CONFIG_REFERENCE_MISSING"
    if isinstance(error,ValueError): return "CONFIG_INVALID"
    if isinstance(error,OSError): return "IO_UNAVAILABLE"
    return "DEPENDENCY_UNAVAILABLE"


def _private_file(path:Path,label:str,*,exact_mode:int)->Path:
    if not path.is_absolute(): raise ValueError(f"{label} path must be absolute")
    status=path.lstat()
    if not stat.S_ISREG(status.st_mode) or stat.S_ISLNK(status.st_mode) or (hasattr(os,"geteuid") and status.st_uid!=os.geteuid()) or stat.S_IMODE(status.st_mode)!=exact_mode: raise PermissionError(f"{label} must be an owner-only regular file")
    return path
def _private_directory(path:Path)->Path:
    if not path.is_absolute(): raise ValueError("state directory must be absolute")
    status=path.lstat()
    if not stat.S_ISDIR(status.st_mode) or stat.S_ISLNK(status.st_mode) or (hasattr(os,"geteuid") and status.st_uid!=os.geteuid()) or stat.S_IMODE(status.st_mode)!=0o700: raise PermissionError("state directory must be owner-only")
    return path

def _backup_bindings(value:object)->tuple[BackupBinding,...]:
    if not isinstance(value,list): raise ValueError("backup_bindings must be a list")
    expected={"project_id","root_id","policy_revision","source_root","artifact_dir","passphrase_file","gpg_executable"}; bindings=[]; identities=set()
    for item in value:
        if not isinstance(item,dict) or set(item)!=expected: raise ValueError("each backup binding must contain the exact supported fields")
        identity=tuple(item[name] for name in ("project_id","root_id","policy_revision"))
        if any(not isinstance(part,str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}",part) is None for part in identity) or identity in identities: raise ValueError("backup binding identity must be unique, exact, and use opaque IDs")
        identities.add(identity)
        source=Path(str(item["source_root"])); artifact=Path(str(item["artifact_dir"])); phrase=Path(str(item["passphrase_file"])); gpg=Path(str(item["gpg_executable"]))
        if not source.is_absolute() or source.is_symlink() or not source.is_dir(): raise ValueError("backup source must be an absolute non-symlink directory")
        _private_directory(artifact); _private_file(phrase,"backup passphrase",exact_mode=0o600)
        if not gpg.is_absolute() or gpg.is_symlink() or not gpg.is_file() or not os.access(gpg,os.X_OK): raise ValueError("GPG executable must be an absolute executable regular file")
        bindings.append(BackupBinding(str(identity[0]),str(identity[1]),str(identity[2]),source,artifact,phrase,str(gpg)))
    return tuple(bindings)

if __name__=="__main__": raise SystemExit(main())
