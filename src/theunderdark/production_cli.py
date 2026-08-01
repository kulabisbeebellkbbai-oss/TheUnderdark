"""Explicit production composition and loopback-only launcher."""
from __future__ import annotations

import argparse
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping
from urllib.request import Request,urlopen

from .admission import AdmissionLimits,SQLiteAdmissionController
from .journal import SQLiteOperationJournal
from .mutation_executor import FsContainMutationExecutor
from .overseer_verifier import OverseerAuthorizationVerifier
from .pagination import SQLiteSnapshotPaginator
from .production import ProductionStorageService
from .read_backend import FsContainReadBackend
from .root_registry import SQLiteRootRegistry
from .root_verifier import OverseerRootControlVerifier


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
    def __init__(self,*resources,service:ProductionStorageService,bind:_Bind): self._resources=resources; self.service=service; self.bind=bind
    def close(self):
        for resource in reversed(self._resources):
            close=getattr(resource,"close",None)
            if callable(close): close()
    def __enter__(self): return self
    def __exit__(self,*_): self.close()


def build_runtime(config_path:str|Path)->ProductionRuntime:
    config_file=_private_file(Path(config_path),"config",exact_mode=0o600); config=json.loads(config_file.read_text())
    required={"host","port","state_dir","journal_path","admission_path","pagination_path","registry_path","overseer_authorization_endpoint","overseer_root_endpoint","overseer_token_file","cursor_key_file","root_authorization_refs","limits"}
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
        service=ProductionStorageService(journal=journal,verifier=verifier,executor=executor,admission=admission,admission_limits=lambda _project:limits,read_backend=reads,paginator=paginator)
    except Exception:
        for resource in reversed(resources):
            try: resource.close()
            except Exception: pass
        raise
    return ProductionRuntime(*resources,service=service,bind=bind)


def main(argv:list[str]|None=None)->int:
    parser=argparse.ArgumentParser(prog="theunderdark-production"); parser.add_argument("command",choices=("check","serve")); parser.add_argument("--config",required=True)
    args=parser.parse_args(argv)
    with build_runtime(args.config) as runtime:
        if args.command=="check": return 0
        import uvicorn
        from .production_app import create_production_http_app
        uvicorn.run(create_production_http_app(runtime.service),host=runtime.bind.host,port=runtime.bind.port,log_config=None)
    return 0


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

if __name__=="__main__": raise SystemExit(main())
