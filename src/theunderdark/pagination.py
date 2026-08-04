"""Durable stable directory pagination over caller-supplied safe metadata."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sqlite3
import os
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping,Sequence


class CursorInvalid(ValueError): pass


@dataclass(frozen=True)
class Page:
    entries: tuple[Mapping[str,object],...]
    next_cursor: str|None
    snapshot_id: str
    total_count: int


class SQLiteSnapshotPaginator:
    def __init__(self,state_path:str|Path,*,cursor_key:bytes,max_page_size:int=200)->None:
        self.path=Path(state_path)
        if not self.path.is_absolute(): raise ValueError("pagination state path must be absolute")
        if max_page_size<=0: raise ValueError("max_page_size must be positive")
        if not isinstance(cursor_key,bytes) or len(cursor_key)<32: raise ValueError("cursor_key must contain at least 32 bytes")
        self._cursor_key=cursor_key
        self.max_page_size=max_page_size; self.path.parent.mkdir(parents=True,exist_ok=True)
        _prepare_private_database(self.path)
        self._connection=sqlite3.connect(self.path)
        self._connection.executescript("""CREATE TABLE IF NOT EXISTS snapshots(snapshot_id TEXT PRIMARY KEY,context_digest TEXT NOT NULL,namespace_identity TEXT NOT NULL,entries TEXT NOT NULL);""")

    def close(self): self._connection.close()
    def __enter__(self): return self
    def __exit__(self,*args): self.close()

    def first_page(self,*,project_id:str,root_id:str,relative_path:str,policy_revision:str,namespace_identity:str,entries:Sequence[Mapping[str,object]],limit:int)->Page:
        self._limit(limit); context=_context(project_id,root_id,relative_path,policy_revision)
        safe=tuple(sorted((self._safe_entry(item) for item in entries),key=lambda item:str(item["name"])))
        snapshot_id=f"snapshot-{uuid.uuid4().hex}"
        self._connection.execute("INSERT INTO snapshots VALUES(?,?,?,?)",(snapshot_id,context,namespace_identity,json.dumps(safe,sort_keys=True,separators=(",",":"))))
        self._connection.commit()
        return self._page(snapshot_id,context,namespace_identity,safe,0,limit)

    def next_page(self,cursor:str,*,project_id:str,root_id:str,relative_path:str,policy_revision:str,namespace_identity:str,limit:int)->Page:
        self._limit(limit); context=_context(project_id,root_id,relative_path,policy_revision)
        try:
            token=json.loads(base64.urlsafe_b64decode(cursor+"="*(-len(cursor)%4)))
            snapshot_id,offset,token_context=token["s"],token["o"],token["c"]
            signature=token.pop("m")
            expected=hmac.new(self._cursor_key,json.dumps(token,sort_keys=True,separators=(",",":")).encode(),hashlib.sha256).hexdigest()
            if not hmac.compare_digest(str(signature),expected) or not isinstance(offset,int) or offset<0 or token_context!=context: raise ValueError
        except Exception as error: raise CursorInvalid("cursor is malformed or belongs to another context") from error
        row=self._connection.execute("SELECT * FROM snapshots WHERE snapshot_id=?",(snapshot_id,)).fetchone()
        if not row or row[1]!=context or row[2]!=namespace_identity: raise CursorInvalid("snapshot expired or namespace identity changed")
        entries=tuple(json.loads(row[3])); return self._page(snapshot_id,context,namespace_identity,entries,offset,limit)

    def _page(self,snapshot_id,context,identity,entries,offset,limit):
        page=entries[offset:offset+limit]; next_cursor=None
        if offset+limit<len(entries):
            token={"s":snapshot_id,"c":context,"o":offset+limit}
            token["m"]=hmac.new(self._cursor_key,json.dumps(token,sort_keys=True,separators=(",",":")).encode(),hashlib.sha256).hexdigest()
            next_cursor=base64.urlsafe_b64encode(json.dumps(token,separators=(",",":")).encode()).decode().rstrip("=")
        return Page(tuple(page),next_cursor,snapshot_id,len(entries))
    def _limit(self,limit):
        if not 1<=limit<=self.max_page_size: raise ValueError("page limit is outside finite bounds")
    @staticmethod
    def _safe_entry(item):
        allowed={"name","type","size","modified_ns","identity"}
        if set(item)-allowed or not isinstance(item.get("name"),str) or "/" in str(item["name"]) or not item["name"]: raise ValueError("entry metadata is not display-safe")
        return dict(item)


def _context(project,root,path,policy): return hashlib.sha256(f"{project}\0{root}\0{path}\0{policy}".encode()).hexdigest()


def _prepare_private_database(path:Path)->None:
    flags=os.O_CREAT|os.O_EXCL|os.O_WRONLY|getattr(os,"O_NOFOLLOW",0)
    try:
        descriptor=os.open(path,flags,0o600)
    except FileExistsError:
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or (hasattr(os,"geteuid") and info.st_uid!=os.geteuid()):
            raise ValueError("pagination database must be a process-owned regular file")
        os.chmod(path,0o600,follow_symlinks=False)
    else:
        os.close(descriptor)
