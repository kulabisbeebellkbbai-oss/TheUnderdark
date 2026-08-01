"""Durable quota, concurrency, and fixed-window rate admission primitives."""
from __future__ import annotations

import sqlite3
import os
import stat
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path


@dataclass(frozen=True)
class AdmissionLimits:
    max_storage_bytes: int
    max_concurrent_operations: int
    max_requests_per_window: int
    rate_window_seconds: int
    lease_seconds: int = 60

    def __post_init__(self):
        if min(self.max_storage_bytes, self.max_concurrent_operations, self.max_requests_per_window, self.rate_window_seconds, self.lease_seconds) <= 0:
            raise ValueError("all admission limits must be finite positive integers")


@dataclass(frozen=True)
class AdmissionReservation:
    reservation_id: str
    project_id: str
    operation_id: str
    growth_bytes: int
    expires_at: str


class AdmissionDenied(RuntimeError):
    def __init__(self, code: str, message: str): super().__init__(message); self.code=code


class SQLiteAdmissionController:
    def __init__(self, state_path: str | Path) -> None:
        self.path=Path(state_path)
        if not self.path.is_absolute(): raise ValueError("admission state path must be absolute")
        self.path.parent.mkdir(parents=True,exist_ok=True)
        _prepare_private_database(self.path)
        self._connection=sqlite3.connect(self.path,timeout=30,isolation_level=None)
        self._connection.row_factory=sqlite3.Row; self._lock=threading.RLock()
        self._connection.execute("PRAGMA journal_mode=WAL"); self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.executescript("""
        CREATE TABLE IF NOT EXISTS project_usage(project_id TEXT PRIMARY KEY, committed_bytes INTEGER NOT NULL CHECK(committed_bytes>=0));
        CREATE TABLE IF NOT EXISTS reservations(reservation_id TEXT PRIMARY KEY,project_id TEXT NOT NULL,operation_id TEXT NOT NULL UNIQUE,growth_bytes INTEGER NOT NULL CHECK(growth_bytes>=0),state TEXT NOT NULL,expires_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS rate_windows(project_id TEXT NOT NULL,window_start INTEGER NOT NULL,count INTEGER NOT NULL,PRIMARY KEY(project_id,window_start));
        """)

    def close(self): self._connection.close()
    def __enter__(self): return self
    def __exit__(self,*args): self.close()

    def set_committed_usage(self,project_id:str,bytes_used:int)->None:
        if bytes_used<0: raise ValueError("bytes_used cannot be negative")
        with self._tx(): self._connection.execute("INSERT OR REPLACE INTO project_usage VALUES(?,?)",(project_id,bytes_used))

    def reserve(self,project_id:str,operation_id:str,growth_bytes:int,limits:AdmissionLimits,*,now:datetime|None=None)->AdmissionReservation:
        if growth_bytes<0: raise AdmissionDenied("INVALID_ARGUMENT","growth reservation cannot be negative")
        current=(now or datetime.now(UTC)).astimezone(UTC); epoch=int(current.timestamp()); window=epoch-(epoch%limits.rate_window_seconds)
        with self._tx():
            self._connection.execute("DELETE FROM reservations WHERE state='active' AND expires_at<=?",(current.isoformat(),))
            prior=self._connection.execute("SELECT * FROM reservations WHERE operation_id=?",(operation_id,)).fetchone()
            if prior:
                if str(prior["project_id"])!=project_id or int(prior["growth_bytes"])!=growth_bytes: raise AdmissionDenied("IDEMPOTENCY_CONFLICT","operation admission differs from its durable reservation")
                return _reservation(prior)
            rate=self._connection.execute("SELECT count FROM rate_windows WHERE project_id=? AND window_start=?",(project_id,window)).fetchone()
            if rate and int(rate["count"])>=limits.max_requests_per_window: raise AdmissionDenied("RATE_LIMITED","project request window is full")
            active=self._connection.execute("SELECT COUNT(*) n FROM reservations WHERE project_id=? AND state='active'",(project_id,)).fetchone()
            held=self._connection.execute("SELECT COALESCE(SUM(growth_bytes),0) growth FROM reservations WHERE project_id=? AND state IN ('active','recovery_hold')",(project_id,)).fetchone()
            if int(active["n"])>=limits.max_concurrent_operations: raise AdmissionDenied("RATE_LIMITED","project concurrency limit is full")
            usage=self._connection.execute("SELECT committed_bytes FROM project_usage WHERE project_id=?",(project_id,)).fetchone()
            committed=int(usage["committed_bytes"]) if usage else 0
            if committed+int(held["growth"])+growth_bytes>limits.max_storage_bytes: raise AdmissionDenied("QUOTA_EXCEEDED","project storage growth limit would be exceeded")
            reservation=AdmissionReservation(f"reservation-{uuid.uuid4().hex}",project_id,operation_id,growth_bytes,(current+timedelta(seconds=limits.lease_seconds)).isoformat())
            self._connection.execute("INSERT INTO reservations VALUES(?,?,?,?,?,?)",(reservation.reservation_id,project_id,operation_id,growth_bytes,"active",reservation.expires_at))
            self._connection.execute("INSERT INTO rate_windows VALUES(?,?,1) ON CONFLICT(project_id,window_start) DO UPDATE SET count=count+1",(project_id,window))
            return reservation

    def commit(self,reservation_id:str,actual_growth_bytes:int)->None:
        if actual_growth_bytes<0: raise ValueError("actual growth cannot be negative")
        with self._tx():
            row=self._connection.execute("SELECT * FROM reservations WHERE reservation_id=?",(reservation_id,)).fetchone()
            if not row: raise KeyError(reservation_id)
            if row["state"]=="committed": return
            if row["state"] not in {"active", "recovery_hold"}: raise AdmissionDenied("INVALID_ARGUMENT","reservation is not settleable")
            if actual_growth_bytes>int(row["growth_bytes"]): raise AdmissionDenied("QUOTA_EXCEEDED","actual growth exceeds reserved growth")
            project=str(row["project_id"])
            self._connection.execute("INSERT INTO project_usage VALUES(?,?) ON CONFLICT(project_id) DO UPDATE SET committed_bytes=committed_bytes+excluded.committed_bytes",(project,actual_growth_bytes))
            self._connection.execute("UPDATE reservations SET state='committed' WHERE reservation_id=?",(reservation_id,))

    def release(self,reservation_id:str)->None:
        with self._tx(): self._connection.execute("UPDATE reservations SET state='released' WHERE reservation_id=? AND state IN ('active','recovery_hold')",(reservation_id,))

    def hold_for_recovery(self,reservation_id:str)->None:
        with self._tx():
            changed=self._connection.execute("UPDATE reservations SET state='recovery_hold' WHERE reservation_id=? AND state='active'",(reservation_id,)).rowcount
            if not changed:
                row=self._connection.execute("SELECT state FROM reservations WHERE reservation_id=?",(reservation_id,)).fetchone()
                if not row or row["state"]!="recovery_hold": raise KeyError(reservation_id)

    def lookup_operation(self,operation_id:str)->AdmissionReservation|None:
        row=self._connection.execute("SELECT * FROM reservations WHERE operation_id=?",(operation_id,)).fetchone()
        return _reservation(row) if row else None

    class _Tx:
        def __init__(self,o): self.o=o
        def __enter__(self): self.o._lock.acquire(); self.o._connection.execute("BEGIN IMMEDIATE")
        def __exit__(self,t,v,b):
            try:self.o._connection.execute("ROLLBACK" if t else "COMMIT")
            finally:self.o._lock.release()
    def _tx(self): return self._Tx(self)


def _reservation(row:sqlite3.Row)->AdmissionReservation:
    return AdmissionReservation(str(row["reservation_id"]),str(row["project_id"]),str(row["operation_id"]),int(row["growth_bytes"]),str(row["expires_at"]))


def _prepare_private_database(path:Path)->None:
    flags=os.O_CREAT|os.O_EXCL|os.O_WRONLY|getattr(os,"O_NOFOLLOW",0)
    try:
        descriptor=os.open(path,flags,0o600)
    except FileExistsError:
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or (hasattr(os,"geteuid") and info.st_uid!=os.geteuid()):
            raise ValueError("admission database must be a process-owned regular file")
        os.chmod(path,0o600,follow_symlinks=False)
    else:
        os.close(descriptor)
