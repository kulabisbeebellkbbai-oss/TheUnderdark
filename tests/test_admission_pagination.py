from datetime import UTC,datetime,timedelta
import os

import pytest

from theunderdark.admission import AdmissionDenied,AdmissionLimits,SQLiteAdmissionController
from theunderdark.pagination import CursorInvalid,SQLiteSnapshotPaginator


def test_growth_concurrency_rate_and_restart_idempotency(tmp_path):
    path=(tmp_path/"admission.sqlite3").resolve(); limits=AdmissionLimits(10,1,2,60,30); now=datetime.now(UTC)
    with SQLiteAdmissionController(path) as admission:
        admission.set_committed_usage("project",4); first=admission.reserve("project","op-1",5,limits,now=now)
        with pytest.raises(AdmissionDenied) as full: admission.reserve("project","op-2",1,limits,now=now)
        assert full.value.code=="RATE_LIMITED"; admission.commit(first.reservation_id,5)
    with SQLiteAdmissionController(path) as admission:
        same=admission.reserve("project","op-1",5,limits,now=now); assert same.reservation_id==first.reservation_id
        with pytest.raises(AdmissionDenied) as quota: admission.reserve("project","op-2",2,limits,now=now)
        assert quota.value.code=="QUOTA_EXCEEDED"


def test_rate_window_and_expired_concurrency_lease(tmp_path):
    limits=AdmissionLimits(100,1,1,60,1); now=datetime.now(UTC)
    with SQLiteAdmissionController((tmp_path/"a.sqlite3").resolve()) as admission:
        admission.reserve("p","one",1,limits,now=now)
        with pytest.raises(AdmissionDenied) as rate: admission.reserve("p","two",1,limits,now=now+timedelta(seconds=2))
        assert rate.value.code=="RATE_LIMITED"
        assert admission.reserve("p","two",1,limits,now=now+timedelta(seconds=61)).operation_id=="two"


def test_recovery_hold_preserves_unknown_growth_until_settled(tmp_path):
    limits=AdmissionLimits(10,1,10,60,1); now=datetime.now(UTC)
    with SQLiteAdmissionController((tmp_path/"hold.sqlite3").resolve()) as admission:
        held=admission.reserve("p","unknown-op",8,limits,now=now)
        admission.hold_for_recovery(held.reservation_id)
        assert admission.lookup_operation("unknown-op")==held
        with pytest.raises(AdmissionDenied) as quota:
            admission.reserve("p","later-op",3,limits,now=now+timedelta(seconds=61))
        assert quota.value.code=="QUOTA_EXCEEDED"
        admission.commit(held.reservation_id,8)


def test_snapshot_is_stable_and_bound_to_namespace(tmp_path):
    path=(tmp_path/"pages.sqlite3").resolve()
    with SQLiteSnapshotPaginator(path,cursor_key=b"k"*32,max_page_size=2) as pages:
        first=pages.first_page(project_id="p",root_id="r",relative_path="dir",policy_revision="1",namespace_identity="inode:1",entries=[{"name":n,"type":"file","size":1} for n in ("b","c","d")],limit=2)
        assert [e["name"] for e in first.entries]==["b","c"]
        second=pages.next_page(first.next_cursor,project_id="p",root_id="r",relative_path="dir",policy_revision="1",namespace_identity="inode:1",limit=2)
        assert [e["name"] for e in second.entries]==["d"]
        assert first.snapshot_id == second.snapshot_id
        assert first.total_count == second.total_count == 3
        with pytest.raises(CursorInvalid): pages.next_page(first.next_cursor,project_id="p",root_id="r",relative_path="dir",policy_revision="2",namespace_identity="inode:1",limit=2)
        with pytest.raises(CursorInvalid): pages.next_page(first.next_cursor,project_id="p",root_id="r",relative_path="dir",policy_revision="1",namespace_identity="inode:changed",limit=2)


def test_snapshot_accepts_canonical_read_backend_metadata(tmp_path):
    path=(tmp_path/"canonical-pages.sqlite3").resolve()
    entry={"name":"payload.txt","type":"file","size":7,"modified_ns":123,"identity":"sha256:"+"a"*64}
    with SQLiteSnapshotPaginator(path,cursor_key=b"m"*32) as pages:
        first=pages.first_page(project_id="p",root_id="r",relative_path="",policy_revision="1",namespace_identity="sha256:"+"b"*64,entries=[entry],limit=1)
    assert first.entries == (entry,)


def test_state_databases_are_private_and_reject_symlinks(tmp_path):
    admission_path=(tmp_path/"private-admission.sqlite3").resolve()
    pages_path=(tmp_path/"private-pages.sqlite3").resolve()
    with SQLiteAdmissionController(admission_path), SQLiteSnapshotPaginator(pages_path,cursor_key=b"s"*32):
        assert os.stat(admission_path).st_mode & 0o777 == 0o600
        assert os.stat(pages_path).st_mode & 0o777 == 0o600
    target=tmp_path/"target"; target.write_text("sentinel")
    linked=tmp_path/"linked.sqlite3"; linked.symlink_to(target)
    with pytest.raises(ValueError): SQLiteAdmissionController(linked)
