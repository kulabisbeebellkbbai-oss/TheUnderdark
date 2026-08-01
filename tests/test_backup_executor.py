from pathlib import Path
import os
import pytest
from theunderdark.backup_executor import EncryptedBackupExecutor,BackupFailure

def setup(tmp_path):
    source=tmp_path/"source"; artifacts=tmp_path/"artifacts"; source.mkdir(); artifacts.mkdir(); artifacts.chmod(0o700); phrase=tmp_path/"passphrase"; phrase.write_text("correct horse battery staple"); phrase.chmod(0o600); return source,artifacts,phrase

def test_encrypted_backup_excludes_sensitive_and_is_idempotent(tmp_path):
    source,artifacts,phrase=setup(tmp_path); (source/"keep.txt").write_text("hello"); (source/".env.local").write_text("SECRET=bad"); (source/"state.sqlite3").write_text("db"); (source/".git").mkdir(); (source/".git/config").write_text("private")
    executor=EncryptedBackupExecutor(source_root=source,artifact_dir=artifacts,passphrase_file=phrase)
    first=executor.execute(); second=executor.execute()
    assert first["ok"] and first["result"]["verified"] and second["result"]["reused"] is True
    assert first["result"]["files"]==1 and len(list(artifacts.glob("backup-*.tar.gpg")))==1
    assert "correct horse" not in repr(first) and str(source) not in repr(first)

def test_symlink_and_special_input_fail_closed(tmp_path):
    source,artifacts,phrase=setup(tmp_path); outside=tmp_path/"outside"; outside.write_text("private"); (source/"link").symlink_to(outside)
    with pytest.raises(BackupFailure) as error: EncryptedBackupExecutor(source_root=source,artifact_dir=artifacts,passphrase_file=phrase).execute()
    assert error.value.code=="SYMLINK_DENIED" and not list(artifacts.glob("backup-*.tar.gpg"))

def test_retains_latest_three_verified_artifacts(tmp_path):
    source,artifacts,phrase=setup(tmp_path); target=source/"file"; executor=EncryptedBackupExecutor(source_root=source,artifact_dir=artifacts,passphrase_file=phrase)
    for value in ("one","two","three","four"): target.write_text(value); result=executor.execute(); assert result["result"]["verified"]
    assert len(list(artifacts.glob("backup-*.tar.gpg")))==3
