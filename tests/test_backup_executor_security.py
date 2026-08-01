from __future__ import annotations

import io
import os
import subprocess
import tarfile
from pathlib import Path

import pytest

from theunderdark.backup_executor import BackupFailure, EncryptedBackupExecutor


def layout(tmp_path: Path):
    source = tmp_path / "project-a"
    artifacts = tmp_path / "artifacts"
    source.mkdir(); artifacts.mkdir(mode=0o700)
    passphrase = tmp_path / "passphrase"
    passphrase.write_text("fixture-key-material")
    passphrase.chmod(0o600)
    return source, artifacts, passphrase


def test_nested_exclusions_are_component_bound_and_case_insensitive(tmp_path: Path) -> None:
    source, artifacts, passphrase = layout(tmp_path)
    (source / "safe").mkdir()
    (source / "safe" / "keep.txt").write_text("keep")
    for name in (".git", ".GIT", "Secrets", "credentials", "node_modules"):
        directory = source / "safe" / name
        directory.mkdir()
        (directory / "private.txt").write_text("must-not-back-up")
    result = EncryptedBackupExecutor(
        source_root=source, artifact_dir=artifacts, passphrase_file=passphrase,
    ).execute()
    assert result["result"]["files"] == 1


def test_directory_symlink_cannot_hide_cross_project_input(tmp_path: Path) -> None:
    source, artifacts, passphrase = layout(tmp_path)
    other_project = tmp_path / "project-b"
    other_project.mkdir()
    sentinel = other_project / "private.txt"
    sentinel.write_text("project-b-secret")
    (source / "project-b-link").symlink_to(other_project, target_is_directory=True)
    with pytest.raises(BackupFailure) as denied:
        EncryptedBackupExecutor(
            source_root=source, artifact_dir=artifacts, passphrase_file=passphrase,
        ).execute()
    assert denied.value.code == "SYMLINK_DENIED"
    assert sentinel.read_text() == "project-b-secret"
    assert not list(artifacts.glob("backup-*.tar.gpg"))


def test_fifo_is_rejected_without_opening_or_persisting_output(tmp_path: Path) -> None:
    source, artifacts, passphrase = layout(tmp_path)
    os.mkfifo(source / "pipe")
    with pytest.raises(BackupFailure) as denied:
        EncryptedBackupExecutor(
            source_root=source, artifact_dir=artifacts, passphrase_file=passphrase,
        ).execute()
    assert denied.value.code == "SPECIAL_FILE_DENIED"
    assert list(artifacts.iterdir()) == []


def test_gpg_argv_is_exact_list_and_never_uses_shell(tmp_path: Path) -> None:
    source, artifacts, passphrase = layout(tmp_path)
    (source / "payload.txt").write_text("payload")
    calls: list[tuple[list[str], dict]] = []

    def recording_popen(argv, **kwargs):
        calls.append((list(argv), dict(kwargs)))
        return subprocess.Popen(argv, **kwargs)

    result = EncryptedBackupExecutor(
        source_root=source, artifact_dir=artifacts, passphrase_file=passphrase,
        process_factory=recording_popen,
    ).execute()
    assert result["ok"] and len(calls) == 2
    encrypt, decrypt = calls
    encrypted_target = Path(encrypt[0][-1])
    assert encrypted_target.parent == artifacts
    assert encrypted_target.name.startswith(".backup-") and encrypted_target.name.endswith(".tar.gpg")
    assert encrypt[0] == [
        "/usr/bin/gpg", "--batch", "--yes", "--pinentry-mode", "loopback",
        "--passphrase-file", str(passphrase), "--cipher-algo", "AES256",
        "--s2k-mode", "3", "--s2k-digest-algo", "SHA512", "--s2k-count",
        "65011712", "--compress-algo", "none", "--symmetric", "--output",
        str(encrypted_target),
    ]
    assert decrypt[0][0:6] == [
        "/usr/bin/gpg", "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase-file",
    ]
    assert all(call[1]["shell"] is False for call in calls)
    assert "fixture-key-material" not in repr(result)


def test_no_plaintext_archive_or_restore_survives_success(tmp_path: Path) -> None:
    source, artifacts, passphrase = layout(tmp_path)
    plaintext = "unique-plaintext-sentinel"
    (source / "payload.txt").write_text(plaintext)
    result = EncryptedBackupExecutor(
        source_root=source, artifact_dir=artifacts, passphrase_file=passphrase,
    ).execute()
    assert result["result"]["verified"] is True
    assert {path.suffix for path in artifacts.iterdir()} in ({".gpg"}, {".gpg", ".verified"})
    assert not list(artifacts.glob(".restore-*"))
    assert not list(artifacts.glob("*.tar"))
    assert all(plaintext.encode() not in path.read_bytes() for path in artifacts.iterdir())


def test_failed_verification_preserves_previous_verified_artifacts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, artifacts, passphrase = layout(tmp_path)
    payload = source / "payload.txt"
    payload.write_text("version-one")
    executor = EncryptedBackupExecutor(
        source_root=source, artifact_dir=artifacts, passphrase_file=passphrase,
    )
    first = executor.execute()
    previous = artifacts / first["result"]["artifact_name"]
    previous_bytes = previous.read_bytes()
    payload.write_text("version-two")
    monkeypatch.setattr(
        executor, "_validate",
        lambda *_: (_ for _ in ()).throw(BackupFailure("VERIFY_FAILED", "verification failed")),
    )
    with pytest.raises(BackupFailure, match="verification failed"):
        executor.execute()
    assert previous.read_bytes() == previous_bytes
    assert list(artifacts.glob("backup-*.tar.gpg")) == [previous]
    assert not list(artifacts.glob(".backup-*"))


def test_restore_validation_denies_parent_traversal_and_cleans_plaintext(tmp_path: Path) -> None:
    source, artifacts, passphrase = layout(tmp_path)
    archive_bytes = io.BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode="w") as archive:
        data = b"escape"
        member = tarfile.TarInfo("../outside.txt")
        member.size = len(data)
        archive.addfile(member, io.BytesIO(data))
    payload = archive_bytes.getvalue()

    class Process:
        def __init__(self):
            self.stdout = io.BytesIO(payload)
            self.returncode = 0

        def communicate(self): return b"", b""
        def poll(self): return 0
        def kill(self): self.returncode = -9

    artifact = artifacts / "backup-invalid.tar.gpg"
    artifact.write_bytes(b"encrypted-placeholder")
    executor = EncryptedBackupExecutor(
        source_root=source, artifact_dir=artifacts, passphrase_file=passphrase,
        process_factory=lambda *_args, **_kwargs: Process(),
    )
    with pytest.raises(BackupFailure) as denied:
        executor._validate(artifact, "0" * 64)
    assert denied.value.code == "VERIFY_FAILED"
    assert not (tmp_path / "outside.txt").exists()
    assert not list(artifacts.glob(".restore-*"))
