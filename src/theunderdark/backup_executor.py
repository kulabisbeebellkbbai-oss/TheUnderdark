"""Bounded encrypted project backup executor; no service wiring or activation."""
from __future__ import annotations
import hashlib,json,os,shutil,stat,subprocess,tarfile,tempfile
from dataclasses import dataclass
from pathlib import Path,PurePosixPath
from typing import Callable,Mapping

DENIED_DIRS=frozenset({".git",".codex",".agents","node_modules","vendor",".venv","venv","build","dist","coverage",".coverage","__pycache__",".cache","cache","tmp","temp"})
DENIED_NAMES=frozenset({"credentials","credentials.json","secrets","secrets.json","id_rsa","id_ed25519"})
DENIED_SUFFIXES=(".db",".sqlite",".sqlite3",".pem",".key",".p12",".pfx",".pyc")
MANIFEST_NAME="THEUNDERDARK-MANIFEST.json"

@dataclass(frozen=True)
class BackupEvidence:
    artifact_id:str; artifact_name:str; manifest_digest:str; artifact_digest:str; files:int; bytes:int; verified:bool; reused:bool; retained:int; redactions_applied:bool=True

class BackupFailure(RuntimeError):
    def __init__(self,code:str,message:str): super().__init__(message); self.code=code

class EncryptedBackupExecutor:
    def __init__(self,*,source_root:str|Path,artifact_dir:str|Path,passphrase_file:str|Path,gpg_executable:str="/usr/bin/gpg",process_factory:Callable[...,subprocess.Popen]=subprocess.Popen,retain:int=3)->None:
        self.source=_directory(Path(source_root),"source",private=False); self.artifacts=_directory(Path(artifact_dir),"artifact",private=True); self.passphrase=_private_file(Path(passphrase_file)); self.gpg=gpg_executable; self._popen=process_factory
        if retain!=3: raise ValueError("approved retention is exactly three verified artifacts")
        if not Path(gpg_executable).is_absolute(): raise ValueError("gpg executable must be absolute")
        if self.source == self.artifacts or self.source in self.artifacts.parents:
            raise ValueError("artifact directory must be outside the source tree")
        if self.source == self.passphrase or self.source in self.passphrase.parents:
            raise ValueError("passphrase file must be outside the source tree")

    def execute(self)->Mapping[str,object]:
        entries=self._scan(); public_entries=[{key:item[key] for key in ("path","size","sha256","mode")} for item in entries]; manifest={"version":1,"files":public_entries}; manifest_bytes=json.dumps(manifest,sort_keys=True,separators=(",",":")).encode(); manifest_digest=hashlib.sha256(manifest_bytes).hexdigest(); final=self.artifacts/f"backup-{manifest_digest}.tar.gpg"
        if final.exists():
            artifact_digest=self._validate(final,manifest_digest); reused=True
        else:
            fd,temp_name=tempfile.mkstemp(prefix=".backup-",suffix=".tar.gpg",dir=self.artifacts); os.close(fd); temp=Path(temp_name); os.chmod(temp,0o600)
            try:
                self._encrypt(temp,manifest_bytes,entries); artifact_digest=self._validate(temp,manifest_digest); os.replace(temp,final)
            finally:
                try: temp.unlink()
                except FileNotFoundError: pass
            reused=False
        self._mark_verified(final,manifest_digest,artifact_digest)
        retained=self._retain(final)
        total=sum(int(item["size"]) for item in entries)
        evidence=BackupEvidence(f"backup-{manifest_digest}",final.name,manifest_digest,artifact_digest,len(entries),total,True,reused,retained)
        return {"ok":True,"result":evidence.__dict__,"evidence":{"host_state_changed":not reused,"redactions_applied":True}}

    def verify_restore(self,*,artifact_id:str,expected_manifest_digest:str,expected_artifact_digest:str)->Mapping[str,object]:
        """Verify one provider-bound artifact without creating a new backup."""
        manifest_digest=_bare_digest(expected_manifest_digest); artifact_digest=_bare_digest(expected_artifact_digest)
        if artifact_id!=f"backup-{manifest_digest}":
            raise BackupFailure("INVALID_ARGUMENT","artifact identity or digest is invalid")
        artifact=self.artifacts/f"{artifact_id}.tar.gpg"
        if not artifact.is_file() or artifact.is_symlink(): raise BackupFailure("SOURCE_NOT_FOUND","verified artifact was not found")
        actual=self._validate(artifact,manifest_digest)
        if actual!=artifact_digest: raise BackupFailure("VERIFY_FAILED","artifact digest mismatch")
        return {"artifact_id":artifact_id,"manifest_digest":"sha256:"+manifest_digest,"artifact_digest":"sha256:"+actual,"verified":True,"host_state_changed":False,"redactions_applied":True}

    def _scan(self):
        entries=[]
        for base,dirs,files in os.walk(self.source,topdown=True,followlinks=False):
            base_path=Path(base); kept=[]
            for name in sorted(dirs):
                relative=(base_path/name).relative_to(self.source).as_posix()
                if _denied(relative): continue
                if (base_path/name).is_symlink(): raise BackupFailure("SYMLINK_DENIED","symbolic links are denied from backup input")
                kept.append(name)
            dirs[:]=kept
            for name in sorted(files):
                path=base_path/name; relative=path.relative_to(self.source).as_posix()
                if _denied(relative): continue
                info=path.lstat()
                if stat.S_ISLNK(info.st_mode): raise BackupFailure("SYMLINK_DENIED","symbolic links are denied from backup input")
                if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1: raise BackupFailure("SPECIAL_FILE_DENIED","special or hard-linked files are denied")
                digest=hashlib.sha256()
                with path.open("rb") as stream:
                    for chunk in iter(lambda:stream.read(1024*1024),b""): digest.update(chunk)
                entries.append({"path":relative,"size":info.st_size,"sha256":digest.hexdigest(),"mode":stat.S_IMODE(info.st_mode),"device":info.st_dev,"inode":info.st_ino})
        return entries

    def _encrypt(self,target:Path,manifest:bytes,entries:list[dict[str,object]])->None:
        argv=[self.gpg,"--batch","--yes","--pinentry-mode","loopback","--passphrase-file",str(self.passphrase),"--cipher-algo","AES256","--s2k-mode","3","--s2k-digest-algo","SHA512","--s2k-count","65011712","--compress-algo","none","--symmetric","--output",str(target)]
        process=self._popen(argv,stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,shell=False)
        try:
            if process.stdin is None: raise BackupFailure("ENCRYPT_FAILED","encryption pipe is unavailable")
            with tarfile.open(fileobj=process.stdin,mode="w|") as archive:
                info=tarfile.TarInfo(MANIFEST_NAME); info.size=len(manifest); info.mode=0o600; info.mtime=0; archive.addfile(info,__import__("io").BytesIO(manifest))
                for item in entries:
                    path=self.source/str(item["path"]); current=path.stat(follow_symlinks=False)
                    if (current.st_dev,current.st_ino,current.st_size)!=(item["device"],item["inode"],item["size"]): raise BackupFailure("SOURCE_CHANGED","source changed while backup was streaming")
                    member=tarfile.TarInfo(str(item["path"])); member.size=current.st_size; member.mode=int(item["mode"]); member.mtime=0
                    with path.open("rb") as stream: archive.addfile(member,stream)
            process.stdin.close(); process.stdin=None; stderr=process.communicate()[1]
            if process.returncode!=0: raise BackupFailure("ENCRYPT_FAILED","GPG encryption failed")
        except Exception:
            if process.poll() is None: process.kill(); process.communicate()
            raise

    def _validate(self,artifact:Path,expected_manifest_digest:str)->str:
        argv=[self.gpg,"--batch","--yes","--pinentry-mode","loopback","--passphrase-file",str(self.passphrase),"--decrypt",str(artifact)]
        process=self._popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=False)
        restore=Path(tempfile.mkdtemp(prefix=".restore-",dir=self.artifacts)); os.chmod(restore,0o700)
        try:
            if process.stdout is None: raise BackupFailure("VERIFY_FAILED","decryption pipe is unavailable")
            manifest=None; expected=None; restored={}
            with tarfile.open(fileobj=process.stdout,mode="r|") as archive:
                for member in archive:
                    if not member.isfile() or member.issym() or member.islnk(): raise BackupFailure("VERIFY_FAILED","archive contains an unsupported member")
                    relative=PurePosixPath(member.name)
                    if relative.is_absolute() or ".." in relative.parts: raise BackupFailure("VERIFY_FAILED","archive path is unsafe")
                    stream=archive.extractfile(member)
                    if stream is None: raise BackupFailure("VERIFY_FAILED","archive member is unreadable")
                    if member.name==MANIFEST_NAME:
                        if manifest is not None or restored or member.size>1024*1024: raise BackupFailure("VERIFY_FAILED","archive manifest is invalid")
                        data=stream.read(1024*1024+1); manifest=json.loads(data)
                        encoded=json.dumps(manifest,sort_keys=True,separators=(",",":")).encode()
                        if hashlib.sha256(encoded).hexdigest()!=expected_manifest_digest: raise BackupFailure("VERIFY_FAILED","manifest identity mismatch")
                        files=manifest.get("files",[]) if isinstance(manifest,dict) else []
                        if not isinstance(files,list): raise BackupFailure("VERIFY_FAILED","manifest file list is invalid")
                        expected={str(item["path"]):(int(item["size"]),str(item["sha256"])) for item in files}
                        if len(expected)!=len(files): raise BackupFailure("VERIFY_FAILED","manifest contains duplicate paths")
                    else:
                        if expected is None or member.name not in expected or member.name in restored: raise BackupFailure("VERIFY_FAILED","archive member is not declared exactly once")
                        expected_size,expected_hash=expected[member.name]
                        if member.size!=expected_size: raise BackupFailure("VERIFY_FAILED","archive member size does not match manifest")
                        target=restore.joinpath(*relative.parts); target.parent.mkdir(parents=True,exist_ok=True)
                        digest=hashlib.sha256(); written=0
                        with target.open("xb") as output:
                            for chunk in iter(lambda:stream.read(1024*1024),b""):
                                written+=len(chunk)
                                if written>expected_size: raise BackupFailure("VERIFY_FAILED","archive member exceeds declared size")
                                digest.update(chunk); output.write(chunk)
                        if written!=expected_size or digest.hexdigest()!=expected_hash: raise BackupFailure("VERIFY_FAILED","restored content does not match manifest")
                        restored[member.name]=digest.hexdigest()
            stderr=process.communicate()[1]
            if process.returncode!=0 or not isinstance(manifest,dict): raise BackupFailure("VERIFY_FAILED","encrypted backup could not be validated")
            expected={item["path"]:item["sha256"] for item in manifest.get("files",[])}
            if restored!=expected: raise BackupFailure("VERIFY_FAILED","restored content does not match manifest")
            digest=hashlib.sha256()
            with artifact.open("rb") as source:
                for chunk in iter(lambda:source.read(1024*1024),b""): digest.update(chunk)
            return digest.hexdigest()
        finally:
            if process.poll() is None: process.kill(); process.communicate()
            shutil.rmtree(restore,ignore_errors=True)

    def _mark_verified(self,artifact:Path,manifest_digest:str,artifact_digest:str)->None:
        marker=artifact.with_suffix(artifact.suffix+".verified")
        fd,name=tempfile.mkstemp(prefix=".verified-",dir=self.artifacts); temp=Path(name)
        try:
            with os.fdopen(fd,"w",encoding="utf-8") as output: json.dump({"manifest_sha256":manifest_digest,"artifact_sha256":artifact_digest},output,sort_keys=True)
            temp.chmod(0o600); os.replace(temp,marker)
        finally:
            temp.unlink(missing_ok=True)

    def _retain(self,current:Path)->int:
        # Markers are published only after decrypt-and-compare succeeds. Unmarked
        # files are never assumed to be ours and are never deleted.
        verified=[]
        for marker in self.artifacts.glob("backup-*.tar.gpg.verified"):
            artifact=Path(str(marker)[:-len(".verified")])
            if artifact.is_file() and marker.is_file(): verified.append(artifact)
        others=sorted((p for p in verified if p!=current),key=lambda p:p.stat().st_mtime_ns,reverse=True)
        keep={current,*others[:2]}
        for old in verified:
            if old not in keep:
                old.unlink(); old.with_suffix(old.suffix+".verified").unlink(missing_ok=True)
        return len(keep)

def _denied(relative:str)->bool:
    parts=PurePosixPath(relative).parts; lowered=tuple(part.lower() for part in parts); name=lowered[-1] if lowered else relative.lower()
    return any(part in DENIED_DIRS for part in lowered) or name in DENIED_NAMES or name.startswith(".env") or name.endswith(DENIED_SUFFIXES) or any(part in {"secret","secrets","credential","credentials"} for part in lowered)
def _directory(path:Path,label:str,private:bool)->Path:
    if not path.is_absolute() or not path.is_dir() or path.is_symlink(): raise ValueError(f"{label} directory must be an absolute non-symlink directory")
    if private and (stat.S_IMODE(path.stat().st_mode)!=0o700 or path.stat().st_uid!=os.getuid()): raise PermissionError("artifact directory must be owner-owned mode 0700")
    return path.resolve()
def _private_file(path:Path)->Path:
    if not path.is_absolute() or path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode)!=0o600 or path.stat().st_uid!=os.getuid(): raise PermissionError("passphrase file must be an absolute owner-owned mode 0600 regular file")
    return path.resolve()

def _bare_digest(value:str)->str:
    bare=value[7:] if value.startswith("sha256:") else ""
    if len(bare)!=64 or any(character not in "0123456789abcdef" for character in bare): raise BackupFailure("INVALID_ARGUMENT","SHA-256 digest is invalid")
    return bare

__all__=["EncryptedBackupExecutor","BackupFailure","BackupEvidence"]
