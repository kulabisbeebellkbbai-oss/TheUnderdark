"""Explicit production dependency composition; importing never activates a service."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Sequence
from typing import Callable

from .admission import AdmissionLimits, SQLiteAdmissionController
from .backup_executor import EncryptedBackupExecutor
from .journal import SQLiteOperationJournal
from .mutation_executor import FsContainMutationExecutor
from .pagination import SQLiteSnapshotPaginator
from .production import AuthorizationVerifier, BackupExecutor, ProductionStorageService
from .production_app import create_production_http_app, create_production_mcp
from .read_backend import FsContainReadBackend
from .root_registry import SQLiteRootRegistry
from .runtime_identity import RuntimeIdentity


@dataclass(frozen=True)
class ProductionComposition:
    service: ProductionStorageService
    mcp: object
    http_app: object

@dataclass(frozen=True)
class BackupBinding:
    project_id: str
    root_id: str
    policy_revision: str
    source_root: Path
    artifact_dir: Path
    passphrase_file: Path
    gpg_executable: str = "/usr/bin/gpg"

def build_backup_executor_provider(registry: SQLiteRootRegistry, bindings: Sequence[BackupBinding]):
    """Build an exact-match, deny-by-default provider without touching services."""
    indexed={}
    for binding in bindings:
        key=(binding.project_id,binding.root_id,binding.policy_revision)
        if any(not value or value=="*" for value in key) or key in indexed: raise ValueError("backup bindings require unique exact identities")
        resolved=registry.resolve(binding.project_id,binding.root_id,binding.policy_revision)
        source=Path(binding.source_root).resolve(strict=True)
        if not isinstance(resolved.root,Path) or source!=resolved.root.resolve(strict=True): raise ValueError("backup source must equal the registered root revision")
        indexed[key]=EncryptedBackupExecutor(source_root=source,artifact_dir=binding.artifact_dir,passphrase_file=binding.passphrase_file,gpg_executable=binding.gpg_executable)
    def provide(project_id:str,root_id:str,policy_revision:str)->BackupExecutor:
        try: return indexed[(project_id,root_id,policy_revision)]
        except KeyError as exc: raise PermissionError("no exact backup binding is approved") from exc
    return provide


def compose_production_runtime(
    *,
    registry: SQLiteRootRegistry,
    journal: SQLiteOperationJournal,
    admission: SQLiteAdmissionController,
    paginator: SQLiteSnapshotPaginator,
    verifier: AuthorizationVerifier,
    limits_provider: Callable[[str], AdmissionLimits],
    max_content_bytes: int = 1_048_576,
    max_concurrent_per_project: int = 4,
    backup_executor_provider: Callable[[str, str, str], BackupExecutor] | None = None,
    backup_bindings: Sequence[BackupBinding] = (),
    runtime_identity: RuntimeIdentity,
) -> ProductionComposition:
    """Join already-created protected dependencies without opening a listener."""
    if any(value is None for value in (registry, journal, admission, paginator, verifier, limits_provider)):
        raise TypeError("all production dependencies are required")
    executor = FsContainMutationExecutor(
        registry.resolve_current,
        max_content_bytes=max_content_bytes,
        max_concurrent_per_project=max_concurrent_per_project,
    )
    reads = FsContainReadBackend(registry.resolve_current, registry.root_ids, max_digest_bytes=max_content_bytes)
    if backup_executor_provider is not None and backup_bindings: raise ValueError("configure one backup provider source")
    provider=backup_executor_provider or (build_backup_executor_provider(registry,backup_bindings) if backup_bindings else None)
    service = ProductionStorageService(
        journal=journal,
        verifier=verifier,
        executor=executor,
        admission=admission,
        admission_limits=limits_provider,
        read_backend=reads,
        paginator=paginator,
        backup_executor_provider=provider,
    )
    if not isinstance(runtime_identity, RuntimeIdentity):
        raise TypeError("a verified RuntimeIdentity is required")
    return ProductionComposition(
        service,
        create_production_mcp(service, runtime_identity=runtime_identity),
        create_production_http_app(service, runtime_identity=runtime_identity),
    )


__all__ = ["BackupBinding", "ProductionComposition", "build_backup_executor_provider", "compose_production_runtime"]
