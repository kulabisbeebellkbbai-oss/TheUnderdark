"""Explicit production dependency composition; importing never activates a service."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .admission import AdmissionLimits, SQLiteAdmissionController
from .journal import SQLiteOperationJournal
from .mutation_executor import FsContainMutationExecutor
from .pagination import SQLiteSnapshotPaginator
from .production import AuthorizationVerifier, ProductionStorageService
from .production_app import create_production_http_app, create_production_mcp
from .read_backend import FsContainReadBackend
from .root_registry import SQLiteRootRegistry


@dataclass(frozen=True)
class ProductionComposition:
    service: ProductionStorageService
    mcp: object
    http_app: object


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
    service = ProductionStorageService(
        journal=journal,
        verifier=verifier,
        executor=executor,
        admission=admission,
        admission_limits=limits_provider,
        read_backend=reads,
        paginator=paginator,
    )
    return ProductionComposition(service, create_production_mcp(service), create_production_http_app(service))


__all__ = ["ProductionComposition", "compose_production_runtime"]
