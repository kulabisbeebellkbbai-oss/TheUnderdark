"""Side-effect-free HTTP/MCP composition for an injected production service."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from .production import CONTRACT_VERSION, ProductionStorageService


@dataclass(frozen=True)
class LoopbackBindConfig:
    """Validated bind intent; constructing it never opens a socket."""

    host: str = "127.0.0.1"
    port: int | None = None

    def __post_init__(self) -> None:
        if self.host != "127.0.0.1":
            raise ValueError("production HTTP may bind only to 127.0.0.1")
        if self.port is not None and not 1 <= self.port <= 65535:
            raise ValueError("port must be between 1 and 65535")


def _strict(mcp: FastMCP) -> None:
    """Make FastMCP's generated Pydantic argument models reject extras."""

    for tool in mcp._tool_manager._tools.values():
        tool.fn_metadata.arg_model.model_config["extra"] = "forbid"
        tool.fn_metadata.arg_model.model_rebuild(force=True)
        tool.parameters = tool.fn_metadata.arg_model.model_json_schema(by_alias=True)


def _health_payload(service: ProductionStorageService) -> dict[str, Any]:
    dependencies = {
        "operation_journal": getattr(service, "journal", None),
        "authorization_verifier": getattr(service, "verifier", None),
        "bounded_executor": getattr(service, "executor", None),
        "admission_controller": getattr(service, "admission", None),
        "read_backend": getattr(service, "read_backend", None),
        "snapshot_paginator": getattr(service, "paginator", None),
    }
    ready = all(value is not None for value in dependencies.values())
    return {
        "status": "healthy" if ready else "not_ready",
        "contract_version": CONTRACT_VERSION,
        "dependencies": {name: "ready" if value is not None else "not_ready" for name, value in dependencies.items()},
    }


def create_production_mcp(service: ProductionStorageService) -> FastMCP:
    """Create the production MCP tool surface without binding or running it."""

    if not isinstance(service, ProductionStorageService):
        raise TypeError("an injected ProductionStorageService is required")
    mcp = FastMCP("TheUnderdark", instructions="Approval-bound production storage execution adapter")

    @mcp.tool(name="underdark_project_get")
    def project_get(project_id: str) -> dict[str, Any]:
        return service.project_get(project_id)

    @mcp.tool(name="underdark_root_get")
    def root_get(project_id: str, root_id: str) -> dict[str, Any]:
        return service.root_get(project_id, root_id)

    @mcp.tool(name="underdark_path_stat")
    def path_stat(project_id: str, root_id: str, relative_path: str, include_digest: bool = False) -> dict[str, Any]:
        return service.path_stat(project_id, root_id, relative_path, include_digest)

    @mcp.tool(name="underdark_directory_list")
    def directory_list(project_id: str, root_id: str, relative_path: str, policy_revision: str = "", cursor: str | None = None, limit: int = 100) -> dict[str, Any]:
        return service.directory_list(project_id, root_id, relative_path, policy_revision, cursor, limit)

    @mcp.tool(name="underdark_operation_get")
    def operation_get(project_id: str, operation_id: str) -> dict[str, Any]:
        return service.operation_get(project_id, operation_id)

    @mcp.tool(name="underdark_health_get")
    def health_get() -> dict[str, Any]:
        return {"ok": True, "contract_version": CONTRACT_VERSION, "result": _health_payload(service)}

    @mcp.tool(name="underdark_directory_create")
    def directory_create(project_id: str, root_id: str, request_id: str, idempotency_key: str, authorization_ref: str, policy_revision: str, reason: str, relative_path: str, parents: bool = False) -> dict[str, Any]:
        return service.directory_create(**locals())

    @mcp.tool(name="underdark_file_write")
    def file_write(project_id: str, root_id: str, request_id: str, idempotency_key: str, authorization_ref: str, policy_revision: str, reason: str, relative_path: str, content: str, content_digest: dict[str, str], write_mode: str, content_encoding: str = "utf8", expected_prior_digest: dict[str, str] | None = None) -> dict[str, Any]:
        return service.file_write(**locals())

    @mcp.tool(name="underdark_path_copy")
    def path_copy(project_id: str, root_id: str, request_id: str, idempotency_key: str, authorization_ref: str, policy_revision: str, reason: str, source_root_id: str, source_relative_path: str, relative_path: str, destination_mode: str = "create_only") -> dict[str, Any]:
        return service.path_copy(**locals())

    @mcp.tool(name="underdark_path_move")
    def path_move(project_id: str, root_id: str, request_id: str, idempotency_key: str, authorization_ref: str, policy_revision: str, reason: str, source_relative_path: str, relative_path: str, expected_source_digest: dict[str, str] | None = None, expected_source_type: str | None = None, destination_mode: str = "create_only") -> dict[str, Any]:
        return service.path_move(**locals())

    @mcp.tool(name="underdark_path_delete")
    def path_delete(project_id: str, root_id: str, request_id: str, idempotency_key: str, authorization_ref: str, policy_revision: str, reason: str, relative_path: str, expected_type: str, expected_digest: dict[str, str] | None = None, recursive: bool = False) -> dict[str, Any]:
        return service.path_delete(**locals())

    _strict(mcp)
    return mcp


def create_production_http_app(service: ProductionStorageService):
    """Compose GET /health and Streamable HTTP /mcp without opening a listener."""

    mcp = create_production_mcp(service)
    app = mcp.streamable_http_app()

    async def health(_request: Request) -> JSONResponse:
        return JSONResponse(_health_payload(service))

    app.routes.insert(0, Route("/health", health, methods=["GET"], name="health"))
    return app


__all__ = ["LoopbackBindConfig", "create_production_http_app", "create_production_mcp"]
