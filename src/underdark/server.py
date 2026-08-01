"""FastMCP factory. Server construction is side-effect free and does not bind."""
from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from .service import StorageService


def create_mcp_server(service: StorageService) -> FastMCP:
    mcp = FastMCP("TheUnderdark", instructions="Bounded fixture-only storage execution adapter")

    @mcp.tool(name="underdark_project_get")
    def project_get(project_id: str) -> dict[str, Any]: return service.project_get(project_id)
    @mcp.tool(name="underdark_root_get")
    def root_get(project_id: str, root_id: str) -> dict[str, Any]: return service.root_get(project_id, root_id)
    @mcp.tool(name="underdark_path_stat")
    def path_stat(project_id: str, root_id: str, relative_path: str, include_digest: bool = False) -> dict[str, Any]: return service.path_stat(project_id, root_id, relative_path, include_digest)
    @mcp.tool(name="underdark_directory_list")
    def directory_list(project_id: str, root_id: str, relative_path: str, cursor: str | None = None, limit: int = 100) -> dict[str, Any]: return service.directory_list(project_id, root_id, relative_path, cursor, limit)
    @mcp.tool(name="underdark_operation_get")
    def operation_get(project_id: str, operation_id: str) -> dict[str, Any]: return service.operation_get(project_id, operation_id)
    @mcp.tool(name="underdark_health_get")
    def health_get() -> dict[str, Any]: return service.health_get()
    @mcp.tool(name="underdark_directory_create")
    def directory_create(project_id: str, root_id: str, request_id: str, idempotency_key: str, authorization_ref: str, policy_revision: str, reason: str, relative_path: str, parents: bool = False) -> dict[str, Any]: return service.directory_create(**locals())
    @mcp.tool(name="underdark_file_write")
    def file_write(project_id: str, root_id: str, request_id: str, idempotency_key: str, authorization_ref: str, policy_revision: str, reason: str, relative_path: str, content: str, content_digest: dict[str, str], write_mode: str, content_encoding: str = "utf8", expected_prior_digest: dict[str, str] | None = None) -> dict[str, Any]: return service.file_write(**locals())
    @mcp.tool(name="underdark_path_copy")
    def path_copy(project_id: str, root_id: str, request_id: str, idempotency_key: str, authorization_ref: str, policy_revision: str, reason: str, source_root_id: str, source_relative_path: str, relative_path: str, destination_mode: str = "create_only") -> dict[str, Any]: return service.path_copy(**locals())
    @mcp.tool(name="underdark_path_move")
    def path_move(project_id: str, root_id: str, request_id: str, idempotency_key: str, authorization_ref: str, policy_revision: str, reason: str, source_relative_path: str, relative_path: str, expected_source_digest: dict[str, str] | None = None, expected_source_type: str | None = None, destination_mode: str = "create_only") -> dict[str, Any]: return service.path_move(**locals())
    @mcp.tool(name="underdark_path_delete")
    def path_delete(project_id: str, root_id: str, request_id: str, idempotency_key: str, authorization_ref: str, policy_revision: str, reason: str, relative_path: str, expected_type: str, expected_digest: dict[str, str] | None = None, recursive: bool = False) -> dict[str, Any]: return service.path_delete(**locals())
    return mcp
