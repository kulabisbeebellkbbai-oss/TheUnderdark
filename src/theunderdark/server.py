"""MCP surface. Importing this module never binds a socket."""
from __future__ import annotations

import argparse
from typing import Any

from mcp.server.fastmcp import FastMCP

from .adapter import StorageAdapter

adapter = StorageAdapter()
mcp = FastMCP("TheUnderdark", instructions="Bounded fixture-only storage execution adapter")

@mcp.tool()
def underdark_project_get(project_id: str) -> dict[str, Any]: return adapter.project_get(project_id)
@mcp.tool()
def underdark_root_get(project_id: str, root_id: str) -> dict[str, Any]: return adapter.root_get(project_id, root_id)
@mcp.tool()
def underdark_path_stat(project_id: str, root_id: str, relative_path: str, include_digest: bool = False) -> dict[str, Any]: return adapter.path_stat(project_id, root_id, relative_path, include_digest)
@mcp.tool()
def underdark_directory_list(project_id: str, root_id: str, relative_path: str, cursor: str | None = None, limit: int = 100) -> dict[str, Any]: return adapter.directory_list(project_id, root_id, relative_path, cursor, limit)
@mcp.tool()
def underdark_operation_get(project_id: str, operation_id: str) -> dict[str, Any]: return adapter.operation_get(project_id, operation_id)
@mcp.tool()
def underdark_health_get() -> dict[str, Any]: return adapter.health_get()

@mcp.tool()
def underdark_directory_create(project_id: str, root_id: str, request_id: str, idempotency_key: str, authorization_ref: str, policy_revision: str, reason: str, relative_path: str, parents: bool = False) -> dict[str, Any]:
    return adapter.directory_create(**locals())
@mcp.tool()
def underdark_file_write(project_id: str, root_id: str, request_id: str, idempotency_key: str, authorization_ref: str, policy_revision: str, reason: str, relative_path: str, content: str, content_digest: dict[str, str], write_mode: str, content_encoding: str = "utf8", expected_prior_digest: dict[str, str] | None = None) -> dict[str, Any]:
    return adapter.file_write(**locals())
@mcp.tool()
def underdark_path_copy(project_id: str, root_id: str, request_id: str, idempotency_key: str, authorization_ref: str, policy_revision: str, reason: str, source_root_id: str, source_relative_path: str, relative_path: str, destination_mode: str = "create_only") -> dict[str, Any]:
    return adapter.path_copy(**locals())
@mcp.tool()
def underdark_path_move(project_id: str, root_id: str, request_id: str, idempotency_key: str, authorization_ref: str, policy_revision: str, reason: str, source_relative_path: str, relative_path: str, expected_source_digest: dict[str, str] | None = None, expected_source_type: str | None = None, destination_mode: str = "create_only") -> dict[str, Any]:
    return adapter.path_move(**locals())
@mcp.tool()
def underdark_path_delete(project_id: str, root_id: str, request_id: str, idempotency_key: str, authorization_ref: str, policy_revision: str, reason: str, relative_path: str, expected_type: str, expected_digest: dict[str, str] | None = None, recursive: bool = False) -> dict[str, Any]:
    return adapter.path_delete(**locals())


def _forbid_unknown_tool_arguments(server: FastMCP) -> None:
    """Make FastMCP's generated argument models fail closed on extra keys."""
    for tool in server._tool_manager._tools.values():
        tool.fn_metadata.arg_model.model_config["extra"] = "forbid"
        tool.fn_metadata.arg_model.model_rebuild(force=True)
        tool.parameters = tool.fn_metadata.arg_model.model_json_schema(by_alias=True)


_forbid_unknown_tool_arguments(mcp)

def main() -> None:
    """Run the fixture server over client-spawned stdio only."""
    parser = argparse.ArgumentParser(prog="theunderdark-mcp")
    subcommands = parser.add_subparsers(dest="command", required=True)
    serve = subcommands.add_parser("serve")
    serve.add_argument("--stdio", action="store_true", required=True)
    args = parser.parse_args()
    if args.command == "serve" and args.stdio:
        mcp.run(transport="stdio")

if __name__ == "__main__":
    main()
