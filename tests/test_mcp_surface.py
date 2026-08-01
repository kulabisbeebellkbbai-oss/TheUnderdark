from __future__ import annotations

import asyncio
import importlib.util

import pytest


EXPECTED_TOOLS = {
    "underdark_project_get",
    "underdark_root_get",
    "underdark_path_stat",
    "underdark_directory_list",
    "underdark_operation_get",
    "underdark_health_get",
    "underdark_directory_create",
    "underdark_file_write",
    "underdark_path_copy",
    "underdark_path_move",
    "underdark_path_delete",
}


def test_mcp_inventory_is_exact_and_bounded() -> None:
    if importlib.util.find_spec("mcp") is None:
        pytest.skip("MCP dependency is not installed in this base environment")
    from underdark.server import create_mcp_server
    from underdark.service import StorageService

    tools = asyncio.run(create_mcp_server(StorageService()).list_tools())
    names = {tool.name for tool in tools}
    assert names == EXPECTED_TOOLS
    assert not any(fragment in name for name in names for fragment in ("shell", "execute", "command", "recursive", "register"))
    assert all(tool.inputSchema.get("additionalProperties") is False for tool in tools)


def test_mcp_rejects_unknown_tool_arguments() -> None:
    if importlib.util.find_spec("mcp") is None:
        pytest.skip("MCP dependency is not installed in this base environment")
    from pydantic import ValidationError
    from underdark.server import create_mcp_server
    from underdark.service import StorageService

    server = create_mcp_server(StorageService())
    tool = server._tool_manager._tools["underdark_health_get"]
    with pytest.raises(ValidationError):
        tool.fn_metadata.arg_model.model_validate({"unexpected": True})


def test_import_does_not_bind_or_start_server() -> None:
    if importlib.util.find_spec("mcp") is None:
        pytest.skip("MCP dependency is not installed in this base environment")
    import underdark.server as server

    assert callable(server.create_mcp_server)


def test_fixture_cli_exposes_stdio_only(monkeypatch: pytest.MonkeyPatch) -> None:
    from theunderdark import server

    invoked: list[str] = []
    monkeypatch.setattr(server.mcp, "run", lambda *, transport: invoked.append(transport))
    monkeypatch.setattr("sys.argv", ["theunderdark-mcp", "serve", "--stdio"])
    server.main()
    assert invoked == ["stdio"]
