"""Run an in-memory MCP initialize/list/call smoke without binding a socket."""

from __future__ import annotations

import asyncio

from mcp.shared.memory import create_connected_server_and_client_session

from underdark.server import create_mcp_server
from underdark.service import StorageService


async def smoke() -> None:
    server = create_mcp_server(StorageService())
    async with create_connected_server_and_client_session(
        server, raise_exceptions=True
    ) as session:
        tools = await session.list_tools()
        names = {tool.name for tool in tools.tools}
        if len(names) != 11 or "underdark_health_get" not in names:
            raise RuntimeError(f"unexpected MCP tool inventory: {sorted(names)}")

        valid = await session.call_tool("underdark_health_get", {})
        if valid.isError:
            raise RuntimeError("health tool returned an MCP error")

        invalid = await session.call_tool(
            "underdark_path_stat",
            {
                "project_id": "missing",
                "root_id": "missing",
                "relative_path": "../escape",
            },
        )
        result = invalid.structuredContent
        if invalid.isError or not result or result.get("ok") is not False:
            raise RuntimeError("invalid-input call did not return a controlled result")

        print(
            "ok "
            f"tools={len(names)} "
            "valid=underdark_health_get "
            f"invalid={result['error']['code']}"
        )


if __name__ == "__main__":
    asyncio.run(smoke())
