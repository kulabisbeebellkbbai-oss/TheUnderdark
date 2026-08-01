from __future__ import annotations

import asyncio

import httpx
import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from theunderdark.journal import SQLiteOperationJournal
from theunderdark.production import ProductionStorageService
from theunderdark.production_app import LoopbackBindConfig, create_production_http_app, create_production_mcp


class Dependency:
    pass


def injected_service(tmp_path) -> ProductionStorageService:
    return ProductionStorageService(
        journal=SQLiteOperationJournal(tmp_path / "operations.sqlite3"),
        verifier=Dependency(),
        executor=Dependency(),
        admission=Dependency(),
        admission_limits=lambda _project_id: Dependency(),
        read_backend=Dependency(),
        paginator=Dependency(),
    )


def test_loopback_config_rejects_exposure_without_binding() -> None:
    assert LoopbackBindConfig().host == "127.0.0.1"
    assert LoopbackBindConfig(port=8788).port == 8788
    with pytest.raises(ValueError, match="127.0.0.1"):
        LoopbackBindConfig(host="0.0.0.0", port=8788)
    with pytest.raises(ValueError, match="port"):
        LoopbackBindConfig(port=0)


def test_http_health_is_minimal_and_mcp_route_is_separate(tmp_path) -> None:
    service = injected_service(tmp_path)
    app = create_production_http_app(service)

    async def request_health():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            return await client.get("/health")

    response = asyncio.run(request_health())
    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy",
        "contract_version": "1.0",
        "dependencies": {
            "operation_journal": "ready",
            "authorization_verifier": "ready",
            "bounded_executor": "ready",
            "admission_controller": "ready",
            "read_backend": "ready",
            "snapshot_paginator": "ready",
        },
    }
    assert "operations.sqlite3" not in response.text
    assert any(getattr(route, "path", None) == "/mcp" for route in app.routes)
    service.journal.close()


def test_production_mcp_has_strict_bounded_inventory(tmp_path) -> None:
    service = injected_service(tmp_path)
    mcp = create_production_mcp(service)

    async def exercise():
        tools = await mcp.list_tools()
        async with create_connected_server_and_client_session(mcp) as client:
            invalid = await client.call_tool("underdark_health_get", {"unexpected": True})
        return tools, invalid

    tools, invalid = asyncio.run(exercise())
    assert {tool.name for tool in tools} == {
        "underdark_project_get", "underdark_root_get", "underdark_path_stat",
        "underdark_directory_list", "underdark_operation_get", "underdark_health_get", "underdark_directory_create",
        "underdark_file_write", "underdark_path_copy", "underdark_path_move", "underdark_path_delete",
    }
    assert all(tool.inputSchema.get("additionalProperties") is False for tool in tools)
    assert invalid.isError is True
    service.journal.close()
