from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from theunderdark.backup_contract import load_provisioning_contract
from theunderdark.journal import SQLiteOperationJournal
from theunderdark.production import ACTION_FIELDS, COMMON_FIELDS, ProductionStorageService
from theunderdark.production_app import LoopbackBindConfig, create_production_http_app, create_production_mcp


BACKUP_CONTRACT_FIXTURE = Path(__file__).parent / "fixtures/contracts/donuthole_backup_provisioning_v1.json"


def _contract_schema_view(schema: dict) -> dict:
    return _normalize_schema_value(schema)


def _normalize_schema_value(value):
    if isinstance(value, dict):
        normalized = {
            name: _normalize_schema_value(child)
            for name, child in value.items()
            if name != "title"
        }
        if isinstance(normalized.get("required"), list):
            normalized["required"] = sorted(normalized["required"])
        return normalized
    if isinstance(value, list):
        return [_normalize_schema_value(child) for child in value]
    return value


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


def runtime_identity():
    from theunderdark.runtime_identity import RuntimeIdentity

    return RuntimeIdentity("sha256:" + "a" * 64, "sha256:" + "b" * 64, "sha256:" + "c" * 64)


def test_loopback_config_rejects_exposure_without_binding() -> None:
    assert LoopbackBindConfig().host == "127.0.0.1"
    assert LoopbackBindConfig(port=8788).port == 8788
    with pytest.raises(ValueError, match="127.0.0.1"):
        LoopbackBindConfig(host="0.0.0.0", port=8788)
    with pytest.raises(ValueError, match="port"):
        LoopbackBindConfig(port=0)


def test_http_health_is_minimal_and_mcp_route_is_separate(tmp_path) -> None:
    service = injected_service(tmp_path)
    identity = runtime_identity()
    app = create_production_http_app(service, runtime_identity=identity)

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
        "runtime": {
            "runtime_digest": identity.runtime_digest,
            "config_digest": identity.config_digest,
            "process_start_id": identity.process_start_id,
        },
    }
    assert "operations.sqlite3" not in response.text
    assert any(getattr(route, "path", None) == "/mcp" for route in app.routes)
    service.journal.close()


def test_production_mcp_has_strict_bounded_inventory(tmp_path) -> None:
    service = injected_service(tmp_path)
    mcp = create_production_mcp(service, runtime_identity=runtime_identity())

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
        "underdark_backup_create", "underdark_backup_verify_restore",
    }
    assert all(tool.inputSchema.get("additionalProperties") is False for tool in tools)
    assert invalid.isError is True
    service.journal.close()


def test_production_app_accepts_runtime_identity_only_as_safe_health_extension(tmp_path) -> None:
    service = injected_service(tmp_path)
    identity = runtime_identity()
    app = create_production_http_app(service, runtime_identity=identity)
    assert app is not None
    service.journal.close()


@pytest.mark.parametrize("factory", [create_production_mcp, create_production_http_app])
def test_production_surface_requires_verified_runtime_identity(tmp_path, factory) -> None:
    service = injected_service(tmp_path)
    with pytest.raises(TypeError, match="RuntimeIdentity"):
        factory(service, runtime_identity=None)
    service.journal.close()


def test_production_backup_tool_schemas_match_contract_and_production_constants(tmp_path) -> None:
    service = injected_service(tmp_path)
    contract = load_provisioning_contract(BACKUP_CONTRACT_FIXTURE)

    async def list_tools():
        return {tool.name: tool for tool in await create_production_mcp(service, runtime_identity=runtime_identity()).list_tools()}

    tools = asyncio.run(list_tools())
    for tool_name, action in (
        ("underdark_backup_create", "backup.create"),
        ("underdark_backup_verify_restore", "backup.verify_restore"),
    ):
        actual = _contract_schema_view(tools[tool_name].inputSchema)
        expected = contract.raw["mcp_tools"][tool_name]
        assert set(actual["properties"]) == set(COMMON_FIELDS) | set(ACTION_FIELDS[action])
        assert actual == expected
    service.journal.close()


def test_production_backup_handlers_forward_only_declared_contract_fields(tmp_path) -> None:
    service = injected_service(tmp_path)
    captured: dict[str, dict[str, object]] = {}

    def capture_create(**payload: object) -> dict[str, object]:
        captured["create"] = dict(payload)
        return {"ok": True}

    def capture_verify_restore(**payload: object) -> dict[str, object]:
        captured["verify_restore"] = dict(payload)
        return {"ok": True}

    service.backup_create = capture_create
    service.backup_verify_restore = capture_verify_restore
    create = {
        "project_id": "project.donuthole",
        "root_id": "backup-root",
        "request_id": "request.backup-create",
        "idempotency_key": "backup-create",
        "authorization_ref": "root-auth.backup-root",
        "policy_revision": "1",
        "reason": "disposable backup acceptance",
        "source_root_id": "backup-root",
        "retention_count": 3,
        "encryption_profile": "gpg-symmetric-aes256-iterated-s2k",
    }
    verify_restore = {
        "project_id": "project.donuthole",
        "root_id": "backup-root",
        "request_id": "request.backup-verify",
        "idempotency_key": "backup-verify",
        "authorization_ref": "root-auth.backup-root",
        "policy_revision": "1",
        "reason": "disposable restore acceptance",
        "artifact_id": "backup-fixture",
        "expected_artifact_digest": "sha256:" + "a" * 64,
        "expected_manifest_digest": "sha256:" + "b" * 64,
    }

    async def invoke() -> None:
        async with create_connected_server_and_client_session(create_production_mcp(service, runtime_identity=runtime_identity())) as client:
            await client.call_tool("underdark_backup_create", create)
            await client.call_tool("underdark_backup_verify_restore", verify_restore)

    asyncio.run(invoke())
    assert captured["create"] == create
    assert captured["verify_restore"] == verify_restore
    assert "service" not in captured["create"]
    assert "service" not in captured["verify_restore"]
    service.journal.close()


def test_contract_schema_view_keeps_all_non_presentation_schema_details() -> None:
    schema = {
        "title": "Backup Create",
        "type": "object",
        "additionalProperties": False,
        "minProperties": 2,
        "properties": {
            "retention_count": {
                "title": "Retention Count",
                "type": "integer",
                "minimum": 3,
                "default": 3,
            },
            "profile": {"title": "Profile", "type": "string", "enum": ["expected"]},
        },
        "required": ["profile", "retention_count"],
        "$defs": {"digest": {"title": "Digest", "type": "string", "pattern": "^sha256:"}},
        "allOf": [{"title": "Tighten", "minProperties": 2}],
    }

    assert _contract_schema_view(schema) == {
        "type": "object",
        "additionalProperties": False,
        "minProperties": 2,
        "properties": {
            "retention_count": {"type": "integer", "minimum": 3, "default": 3},
            "profile": {"type": "string", "enum": ["expected"]},
        },
        "required": ["profile", "retention_count"],
        "$defs": {"digest": {"type": "string", "pattern": "^sha256:"}},
        "allOf": [{"minProperties": 2}],
    }
