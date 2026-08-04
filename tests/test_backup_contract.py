from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from theunderdark.backup_contract import (
    PROVISIONING_CONTRACT_VERSION,
    canonical_contract_bytes,
    load_provisioning_contract,
)
from theunderdark.production import ACTION_FIELDS, COMMON_FIELDS


FIXTURE = Path(__file__).parent / "fixtures/contracts/donuthole_backup_provisioning_v1.json"
OVERSEER_FIXTURE_ENV = "OVERSEER_DONUTHOLE_CONTRACT_FIXTURE"


def _overseer_fixture() -> Path:
    configured = os.environ.get(OVERSEER_FIXTURE_ENV)
    if not configured:
        pytest.skip(
            "external Overseer contract fixture is intentionally absent; "
            f"set {OVERSEER_FIXTURE_ENV} to verify the mirror"
        )
    path = Path(configured)
    if not path.is_file():
        pytest.fail(f"configured Overseer contract fixture is not a file: {path}")
    return path


def test_fixture_is_canonical_and_backup_schemas_match_production_constants() -> None:
    contract = load_provisioning_contract(FIXTURE)

    assert contract.version == PROVISIONING_CONTRACT_VERSION == "1"
    assert FIXTURE.read_bytes() == canonical_contract_bytes(contract.raw)
    tools = contract.raw["mcp_tools"]
    assert all(schema.get("type") == "object" for schema in tools.values())
    assert set(tools["underdark_backup_create"]["properties"]) == set(COMMON_FIELDS) | set(
        ACTION_FIELDS["backup.create"]
    )
    assert set(tools["underdark_backup_verify_restore"]["properties"]) == set(
        COMMON_FIELDS
    ) | set(ACTION_FIELDS["backup.verify_restore"])


def test_fixture_bytes_match_explicit_overseer_fixture() -> None:
    overseer_fixture = _overseer_fixture()

    assert FIXTURE.read_bytes() == overseer_fixture.read_bytes()
    assert hashlib.sha256(FIXTURE.read_bytes()).digest() == hashlib.sha256(
        overseer_fixture.read_bytes()
    ).digest()


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda raw: raw["acceptance_requests"]["backup_create"]["parameters"].__setitem__(
                "retention_count", True
            ),
            "retention_count",
        ),
        (
            lambda raw: raw["acceptance_requests"]["backup_create"]["parameters"].__setitem__(
                "policy_revision", "2"
            ),
            "backup_create policy revision does not match root registration",
        ),
        (
            lambda raw: raw["acceptance_requests"]["backup_verify_restore"]["parameters"].__setitem__(
                "policy_revision", "2"
            ),
            "backup_verify_restore policy revision does not match root registration",
        ),
        (
            lambda raw: raw["acceptance_requests"]["backup_create"]["parameters"].__setitem__(
                "source_root_id", "different-root"
            ),
            "backup_create source root does not match root registration",
        ),
        (
            lambda raw: (
                raw["runtime_identity"].__setitem__(
                    "previous_identity", raw["runtime_identity"]["planned_identity"]
                ),
                raw["scenarios"][1].__setitem__(
                    "previous_runtime_identity", raw["runtime_identity"]["planned_identity"]
                ),
            ),
            "previous identity must differ",
        ),
        (
            lambda raw: raw["acceptance_requests"]["root_list"].__setitem__("page_size", 2.0),
            "invalid acceptance_requests.root_list",
        ),
        (
            lambda raw: raw["acceptance_requests"]["nested_list"].__setitem__("page_size", 2.0),
            "invalid acceptance_requests.nested_list",
        ),
        (
            lambda raw: raw["acceptance_requests"]["backup_create"]["parameters"].__setitem__(
                "retention_count", 3.0
            ),
            "retention_count",
        ),
        (
            lambda raw: raw["acceptance_requests"]["backup_create"]["parameters"].__setitem__(
                "encryption_profile", "unapproved-profile"
            ),
            "encryption profile must match BACKUP_ENCRYPTION_PROFILE",
        ),
        (
            lambda raw: raw["acceptance_requests"]["backup_verify_restore"]["parameters"].__setitem__(
                "artifact_id", "artifact-contract-v1"
            ),
            "artifact_id must start with backup-",
        ),
    ],
)
def test_parser_rejects_every_task_1_contract_mutation(tmp_path: Path, mutation, message: str) -> None:
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    mutation(raw)
    path = tmp_path / "invalid-contract.json"
    path.write_bytes(canonical_contract_bytes(raw))

    with pytest.raises(ValueError, match=message):
        load_provisioning_contract(path)


def test_parser_rejects_noncanonical_bytes(tmp_path: Path) -> None:
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    path = tmp_path / "noncanonical-contract.json"
    path.write_text(json.dumps(raw, indent=2), encoding="utf-8")

    with pytest.raises(ValueError, match="canonical JSON"):
        load_provisioning_contract(path)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda schema: schema.pop("type", None),
        lambda schema: schema.__setitem__("type", "array"),
        lambda schema: schema.__setitem__("$defs", {"helper": {"type": "string"}}),
        lambda schema: schema.__setitem__("allOf", [{"minProperties": 1}]),
        lambda schema: schema.__setitem__("minProperties", 1),
    ],
)
def test_parser_rejects_missing_wrong_or_unreviewed_top_level_tool_schema_keywords(
    tmp_path: Path, mutation
) -> None:
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    mutation(raw["mcp_tools"]["underdark_backup_create"])
    path = tmp_path / "invalid-tool-schema.json"
    path.write_bytes(canonical_contract_bytes(raw))

    with pytest.raises(ValueError):
        load_provisioning_contract(path)
