from __future__ import annotations

import hashlib
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
