"""Strict, versioned contract for disposable DonutHole backup acceptance."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from pathlib import Path
from typing import Mapping

from .production import ACTION_FIELDS, COMMON_FIELDS


PROVISIONING_CONTRACT_VERSION = "1"
_REQUIRED_KEYS = frozenset({
    "version", "canonical_plan_input", "crew_requirements", "root_registration",
    "runtime_identity", "mcp_tools", "acceptance_requests", "scenarios",
})
_TOOL_ACTIONS = {
    "underdark_backup_create": "backup.create",
    "underdark_backup_verify_restore": "backup.verify_restore",
}
_TOOL_FIELDS = {name: COMMON_FIELDS | ACTION_FIELDS[action] for name, action in _TOOL_ACTIONS.items()}
_PLAN_FIELDS = (
    "plan_id", "gpg_sha256", "adapter_commit", "runtime_digest", "capability_digest",
    "root_authorization_refs", "root_registrations", "overseer_token_source_file",
    "overseer_token_file", "cursor_key_file", "evidence_ids",
)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}$")
_COMMIT = re.compile(r"[0-9a-f]{40}$")
_FORBIDDEN_KEYS = frozenset({
    "host_path", "source_path", "path", "token", "password", "pid", "timestamp",
    "created_at", "updated_at",
})
_BACKUP_ENCRYPTION_PROFILE = "gpg-symmetric-aes256-iterated-s2k"


@dataclass(frozen=True)
class ProvisioningContract:
    version: str
    raw: Mapping[str, object]


def canonical_contract_bytes(contract: Mapping[str, object]) -> bytes:
    """Return the sole permitted on-disk representation of a contract."""
    return (json.dumps(contract, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def runtime_artifact_bytes(commit: str, schemas: Mapping[str, object]) -> bytes:
    """Return the canonical immutable bytes for the planned runtime artifact."""
    if not isinstance(commit, str) or _COMMIT.fullmatch(commit) is None:
        raise ValueError("runtime commit must be a 40-character lowercase hexadecimal revision")
    if not isinstance(schemas, Mapping):
        raise ValueError("runtime schemas must be a mapping")
    payload = {"commit": commit, "schemas": schemas, "version": PROVISIONING_CONTRACT_VERSION}
    return canonical_contract_bytes(payload)


def previous_runtime_artifact_bytes(commit: str, schemas: Mapping[str, object]) -> bytes:
    """Return canonical immutable bytes for the known previous runtime artifact."""
    if not isinstance(commit, str) or _COMMIT.fullmatch(commit) is None:
        raise ValueError("runtime commit must be a 40-character lowercase hexadecimal revision")
    if not isinstance(schemas, Mapping):
        raise ValueError("runtime schemas must be a mapping")
    payload = {
        "commit": commit,
        "runtime_state": "previous",
        "schemas": schemas,
        "version": PROVISIONING_CONTRACT_VERSION,
    }
    return canonical_contract_bytes(payload)


def runtime_artifact_identity(commit: str, schemas: Mapping[str, object]) -> str:
    """Bind the planned runtime identity to the SHA-256 of its immutable bytes."""
    return "sha256:" + hashlib.sha256(runtime_artifact_bytes(commit, schemas)).hexdigest()


def previous_runtime_artifact_identity(commit: str, schemas: Mapping[str, object]) -> str:
    """Bind the previous runtime identity to the SHA-256 of its immutable bytes."""
    return "sha256:" + hashlib.sha256(previous_runtime_artifact_bytes(commit, schemas)).hexdigest()


def load_provisioning_contract(path: Path) -> ProvisioningContract:
    """Load one canonical v1 fixture, rejecting unknown fields and malformed values."""
    encoded = path.read_bytes()
    try:
        raw = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid provisioning contract JSON") from error
    if not isinstance(raw, dict) or set(raw) != _REQUIRED_KEYS:
        raise ValueError("invalid provisioning contract fields")
    if encoded != canonical_contract_bytes(raw):
        raise ValueError("provisioning contract is not canonical JSON")
    _validate_contract(raw)
    return ProvisioningContract(version=raw["version"], raw=raw)


def _validate_contract(raw: dict[str, object]) -> None:
    _reject_forbidden_values(raw)
    if raw["version"] != PROVISIONING_CONTRACT_VERSION:
        raise ValueError("unsupported provisioning contract version")
    _validate_plan_input(raw["canonical_plan_input"])
    _validate_crew_requirements(raw["crew_requirements"])
    root = _validate_root_registration(raw["root_registration"])
    schemas = _validate_mcp_tools(raw["mcp_tools"])
    runtime = _validate_runtime_identity(raw["runtime_identity"], schemas)
    requests = _validate_acceptance_requests(raw["acceptance_requests"])
    _validate_scenarios(raw["scenarios"], runtime)
    _validate_cross_references(root, requests)


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _exact_fields(value: object, fields: frozenset[str] | set[str], label: str) -> Mapping[str, object]:
    mapping = _mapping(value, label)
    if set(mapping) != fields:
        raise ValueError(f"invalid {label} fields")
    return mapping


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _digest(value: object, label: str) -> str:
    value = _string(value, label)
    if _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{label} must be a sha256 digest")
    return value


def _validate_plan_input(value: object) -> None:
    mapping = _exact_fields(value, {"kind", "fields"}, "canonical_plan_input")
    if mapping["kind"] != "donuthole_encrypted_backup_provisioning_v1":
        raise ValueError("invalid canonical plan kind")
    if not isinstance(mapping["fields"], list) or tuple(mapping["fields"]) != _PLAN_FIELDS:
        raise ValueError("invalid canonical plan input fields")


def _validate_crew_requirements(value: object) -> None:
    mapping = _exact_fields(value, {"roles", "review_status", "human_approval_required"}, "crew_requirements")
    roles = _exact_fields(mapping["roles"], {"kira", "obrien", "security", "sisko"}, "crew requirement roles")
    if roles != {"kira": "kira", "obrien": "obrien", "security": "odo_ids", "sisko": "sisko"}:
        raise ValueError("invalid crew requirement roles")
    if mapping["review_status"] != "approved" or mapping["human_approval_required"] is not True:
        raise ValueError("invalid crew requirement state")


def _validate_root_registration(value: object) -> Mapping[str, object]:
    mapping = _exact_fields(value, {"alias", "authorization_ref", "max_bytes", "policy_revision", "project_id", "root_id", "root_identity"}, "root_registration")
    for name in ("alias", "authorization_ref", "policy_revision", "project_id", "root_id"):
        _string(mapping[name], f"root_registration.{name}")
    if isinstance(mapping["max_bytes"], bool) or not isinstance(mapping["max_bytes"], int) or mapping["max_bytes"] <= 0:
        raise ValueError("root_registration.max_bytes must be a positive integer")
    _digest(mapping["root_identity"], "root_registration.root_identity")
    return mapping


def _validate_mcp_tools(value: object) -> Mapping[str, object]:
    tools = _exact_fields(value, set(_TOOL_FIELDS), "mcp_tools")
    for name, required_fields in _TOOL_FIELDS.items():
        schema = _exact_fields(tools[name], {"additionalProperties", "properties", "required", "type"}, f"mcp_tools.{name}")
        if schema["type"] != "object":
            raise ValueError(f"mcp_tools.{name}.type must be object")
        if schema["additionalProperties"] is not False:
            raise ValueError(f"mcp_tools.{name} must reject additional properties")
        properties = _mapping(schema["properties"], f"mcp_tools.{name}.properties")
        if set(properties) != required_fields:
            raise ValueError(f"invalid mcp_tools.{name} properties")
        if not isinstance(schema["required"], list) or schema["required"] != sorted(required_fields):
            raise ValueError(f"invalid mcp_tools.{name} required fields")
        for field, definition in properties.items():
            definition = _exact_fields(definition, {"type"}, f"mcp_tools.{name}.{field}")
            expected_type = "integer" if field == "retention_count" else "string"
            if definition["type"] != expected_type:
                raise ValueError(f"invalid mcp_tools.{name}.{field} type")
    return tools


def _validate_runtime_identity(value: object, schemas: Mapping[str, object]) -> Mapping[str, object]:
    mapping = _exact_fields(value, {"commit", "planned_identity", "previous_identity"}, "runtime_identity")
    commit = _string(mapping["commit"], "runtime_identity.commit")
    if _COMMIT.fullmatch(commit) is None:
        raise ValueError("runtime_identity.commit must be a 40-character lowercase hexadecimal revision")
    _digest(mapping["previous_identity"], "runtime_identity.previous_identity")
    expected = runtime_artifact_identity(commit, schemas)
    if mapping["planned_identity"] != expected:
        raise ValueError("runtime_identity.planned_identity does not match commit and schemas")
    if mapping["previous_identity"] == mapping["planned_identity"]:
        raise ValueError("runtime_identity previous identity must differ from planned identity")
    if mapping["previous_identity"] != previous_runtime_artifact_identity(commit, schemas):
        raise ValueError("runtime_identity.previous_identity does not match commit and schemas")
    return mapping


def _validate_acceptance_requests(value: object) -> Mapping[str, object]:
    requests = _exact_fields(value, {"initialize", "tools_list", "project_get", "root_get", "root_list", "nested_list", "backup_create", "backup_verify_restore"}, "acceptance_requests")
    if _exact_fields(requests["initialize"], {"method", "protocol_version"}, "acceptance_requests.initialize") != {"method": "initialize", "protocol_version": "2025-06-18"}:
        raise ValueError("invalid initialize acceptance request")
    if _exact_fields(requests["tools_list"], {"method"}, "acceptance_requests.tools_list") != {"method": "tools/list"}:
        raise ValueError("invalid tools-list acceptance request")
    _validate_lookup_request(requests["project_get"], {"project_id"}, "acceptance_requests.project_get")
    _validate_lookup_request(requests["root_get"], {"project_id", "root_id"}, "acceptance_requests.root_get")
    for name, relative_path in (("root_list", ""), ("nested_list", "nested")):
        request = _exact_fields(requests[name], {"page_size", "project_id", "relative_path", "root_id"}, f"acceptance_requests.{name}")
        if request["relative_path"] != relative_path or isinstance(request["page_size"], bool) or not isinstance(request["page_size"], int) or request["page_size"] != 2:
            raise ValueError(f"invalid acceptance_requests.{name}")
        _string(request["project_id"], f"acceptance_requests.{name}.project_id")
        _string(request["root_id"], f"acceptance_requests.{name}.root_id")
    for request_name, tool_name in (("backup_create", "underdark_backup_create"), ("backup_verify_restore", "underdark_backup_verify_restore")):
        request = _exact_fields(requests[request_name], {"parameters", "tool"}, f"acceptance_requests.{request_name}")
        if request["tool"] != tool_name:
            raise ValueError(f"invalid acceptance_requests.{request_name} tool")
        _validate_tool_parameters(request["parameters"], tool_name, f"acceptance_requests.{request_name}.parameters")
    return requests


def _validate_lookup_request(value: object, fields: set[str], label: str) -> None:
    request = _exact_fields(value, fields, label)
    for name in fields:
        _string(request[name], f"{label}.{name}")


def _validate_tool_parameters(value: object, tool_name: str, label: str) -> None:
    parameters = _exact_fields(value, set(_TOOL_FIELDS[tool_name]), label)
    for name, parameter in parameters.items():
        if name == "retention_count":
            if isinstance(parameter, bool) or not isinstance(parameter, int) or parameter != 3:
                raise ValueError(f"{label}.retention_count must be integer 3")
        elif name == "encryption_profile":
            if parameter != _BACKUP_ENCRYPTION_PROFILE:
                raise ValueError(f"{label}.encryption profile must match BACKUP_ENCRYPTION_PROFILE")
        elif name == "artifact_id":
            artifact_id = _string(parameter, f"{label}.artifact_id")
            if not artifact_id.startswith("backup-"):
                raise ValueError(f"{label}.artifact_id must start with backup-")
        elif name.endswith("digest"):
            _digest(parameter, f"{label}.{name}")
        else:
            _string(parameter, f"{label}.{name}")


def _validate_scenarios(value: object, runtime: Mapping[str, object]) -> None:
    if not isinstance(value, list) or len(value) != 2:
        raise ValueError("scenarios must contain clean-install and active-upgrade cases")
    expected = (("clean_install", "absent", "absent", "absent"), ("active_service_upgrade", "present", "registered", "previous"))
    for scenario, (name, service_state, registration_state, artifact_state) in zip(value, expected, strict=True):
        fields = {"expected_terminal_status", "initial_state", "name"}
        if name == "active_service_upgrade":
            fields |= {"planned_runtime_identity", "previous_runtime_identity"}
        scenario = _exact_fields(scenario, fields, f"scenario {name}")
        if scenario["name"] != name or scenario["expected_terminal_status"] != "acceptance_passed":
            raise ValueError(f"invalid scenario {name}")
        state = _exact_fields(scenario["initial_state"], {"mutable_service_state", "root_registration", "runtime_artifact_identity"}, f"scenario {name} initial_state")
        if state != {"mutable_service_state": service_state, "root_registration": registration_state, "runtime_artifact_identity": artifact_state}:
            raise ValueError(f"invalid scenario {name} initial_state")
        if name == "active_service_upgrade" and (scenario["planned_runtime_identity"] != runtime["planned_identity"] or scenario["previous_runtime_identity"] != runtime["previous_identity"]):
            raise ValueError("active upgrade runtime identities must match runtime_identity")


def _validate_cross_references(root: Mapping[str, object], requests: Mapping[str, object]) -> None:
    for request_name in ("project_get", "root_get", "root_list", "nested_list"):
        request = requests[request_name]
        if isinstance(request, Mapping) and request.get("project_id") != root["project_id"]:
            raise ValueError(f"{request_name} project does not match root registration")
        if request_name != "project_get" and isinstance(request, Mapping) and request.get("root_id") != root["root_id"]:
            raise ValueError(f"{request_name} root does not match root registration")
    for request_name in ("backup_create", "backup_verify_restore"):
        parameters = requests[request_name]["parameters"]
        if parameters["project_id"] != root["project_id"] or parameters["root_id"] != root["root_id"] or parameters["authorization_ref"] != root["authorization_ref"]:
            raise ValueError(f"{request_name} does not match root registration")
        if parameters["policy_revision"] != root["policy_revision"]:
            raise ValueError(f"{request_name} policy revision does not match root registration")
        if request_name == "backup_create" and parameters["source_root_id"] != root["root_id"]:
            raise ValueError("backup_create source root does not match root registration")


def _reject_forbidden_values(value: object) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str) or key in _FORBIDDEN_KEYS:
                raise ValueError("provisioning contract contains forbidden environment-specific data")
            _reject_forbidden_values(child)
    elif isinstance(value, list):
        for child in value:
            _reject_forbidden_values(child)
    elif isinstance(value, str) and value.startswith("/"):
        raise ValueError("provisioning contract contains an absolute path")
