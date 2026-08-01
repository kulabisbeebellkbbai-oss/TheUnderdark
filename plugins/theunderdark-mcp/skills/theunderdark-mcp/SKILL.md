---
name: theunderdark-mcp
description: Use TheUnderdark's MCP service for registered Roadex project storage metadata and explicitly approved bounded mutations. Trigger for TheUnderdark operations, Overseer storage workflow execution, O'Brien-approved adapter calls, DonutHole storage requests, or verification of durable redacted storage evidence.
---

# TheUnderdark MCP

Use only the `theunderdark` MCP server configured by this plugin. Treat MCP availability, project registration, adapter readiness, a claim, and an acknowledgment as coordination facts—not mutation authorization.

## Route the request

1. Call `underdark_health_get` before relying on the adapter.
2. For inspection, use only `underdark_project_get`, `underdark_root_get`, `underdark_path_stat`, `underdark_directory_list`, or `underdark_operation_get`.
3. For a mutation, require the exact immutable Overseer authorization fields and action-specific preconditions documented in [the contract reference](references/contract.md).
4. Refuse to invent IDs, host paths, policy revisions, digests, approvals, or successful results.

## Execute a mutation

Before calling a mutation tool, confirm all of the following:

- the project and root are active and the requested action is allowed;
- `request_id`, `authorization_ref`, `policy_revision`, and `idempotency_key` are present;
- the approved action, project, root, relative path, limits, and request digest exactly match;
- the relative path contains no glob, URL, command, special-file target, or implicit recursion;
- required expected metadata or content digests are present.

Use the same idempotency key only for an identical request. If dispatch becomes uncertain, query `underdark_operation_get`; never submit a guessed retry with a new key.

## Report evidence

Report the tool used, operation ID, terminal lifecycle state, and redacted evidence summary. Do not expose host paths, credentials, authorization material, file contents, or private exports. Do not report success from an acknowledgment, claim, healthy response, or non-terminal operation.

For DonutHole or another waiting Overseer workflow, preserve the original blocked request as history and act only on a current superseding request with matching approval.
