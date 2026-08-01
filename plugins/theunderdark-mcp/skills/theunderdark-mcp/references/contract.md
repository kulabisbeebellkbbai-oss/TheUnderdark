# Agent contract reference

The repository's normative contracts remain authoritative. This portable summary prevents accidental widening of the agent surface.

## Read-only tools

- `underdark_health_get`
- `underdark_project_get`
- `underdark_root_get`
- `underdark_path_stat`
- `underdark_directory_list`
- `underdark_operation_get`

Metadata tools never return arbitrary file content or host root paths.

## Mutation tools

- `underdark_directory_create`
- `underdark_file_write`
- `underdark_path_copy`
- `underdark_path_move`
- `underdark_path_delete`

Every mutation requires `project_id`, the applicable root ID or IDs, `request_id`, `idempotency_key`, `authorization_ref`, `policy_revision`, and a display-safe `reason`. Tool-specific digests, expected metadata, destination modes, and bounded content are also mandatory. Version 1 forbids recursive deletion, glob expansion, arbitrary commands, URLs, callbacks, ownership or permission changes, and special files.

## Lifecycle and evidence

Accept only terminal `succeeded` as success. Treat `accepted`, `authorized`, and `executing` as in progress; resolve uncertain dispatch by operation lookup. Report redacted evidence and stable aliases, never host paths or authorization payloads.
