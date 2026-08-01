# TheUnderdark storage execution contract

Status: approved design slice; no service or adapter is active.

This document defines the first-version contract between MCP clients,
TheUnderdark, and Overseer. TheUnderdark is a deny-by-default execution
adapter: registration identifies a bounded storage target, while an Overseer
authorization permits one exact mutation. Neither fact implies the other.

## Transport and trust boundary

- The primary transport is MCP Streamable HTTP at
  `http://127.0.0.1:<allocated-port>/mcp`.
- The backend MUST bind only to `127.0.0.1`. A remote route, alternate bind,
  persistent service, or port allocation is outside this contract and requires
  separate coordination and approval.
- MCP session establishment and local-host access authenticate a client
  channel; they do not authorize a filesystem operation.
- Requests MUST use JSON-compatible structured inputs and outputs. Unknown
  fields, unknown enum values, and values outside documented limits MUST fail
  validation rather than be ignored.
- The service MUST expose a non-MCP `GET /health` endpoint that reports only
  service readiness, contract version, and dependency state. It MUST NOT expose
  registrations, host paths, authorization data, or operation results.

## Identifiers and common types

All identifiers are opaque, case-sensitive ASCII strings with a maximum length
of 128 characters. They MUST NOT contain credentials or raw host paths.

- `project_id`: stable Roadex/Overseer project identity.
- `root_id`: stable identity for one registered storage root.
- `request_id`: unique Overseer execution-request identity.
- `operation_id`: stable TheUnderdark identity assigned to an accepted call.
- `idempotency_key`: caller-supplied retry identity, unique within a project.
- `authorization_ref`: immutable reference to the exact Overseer approval or
  approved execution request. It is evidence to verify, not a bearer token.
- `relative_path`: UTF-8 path relative to a registered root, using `/` as the
  separator. Absolute paths, empty components, `.` and `..` components, NUL,
  control characters, URI syntax, and platform-specific drive prefixes are
  invalid.

Timestamps use RFC 3339 UTC. Byte counts are non-negative integers. Digests use
an object such as `{"algorithm":"sha256","value":"<lowercase hex>"}`.

Every successful tool result uses this envelope:

```json
{
  "ok": true,
  "contract_version": "1.0",
  "request_id": "req...",
  "operation_id": "op...",
  "result": {},
  "evidence": {
    "evidence_ids": ["evidence..."],
    "host_state_changed": false,
    "redactions_applied": false
  }
}
```

Read-only calls MAY omit `operation_id` when no durable operation is created.
Failures use the error envelope defined below and never report a mutation as
successful when verification is incomplete.

## Registration model

A project registration contains `project_id`, display-safe label, lifecycle
status (`active`, `suspended`, or `retired`), policy revision, quota profile,
and one or more root registrations. A root registration contains:

- `root_id` and owning `project_id`;
- a canonical host path held only in the protected local configuration;
- a display-safe path alias returned to clients;
- allowed read classes and mutation actions;
- symlink policy, fixed to `deny` in contract version 1;
- per-operation and aggregate quota overrides; and
- registration revision, creator, creation time, and retirement time.

Canonical host paths MUST NOT be accepted from ordinary project agents or
returned by MCP tools. Creating, changing, suspending, or retiring a
registration is an operator control-plane action. It requires a separately
approved Overseer request whose target is the exact `project_id`/`root_id` and
whose action names the registration transition. Registration changes MUST be
durable and audited before they become effective.

A registration MUST NOT overlap another active root after canonical
resolution, unless an explicit policy permits the exact parent/child pairing.
The implementation MUST reject filesystem roots, user home directories,
credential stores, device files, pseudo-filesystems, sockets, and the
TheUnderdark/Overseer state directories. Retiring a registration prevents new
operations but does not erase its audit history.

## MCP tool surface

Tool names below are normative. Every tool declares strict input and output
schemas. Tools in the first group MUST NOT modify host filesystem state.

### Read-only tools

| Tool | Required input | Result |
| --- | --- | --- |
| `underdark_project_get` | `project_id` | Redacted project status, policy revision, quota profile, and root aliases |
| `underdark_root_get` | `project_id`, `root_id` | Root status, allowed actions, limits, and alias; never the host path |
| `underdark_path_stat` | `project_id`, `root_id`, `relative_path` | Type, size, modification time, and optional digest; no content |
| `underdark_directory_list` | project/root/path plus optional bounded `cursor` and `limit` | Sorted child metadata and next cursor |
| `underdark_operation_get` | `project_id`, `operation_id` | Durable lifecycle state and redacted evidence summary |
| `underdark_health_get` | none | MCP-facing readiness and contract version; no sensitive state |

`underdark_path_stat` and `underdark_directory_list` require an active
registration but no mutation approval. The project policy may still require a
read authorization. Directory pagination MUST be stable, bounded, and reject a
cursor issued for a different project, root, path, or policy revision.

Version 1 intentionally provides metadata and digests, not arbitrary file
content reads. A later content-read tool requires a separate data-classification
and response-size design.

### Mutation tools

| Tool | Action | Action-specific input |
| --- | --- | --- |
| `underdark_directory_create` | `directory.create` | `relative_path`, optional `parents` |
| `underdark_file_write` | `file.write` | `relative_path`, bounded UTF-8 or base64 `content`, required `content_digest`, `write_mode` (`create_only` or `replace_exact`) and, for replacement, `expected_prior_digest` |
| `underdark_path_copy` | `path.copy` | source and destination within registered roots, `destination_mode` (`create_only` only in v1) |
| `underdark_path_move` | `path.move` | source and destination within the same registered root, required expected source metadata/digest, `destination_mode` (`create_only` only in v1) |
| `underdark_path_delete` | `path.delete` | `relative_path`, expected type and metadata/digest; `recursive` is always false in v1 |

Every mutation input also requires:

```json
{
  "project_id": "project...",
  "root_id": "root...",
  "request_id": "request...",
  "idempotency_key": "retry...",
  "authorization_ref": "approval...",
  "policy_revision": "revision...",
  "reason": "display-safe bounded purpose"
}
```

Copying across roots additionally names `source_root_id` and
`destination_root_id`; both roots MUST belong to the same project and the exact
pair MUST be authorized. Mutation tools MUST reject wildcards, implicit glob
expansion, arbitrary commands, URLs, callbacks, permission/ownership changes,
special files, and unbounded recursion.

Registration control-plane actions are deliberately not exposed as ordinary
MCP tools in version 1. Overseer adapter registration is also a separate
Overseer change; registering a TheUnderdark project root cannot register or
approve TheUnderdark itself.

## Authorization and execution lifecycle

For each mutation, TheUnderdark MUST:

1. Validate the complete schema and request size without touching the target.
2. Load the active project/root registrations and exact policy revision.
3. Resolve every path using the rules below and snapshot relevant preconditions.
4. Retrieve and validate `authorization_ref` against Overseer. An acknowledged
   crew message is insufficient. The request MUST be pending/claimed by the
   expected adapter, approved, unexpired, and match project, roots, action,
   targets, limits, requester, and acceptance criteria.
5. Reserve the idempotency key and durably record state `accepted` before any
   host mutation.
6. Transition through `authorized` and `executing`; perform only the authorized
   action; then verify postconditions.
7. Finish as `succeeded`, `failed`, or `indeterminate`, with redacted durable
   evidence and an explicit `host_state_changed` value (`true`, `false`, or
   `unknown`).

Normative operation states are `accepted`, `authorized`, `executing`,
`succeeded`, `failed`, `indeterminate`, and `cancelled`. Terminal states are the
last four. Cancellation is allowed only before execution begins. A crash or
timeout after mutation may have started MUST become `indeterminate`, never a
blind retry or a reported success. Reconciliation inspects the recorded
preconditions and postconditions and appends evidence; it does not silently
repeat the action.

Only terminal `succeeded` evidence may satisfy an Overseer workflow. Transport
success, MCP acknowledgment, `accepted`, and `authorized` are not execution
success.

## Path and symlink resolution

Path safety is evaluated against the registered root at execution time, not by
string-prefix comparison.

1. Validate `relative_path` syntax before filesystem access.
2. Open the registered root by a trusted canonical handle.
3. Walk each existing component relative to that handle using no-follow
   semantics. Reject symbolic links, junction-like redirects, mount traversal,
   sockets, devices, FIFOs, and any component that changes during validation.
4. For a new leaf, resolve and validate its existing parent by handle. Recheck
   the parent and target immediately before committing the mutation.
5. Confirm every source, destination, temporary file, and final target remains
   beneath the same registered root device/boundary required by policy.

Symlinks are denied whether they point inside or outside the root. Hard links
are allowed only when the policy explicitly permits regular files with link
count one; otherwise they are rejected. Cross-device moves, mount points, and
filesystem case/Unicode aliases that cannot be compared unambiguously are
rejected. Temporary files MUST be created inside the authorized destination
directory and cleaned up or recorded for reconciliation.

## Idempotency and concurrency

The tuple `(project_id, idempotency_key)` identifies exactly one logical
mutation. The service stores a canonical digest of the validated request,
including authorization and policy revision.

- The same tuple and same digest returns the original operation and result; it
  MUST NOT execute again.
- The same tuple with a different digest returns `IDEMPOTENCY_CONFLICT`.
- An operation already executing returns its current state.
- Authorization expiry after execution starts does not erase evidence, but
  authorization expiry before host mutation prevents execution.

Conflicting paths MUST be serialized by canonical root/path locks. Lock order
must be deterministic for two-path operations. Preconditions such as expected
digest, type, size, and modification identity are checked under the execution
lock to prevent time-of-check/time-of-use replacement.

## Quotas and limits

Limits are the minimum of service, project, root, action, and authorization
limits. Version 1 MUST define finite values for request bytes, decoded content
bytes, files/directories touched, directory page size, operation duration,
concurrent operations per project, and retained evidence. No client may raise a
limit in its request.

Quota is reserved before execution and reconciled afterward. Exceeding a limit
fails closed with `QUOTA_EXCEEDED`; partial completion is not treated as
success. Aggregate storage checks MUST account for replacement and copy growth,
not only incoming payload size.

## Evidence and redaction

Durable evidence records the operation and request IDs, project/root aliases,
action, policy and registration revisions, authorization reference digest,
timestamps, lifecycle transitions, precondition/postcondition metadata,
content digests where allowed, byte/item counts, verification outcome, error
code, and `host_state_changed`.

Responses, errors, logs, health data, and Overseer evidence MUST NOT contain:

- canonical host paths or unregistered path fragments;
- tokens, credentials, environment dumps, private keys, or authorization
  payloads;
- file content, raw databases, personal exports, or temporary-file names; or
- stack traces and framework internals.

Paths are rendered as `project_id/root_id/relative_path`, subject to
classification policy. Free text is length-limited and scrubbed. Evidence
reports whether redaction occurred without returning the removed value.

## Error contract

Tool-level failures use a stable structured result, in addition to the MCP
protocol error when required:

```json
{
  "ok": false,
  "contract_version": "1.0",
  "request_id": "request...",
  "operation_id": "op...",
  "error": {
    "code": "AUTHORIZATION_MISMATCH",
    "message": "The approval does not match the requested action.",
    "retryable": false,
    "details": {}
  },
  "evidence": {
    "evidence_ids": ["evidence..."],
    "host_state_changed": false,
    "redactions_applied": true
  }
}
```

Stable version-1 codes are:

- `INVALID_ARGUMENT`, `REQUEST_TOO_LARGE`, `UNSUPPORTED_ACTION`;
- `PROJECT_NOT_REGISTERED`, `ROOT_NOT_REGISTERED`,
  `REGISTRATION_INACTIVE`, `POLICY_REVISION_MISMATCH`;
- `PATH_INVALID`, `PATH_OUTSIDE_ROOT`, `SYMLINK_DENIED`,
  `SPECIAL_FILE_DENIED`, `PATH_CONFLICT`, `PRECONDITION_FAILED`;
- `AUTHORIZATION_REQUIRED`, `AUTHORIZATION_NOT_APPROVED`,
  `AUTHORIZATION_EXPIRED`, `AUTHORIZATION_MISMATCH`, `CLAIM_MISMATCH`;
- `IDEMPOTENCY_CONFLICT`, `OPERATION_IN_PROGRESS`, `QUOTA_EXCEEDED`,
  `RATE_LIMITED`;
- `SOURCE_NOT_FOUND`, `DESTINATION_EXISTS`, `NOT_EMPTY`;
- `DEPENDENCY_UNAVAILABLE`, `EXECUTION_FAILED`, `VERIFY_FAILED`,
  `RESULT_INDETERMINATE`, and `INTERNAL_ERROR`.

Errors reveal only safe corrective guidance. `retryable` means the identical
request may be retried with the same idempotency key; it never authorizes a new
or changed request.

## Health and readiness

`/health` and `underdark_health_get` distinguish `healthy`, `degraded`, and
`not_ready`. Readiness requires the policy/registration store and durable
operation journal. Mutation readiness additionally requires successful
Overseer verification connectivity. When Overseer is unavailable, mutation
tools fail closed with `DEPENDENCY_UNAVAILABLE`; cached or remembered approval
is insufficient unless a future contract explicitly defines signed offline
authorizations.

Health responses MUST remain harmless to unauthenticated local probes. Detailed
dependency diagnostics belong in protected logs and operator checks.

## Explicit non-goals for version 1

- Arbitrary filesystem browsing, arbitrary file-content reads, shell execution,
  scripts, globbing, archive extraction, or network transfer.
- Recursive deletion, destination overwrite by copy/move, permission or owner
  changes, symlink creation/following, device access, snapshots, mounting,
  encryption-key management, or storage provisioning.
- Acting as an object store, database, backup system, sync engine, secrets
  manager, or general remote file server.
- Treating MCP authentication, resource registration, a crew-message
  acknowledgment, or an adapter health response as mutation approval.
- Automatically registering TheUnderdark with Overseer, changing O'Brien's
  dispatcher, satisfying DonutHole without terminal verified evidence, or
  enabling a service/gateway route as part of this design document.
