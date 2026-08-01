# Proposed Overseer storage-adapter contract

Status: proposed design for separate review. Nothing in this document registers,
enables, calls, installs, or restarts TheUnderdark or changes Overseer state.

This contract defines the paired Overseer change required for TheUnderdark to
serve as a bounded storage execution adapter. It extends, rather than weakens,
Overseer's current fail-closed behavior: today O'Brien deliberately skips every
`storage.*` request because no approved bounded adapter exists. A generic
resource record, healthy MCP endpoint, acknowledged crew message, or approved
adapter installation MUST NOT by itself authorize a storage mutation.

## Existing seams and compatibility gap

Overseer currently provides typed resources and claims, approval records, crew
messages, and generic `ExecutionRequest`/`ExecutionResult` records. These remain
authoritative for coordination, but the generic execution types do not bind an
operation to project/root aliases, exact targets, policy revision, approval and
claim expiry, idempotency, postconditions, or an indeterminate result. Their
`changed_host_state()` helper also infers change from `live + completed`; storage
results need an explicit three-valued field.

The paired implementation therefore adds storage-specific records and a typed
client. It MUST NOT silently reinterpret existing generic execution records as
storage authorization.

## Adapter registry record

Overseer stores a durable, revisioned `StorageAdapterRegistration`:

```json
{
  "adapter_id": "storage-adapter.theunderdark",
  "kind": "bounded_storage_v1",
  "contract_version": "1.0",
  "display_name": "TheUnderdark",
  "endpoint_ref": "loopback-service.theunderdark",
  "transport": "streamable_http",
  "tool_prefix": "underdark_",
  "owner_domain": "obrien",
  "operator_owner": "local-operator",
  "allowed_resource_prefixes": ["storage."],
  "allowed_actions": ["directory.create", "file.write", "path.copy", "path.move", "path.delete"],
  "status": "registered",
  "registration_revision": 1,
  "capability_digest": "sha256:...",
  "approval_id": null,
  "approved_revision": null,
  "enabled_at": null,
  "expires_at": null,
  "revoked_at": null,
  "created_at": "...",
  "updated_at": "..."
}
```

`endpoint_ref` resolves through protected local configuration; public API, CLI,
crew messages, evidence, and logs MUST NOT reveal tokens or configuration file
paths. The registered endpoint MUST be loopback. The capability digest covers
the contract version, endpoint identity, tool catalog, action allowlist, result
schema, and client trust settings. Any covered change creates a new revision and
automatically disables the prior approval until the new revision is approved.

Registry states are `registered`, `approval_pending`, `approved`, `enabled`,
`suspended`, `expired`, `revoked`, and `retired`. Only `enabled` can accept new
dispatches. Exactly one enabled adapter may own a resource/action tuple in v1;
ambiguous routing fails closed.

## Approval and enablement lifecycle

Registration readiness is owned by O'Brien. Because version 1 is mutation
capable, initial activation and every capability-changing revision also require
an exact human/Sisko approval under Overseer's high-risk enablement precedent:

1. Register a disabled record after schema and capability validation.
2. Stage an exact approval request binding `adapter_id`, registration revision,
   capability digest, contract version, endpoint identity, allowed resource
   prefix/actions, expiry, rollback steps, and required verification evidence.
3. O'Brien records readiness acceptance for the exact package. Human/Sisko
   approval is then mandatory for activation of that exact mutation-capable
   revision; neither approval substitutes for the other.
4. Approval changes the registry to `approved`; it does not enable dispatch.
5. A separately gated enable step verifies health and MCP capabilities against
   the approved digest, then atomically records `enabled`.
6. Suspension, expiry, revocation, capability drift, or failed trust validation
   prevents new requests immediately. Retirement is irreversible and preserves
   audit history.

Adapter approval authorizes the integration capability, not an individual
operation. Every mutation still needs an active storage resource registration,
an active compatible claim, and an exact unexpired operation approval.

## Storage execution request

Overseer creates an immutable `StorageExecutionRequest` after coordination and
approval checks. The canonical request digest is stored before dispatch.

```json
{
  "request_id": "storage-request...",
  "adapter_id": "storage-adapter.theunderdark",
  "adapter_revision": 1,
  "contract_version": "1.0",
  "project_id": "project.donuthole",
  "resource_id": "storage.donuthole...",
  "root_id": "root...",
  "action": "file.write",
  "parameters": {"relative_path": "...", "write_mode": "create_only", "content_digest": {"algorithm": "sha256", "value": "..."}},
  "policy_revision": "...",
  "claim_id": "claim...",
  "approval_id": "approval...",
  "authorization_ref": "authorization...",
  "idempotency_key": "...",
  "requested_by": "project.donuthole",
  "reason": "bounded display-safe purpose",
  "acceptance_criteria": ["..."],
  "limits": {"max_bytes": 0, "max_items": 0, "deadline_at": "..."},
  "created_at": "...",
  "expires_at": "...",
  "request_digest": "sha256:..."
}
```

For two-root operations the request names source and destination root IDs and
the approval binds the exact pair. Canonical host paths and content are never
placed in this record. Overseer validates that the resource, claim, approval,
adapter revision, action, targets, requester, limits, and acceptance criteria
all match; TheUnderdark independently retrieves and validates the authorization
instead of trusting caller assertions.

## Claim semantics

- Mutations require a compatible exclusive claim (`lease`, `lock`, `checkout`,
  or `hold`) in `approved` or `active` state. `requested`, `queued`, `blocked`,
  `releasing`, `released`, `expired`, or `revoked` claims cannot dispatch.
- The claim MUST identify the same `storage.*` resource, requesting project,
  action intent, dependency set, and risk level used by the execution request.
- The dispatcher activates an approved claim before accepting the operation and
  durably links the operation ID when acceptance is returned.
- A claim cannot expire before the request deadline. Claim expiry or revocation
  before host mutation cancels/blocks execution. Once mutation may have begun,
  revocation stops further steps where safe but does not erase or rewrite the
  result; the outcome may be `indeterminate` and requires reconciliation.
- Claims release only after a terminal result is durably stored. `indeterminate`
  claims remain held or enter an explicit recovery hold until reconciliation.
- Read-only metadata operations may use an observation claim when project policy
  requires it; they never inherit mutation authorization from that claim.

## Typed client boundary

Overseer uses a narrow interface, implemented by a Streamable HTTP MCP client:

```python
class BoundedStorageAdapterClient(Protocol):
    def capabilities(self) -> StorageAdapterCapabilities: ...
    def health(self) -> StorageAdapterHealth: ...
    def submit(self, request: StorageExecutionRequest) -> StorageExecutionReceipt: ...
    def get_operation(self, project_id: str, operation_id: str) -> StorageExecutionResult: ...
```

`submit` calls exactly one action-mapped `underdark_*` tool. It never constructs
tool names from untrusted text. Receipt states are `accepted`, `authorized`, or
an explicit rejection and include `operation_id`, `request_id`, request digest,
and adapter revision. Transport success is not execution success. Long-running
work is polled through `underdark_operation_get`; polling is bounded and
cancellable. The client validates strict response schemas, matching IDs and
digests, contract version, finite timestamps/counts, and known enums. Unknown or
malformed values become typed failures rather than successful generic results.

Client errors include `ADAPTER_DISABLED`, `ADAPTER_UNAVAILABLE`,
`CONTRACT_MISMATCH`, `CAPABILITY_DRIFT`, `REQUEST_REJECTED`, `AUTHORIZATION_INVALID`,
`CLAIM_INVALID`, `IDEMPOTENCY_CONFLICT`, `RESULT_INVALID`, and `TIMEOUT_UNKNOWN`.
Secrets, response bodies, and stack traces are not copied into public evidence.

## Result and evidence mapping

TheUnderdark's operation envelope maps to a storage-specific Overseer result:

| TheUnderdark state | Overseer storage status | Crew/workflow meaning |
| --- | --- | --- |
| `accepted`, `authorized`, `executing` | `in_progress` | Never complete or approved |
| `succeeded` with verified evidence | `completed` | May satisfy exact acceptance criteria |
| `failed` | `failed` | Terminal failure; no blind retry |
| `indeterminate` | `indeterminate` | Recovery hold and reconciliation required |
| `cancelled` | `cancelled` | Terminal only when mutation never began |

`StorageExecutionResult` records request/operation IDs, adapter ID and revision,
request digest, status, action, redacted summary, evidence IDs, started/finished
timestamps, verification outcome, stable error code, and explicit
`host_state_changed` (`true`, `false`, or `unknown`). It is immutable except for
append-only reconciliation records.

Overseer stores its own evidence wrapper referencing—not copying—the adapter's
redacted evidence. Before a crew message can become `approved`, the dispatcher
MUST verify all of the following: result is terminal `completed`; IDs, digest,
adapter revision, project/resource/root/action, approval, and claim match; each
required evidence ID resolves; postconditions satisfy every acceptance
criterion; `host_state_changed` is the expected value; and redaction validation
passes. A receipt, dispatch evidence, crew acknowledgment, or `in_progress`
state is insufficient.

For failure, cancellation, timeout, or indeterminate outcomes, O'Brien records
correction/recovery evidence and does not approve the crew request. Existing
request evidence IDs are preserved and deduplicated when terminal evidence is
appended.

## Dispatcher integration

The current hard-coded O'Brien `storage.*` rejection remains the fallback. The
new branch runs only when a single enabled, unexpired, capability-matching
adapter exists.

1. Validate the crew message has a registered `storage.*` resource, exact
   operation request, acceptance criteria, and durable request evidence.
2. Resolve the adapter by kind/resource/action; reject ambiguous or absent
   routes with the existing correction behavior.
3. Revalidate adapter enablement, operation approval, claim, expiry, and request
   digest immediately before dispatch.
4. Persist dispatch intent and idempotency tuple before making the client call.
5. Submit once, persist the receipt, and poll/get by operation ID. Never create
   a new idempotency key for a transport retry.
6. Map and validate terminal evidence. Only then close the execution request,
   release its claim, and approve the crew workflow.

The dispatcher MUST NOT fall back to package maintenance, generic
`DryRunExecutor`, shell execution, an alternate adapter, or a new request after
a storage dispatch fails.

## Idempotency, failures, and reconciliation

Overseer enforces uniqueness for `(adapter_id, project_id, idempotency_key)` and
stores the canonical request digest. Same key/same digest returns the existing
record; same key/different digest returns `IDEMPOTENCY_CONFLICT`. Retries reuse
the original request ID, idempotency key, and digest.

Failures before an accepted receipt are `not_dispatched` only when Overseer can
prove no operation was created. Connection loss after submission is
`dispatch_unknown`; reconciliation queries by request/idempotency identity and
MUST NOT resubmit blindly. Timeout after execution may have started maps to
`indeterminate`, even if a generic client would normally label it failed.

The reconciler scans nonterminal, dispatch-unknown, and indeterminate records;
revalidates adapter trust; retrieves existing operation state; checks evidence
digests and postconditions; appends a reconciliation record; and either maps a
known terminal result or retains/escalates the recovery hold. It never repeats a
mutation. Manual resolution requires a new approval that references the prior
request/result and declares the observed host state.

Adapter revocation blocks new dispatches immediately. Already accepted work is
queried only through the revoked revision's read-only status boundary. If that
boundary is unavailable, records remain indeterminate until independently
reconciled. Approval or claim revocation never deletes evidence.

## Proposed API and CLI shapes

Names are proposed and MUST receive Overseer review before implementation.

| Purpose | API | CLI |
| --- | --- | --- |
| List/get redacted capabilities | `GET /storage-adapters`, `GET /storage-adapters/{id}` | `storage-adapter-list`, `storage-adapter-status` |
| Stage registration | `POST /storage-adapters/registrations` | `register-storage-adapter` |
| Request/decide enablement | `POST /storage-adapters/{id}/enablement-requests`, `POST .../approve` | `request-storage-adapter-enablement`, `approve-storage-adapter-enablement` |
| Enable/suspend/revoke | `POST /storage-adapters/{id}/enable`, `/suspend`, `/revoke` | `enable-storage-adapter`, `suspend-storage-adapter`, `revoke-storage-adapter` |
| Stage/approve operation | `POST /storage-execution-requests`, `POST /storage-execution-requests/{id}/approve` | `stage-storage-execution`, `approve-storage-execution` |
| Dispatch/status | `POST /storage-execution-requests/{id}/dispatch`, `GET /storage-execution-requests/{id}` | `dispatch-storage-execution`, `storage-execution-status` |
| Reconcile | `POST /storage-execution-requests/{id}/reconcile` | `reconcile-storage-execution` |

All mutation endpoints require existing Overseer authentication and CSRF/session
protections where applicable, reject unknown fields, accept an exact record
revision, and return redacted typed envelopes. List/status routes never return
endpoint credentials, canonical host paths, content, or raw authorization data.

## Migration and backward compatibility

- Add new storage-specific tables/records through an additive schema migration;
  do not rewrite existing resources, claims, approvals, crew messages, or
  generic execution results.
- Default registry state is empty/disabled, preserving today's hard stop.
- Existing `storage.*` messages, including DonutHole's correction-requested
  items, are not silently reopened or executed. After enablement, an operator or
  project submits a superseding message and new immutable execution request that
  references the prior message/evidence.
- Existing generic `ExecutionStatus` and `changed_host_state()` semantics remain
  unchanged for non-storage adapters. Storage code uses its explicit result type.
- API additions are versioned and optional. Older clients continue to see the
  current correction request; they never gain mutation capability accidentally.
- Rollback disables/removes routing to the new adapter while preserving records
  and restoring the existing storage rejection branch. Database downgrade must
  not be required to stop execution.

## Separately gated implementation sequence

Each numbered stage requires its own review; approval of this document does not
authorize later stages.

1. **Contract review:** approve schemas, lifecycle, claim semantics, redaction,
   reconciliation, and DonutHole acceptance fixtures.
2. **Overseer code and migration:** implement storage-specific records, client
   abstraction, API/CLI, dispatcher branch, and tests in the Overseer repository.
   No live endpoint or registration.
3. **TheUnderdark local implementation:** implement MCP tools and fixture-only
   tests in this repository. No shared port or persistent service.
4. **Loopback integration test:** separately coordinate a temporary unique port
   and test roots; validate initialize/list/call, failure, retry, crash, expiry,
   revocation, and reconciliation paths.
5. **Persistent service plan:** stage and approve port reservation, least-
   privilege runtime, local configuration, installation, and restart/rollback.
6. **Adapter registration:** stage the exact disabled registry record and verify
   its capability digest. Registration alone cannot dispatch.
7. **O'Brien enablement approval:** review contract/test/security evidence,
   expiry and rollback; approve the exact adapter revision; then separately
   enable and verify it.
8. **DonutHole acceptance:** create a superseding request and exact operation
   approval, acquire/activate the claim, execute the smallest bounded case, and
   require terminal redacted evidence before reporting success.
9. **Optional remote publication:** protected gateway, firewall, VPN, routing,
   or non-loopback access requires its own security/IDS and explicit approval;
   it is not needed for localhost Roadex use.

No stage may infer authorization from completion of an earlier stage.
Before implementing against Overseer, refresh this mapping against its current
clean reviewed source because dispatcher, reconciliation, and policy contracts
may change independently of TheUnderdark.
