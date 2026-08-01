# Threat model

This threat model defines the security gates for TheUnderdark's bounded storage
execution adapter. It is a design artifact, not authorization to implement or
enable mutation tools, install a service, or register an Overseer adapter.

## Scope and security objective

TheUnderdark must execute only the exact storage action authorized by Overseer,
for the registered project and approved root, once, within explicit resource
limits, while producing redacted and verifiable evidence. Any missing,
ambiguous, expired, inconsistent, or unverifiable input must fail closed.

The first acceptance workflow is DonutHole, but its approval cannot confer
authority over another project, root, action, or request.

## Assets

- Project files and directories under registered storage roots
- Host files, devices, mounts, and services outside those roots
- Overseer requests, claims, approvals, adapter registrations, and evidence IDs
- The mapping from a project identity to its approved roots and operations
- Idempotency records and operation state needed for safe recovery
- Credentials, tokens, private paths, database contents, and personal exports
- Audit records and evidence used to decide whether an operation completed
- Service availability, storage capacity, and filesystem integrity

## Actors and trust boundaries

- **Operator:** grants narrowly scoped approval and reviews evidence. Operator
  intent is authoritative only when represented by valid Overseer records.
- **Overseer and O'Brien:** coordinate requests and approval state. A message
  acknowledgment, request, lease, or claim alone is not execution authority.
- **Roadex project agent:** requests an operation through MCP. It is potentially
  buggy or compromised and cannot choose its own authority or storage root.
- **TheUnderdark:** validates policy and performs bounded filesystem work. It is
  a privileged deputy and must not infer authority from caller identity alone.
- **Filesystem and host:** are outside the MCP protocol trust boundary. Their
  namespace can change concurrently through symlinks, mounts, renames, or other
  processes.
- **Logs and evidence consumers:** require useful results but are not entitled
  to raw file contents, credentials, or unrestricted host paths.

The principal boundaries are MCP caller to adapter, Overseer approval records
to adapter policy, registered project to approved root, resolved root to host
filesystem, and execution results to logs/evidence. Authentication, loopback
binding, resource registration, and message acknowledgment do not cross the
authorization boundary by themselves.

## Threats, controls, and required verification

| Attack or failure case | Deny-by-default controls | Verification required before release |
| --- | --- | --- |
| Path traversal through absolute paths, `..`, alternate separators, encoding, or prefix collisions | Accept project-relative paths only; reject empty, absolute, malformed, and parent segments; bind each request to a registered root; compare path components rather than string prefixes; allowlist typed operations | Table-driven tests for traversal and sibling-prefix escapes; property/fuzz tests over path inputs; tests prove no host change on rejection |
| Symlink, hard-link, mount, rename, or time-of-check/time-of-use escape | Resolve from a pre-opened approved root using descriptor-relative operations and no-follow semantics; validate every traversed component; forbid symlinks and unexpected filesystem/mount transitions in mutation scope; avoid check-then-open path APIs; revalidate identity at commit | Adversarial tests swap links and directories between validation and use; tests cover final-component links, intermediate links, hard links where relevant, and concurrent rename; verify outside-root sentinels remain unchanged |
| Confused deputy or cross-project authority reuse | Derive project, root, action, owner, and mode from matched registration and approval records; require all identifiers to agree; never accept caller-supplied authority fields as proof; prohibit arbitrary shell commands | Contract tests mix valid identities from different projects, roots, owners, actions, and registrations and require rejection with no mutation |
| Approval bypass, replay, expiry, revocation, or treating acknowledgment as approval | Require a claimed request plus exact, unexpired, unrevoked approval and approved adapter registration; bind approval to request ID, operation class, normalized target, project, limits, and nonce/version; consume or terminally account for single-use authority; recheck immediately before commit | Tests cover missing, forged, stale, revoked, already-consumed, wrong-target, wrong-action, wrong-owner, and changed-policy approvals; acknowledged-only and claimed-only states fail |
| Duplicate execution caused by retries or concurrent callers | Require an idempotency key scoped to the canonical request and operation; persist intent and state before mutation; serialize conflicting work; return the recorded terminal result for identical retries; reject key reuse with a different payload | Concurrent and crash-retry tests show at-most-once externally visible mutation; payload mismatch is rejected; terminal evidence remains stable across retries |
| Crash or partial failure leaves ambiguous or corrupt state | Define explicit prepared, executing, committed, failed, and reconciliation states; use atomic filesystem primitives where possible; stage writes on the same filesystem; fsync/rename as required; never report success until postcondition verification; make compensation explicit rather than assumed | Fault-injection tests at each transition; restart reconciliation distinguishes committed, safely retryable, and manual-review states; evidence states whether host state changed |
| Quota exhaustion, oversized work, deep trees, decompression bombs, lock starvation, or request floods | Per-project and per-operation byte, item, depth, duration, concurrency, and rate limits; bounded parsing and evidence; preflight available capacity without promising it remains; cancellation and cleanup; reject unsupported recursive or archive behavior | Boundary and over-limit tests, concurrency/load tests, timeout tests, disk-full/inode-full fault tests, and cleanup verification; one project cannot starve another |
| Evidence or log leakage | Structured allowlisted fields only; opaque IDs or approved path aliases instead of raw host paths; redact secrets and content; cap field sizes; sanitize errors; never log request bodies or file contents by default; separate operator diagnostics from agent-visible results | Golden redaction tests with tokens, credentials, private paths, database content, control characters, and oversized errors; public artifact and log review finds no sensitive fixtures |
| Policy or registration changes during execution | Snapshot policy identity/version at authorization, revalidate before commit, and fail or reconcile if the registration, root, approval, or limits change | Race tests revoke or alter registration and approval during preparation; mutation cannot commit under changed authority |
| Malicious or ambiguous operation semantics | Expose narrow typed tools with documented postconditions; reject unknown fields and operations; prohibit command strings, glob expansion, implicit recursion, and caller-selected execution binaries | Schema-negative and contract tests prove ambiguous and extra inputs fail closed; tool inventory contains no generic execute or unrestricted filesystem method |

## Evidence and state invariants

Every accepted request must have one stable operation ID and an append-only
record of authorization decision, policy version, canonical target alias,
limits, state transitions, and redacted terminal result. Evidence must clearly
distinguish requested, acknowledged, leased, claimed, approved, executing,
committed, failed, and reconciliation-required states.

Only a committed state with verified postconditions may report successful host
mutation. A failure must report whether the host was unchanged, changed within
the approved boundary, or has an indeterminate state requiring operator review.
Evidence must not contain file contents, secrets, raw credentials, unrestricted
absolute paths, or verbose exception objects.

## Residual risks

- A compromised host or privileged process can bypass application-level
  filesystem controls and alter evidence or storage concurrently.
- Kernel, filesystem, network filesystem, and runtime defects can violate the
  expected semantics of descriptor-relative or atomic operations.
- Hard links and bind mounts may require platform-specific restrictions beyond
  portable path validation; unsupported filesystems must be rejected.
- Correctly scoped but maliciously intended operator approval remains possible.
- Capacity and timing checks are snapshots; exhaustion can occur after preflight.
- Atomicity across filesystems or multi-file operations is generally
  unavailable. Such operations need an explicit transactional design or must be
  excluded from the first release.
- Redaction rules can miss novel secret formats, so evidence minimization is the
  primary defense and pattern redaction is secondary.

These risks require least-privilege service credentials, OS-level confinement,
backups, monitoring, and documented recovery. Those deployment controls remain
subject to separate shared-service and Overseer approval.

## Hard gates before mutation implementation

Mutation-tool implementation must not begin until all of the following are
reviewed and explicitly approved:

1. A narrow MCP operation catalog with schemas, postconditions, unsupported
   behavior, quotas, and per-operation atomicity/recovery guarantees.
2. The paired Overseer contract for adapter registration, request/claim state,
   exact approval binding, revocation, expiry, evidence, and reconciliation.
3. The project/root registration model and filesystem containment strategy,
   including symlink, hard-link, mount, and TOCTOU behavior on supported filesystems.
4. A durable idempotency and operation-state design with crash recovery and
   key-reuse semantics.
5. A redacted evidence schema and explicit classification of fields visible to
   agents, operators, and local diagnostics.
6. A test plan covering every verification item in the threat table, including
   fault injection and proof that rejected requests do not change host state.
7. A least-privilege runtime and deployment plan. Port reservation, persistent
   service installation, Overseer registration, restarts, gateway exposure, and
   live storage execution each require their own coordination and approval.

Read-only prototypes may validate schemas and authorization decisions, but must
use fixtures or temporary test roots and must not expose a generic filesystem
interface. Passing unit tests alone does not authorize mutation: the paired
Overseer contract and all applicable deployment gates must also be satisfied.
