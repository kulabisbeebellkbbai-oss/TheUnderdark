# Approved A-Team plan

Team ID: `VYIuwjTnyW09`

The active execution plan is intentionally limited to the workstreams below.
The saved team also retains advisory roles for MCP enablement, runtime
operations, storage state, and documentation.

## Assignments

### Hannibal — delivery sequence

Define milestones for contract design, local MCP implementation, separately
reviewed Overseer integration, O'Brien approval, and DonutHole validation.
Shared-service and Overseer mutations remain explicit approval points.

### Face — bounded MCP storage contract

Define narrow read and mutation tools, project-root registration, safe path
resolution, operation states, idempotency, redaction, health, and deterministic
errors. Arbitrary paths and shell execution are out of scope.

### Tawnia — storage-execution threat model

Review authorization, path and symlink boundaries, destructive operations,
secrets, quotas, audit evidence, retries, partial failures, and approval bypass
before mutation tools are implemented.

### Murdock — verification

Cover unit, contract, security, MCP transport, and DonutHole acceptance paths.
Completion requires terminal redacted execution evidence, not acknowledgment.

### Frankie — Overseer integration

Design the separately reviewed adapter registry/client seam, exact O'Brien
approval record, dispatcher behavior, failure handling, and operational handoff.
Resource registration alone must never be treated as execution authorization.

## Approval boundaries

The project summary, team, and assignments are approved. This approval permits
local project design and implementation within the repository. It does not
authorize shared port reservation, persistent service installation or restart,
Overseer source or state changes, adapter registration, gateway publication, or
live storage execution.
