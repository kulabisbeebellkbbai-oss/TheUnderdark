# Production readiness gates

The repository now contains production-oriented storage components as well as
the fixture adapter. Passing their unit, integration, and in-memory MCP tests
does not authorize persistent installation, Overseer registration, O'Brien
approval, or live project storage access.

`tests/test_production_readiness.py` exercises the production journal,
containment, executor, admission, pagination, transport, and health components
together where practical. The authoritative Overseer clients, protected root
registry, and side-effect-free production composition are implemented. Live
activation remains blocked until the exact deployment package is reviewed and
approved.

## Required gates

| Gate | Current state | Production acceptance evidence |
| --- | --- | --- |
| Durable journal and restart reconciliation | Implemented with SQLite durable reservations, lifecycle evidence, interrupted-operation recovery, and explicit reconciliation | Identical retry after process restart returns the same operation; restart during execution reconciles to verified success, safe failure, or indeterminate without replay |
| Descriptor-relative containment | Implemented for supported Linux architectures with root descriptors, `openat2` beneath/no-follow/no-cross-device resolution, identity checks, and descriptor-relative mutation | Root-handle traversal with no-follow semantics; adversarial symlink, rename, hard-link, mount, and TOCTOU tests preserve outside sentinels |
| Aggregate quotas | Implemented through durable per-project committed usage and growth reservations; action-specific byte estimation remains subject to integration review | Project/root/action/authorization minimum limits for bytes, item count, retained evidence, and storage growth; reservation and post-operation reconciliation |
| Concurrency and rate limiting | Implemented through durable admission leases/rate windows plus nonblocking executor admission and ordered path locks | Per-project concurrent limits, deterministic path-lock order, bounded waits, rate limits, and proof one project cannot starve another |
| Stable pagination | Implemented with durable HMAC-bound snapshots tied to project, root, path, policy revision, and namespace identity | Cursor binds a stable snapshot or detects namespace changes without duplicates, omissions, or cross-context reuse |
| Strict MCP validation | Implemented for unknown fields at the MCP boundary; enum and boundary cases remain release-test scope | Every tool schema rejects extra fields and unknown enum values before authorization, journaling, or filesystem access |
| Non-MCP health | Implemented by the side-effect-free production application factory; listener activation remains prohibited | Loopback `GET /health` reports only readiness, contract version, and dependency state; no registrations, host paths, authority, or results |
| Fail-closed activation | Production composition requires an approved durable root registry, exact loopback Overseer verifiers, journal, admission controller, paginator, and bounded executor; no listener or live configuration is created implicitly | Durable approved adapter registration, exact live verifier smoke, least-privilege runtime, and explicit activation approval |

## Activation rule

Activation is prohibited until the composed deployment, adapter revision,
root authorization, service plan, and verification evidence are reviewed and
explicitly approved. A healthy process, available MCP tool inventory, fixture authorization, message
acknowledgment, lease, or claim is not mutation authority. Only an exact,
unexpired, unrevoked Overseer approval claimed by the approved adapter may
reach execution, and only terminal verified evidence may satisfy a workflow.

Port allocation, persistent service installation, gateway exposure, Overseer
source or state changes, adapter registration, and DonutHole execution remain
separate approval-controlled actions.
