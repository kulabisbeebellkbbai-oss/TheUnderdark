# TheUnderdark

TheUnderdark is a planned storage execution adapter for Roadex projects. It
will expose narrowly scoped storage workflows through MCP, integrate with
Overseer approvals, and produce redacted execution evidence for O'Brien's
bounded maintenance workflows.

The first acceptance target is the storage-dependent Overseer workflow used
by DonutHole.

Overseer does not currently provide a pluggable storage-adapter registry. The
first integration slice must therefore define both TheUnderdark's MCP contract
and the separately reviewed Overseer adapter-client/registration seam.

## Status

The project summary is approved and the implementation team is under review.
No storage adapter, persistent service, Overseer registration, or live storage
execution is enabled yet.

## Safety principles

- Bind the MCP backend to loopback only.
- Deny access outside explicitly registered project roots.
- Treat acknowledgment as message processing, not execution authorization.
- Require exact approval and idempotency controls for mutating operations.
- Return redacted evidence rather than credentials, raw databases, or private
  project exports.
- Keep service installation, registration, restarts, and remote exposure behind
  separate Overseer and human approval gates.

See [the approved project summary](docs/a-team-summary.md) and
[security boundaries](docs/security-boundaries.md) for the initial contract.
The [Overseer integration findings](docs/overseer-integration.md) capture the
verified current blocker.
The [approved A-Team plan](docs/a-team-plan.md) defines ownership and approval
boundaries for implementation.
The first approved design slice consists of the
[bounded storage contract](docs/storage-contract.md) and
[threat model](docs/threat-model.md).
The proposed [Overseer adapter contract](docs/overseer-adapter-contract.md)
defines the separately gated registry, approval, dispatch, and reconciliation
integration.

## Repository layout

- `src/` — service implementation
- `tests/` — unit, contract, and integration tests
- `assets/` — non-secret project assets
- `docs/` — architecture, security, and operator documentation

Build, test, and run commands will be added with the first approved
implementation slice.
