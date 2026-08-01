# TheUnderdark project summary

## Intended outcome

Build a secure, bounded storage execution adapter that Roadex projects can use
through MCP. The adapter will integrate with Overseer's request, claim,
approval, dispatch, and evidence lifecycle; be registered and approved by
O'Brien; and enable storage-dependent workflows that cannot currently execute.

DonutHole's waiting storage workflow is the first end-to-end acceptance case.

## Primary users

- Codex and other MCP-capable agents working on Roadex projects
- Overseer, especially O'Brien's maintenance and execution domain
- Operators who review and approve storage operations
- Roadex projects such as DonutHole that require bounded storage execution

## Major components

- A localhost-first MCP service with narrow, typed tools
- Project and operation registration with explicit storage boundaries
- Enforcement for approved roots, actions, identities, quotas, and request IDs
- Overseer integration for claims, approvals, dispatch, and redacted evidence
- A separately reviewed Overseer adapter registry/client seam; the current
  O'Brien dispatcher has no pluggable storage adapter contract
- O'Brien registration and adapter-approval workflow
- Idempotency, audit records, failure handling, and health checks
- Unit, contract, security, and end-to-end workflow tests
- Public-safe configuration examples and operator/agent documentation

## Likely risks

- Path traversal or access outside an approved project root
- Approval bypass or confused-deputy behavior
- Treating acknowledgment as authorization or completed execution
- Destructive, duplicated, or partially completed storage operations
- Leakage of credentials, databases, private paths, or project exports
- Contract mismatch with Overseer's crew-message dispatcher
- Shared port, service, or deployment conflicts
- Reporting success without approved state and redacted execution evidence

## Immediate next steps

1. Review and approve the reusable A-Team roster and assignments.
2. Define the bounded storage-operation contract and threat model.
3. Define the paired Overseer registry/client contract and approval record.
4. Implement the MCP service and its tests.
5. Validate MCP initialization, tool listing, read-only calls, invalid inputs,
   and approval-gated mutations on loopback.
6. Request O'Brien review and registration through Overseer.
7. Validate DonutHole's storage-dependent workflow end to end.

Shared-service installation, port reservation, Overseer registration, service
restart, gateway publication, and live storage execution remain separate
approval-gated actions.
