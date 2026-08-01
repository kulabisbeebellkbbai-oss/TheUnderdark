# Overseer integration findings

This document records the read-only bootstrap inspection of Overseer's current
storage workflow. It contains no private state or credentials.

## Current blocker

Overseer does not currently expose a pluggable bounded-storage adapter registry.
O'Brien's dispatcher detects `storage.*` resource requests and deliberately
returns a skipped/correction result stating that an approved storage adapter or
exact admin plan is required. Registering an MCP server as a generic resource
will not change that behavior.

## Existing integration seams

- Crew messages already carry owner, related resource and plan identifiers,
  acceptance criteria, and durable evidence identifiers.
- Overseer already models bounded execution requests and results with an action,
  target, owner, mode, status, summary, and evidence identifiers.
- Storage advisory review requires a registered storage resource, explicit
  capacity/access/failure-domain criteria, and durable request evidence.
- Resource registration proves that a typed target exists; it does not authorize
  execution.

## Required paired change

The first integration design must add an explicit storage-adapter registration
record or configuration, a typed TheUnderdark client boundary, exact approval
metadata, and dispatcher/reconciliation behavior that accepts only terminal
execution evidence. That change belongs to Overseer and remains separately
approval-gated from this repository's implementation.

Contract tests must cover approved dispatch, evidence propagation, missing or
invalid approval, adapter failure, retries and idempotency, path-boundary
rejection, and an explicit indication of whether host state changed.
