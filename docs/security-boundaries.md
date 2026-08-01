# Initial security boundaries

TheUnderdark starts deny-by-default. These boundaries are requirements for the
first implementation, not evidence that an adapter is already active.

## Trust boundaries

- MCP authentication or local access is necessary but is not storage-operation
  authorization.
- Every operation must identify a registered project, approved root, bounded
  action, request ID, and applicable Overseer authorization evidence.
- Filesystem paths must be resolved and checked after normalization, including
  symlink handling, before any read or mutation.
- The service must never accept arbitrary shell commands or unrestricted paths.

## Mutation controls

- Separate read-only inspection tools from mutating tools.
- Require exact approval for each mutation class and target boundary.
- Use idempotency keys and durable operation states so retries cannot duplicate
  destructive work.
- Define explicit size, count, and time limits.
- Fail closed when authorization, registration, claims, or evidence is missing.

## Evidence and privacy

- Record stable operation IDs, state transitions, policy decisions, and bounded
  result metadata.
- Redact credentials, tokens, raw database content, personal exports, and
  sensitive host paths from responses and logs.
- Do not equate an acknowledged crew message with claimed, approved, executed,
  or verified work.

## Deployment boundary

- Bind the backend only to `127.0.0.1`.
- Do not install or restart a persistent service, register an Overseer adapter,
  reserve a shared port, or publish a protected gateway route without the
  corresponding coordination and explicit approval.
