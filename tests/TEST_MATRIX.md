# Fixture-only verification matrix

This matrix maps the approved version-1 storage contract to executable tests.
All filesystem cases use temporary roots and sentinels; no live registration or
Overseer state is used.

| Area | Required cases |
| --- | --- |
| Registration | active lookup, redacted root alias, unknown project/root, inactive registration, policy revision mismatch |
| Paths | relative path accepted; absolute, empty, dot, parent, empty component, drive prefix, URI, NUL, control, and sibling-prefix traversal rejected |
| Filesystem boundaries | intermediate and final symlinks rejected; outside sentinel unchanged; special files rejected where portable |
| Authority | approved and claimed exact match accepted; acknowledged-only, pending-only, wrong claim, expired, wrong project/root/action/target rejected |
| Idempotency | identical retry returns stable operation/result without a second mutation; changed payload returns `IDEMPOTENCY_CONFLICT` |
| Mutations | directory create; create-only and exact-replace write; same-root move; bounded copy; non-recursive delete; precondition and destination conflicts |
| Quotas | content boundary accepted; over-limit content rejected before mutation; copy/replacement growth accounted for |
| Evidence | stable operation ID, lifecycle transitions, terminal success only after verification, host-state-changed accurate, safe path alias and digests present |
| Redaction | canonical host roots, tokens, content, temporary names, stack traces, database/personal-export fixtures absent from results and errors |
| MCP surface | six read-only and five mutation tool names present; no generic execute, arbitrary read, shell, glob, recursive-delete, or registration mutation tool |
