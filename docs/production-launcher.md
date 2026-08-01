# Production launcher

`theunderdark-production` is source-only and is not installed or started by the
repository. Importing it does not open files or sockets.

Use `theunderdark-production check --config /absolute/private/config.json` to
compose and validate dependencies without binding a port. `serve` is a separate
operator action and accepts only `127.0.0.1` plus an explicit port.

The config must be an owner-owned mode `0600` regular file with exactly these
fields: `host`, `port`, `state_dir`, four database paths (`journal_path`,
`admission_path`, `pagination_path`, `registry_path`), both exact Overseer
verification endpoints, `overseer_token_file`, `cursor_key_file`,
`root_authorization_refs`, exact private `backup_bindings`, and finite admission `limits`. The state directory
must be mode `0700`; token and cursor-key files must be mode `0600`. Database
paths must be direct children of that directory. Credentials remain in the
injected token file and are read only for an individual verification call.

This launcher does not register an adapter, create root approvals, modify
Overseer, reserve a port, install a service, or authorize live execution.

An operator can consume an approval that already exists in Overseer with
`theunderdark-production register-root --config CONFIG --project-id PROJECT
--root-id ROOT --policy-revision REVISION --host-path PATH --alias ALIAS
--max-bytes BYTES --authorization-ref APPROVAL_REF`. Identifiers and the
authorization reference use the exact opaque-ID grammar; wildcards are denied.
The command derives the inode-bound target digest, binds that digest to the
provided authorization reference in the owner-only config, and asks Overseer
to verify the exact root registration before committing it to the registry.
An approval mismatch restores the prior config. It never creates or approves
an Overseer authorization and is deliberately not exposed as an MCP tool.
