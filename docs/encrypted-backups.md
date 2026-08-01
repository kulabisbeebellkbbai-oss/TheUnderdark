# Encrypted backup executor

`EncryptedBackupExecutor` is an isolated source component; it is not registered
or started by the service. It streams a deterministic tar directly into GPG
AES-256 symmetric encryption using iterated S2K and an owner-only passphrase
file. It never creates a plaintext archive and never invokes a shell.

The executor excludes agent metadata, VCS data, environment files, credentials,
secrets, databases, dependencies, build outputs, coverage, and caches. Included
paths must be ordinary single-link files; symlinks and special files fail the
whole operation. Each artifact embeds a SHA-256 manifest, is decrypted into an
isolated mode-0700 temporary restore, compared, and cleaned before success.
Identical content reuses its content-addressed verified artifact. Retention is
fixed to the newest three verified encrypted artifacts.

Production composition accepts private `BackupBinding` records containing the
exact project, root, and policy revision plus source, artifact, passphrase, and
GPG paths. The provider rejects wildcards, duplicates, unregistered source-root
mismatches, and every request without an exact binding. These host paths and the
passphrase are never MCP request fields or response evidence.

The production JSON configuration has an exact `backup_bindings` array (use an
empty array when none are approved). Every entry must contain exactly
`project_id`, `root_id`, `policy_revision`, `source_root`, `artifact_dir`,
`passphrase_file`, and `gpg_executable`. Wildcards and duplicate identities are
rejected; the artifact directory must be process-owned mode 0700 and the
passphrase must be a process-owned regular file mode 0600. `check` validates
and composes these dependencies but does not open the HTTP listener.

The approval-bound tools match Overseer's canonical contract exactly:
`backup.create` requires `source_root_id`, a retention count of `3`, and the
`gpg-symmetric-aes256-iterated-s2k` profile. `backup.verify_restore` requires an
opaque artifact ID and `sha256:`-prefixed expected artifact and manifest
digests. Verification decrypts and compares an existing artifact but never
creates another one. Fresh creation reports host-state change, while reuse and
restore verification report no durable host-state change; all backup envelopes
mark evidence as redacted.
