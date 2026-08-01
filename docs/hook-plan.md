# TheUnderdark agent hook plan

This repository contains hook source only. Nothing in `plugins/theunderdark-mcp/hooks/` is installed, trusted, merged into user configuration, or active.

## Intended behavior

The `UserPromptSubmit` preflight activates only for explicit TheUnderdark, named `underdark_*` tool, storage-adapter, or Roadex/DonutHole storage language. It fails early with a configuration-only remediation when the stdio executable is absent; otherwise it reminds the agent to use the MCP route and exact Overseer authorization for mutations. It performs no network health probe and reserves no port.

The `Stop` guard applies the same narrow domain match and only blocks an execution-oriented answer when it lacks recognizable TheUnderdark MCP evidence. Read-only discussion, design work, and unrelated storage requests pass unchanged.

## Configuration boundaries

- `.mcp.json` is a portable stdio template. The `theunderdark-mcp` executable must be supplied through an installation-specific trusted path; the template contains no host, allocated port, credential, database, or project root.
- `hooks.example.json` uses `<PLUGIN_ROOT>` deliberately. Installation tooling must resolve it to the reviewed plugin checkout or installed plugin path.
- Do not place authorization references, registered roots, credentials, or environment-specific paths in repository configuration.
- Review and trust non-managed hook changes through `/hooks` before activation.
- Activate only after the MCP executable exists, the plugin has been installed through the chosen scope, and the adapter has completed the separate Overseer/O'Brien registration and approval process.

## Proposed activation sequence

1. Validate the plugin and skill source.
2. Install the plugin at the explicitly selected Codex scope.
3. Resolve the executable and hook paths without editing this portable template with secrets.
4. Review the two hook entries through `/hooks`.
5. Test irrelevant, read-only, mutation, missing-evidence, and terminal-evidence prompts.
6. Roll back by removing only the two reviewed entries; plugin removal and Overseer adapter revocation remain separate actions.
