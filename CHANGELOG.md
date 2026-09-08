## v0.1.2 (2026-09-08)

- Add top-level `name` ("Agent Passport System") to `openclaw.plugin.json`, the field OpenClaw's own bundled manifests carry (workboard, telegram, reef). Clears the ClawHub validator warning.
- Gitignore the validator's `reports/` output so it is never committed.

## v0.1.1 (2026-04-26)

- Fix: declare `openclaw.extensions`, `runtimeExtensions`, `compat`, `build` in package.json (required by ClawHub `package publish` for code-plugin family).
- Fix: rewrite `openclaw.plugin.json` to match canonical schema (`id`, `description`, `configSchema`). Custom `contracts` / `deferredContracts` / `gatewayMethods` / `conformance` fields removed; that information lives in the README and the spec instead.

## v0.1.0 (2026-04-26)

- Initial release. Conformance against `Agent Trust Verification Provider Pattern v0.1`.
- Implements `before_install`, `before_tool_call`, `gateway_start` hooks.
- Implements `aps.checkGrade`, `aps.verifyDelegation`, `aps.signMessage` RPC methods.
- `inbound_claim` and `before_dispatch` deferred to v0.2.
