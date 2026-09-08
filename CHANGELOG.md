## v0.2.0 (2026-09-08)

- **Depends on `agent-passport-system` ^6.0.1**, up from ^2.2.0. The 2.x line is inside the September 2026 advisories (GHSA-r2fw-x6mg-f6h8, high: verification could succeed with untrusted authority, unlinked artifacts, replayable context; GHSA-72cm-hhw9-f66f, medium: Ed25519 accepts inadmissible small-order keys).
- **`aps.verifyDelegation` moves to the authority-aware verifier.** It called `verifyDelegation`, an integrity check that establishes no authority: it answers whether a delegation is well-formed, unexpired and unrevoked, not whether anyone trusted its issuer. It now calls `verifyAuthorityDelegationChain` with every trust input supplied by the operator, and takes the chain as an array rather than one token.
- **Trust anchors are configuration, never artifact content.** `policy.delegation.trustedIssuers` names each issuer and the key it signs with. The key that checks a signature is looked up there and never read out of the record being verified. With no anchors configured nothing verifies. A malformed anchor list is a configuration error and throws, rather than being read as an empty list.
- **Self-signed roots are refused** unless `policy.delegation.allowSelfSignedRoot` is set, and the opt-in is not a substitute for issuer trust: the root's issuer must still resolve to a configured key.
- **`checkGrade` reads `found: false` as "not known".** The live gateway answers 200 with `found: false` and `grade: 0` for an agent it does not know, so an unverified identity was being reported as a verified one holding the lowest grade. An operator with `blockBelow` set would have blocked unknown authors as though the registry had graded them.
- **The JWKS `kid` is binding.** Envelope verification fell back to `keys[0]` when the kid matched nothing, so the kid decided nothing. An envelope naming a key is now checked against that key or refused.
- OpenClaw compat set to what the plugin needs and has been checked against: `pluginApi >=2026.4.11`, the first release carrying the hook contract types it codes against. The previous `>=2026.3.24-beta.2` claimed support from before those types existed. Built and verified against OpenClaw 2026.9.2.
- `requireApproval.timeoutBehavior` dropped; it is deprecated at 2026.9.2, where unresolved approvals always deny.
- Tests: 11 to 19. Added a tampered body, a replaced signature, a self-signed root, the opt-in still needing an anchor, the fail-closed default, a key never resolved from the artifact, unknown revocation reported rather than assumed, and the `found: false` lookup.

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
