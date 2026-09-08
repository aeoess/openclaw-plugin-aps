## v0.2.1 (2026-09-08)

Answers the ClawHub 0.2.0 review, which put the plugin in Review because a configured passport private key was reachable for arbitrary signing by any other installed plugin through the `aps.signMessage` RPC.

- **Signing is off by default.** New `signing.enabled`, default `false`. While it is off, `aps.signMessage` refuses every request and the passport file is never opened. Install and tool gates are unaffected.
- **When on, every call is gated on caller identity.** `signing.allowedCallers` lists OpenClaw plugin ids, or the literal `gateway-client` for an authenticated client the host did not name as a plugin. Empty, the default, allows nobody. The caller comes from the `client` the host passes to the handler: a plugin calling through the trusted in-process runtime is named by `client.internal.pluginRuntimeOwnerId`, which OpenClaw stamps itself and never reads from request parameters.
- **`signing.requireApproval` defaults to false; the allowlist is the gate.** OpenClaw 2026.9.2 exposes no approval channel to a gateway RPC handler (the `requireApproval` field the tool-call gate uses is a return value of the `before_tool_call` hook, and the SDK dispatch helper that could reach `plugin.approval.request` is restricted to plugin HTTP routes), so setting it true refuses every request rather than signing unattended. It is a hard-stop, not a workflow, until the host offers one. Citations are in the header of `src/signing.ts`.
- **Every signature carries a domain-separation prefix.** Signing input is `APS-OPENCLAW-PLUGIN-SIGN-MESSAGE-V1\0` plus the message, following the convention the SDK uses for authority delegations. A signature minted here does not verify as a passport, attestation or delegation signature over the same bytes.
- **Local audit log.** Every request and refusal appends one JSON line to `signing.auditLogPath`, default `~/.openclaw/aps-signing-audit.log`, recording outcome, caller, domain prefix and message digest. Never the message body.
- `aps.signMessage` now takes `{ message }` and returns `{ signature, domain, digest }`.
- **`aps.checkGrade` and `aps.verifyDelegation` work again.** Gateway method handlers receive one options object from the host, and the host delivers a returned value as the response; 0.2.0 read positional arguments, so `checkGrade` fetched `/trust/[object Object]` and `verifyDelegation` always threw. Both now read `params.agentId` and `params.chain`.
- Tests: 19 to 32. Added refusal while disabled with the passport never read, refusal for a caller off the allowlist across all three caller kinds, the approval path approved and denied, refusal when no approval channel exists, the prefix present and non-replayable on every signature, the audit record carrying a digest and not a body, and the signing config staying fail-closed.

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
