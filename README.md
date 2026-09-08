# agent-passport-system-openclaw-plugin

OpenClaw plugin: Agent Passport System trust verification provider. Reference implementation of [Agent Trust Verification Provider Pattern v0.1](https://github.com/aeoess/agent-trust-verification-providers).

> **Known issue: versions through 0.2.1 do not register successfully with current OpenClaw and do not provide the gating described below.** Registration fails on the first hook, before the enforcement hooks and the gateway methods are installed. A corrected release is in progress.
>
> To check an installation, run `openclaw plugins inspect aps --runtime`. On the affected versions it reports a registration error. `openclaw plugins list --json` may still report the plugin as `loaded`, so use runtime inspection for this issue.

The plugin's intended behaviour is to gate skill installs against the APS public trust registry, gate high-risk tool calls behind explicit approval, and expose APS primitives (grade lookup, delegation verification, message signing) via OpenClaw gateway RPC. It runs entirely in the OpenClaw plugin lifecycle and adds no requirement on OpenClaw core.

Verification runs in `agent-passport-system` 6.0.1. The plugin calls the SDK and implements no verification of its own. Delegation verification uses the authority-aware chain verifier with trust anchors the operator configures, so an integrity result is never returned as an authorization decision (SDK 6.0.0, advisory GHSA-r2fw-x6mg-f6h8).

## Install

```bash
clawhub install agent-passport-system-openclaw-plugin
# or
npm install agent-passport-system-openclaw-plugin
```

## Configuration

Config is read from, in order:

1. `$OPENCLAW_APS_CONFIG_PATH` (env var)
2. `~/.openclaw/aps.config.json`
3. Built-in defaults (permissive-with-warnings)

Schema (matches spec section 8):

```json
{
  "provider": "aps",
  "endpoints": {
    "verifier": "https://gateway.aeoess.com/api/v1/public/trust",
    "jwks": "https://gateway.aeoess.com/.well-known/jwks.json"
  },
  "credentials": { "passportPath": "~/.openclaw/aps-credentials.json" },
  "signing": {
    "enabled": false,
    "allowedCallers": [],
    "requireApproval": false,
    "auditLogPath": "~/.openclaw/aps-signing-audit.log"
  },
  "policy": {
    "skillAuthor": { "minGrade": 0, "warnBelow": 1, "blockBelow": null },
    "toolCalls": { "enforceScope": true, "highRiskTools": ["bash", "exec", "fetch"], "highRiskBehavior": "approval" },
    "inboundMessages": { "requireSignature": false, "warnUnsigned": true }
  }
}
```

| Field | Meaning |
|---|---|
| `endpoints.verifier` | Public APS trust profile API base URL |
| `endpoints.jwks` | APS gateway JWKS endpoint for envelope signature verification |
| `credentials.passportPath` | Local APS passport file. Read only when `signing.enabled` is true |
| `signing.enabled` | Turn on `aps.signMessage`. Default `false`. See [Signing](#signing) |
| `signing.allowedCallers` | Plugin ids, or the literal `gateway-client`, permitted to sign. Empty means nobody |
| `signing.requireApproval` | Refuse every signing request until the host can ask a person. Default `false`; the allowlist is the gate |
| `signing.auditLogPath` | Local log of every signing request and refusal |
| `policy.skillAuthor.warnBelow` | Surface install-time warning when author grade < this |
| `policy.skillAuthor.blockBelow` | Block install when author grade < this; `null` = never block |
| `policy.toolCalls.highRiskTools` | Tool names treated as high-risk |
| `policy.toolCalls.highRiskBehavior` | `"approval"` (default), `"block"`, or `"warn"` |
| `policy.inboundMessages.*` | Reserved for v0.2 (`inbound_claim` hook) |

## Hook coverage (v0.1)

| Hook | Status | Behavior |
|---|---|---|
| `before_install` | does not register with current OpenClaw | Looks up author grade against APS gateway. Returns `block` if grade < `blockBelow`, `findings` if grade < `warnBelow`, pass-through otherwise. Missing author or unknown author → warn finding. 500ms cold latency budget; on timeout, fails open. |
| `before_tool_call` | does not register with current OpenClaw; high-risk tools only | Tools listed in `policy.toolCalls.highRiskTools` go through `highRiskBehavior` (approval / block / warn). Non-high-risk calls pass through. |
| `gateway_start` | does not register with current OpenClaw | Loads config, fetches JWKS, validates passport file format. Failures log via plugin diagnostic channel; do not block startup. |
| `inbound_claim` | deferred to v0.2 | |
| `before_dispatch` | deferred to v0.2 | |

The Behavior column describes intended behaviour. With current OpenClaw, versions through 0.2.1 do not register any of these handlers.

## Gateway RPC methods

Exposed via `api.registerGatewayMethod()`, namespaced `aps.`:

- `aps.checkGrade` with `params: { agentId }` → `TrustProfile | null` from the public APS gateway
- `aps.verifyDelegation` with `params: { chain }` → result of APS SDK `verifyAuthorityDelegationChain()`. `chain` is the delegation chain as an array, root first, not a single token. Gateway methods take one options object from the host; 0.2.0 read positional arguments and both RPCs were unusable. Trust anchors come from `policy.delegation.trustedIssuers`; with none configured nothing verifies, which is the default. Revocation resolves to `unknown` because this plugin carries no revocation feed, so a cryptographically sound chain returns `state: "indeterminate"` rather than a `valid: true` it cannot establish.
- `aps.signMessage({ message })` → `{ signature, domain, digest }`. Ed25519 signature over a domain-separated input, using the local passport's private key. Off unless the operator turns it on. See [Signing](#signing).

Other plugins can call these by their namespaced names.

## Signing

`aps.signMessage` signs with the private key in the passport file at `credentials.passportPath`. A gateway method registered by a plugin is not private to that plugin: OpenClaw dispatches it for authenticated gateway clients, and other plugins can reach it through the in-process runtime. So configuring a passport path used to mean handing that key's signing power to every plugin installed alongside this one. That is what the ClawHub review of 0.2.0 flagged, and it is what 0.2.1 changes.

What the reviewers told installers still holds. 0.2.1 adds allowlist enforcement inside the signing handler, but with current OpenClaw that handler is not registered, so the points below describe intended behaviour:

- Signing is **off by default**. With `signing.enabled` false, `aps.signMessage` refuses every request and the passport file is never opened.
- Turning it on is a decision about every plugin on the host, not just this one. Turn it on only if you trust each installed plugin that could call `aps.signMessage`, and prefer a limited-purpose passport identity over your main one.
- `signing.allowedCallers` names who may sign. Entries are OpenClaw plugin ids, or the literal `gateway-client` for an authenticated gateway client that the host did not identify as a plugin. An empty list, the default, allows nobody.
- `signing.requireApproval` defaults to false, and the allowlist is the gate: signing is off unless `signing.enabled` is true, and an empty `allowedCallers` refuses everything. Setting `requireApproval` to true refuses every request, because OpenClaw 2026.9.2 gives a gateway RPC handler no channel to ask a person for a decision: the mechanism the tool-call gate uses is a return value of the `before_tool_call` hook, and the SDK helper that reaches the host approval method is limited to plugin HTTP routes. It exists so an operator can hard-stop signing without editing the allowlist, and it will become a real approval once the host offers one. Citations are in the header of `src/signing.ts`.

Every signature is minted over `APS-OPENCLAW-PLUGIN-SIGN-MESSAGE-V1\0` plus the message, following the domain-separation convention the SDK uses for authority delegations. A signature produced here therefore does not verify as a passport, attestation or delegation signature over the same bytes, and cannot be replayed into one of those contexts.

Every request and every refusal is appended as one JSON line to `signing.auditLogPath`, by default `~/.openclaw/aps-signing-audit.log`. Each line records the timestamp, the outcome, the caller, the domain prefix and the sha256 digest of the message. The message body is never written.

One limit worth knowing: the caller name comes from what the host supplies. A plugin dispatching through the trusted in-process runtime is named exactly, because OpenClaw stamps the plugin id itself and never takes it from request parameters. A plugin that instead forwards a request from one of its own HTTP routes arrives carrying the original client and is indistinguishable from `gateway-client`. Allowlisting `gateway-client` is therefore broader than allowlisting a plugin id.

## Conformance

This plugin claims conformance to **Agent Trust Verification Provider Pattern v0.1**. Specifically:

- ✅ Registers `before_install`, `before_tool_call`, `gateway_start` (criterion 1)
- ✅ Accepts the section-8 configuration schema (criterion 2)
- ✅ Defaults to permissive-with-warnings (criterion 3)
- ✅ Handles missing-author and missing-credential without crash (criterion 4). Note: the OpenClaw `before_install` payload carries no author field at 2026.9.2, so the author gate resolves the npm scope of a scoped package name and otherwise reports the author as unknown.
- ✅ Cold-case `before_tool_call` is in-process, no gateway call in v0.1 (criterion 5)
- ✅ All gateway RPC methods namespaced `aps.` (criterion 6)
- ⏸ `before_dispatch` headers, deferred to v0.2 (criterion 7 N/A in v0.1)
- ✅ No state mutation outside plugin directory (criterion 8)
- ✅ Verifier endpoint published at `gateway.aeoess.com/api/v1/public/trust/{agentId}` (criterion 9)
- ✅ Trust signal semantics documented in [The Agent Social Contract](https://doi.org/10.5281/zenodo.18749779) (criterion 10)

## v0.1 scope and known limitations

- **High-risk-tool gate is the only `before_tool_call` enforcement.** Full delegation-scope verification requires the agent to be running with an APS passport context; that ships in v0.2 with caching to keep the typical-case latency under 100ms (spec section 9 #5).
- **`inbound_claim` and `before_dispatch` deferred.** The agent runtime context for inter-agent messaging is still being formalized; v0.2 adds these hooks once the surface is stable.
- **Author identifier extraction is best-effort.** OpenClaw hook event types at commit `45146913007d` do not expose `author` on `event.skill` or `event.plugin`. The plugin reads `author` if present (forward-compat), falls back to npm scope from `packageName` for plugins, and treats local archives without a derivable author as missing-author (warning, not block).
- **No retry layer.** If the gateway is slow (>500ms) the install proceeds with a warning. Caching of grade lookups is also a v0.2 item.

## Examples

### Default (permissive-with-warnings)

No config file needed. The defaults block nothing, surface warnings for unknown or low-grade authors, and require user approval for `bash`/`exec`/`fetch`.

### Strict mode

```json
{
  "provider": "aps",
  "policy": {
    "skillAuthor": { "minGrade": 0, "warnBelow": 2, "blockBelow": 1 },
    "toolCalls": { "enforceScope": true, "highRiskTools": ["bash", "exec", "fetch", "shell"], "highRiskBehavior": "block" },
    "inboundMessages": { "requireSignature": true, "warnUnsigned": false }
  }
}
```

Place at `~/.openclaw/aps.config.json` or set `$OPENCLAW_APS_CONFIG_PATH` to its location.

## Development

```bash
npm install
npm run build      # tsc -> dist/
npm test           # vitest
npm run lint       # tsc --noEmit --strict --noUnusedLocals --noUnusedParameters
```

To link locally into an OpenClaw checkout:

```bash
cd /path/to/openclaw-plugin-aps && npm link
cd /path/to/openclaw && npm link agent-passport-system-openclaw-plugin
```

## License

Apache-2.0. Copyright 2026 Tymofii Pidlisnyi.
