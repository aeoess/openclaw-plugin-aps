> Archived 2026-09-02. Plugin built against an earlier SDK generation; not maintained.

# agent-passport-system-openclaw-plugin

OpenClaw plugin: Agent Passport System trust verification provider. Reference implementation of [Agent Trust Verification Provider Pattern v0.1](https://github.com/aeoess/agent-trust-verification-providers).

The plugin gates skill installs against the APS public trust registry, gates high-risk tool calls behind explicit approval, and exposes APS primitives (grade lookup, delegation verification, message signing) via OpenClaw gateway RPC. It runs entirely in the OpenClaw plugin lifecycle and adds no requirement on OpenClaw core.

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
| `credentials.passportPath` | Local APS passport file (used for signing outbound messages) |
| `policy.skillAuthor.warnBelow` | Surface install-time warning when author grade < this |
| `policy.skillAuthor.blockBelow` | Block install when author grade < this; `null` = never block |
| `policy.toolCalls.highRiskTools` | Tool names treated as high-risk |
| `policy.toolCalls.highRiskBehavior` | `"approval"` (default), `"block"`, or `"warn"` |
| `policy.inboundMessages.*` | Reserved for v0.2 (`inbound_claim` hook) |

## Hook coverage (v0.1)

| Hook | Status | Behavior |
|---|---|---|
| `before_install` | implemented | Looks up author grade against APS gateway. Returns `block` if grade < `blockBelow`, `findings` if grade < `warnBelow`, pass-through otherwise. Missing author or unknown author → warn finding. 500ms cold latency budget; on timeout, fails open. |
| `before_tool_call` | implemented (high-risk-tools only) | Tools listed in `policy.toolCalls.highRiskTools` go through `highRiskBehavior` (approval / block / warn). Non-high-risk calls pass through. |
| `gateway_start` | implemented | Loads config, fetches JWKS, validates passport file format. Failures log via plugin diagnostic channel; do not block startup. |
| `inbound_claim` | deferred to v0.2 | |
| `before_dispatch` | deferred to v0.2 | |

## Gateway RPC methods

Exposed via `api.registerGatewayMethod()`, namespaced `aps.`:

- `aps.checkGrade(agentId)` → `TrustProfile | null` from the public APS gateway
- `aps.verifyDelegation(token)` → result of APS SDK `verifyDelegation()`
- `aps.signMessage(payload)` → Ed25519 signature using local passport's private key

Other plugins can call these by their namespaced names.

## Conformance

This plugin claims conformance to **Agent Trust Verification Provider Pattern v0.1**. Specifically:

- ✅ Registers `before_install`, `before_tool_call`, `gateway_start` (criterion 1)
- ✅ Accepts the section-8 configuration schema (criterion 2)
- ✅ Defaults to permissive-with-warnings (criterion 3)
- ✅ Handles missing-author and missing-credential without crash (criterion 4)
- ✅ Cold-case `before_tool_call` is in-process — no gateway call in v0.1 (criterion 5)
- ✅ All gateway RPC methods namespaced `aps.` (criterion 6)
- ⏸ `before_dispatch` headers — deferred to v0.2 (criterion 7 N/A in v0.1)
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
