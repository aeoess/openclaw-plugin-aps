# agent-passport-system-openclaw-plugin

OpenClaw plugin: Agent Passport System trust verification provider. Targets [Agent Trust Verification Provider Pattern v0.1](https://github.com/aeoess/agent-trust-verification-providers).

> **Known issue (verified 2026-09-08): versions through 0.2.1 do not register successfully with current OpenClaw and do not provide the gating described below.** Registration fails on the first hook, before the enforcement hooks and the gateway methods are installed. A corrected release is in progress.
>
> To check an installation, run `openclaw plugins inspect aps --runtime`. On the affected versions it reports a registration error. `openclaw plugins list --json` may still report the plugin as `loaded`, so use runtime inspection for this issue.

The plugin's intended behaviour is to gate skill installs against the APS public trust registry, gate high-risk tool calls behind explicit approval, and expose APS primitives (grade lookup, delegation verification, message signing) via OpenClaw gateway RPC. It runs entirely in the OpenClaw plugin lifecycle and adds no requirement on OpenClaw core.

Delegation verification is implemented through `agent-passport-system` 6.0.1. The plugin contains no independent verifier. Delegation verification uses the authority-aware chain verifier with trust anchors the operator configures, so an integrity result is never returned as an authorization decision (SDK 6.0.0, advisory GHSA-r2fw-x6mg-f6h8).

## Install

A corrected release is not yet available. These commands currently install affected versions and should not be relied on for enforcement.

```bash
clawhub install agent-passport-system-openclaw-plugin
# or
npm install agent-passport-system-openclaw-plugin
```

## Configuration

Config is read from, in order:

1. `$OPENCLAW_APS_CONFIG_PATH` (env var). If set and the file is missing, loading fails rather than falling back.
2. `~/.openclaw/aps.config.json`
3. Built-in defaults (permissive-with-warnings)

Configuration is **not** read from OpenClaw's plugin config. `plugins.entries.aps.config.*`
is rejected by the manifest schema rather than accepted and ignored, because the plugin
does not read `api.pluginConfig`.

A file that exists but cannot be read is a configuration error, not an absent file: an
unreadable policy never silently becomes the permissive default. Malformed values, unknown
enum values and out-of-range numbers are configuration errors for the same reason.

Some previously documented keys have been removed. `endpoints.jwks` still loads and
warns, because the plugin no longer contacts that service. The removed security
controls (`policy.skillAuthor.minGrade`, `policy.toolCalls.enforceScope`, everything
under `policy.inboundMessages`, and `highRiskBehavior: "warn"`) now fail to load: they
never did anything, and accepting them silently would leave you believing a control was
in force. Any other unrecognized key is also a configuration error.

Custom `passportPath` and `auditLogPath` must be **absolute**. Node does not expand `~`, so
a tilde path is rejected instead of resolving to a literal `./~/...` directory. The built-in
defaults shown below resolve through your home directory.

Schema (targets spec section 8):

```json
{
  "provider": "aps",
  "endpoints": {
    "verifier": "https://gateway.aeoess.com/api/v1/public/trust"
  },
  "credentials": { "passportPath": "/absolute/path/to/aps-credentials.json" },
  "signing": {
    "enabled": false,
    "allowedCallers": [],
    "requireApproval": false,
    "auditLogPath": "/absolute/path/to/aps-signing-audit.log"
  },
  "policy": {
    "skillAuthor": { "warnBelow": 1, "blockBelow": null },
    "toolCalls": { "highRiskTools": ["bash", "exec", "fetch"], "highRiskBehavior": "approval" }
  }
}
```

| Field | Meaning |
|---|---|
| `endpoints.verifier` | Public APS trust profile API base URL. Must be an absolute http or https URL |
| `credentials.passportPath` | Local APS passport file, absolute. Opened only when `signing.enabled` is true |
| `signing.enabled` | Turn on `aps.signMessage`. Default `false`. See [Signing](#signing) |
| `signing.allowedCallers` | Plugin ids, or the literal `gateway-client`, permitted to sign. Empty means nobody |
| `signing.requireApproval` | Refuse every signing request until the host can ask a person. Default `false`; the allowlist is the gate |
| `signing.auditLogPath` | Absolute path. Log of signing requests and refusals; see [Signing](#signing) for what is guaranteed |
| `policy.skillAuthor.warnBelow` | Surface install-time warning when author grade < this. Integer 0-4 |
| `policy.skillAuthor.blockBelow` | Block install when author grade < this. Integer 0-4, or `null` to never block |
| `policy.toolCalls.highRiskTools` | Tool names treated as high-risk |
| `policy.toolCalls.highRiskBehavior` | `"approval"` (default) or `"block"` |

## Hook coverage (Pattern v0.1)

| Hook | Status | Behavior |
|---|---|---|
| `before_install` | does not register with current OpenClaw | Looks up author grade against APS gateway. Returns `block` if grade < `blockBelow`, `findings` if grade < `warnBelow`, pass-through otherwise. Missing author, unknown author, unavailable verifier and malformed response each produce their own warn finding and never block. 500ms cold latency budget; a timeout is reported as an unavailable verifier. |
| `before_tool_call` | does not register with current OpenClaw; high-risk tools only | Tools listed in `policy.toolCalls.highRiskTools` go through `highRiskBehavior` (approval or block). Approval offers only allow-once or deny, never allow-always, so the gate cannot be retired for later calls. Non-high-risk calls pass through. |
| `gateway_start` | does not register with current OpenClaw | Loads config and reports signing state. The passport file is opened only when `signing.enabled` is true. Failures log via the host logger; they do not block startup. |
| `inbound_claim` | not implemented | |
| `before_dispatch` | not implemented | |

The Behavior column describes intended behaviour. With current OpenClaw, versions through 0.2.1 do not register any of these handlers.

## Gateway RPC methods (intended)

The plugin defines the following namespaced RPC handlers. With current OpenClaw, versions through 0.2.1 fail registration before these methods are installed.

- `aps.checkGrade` with `params: { agentId }` → `TrustProfile | null` from the public APS gateway. That is the successful-response contract: a profile for a known author, `null` for an author the registry does not know. It is not the only outcome. If the verifier is unreachable or answers with a profile the plugin cannot trust, the call fails with a Gateway error (`aps_verifier_unavailable` or `aps_verifier_malformed`) rather than returning `null`, because reporting a transport failure as "author not known" is the conflation this release removed.
- `aps.verifyDelegation` with `params: { chain }` → result of APS SDK `verifyAuthorityDelegationChain()`. `chain` is the delegation chain as an array, root first, not a single token. Gateway methods take one options object from the host; 0.2.0 read positional arguments and both RPCs were unusable. Trust anchors come from `policy.delegation.trustedIssuers`; with none configured nothing verifies, which is the default. Revocation resolves to `unknown` because this plugin carries no revocation feed, so a cryptographically sound chain returns `state: "indeterminate"` rather than a `valid: true` it cannot establish.
- `aps.signMessage({ message })` → `{ signature, domain, digest }`. Ed25519 signature over a domain-separated input, using the local passport's private key. Off unless the operator turns it on. See [Signing](#signing).

Once registration succeeds, other plugins can call these by their namespaced names.

## Signing

The `aps.signMessage` handler is designed to sign with the private key in the passport file at `credentials.passportPath`. A gateway method registered by a plugin is not private to that plugin: OpenClaw dispatches it for authenticated gateway clients, and other plugins can reach it through the in-process runtime. The ClawHub review of 0.2.0 identified that, if registered, the original handler would have made that signing capability reachable too broadly. 0.2.1 adds caller allowlisting inside the handler, but with current OpenClaw registration fails before the handler is installed.

What the reviewers told installers still holds. The points below describe intended behaviour:

- Signing is **off by default**. With `signing.enabled` false, `aps.signMessage` refuses every request and the passport file is never opened.
- Turning it on is a decision about every plugin on the host, not just this one. Turn it on only if you trust each installed plugin that could call `aps.signMessage`, and prefer a limited-purpose passport identity over your main one.
- `signing.allowedCallers` names who may sign. Entries are OpenClaw plugin ids, or the literal `gateway-client` for an authenticated gateway client that the host did not identify as a plugin. An empty list, the default, allows nobody.
- `signing.requireApproval` defaults to false, and the allowlist is the gate: signing is off unless `signing.enabled` is true, and an empty `allowedCallers` refuses everything. Setting `requireApproval` to true refuses every request, because OpenClaw 2026.9.2 gives a gateway RPC handler no channel to ask a person for a decision: the mechanism the tool-call gate uses is a return value of the `before_tool_call` hook, and the SDK helper that reaches the host approval method is limited to plugin HTTP routes. It exists so an operator can hard-stop signing without editing the allowlist, and it will become a real approval once the host offers one. Citations are in the header of `src/signing.ts`.

Every signature is minted over `APS-OPENCLAW-PLUGIN-SIGN-MESSAGE-V1\0` plus the message, following the domain-separation convention the SDK uses for authority delegations. A signature produced here therefore does not verify as a passport, attestation or delegation signature over the same bytes, and cannot be replayed into one of those contexts.

The plugin attempts to append one JSON line per signing request and refusal to `signing.auditLogPath`, by default `aps-signing-audit.log` in your `.openclaw` directory. Each line records the timestamp, the outcome, the caller, the domain prefix and the sha256 digest of the message. The message body is never written. A write failure does not abort the request: it is logged and signing continues, and that log is itself best-effort, so the audit log is not a guaranteed record.

One limit worth knowing: the caller name comes from what the host supplies. A plugin dispatching through the trusted in-process runtime is named exactly, because OpenClaw stamps the plugin id itself and never takes it from request parameters. A plugin that instead forwards a request from one of its own HTTP routes arrives carrying the original client and is indistinguishable from `gateway-client`. Allowlisting `gateway-client` is therefore broader than allowlisting a plugin id.

## Conformance status

Versions through 0.2.1 do not claim conformance to Agent Trust Verification Provider Pattern v0.1 with current OpenClaw. Criterion 1 is not met, because the required hooks do not register. The implementation targets the remaining pattern requirements, but those do not establish runtime conformance while registration fails. The per-criterion checklist is withheld until a release is proved against a real Gateway.

## v0.1 scope and known limitations

- **High-risk-tool gate is the only `before_tool_call` enforcement.** Full delegation-scope verification requires the agent to be running with an APS passport context, and is not implemented. Caching to keep the typical-case latency under 100ms is planned alongside it (spec section 9 #5).
- **`inbound_claim` and `before_dispatch` deferred.** The agent runtime context for inter-agent messaging is still being formalized; these hooks are planned once the surface is stable.
- **Author identifier extraction is best-effort.** OpenClaw's hook event types expose no `author` on `event.skill` or `event.plugin`, so binding to the host types removed the branches that read one. The only identifier available is the npm scope of a scoped `packageName`; everything else, including local archives, is treated as missing-author (warning, not block).
- **No retry layer.** If the gateway is slow (>500ms) the install proceeds with a warning. Caching of grade lookups is also planned, not implemented.

## Examples

The examples below describe the intended configuration semantics. On affected versions with current OpenClaw, the handlers that apply these policies do not register.

### Default (permissive-with-warnings)

No config file needed. The defaults block nothing, surface warnings for unknown or low-grade authors, and require user approval for `bash`/`exec`/`fetch`.

### Strict mode

```json
{
  "provider": "aps",
  "policy": {
    "skillAuthor": { "warnBelow": 2, "blockBelow": 1 },
    "toolCalls": { "highRiskTools": ["bash", "exec", "fetch", "shell"], "highRiskBehavior": "block" }
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
