// Agent Passport System OpenClaw plugin — entry.
// Conformance: Agent Trust Verification Provider Pattern v0.1.
// Hooks: before_install, before_tool_call, gateway_start. All three verified
// present in OpenClaw 2026.9.2 at src/plugins/hook-types.ts:139, :119 and :129.
// inbound_claim and before_dispatch remain deferred.
//
// Verification runs in the SDK, never here. aps.verifyDelegation calls the
// authority-aware chain verifier with trust inputs the operator supplied, so an
// integrity-only answer can never be mistaken for an authorization decision
// (agent-passport-system 6.0.0 advisory GHSA-r2fw-x6mg-f6h8).

import { existsSync, readFileSync } from 'node:fs'
import { verifyAuthorityDelegationChain } from 'agent-passport-system'
import type { AuthorityDelegationV1, RevocationResolution } from 'agent-passport-system'
import { type APSPluginConfig, loadConfig } from './config.js'
import { type TrustProfile, checkGrade, fetchJWKS } from './aps-client.js'
import { type GatewayCallerClient, makeSignMessage } from './signing.js'

// Narrow structural types matching the OpenClaw hook surface at 2026.9.2
// (src/plugins/hook-types.ts). Defined locally so the plugin does not depend on
// a moving SDK type export; extra host fields pass through structurally.
//
// The host payload carries NO author on either skill or plugin
// (PluginHookBeforeInstallSkill is { installId, installSpec? };
// PluginHookBeforeInstallPlugin is { pluginId, contentType, packageName?,
// manifestId?, version?, extensions? }). The author fields below are read only
// if a future host adds them; today the author gate resolves scoped npm package
// names and nothing else, which the README states.

interface InstallFinding { ruleId: string; severity: 'info' | 'warn' | 'critical'; file: string; line: number; message: string }
type InstallEvent = {
  targetType: 'skill' | 'plugin'; targetName: string; origin?: string
  skill?: { installId: string; author?: string }
  plugin?: { pluginId: string; packageName?: string; version?: string; author?: string }
}
interface InstallResult { findings?: InstallFinding[]; block?: boolean; blockReason?: string }
interface ToolCallEvent { toolName: string; params: Record<string, unknown>; runId?: string; toolCallId?: string }
interface ToolCallResult {
  block?: boolean; blockReason?: string
  // timeoutBehavior is deprecated at 2026.9.2 (unresolved approvals always
  // deny) and is scheduled for removal; it is not set.
  requireApproval?: { title: string; description: string; severity?: 'info' | 'warning' | 'critical'; timeoutMs?: number }
}
interface GatewayStartEvent { port: number }

export interface PluginAPI {
  registerHook<K extends 'before_install' | 'before_tool_call' | 'gateway_start'>(
    name: K,
    handler: K extends 'before_install' ? (e: InstallEvent) => Promise<InstallResult | void> | InstallResult | void
      : K extends 'before_tool_call' ? (e: ToolCallEvent) => Promise<ToolCallResult | void> | ToolCallResult | void
      : (e: GatewayStartEvent) => Promise<void> | void,
  ): void
  registerGatewayMethod(
    name: string,
    handler: (opts: GatewayMethodOptions) => Promise<unknown> | unknown,
  ): void
  log?: (level: 'info' | 'warn' | 'error', message: string) => void
}

/** The normalized invocation options OpenClaw 2026.9.2 passes to a registered
 *  gateway method (GatewayRequestHandlerOptions,
 *  src/gateway/server-methods/shared-types.ts:449), forwarded verbatim to the
 *  plugin handler by src/plugins/registry-registrars-network.ts:33. Only the
 *  two fields this plugin reads are declared; the host passes more. */
export interface GatewayMethodOptions {
  params?: Record<string, unknown>
  client?: GatewayCallerClient | null
}

const COLD_LATENCY_BUDGET_MS = 500
const log = (api: PluginAPI, level: 'info' | 'warn' | 'error', m: string): void =>
  api.log ? api.log(level, `[aps] ${m}`) : (level === 'error' ? console.error : level === 'warn' ? console.warn : console.log)(`[aps] ${m}`)

function authorOf(event: InstallEvent): string | null {
  // Forward-compat: prefer explicit author if a future SDK adds it. Fall back
  // to npm scope of packageName, then null (handled per spec section 5.1).
  if (event.skill?.author) return event.skill.author
  if (event.plugin?.author) return event.plugin.author
  const pkg = event.plugin?.packageName
  if (pkg && pkg.startsWith('@')) return pkg.split('/')[0]?.slice(1) ?? null
  return null
}

function withTimeout<T>(p: Promise<T>, ms: number, onTimeout: () => T): Promise<T> {
  return new Promise(resolve => {
    let done = false
    const t = setTimeout(() => { if (!done) { done = true; resolve(onTimeout()) } }, ms)
    p.then(v => { if (!done) { done = true; clearTimeout(t); resolve(v) } })
     .catch(() => { if (!done) { done = true; clearTimeout(t); resolve(onTimeout()) } })
  })
}

const finding = (ruleId: string, file: string, message: string): InstallFinding =>
  ({ ruleId, severity: 'warn', file, line: 0, message })

export function makeBeforeInstall(config: APSPluginConfig, api: PluginAPI) {
  return async (event: InstallEvent): Promise<InstallResult | void> => {
    const author = authorOf(event)
    if (!author) return { findings: [finding('aps.author.missing', event.targetName, 'Skill author not registered with APS gateway (no author identifier in install event)')] }
    const profile = await withTimeout<TrustProfile | null>(
      checkGrade(config.endpoints.verifier, author),
      COLD_LATENCY_BUDGET_MS,
      () => { log(api, 'warn', `gateway timeout checking author ${author}`); return null },
    )
    if (profile === null) return { findings: [finding('aps.author.unknown', event.targetName, `Skill author '${author}' not found in APS trust registry`)] }
    const { blockBelow, warnBelow } = config.policy.skillAuthor
    if (blockBelow !== null && profile.grade < blockBelow) return { block: true, blockReason: `APS grade ${profile.grade} below blockBelow ${blockBelow} for ${author}` }
    if (profile.grade < warnBelow) return { findings: [finding('aps.author.low-grade', event.targetName, `APS grade ${profile.grade} below warnBelow ${warnBelow} for ${author}`)] }
    return undefined
  }
}

export function makeBeforeToolCall(config: APSPluginConfig) {
  return (event: ToolCallEvent): ToolCallResult | void => {
    const { highRiskTools, highRiskBehavior } = config.policy.toolCalls
    if (!highRiskTools.includes(event.toolName)) return undefined
    if (highRiskBehavior === 'block') return { block: true, blockReason: `tool ${event.toolName} is on APS high-risk list` }
    if (highRiskBehavior === 'approval') return {
      requireApproval: {
        title: `Approve high-risk tool: ${event.toolName}`,
        description: `APS plugin policy requires explicit approval for ${event.toolName}.`,
        severity: 'warning', timeoutMs: 30_000,
      },
    }
    return undefined
  }
}

/** Authority-aware delegation verification.
 *
 *  Every trust input comes from the operator's config and none from the chain:
 *  the key that checks a signature is looked up by issuer in the configured
 *  anchor list, and a root is trusted only if the operator named its issuer.
 *  With no anchors configured nothing verifies, which is the intended default.
 *
 *  Self-signed roots are refused unless the operator explicitly opts in, and
 *  even then the root's issuer must still resolve to a configured key. That
 *  opt-in is integrity-only and is not issuer trust, in the SDK's terms.
 *
 *  Revocation resolves to 'unknown' because this plugin has no revocation
 *  feed. It is reported, never silently treated as 'active'. */
export function verifyChain(config: APSPluginConfig, chain: readonly unknown[]) {
  const { trustedIssuers, allowSelfSignedRoot } = config.policy.delegation
  const anchorFor = (issuer: string, verificationMethod?: string) =>
    trustedIssuers.find(a =>
      a.issuer === issuer &&
      (a.verificationMethod === undefined || a.verificationMethod === verificationMethod)) ?? null

  return verifyAuthorityDelegationChain(chain, {
    now: new Date().toISOString(),
    resolveVerificationKey: (issuer: string, verificationMethod: string): string | null =>
      anchorFor(issuer, verificationMethod)?.publicKey ?? null,
    trustRoot: (root: AuthorityDelegationV1): boolean => {
      if (anchorFor(root.issuer, root.verification_method) === null) return false
      // A root that delegates to itself is only accepted on an explicit opt-in.
      if (root.issuer === root.subject && !allowSelfSignedRoot) return false
      return true
    },
    resolveRevocation: (_d: AuthorityDelegationV1): RevocationResolution => 'unknown',
  })
}

export default function definePlugin(api: PluginAPI): void {
  const config = loadConfig()

  api.registerHook('before_install', makeBeforeInstall(config, api))
  api.registerHook('before_tool_call', makeBeforeToolCall(config))

  api.registerHook('gateway_start', async (_event: GatewayStartEvent) => {
    try { await fetchJWKS(config.endpoints.jwks); log(api, 'info', `JWKS fetched from ${config.endpoints.jwks}`) }
    catch (e) { log(api, 'warn', `JWKS fetch failed: ${(e as Error).message}`) }
    const passportPath = config.credentials.passportPath
    if (existsSync(passportPath)) {
      try { JSON.parse(readFileSync(passportPath, 'utf8')); log(api, 'info', `passport file present at ${passportPath}`) }
      catch (e) { log(api, 'warn', `passport file at ${passportPath} did not parse: ${(e as Error).message}`) }
    } else log(api, 'info', `no local passport at ${passportPath} (signing methods will be unavailable)`)
    log(api, 'info', config.signing.enabled
      ? `aps.signMessage enabled for callers [${config.signing.allowedCallers.join(', ') || 'none'}], requireApproval=${config.signing.requireApproval}, audit log ${config.signing.auditLogPath}`
      : 'aps.signMessage disabled (signing.enabled is false); the passport key is never loaded')
    log(api, 'info', `aps plugin ready (provider=${config.provider}, verifier=${config.endpoints.verifier})`)
  })

  // Gateway method handlers receive ONE options object from the host
  // ({ params, respond, client, ... }); a returned value is delivered by the
  // host as respond(true, value). Reading positional args here was the 0.2.0
  // defect that made both RPCs unusable.
  api.registerGatewayMethod('aps.checkGrade', async (request: { params?: Record<string, unknown> } = {}) => {
    const agentId = typeof request.params?.agentId === 'string' ? request.params.agentId.trim() : ''
    if (!agentId) throw new Error('aps.checkGrade: params.agentId (string) required')
    return await checkGrade(config.endpoints.verifier, agentId)
  })

  api.registerGatewayMethod('aps.verifyDelegation', async (request: { params?: Record<string, unknown> } = {}) => {
    const chain = request.params?.chain
    if (!Array.isArray(chain) || chain.length === 0) {
      throw new Error('aps.verifyDelegation: params.chain (non-empty array, root first) is required')
    }
    return verifyChain(config, chain)
  })

  // Signing is gated in ./signing.ts: off unless the operator turned it on,
  // then allowlisted against the caller identity the host actually supplies,
  // then approval-gated, and only then does the passport key get loaded.
  api.registerGatewayMethod('aps.signMessage', makeSignMessage(config))
}
