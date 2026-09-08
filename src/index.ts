// Agent Passport System OpenClaw plugin — entry.
// Targets Agent Trust Verification Provider Pattern v0.1. Runtime conformance
// is withheld pending integration proof, matching the README and manifest.
// Hooks: before_install, before_tool_call, gateway_start, registered through
// api.on. inbound_claim and before_dispatch remain unimplemented.
//
// Verification runs in the SDK, never here. aps.verifyDelegation calls the
// authority-aware chain verifier with trust inputs the operator supplied, so an
// integrity-only answer can never be mistaken for an authorization decision
// (agent-passport-system 6.0.0 advisory GHSA-r2fw-x6mg-f6h8).

import { existsSync, readFileSync } from 'node:fs'
import { verifyAuthorityDelegationChain } from 'agent-passport-system'
import type { AuthorityDelegationV1, RevocationResolution } from 'agent-passport-system'
import { type APSPluginConfig, loadConfig } from './config.js'
import { type TrustLookup, checkGrade } from './aps-client.js'
import { makeSignMessage } from './signing.js'
import type { OpenClawPluginApi } from 'openclaw/plugin-sdk/plugin-entry'

// Bound to the host's own contract. openclaw is pinned exactly and is a dev
// dependency only; nothing from it is imported at runtime.
export type PluginAPI = OpenClawPluginApi

// Every hook event, context and result type below is derived from the host's
// own api.on signature through the public plugin-sdk/plugin-entry entrypoint.
// Nothing is restated locally and no OpenClaw internal path is imported. The
// concrete hook types are not themselves exported by that entrypoint, so they
// are named by instantiating the exported generic member at a literal hook
// name. Taking the host types also restores fields the old local mirrors had
// silently dropped: toolKind and toolInputKind on the tool event, scope and
// allowedDecisions on the approval result, and the second ctx argument that
// every handler had been declared without.
declare const hostApi: OpenClawPluginApi

type BeforeInstallHandler = Parameters<typeof hostApi.on<'before_install'>>[1]
type InstallEvent = Parameters<BeforeInstallHandler>[0]
type InstallResult = Exclude<Awaited<ReturnType<BeforeInstallHandler>>, void>
type InstallFinding = NonNullable<InstallResult['findings']>[number]

type BeforeToolCallHandler = Parameters<typeof hostApi.on<'before_tool_call'>>[1]
type ToolCallEvent = Parameters<BeforeToolCallHandler>[0]
type ToolCallResult = Exclude<Awaited<ReturnType<BeforeToolCallHandler>>, void>

/** The invocation options the host passes to a registered gateway method,
 *  derived from the host's own registerGatewayMethod signature. */
export type GatewayMethodOptions = Parameters<
  Parameters<OpenClawPluginApi['registerGatewayMethod']>[1]
>[0]

const COLD_LATENCY_BUDGET_MS = 500
const log = (api: PluginAPI, level: 'info' | 'warn' | 'error', m: string): void =>
  api.logger[level](`[aps] ${m}`)

/** The only author identifier the host actually supplies is the npm scope of a
 *  scoped package name. The previous version also read event.skill.author and
 *  event.plugin.author; binding to the host types proved neither field exists,
 *  so those branches were dead. Everything else resolves to null and is
 *  reported as a missing author, which is what the README describes. */
function authorOf(event: InstallEvent): string | null {
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

    // Unknown author, verifier unavailable and malformed response are three
    // distinct states. All three fail open at this gate, but each reports what
    // actually happened. A timeout is an unavailable verifier, not a missing
    // author, and it is the only case logged as a timeout.
    const lookup = await withTimeout<TrustLookup>(
      checkGrade(config.endpoints.verifier, author),
      COLD_LATENCY_BUDGET_MS,
      () => {
        log(api, 'warn', `APS verifier timed out after ${COLD_LATENCY_BUDGET_MS}ms checking author ${author}`)
        return { state: 'unavailable', reason: `verifier timed out after ${COLD_LATENCY_BUDGET_MS}ms` }
      },
    )

    if (lookup.state === 'unknown') {
      return { findings: [finding('aps.author.unknown', event.targetName, `Skill author '${author}' not found in APS trust registry`)] }
    }
    if (lookup.state === 'unavailable') {
      log(api, 'warn', `APS verifier unavailable checking author ${author}: ${lookup.reason}`)
      return { findings: [finding('aps.verifier.unavailable', event.targetName, `APS trust registry unavailable for '${author}' (${lookup.reason}); install not gated`)] }
    }
    if (lookup.state === 'malformed') {
      log(api, 'warn', `APS verifier returned an unusable profile for ${author}: ${lookup.reason}`)
      return { findings: [finding('aps.verifier.malformed', event.targetName, `APS trust registry returned an unusable profile for '${author}' (${lookup.reason}); install not gated`)] }
    }

    const { grade } = lookup.profile
    const { blockBelow, warnBelow } = config.policy.skillAuthor
    if (blockBelow !== null && grade < blockBelow) return { block: true, blockReason: `APS grade ${grade} below blockBelow ${blockBelow} for ${author}` }
    if (grade < warnBelow) return { findings: [finding('aps.author.low-grade', event.targetName, `APS grade ${grade} below warnBelow ${warnBelow} for ${author}`)] }
    return undefined
  }
}

export function makeBeforeToolCall(config: APSPluginConfig) {
  return (event: ToolCallEvent): ToolCallResult | void => {
    const { highRiskTools, highRiskBehavior } = config.policy.toolCalls
    // Deliberate: match on tool NAME even though the host type now also offers
    // toolKind and toolInputKind. Gating every tool called `exec`, whatever its
    // kind, is the more conservative rule, so the richer type is taken without
    // narrowing the policy.
    if (!highRiskTools.includes(event.toolName)) return undefined
    if (highRiskBehavior === 'block') return { block: true, blockReason: `tool ${event.toolName} is on APS high-risk list` }
    return {
      requireApproval: {
        title: `Approve high-risk tool: ${event.toolName}`,
        description: `APS plugin policy requires explicit approval for ${event.toolName}.`,
        severity: 'warning',
        timeoutMs: 30_000,
        // A per-call high-risk gate must not offer persistent trust: an
        // allow-always here would silently retire the gate for later calls.
        allowedDecisions: ['allow-once', 'deny'],
      },
    }
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

/** Filesystem seam for the passport probe. Injectable so a test can positively
 *  observe that NEITHER call happens while signing is disabled; an early return
 *  in the source is not by itself evidence of that. */
export type PassportProbeDeps = {
  exists?: (path: string) => boolean
  read?: (path: string) => string
}

/** Reports signing state at startup.
 *
 *  When signing is disabled the passport path is not stat-ed, not read and not
 *  parsed. The previous version probed the file unconditionally and then logged
 *  that the key is never loaded, which made the README and CHANGELOG claim
 *  false. It was unreachable only because the plugin never started; the startup
 *  activation fix made it reachable. */
export function reportSigningState(
  config: APSPluginConfig,
  api: PluginAPI,
  deps: PassportProbeDeps = {},
): void {
  if (config.signing.enabled !== true) {
    log(api, 'info', 'aps.signMessage disabled (signing.enabled is false); the passport file is not opened')
    return
  }
  log(api, 'info', `aps.signMessage enabled for callers [${config.signing.allowedCallers.join(', ') || 'none'}], requireApproval=${config.signing.requireApproval}, audit log ${config.signing.auditLogPath}`)
  const exists = deps.exists ?? existsSync
  const read = deps.read ?? ((path: string) => readFileSync(path, 'utf8'))
  const passportPath = config.credentials.passportPath
  if (!exists(passportPath)) {
    log(api, 'info', `no local passport at ${passportPath} (signing methods will be unavailable)`)
    return
  }
  try {
    JSON.parse(read(passportPath))
    log(api, 'info', `passport file present at ${passportPath}`)
  } catch (e) {
    log(api, 'warn', `passport file at ${passportPath} did not parse: ${(e as Error).message}`)
  }
}

/** Adapts a value-returning handler to the host's exported GatewayRequestHandler,
 *  which is typed (opts) => void | Promise<void>. The host's runtime adapter does
 *  deliver a returned value (adaptPluginGatewayMethodHandler,
 *  src/plugins/registry-registrars-network.ts:32-44 wraps every plugin gateway
 *  method and calls respond(true, result) when the handler returned one), so the
 *  exported type is stricter than the runtime. Responding explicitly satisfies
 *  the published type; it is a compatibility choice, not a bug fix. The inner
 *  handlers keep their own signatures and their own unit tests. */
/** An error that reaches the host error channel with a specific code. */
class GatewayMethodError extends Error {
  constructor(readonly code: string, message: string) {
    super(message)
  }
}

function gatewayMethod<T>(
  handler: (request: GatewayMethodOptions) => Promise<T> | T,
): (opts: GatewayMethodOptions) => Promise<void> {
  return async (opts: GatewayMethodOptions): Promise<void> => {
    try {
      opts.respond(true, await handler(opts))
    } catch (e) {
      const code = e instanceof GatewayMethodError ? e.code : 'aps_error'
      opts.respond(false, undefined, { code, message: (e as Error).message })
    }
  }
}

export default function definePlugin(api: PluginAPI): void {
  const config = loadConfig()

  // Typed lifecycle hooks are dispatched only by the typed hook runner, so they
  // must be registered through api.on. api.registerHook is the legacy internal
  // path and never reaches this dispatch.
  api.on('before_install', makeBeforeInstall(config, api))
  api.on('before_tool_call', makeBeforeToolCall(config))

  api.on('gateway_start', (_event) => {
    reportSigningState(config, api)
    log(api, 'info', `aps plugin ready (provider=${config.provider}, verifier=${config.endpoints.verifier})`)
  })

  // The exported GatewayRequestHandler type is (opts) => void | Promise<void>, so
  // returning a value is a type error even though the host's runtime adapter
  // would deliver it. 0.2.0 read positional args, which was a real defect; 0.2.1
  // corrected that to the options object and its RPCs would have worked had
  // plugin registration completed at all.
  // The published contract of this RPC is `TrustProfile | null` and stays that
  // way. TrustLookup is the internal shape the install gate uses; it is mapped
  // back here, at the boundary only. A verifier that is unavailable or that
  // answered with something unusable is a failure, not a `null`: reporting it
  // as "author not known" is exactly the conflation this repair removed, so it
  // travels through the host error channel instead.
  api.registerGatewayMethod('aps.checkGrade', gatewayMethod(async (request) => {
    const agentId = typeof request.params?.agentId === 'string' ? request.params.agentId.trim() : ''
    if (!agentId) throw new Error('aps.checkGrade: params.agentId (string) required')
    const lookup = await checkGrade(config.endpoints.verifier, agentId)
    switch (lookup.state) {
      case 'found': return lookup.profile
      case 'unknown': return null
      case 'unavailable':
        throw new GatewayMethodError('aps_verifier_unavailable', `aps.checkGrade: APS trust registry unavailable (${lookup.reason})`)
      case 'malformed':
        throw new GatewayMethodError('aps_verifier_malformed', `aps.checkGrade: APS trust registry returned an unusable profile (${lookup.reason})`)
    }
  }))

  api.registerGatewayMethod('aps.verifyDelegation', gatewayMethod(async (request) => {
    const chain = request.params?.chain
    if (!Array.isArray(chain) || chain.length === 0) {
      throw new Error('aps.verifyDelegation: params.chain (non-empty array, root first) is required')
    }
    return verifyChain(config, chain)
  }))

  // Signing is gated in ./signing.ts: off unless the operator turned it on,
  // then allowlisted against the caller identity the host actually supplies,
  // then approval-gated, and only then does the passport key get loaded.
  api.registerGatewayMethod('aps.signMessage', gatewayMethod(makeSignMessage(config)))
}
