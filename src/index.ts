// Agent Passport System OpenClaw plugin — entry.
// Conformance: Agent Trust Verification Provider Pattern v0.1.
// Hooks: before_install, before_tool_call, gateway_start. inbound_claim and
// before_dispatch deferred to v0.2.

import { existsSync, readFileSync } from 'node:fs'
import { sign, verifyDelegation } from 'agent-passport-system'
import { type APSPluginConfig, loadConfig } from './config.js'
import { type TrustProfile, checkGrade, fetchJWKS } from './aps-client.js'

// Narrow types matching OpenClaw plugin SDK hook surface (commit 45146913007d).
// Defined locally so we don't depend on a moving SDK type export.

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
  requireApproval?: { title: string; description: string; severity?: 'info' | 'warning' | 'critical'; timeoutMs?: number; timeoutBehavior?: 'allow' | 'deny' }
}
interface GatewayStartEvent { port: number }

export interface PluginAPI {
  registerHook<K extends 'before_install' | 'before_tool_call' | 'gateway_start'>(
    name: K,
    handler: K extends 'before_install' ? (e: InstallEvent) => Promise<InstallResult | void> | InstallResult | void
      : K extends 'before_tool_call' ? (e: ToolCallEvent) => Promise<ToolCallResult | void> | ToolCallResult | void
      : (e: GatewayStartEvent) => Promise<void> | void,
  ): void
  registerGatewayMethod(name: string, handler: (...args: unknown[]) => Promise<unknown> | unknown): void
  log?: (level: 'info' | 'warn' | 'error', message: string) => void
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
        severity: 'warning', timeoutMs: 30_000, timeoutBehavior: 'deny',
      },
    }
    return undefined
  }
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
    log(api, 'info', `aps plugin ready (provider=${config.provider}, verifier=${config.endpoints.verifier})`)
  })

  api.registerGatewayMethod('aps.checkGrade', async (...args: unknown[]) => {
    const agentId = String(args[0] ?? '')
    if (!agentId) throw new Error('aps.checkGrade: agentId required')
    return await checkGrade(config.endpoints.verifier, agentId)
  })

  api.registerGatewayMethod('aps.verifyDelegation', async (...args: unknown[]) => {
    const token = args[0]
    if (!token || typeof token !== 'object') throw new Error('aps.verifyDelegation: delegation token required')
    return verifyDelegation(token as Parameters<typeof verifyDelegation>[0])
  })

  api.registerGatewayMethod('aps.signMessage', async (...args: unknown[]) => {
    const passportPath = config.credentials.passportPath
    if (!existsSync(passportPath)) throw new Error('aps.signMessage: no local passport configured')
    const passport: unknown = JSON.parse(readFileSync(passportPath, 'utf8'))
    if (!passport || typeof passport !== 'object' || !('privateKey' in passport)) throw new Error('aps.signMessage: passport file missing privateKey')
    const payload = typeof args[0] === 'string' ? args[0] : JSON.stringify(args[0])
    return sign(payload, (passport as { privateKey: string }).privateKey)
  })
}
