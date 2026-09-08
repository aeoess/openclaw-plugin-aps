// Agent Passport System OpenClaw plugin — config schema + loader.
// Targets section 8 of Agent Trust Verification Provider Pattern v0.1.
//
// Config is read ONLY from OPENCLAW_APS_CONFIG_PATH or ~/.openclaw/aps.config.json.
// It is not read from OpenClaw's plugin config, so the host's manifest schema
// never validates these values: this module is the only validation they get,
// and a malformed security policy must fail rather than become the permissive
// branch.

import { readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { isAbsolute, join } from 'node:path'

/** 'warn' was accepted and then fell through to no finding at all, so it was a
 *  silently inert third option. Removed rather than implemented. */
export type HighRiskBehavior = 'approval' | 'block'

/** A trust anchor the operator has decided to accept: the issuer identifier
 *  and the Ed25519 public key that issuer signs with. Both are supplied by the
 *  operator, never read out of the artifact being verified. */
export interface TrustedIssuer {
  issuer: string
  /** Ed25519 public key, 64 lowercase hex characters. */
  publicKey: string
  /** Optional: restrict to one verification_method on that issuer. */
  verificationMethod?: string
}

/** Controls for aps.signMessage, which signs with the configured local
 *  passport private key. Off by default: a registered gateway method is
 *  reachable by other plugins and by authenticated gateway clients, so an
 *  operator opts in per host rather than inheriting signing from a passport
 *  path that was configured for something else. */
export interface SigningConfig {
  enabled: boolean
  /** Plugin ids, or the literal 'gateway-client' for any authenticated client
   *  the host did not name as a plugin. Empty means no caller may sign. */
  allowedCallers: string[]
  requireApproval: boolean
  auditLogPath: string
}

export interface APSPluginConfig {
  provider: 'aps'
  endpoints: { verifier: string }
  credentials: { passportPath: string }
  signing: SigningConfig
  policy: {
    skillAuthor: { warnBelow: number; blockBelow: number | null }
    toolCalls: { highRiskTools: string[]; highRiskBehavior: HighRiskBehavior }
    /** Trust inputs for authority-aware delegation verification. The SDK's
     *  chain verifier takes these from the caller and never from the chain, so
     *  an empty trustedIssuers list means nothing verifies: the plugin fails
     *  closed rather than trusting whatever key the artifact carries. */
    delegation: { trustedIssuers: TrustedIssuer[]; allowSelfSignedRoot: boolean }
  }
}

export const DEFAULT_CONFIG: APSPluginConfig = {
  provider: 'aps',
  endpoints: {
    verifier: 'https://gateway.aeoess.com/api/v1/public/trust',
  },
  credentials: { passportPath: join(homedir(), '.openclaw', 'aps-credentials.json') },
  // Signing off, no caller allowed, approval required. All three have to be
  // changed deliberately before the passport key is ever loaded.
  signing: {
    enabled: false,
    allowedCallers: [],
    requireApproval: false,
    auditLogPath: join(homedir(), '.openclaw', 'aps-signing-audit.log'),
  },
  policy: {
    skillAuthor: { warnBelow: 1, blockBelow: null },
    toolCalls: { highRiskTools: ['bash', 'exec', 'fetch'], highRiskBehavior: 'approval' },
    // No anchors and no self-signed roots by default. An operator who wants
    // delegation verification configures the issuers they actually trust.
    delegation: { trustedIssuers: [], allowSelfSignedRoot: false },
  },
}

const KNOWN_TOP_LEVEL = new Set(['provider', 'endpoints', 'credentials', 'signing', 'policy'])
const KNOWN_POLICY = new Set(['skillAuthor', 'toolCalls', 'delegation'])
const KNOWN_ENDPOINTS = new Set(['verifier'])

/** Removing documented config keys is a breaking change, and the two kinds of
 *  removal deserve opposite treatment.
 *
 *  A removed ENDPOINT is benign: it named a service the plugin no longer talks
 *  to, so ignoring it changes nothing an operator was relying on. Warn and
 *  continue.
 *
 *  A removed SECURITY CONTROL is not benign. An operator who set it believed it
 *  did something, and it never did. Accepting the key and quietly ignoring it
 *  would repeat the exact defect this release exists to fix: a control that
 *  looks configured and enforces nothing. So it fails loudly and makes them
 *  look at what their policy actually is now.
 *
 *  Anything else unrecognized also fails, because a key we cannot explain may
 *  be a typo silently disabling a gate. */
const REMOVED_ENDPOINTS = new Map<string, string>([
  ['jwks', 'the JWKS endpoint was removed with the unused envelope-verification code; nothing fetches it'],
])

const REMOVED_SECURITY_CONTROLS = new Map<string, string>([
  ['policy.skillAuthor.minGrade', 'minGrade was never read by any handler; use warnBelow and blockBelow'],
  ['policy.toolCalls.enforceScope', 'enforceScope was never read by any handler; scope enforcement is not implemented'],
  ['policy.inboundMessages', 'the inbound_claim hook is not implemented, so nothing under inboundMessages was ever read'],
  ['policy.inboundMessages.requireSignature', 'the inbound_claim hook is not implemented'],
  ['policy.inboundMessages.warnUnsigned', 'the inbound_claim hook is not implemented'],
])

/** Throws with the removal reason when `field` names a control that used to
 *  exist and enforced nothing. */
function rejectIfRemovedSecurityControl(field: string): void {
  const reason = REMOVED_SECURITY_CONTROLS.get(field)
  if (reason !== undefined) {
    throw new Error(`aps config: ${field} was removed in this release and is no longer accepted (${reason}). Remove it from your config and re-check your policy.`)
  }
}

export function loadConfig(): APSPluginConfig {
  const envPath = process.env.OPENCLAW_APS_CONFIG_PATH
  const homePath = join(homedir(), '.openclaw', 'aps.config.json')
  const path = envPath ?? homePath
  let text: string
  try {
    text = readFileSync(path, 'utf8')
  } catch (e) {
    // Absent is a real state and falls back to defaults. Present but
    // unreadable is NOT absent: treating a permission failure as "no policy
    // file" silently downgraded an operator's policy to permissive defaults.
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') {
      if (envPath !== undefined) {
        throw new Error(`aps config: OPENCLAW_APS_CONFIG_PATH is set to ${path} but no such file exists`)
      }
      return DEFAULT_CONFIG
    }
    throw new Error(`aps config: ${path} exists but could not be read: ${(e as Error).message}`)
  }
  let raw: unknown
  try {
    raw = JSON.parse(text)
  } catch (e) {
    throw new Error(`aps config: ${path} is not valid JSON: ${(e as Error).message}`)
  }
  return validate(raw)
}

function validate(raw: unknown): APSPluginConfig {
  if (!raw || typeof raw !== 'object') throw new Error('aps config: expected object')
  const obj = raw as Record<string, unknown>
  for (const k of Object.keys(obj)) {
    if (!KNOWN_TOP_LEVEL.has(k)) {
      throw new Error(`aps config: unrecognized top-level field: ${k}`)
    }
  }
  const endpoints = (obj.endpoints ?? {}) as Record<string, unknown>
  for (const k of Object.keys(endpoints)) {
    if (KNOWN_ENDPOINTS.has(k)) continue
    const removed = REMOVED_ENDPOINTS.get(k)
    if (removed !== undefined) {
      console.warn(`[aps-plugin] endpoints.${k} is no longer used and is ignored (${removed})`)
      continue
    }
    throw new Error(`aps config: unrecognized endpoints field: ${k}`)
  }
  const policy = (obj.policy ?? {}) as Record<string, unknown>
  for (const k of Object.keys(policy)) {
    rejectIfRemovedSecurityControl(`policy.${k}`)
    if (!KNOWN_POLICY.has(k)) throw new Error(`aps config: unrecognized policy field: ${k}`)
  }
  return mergeWithDefaults(obj)
}

function mergeWithDefaults(obj: Record<string, unknown>): APSPluginConfig {
  const policy = (obj.policy ?? {}) as Partial<APSPluginConfig['policy']>
  const endpoints = (obj.endpoints ?? {}) as Partial<APSPluginConfig['endpoints']>
  const credentials = (obj.credentials ?? {}) as Partial<APSPluginConfig['credentials']>
  return {
    provider: 'aps',
    endpoints: { verifier: normalizeVerifierUrl(endpoints.verifier) },
    credentials: { passportPath: normalizeAbsolutePath('credentials.passportPath', credentials.passportPath, DEFAULT_CONFIG.credentials.passportPath) },
    signing: normalizeSigningConfig(obj.signing),
    policy: {
      skillAuthor: normalizeSkillAuthorPolicy(policy.skillAuthor),
      toolCalls: normalizeToolCallsPolicy(policy.toolCalls),
      delegation: normalizeDelegationPolicy(policy.delegation),
    },
  }
}

const KNOWN_SIGNING = new Set(['enabled', 'allowedCallers', 'requireApproval', 'auditLogPath'])

/** Same fail-closed rule as the delegation trust inputs: a malformed signing
 *  block is a configuration error, not an implied default. Only an explicit
 *  `true` turns signing on, and only an explicit `false` turns approval off. */
function normalizeSigningConfig(raw: unknown): SigningConfig {
  if (raw === undefined || raw === null) return { ...DEFAULT_CONFIG.signing, allowedCallers: [] }
  if (typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('aps config: signing must be an object')
  }
  const obj = raw as Record<string, unknown>
  for (const k of Object.keys(obj)) {
    if (!KNOWN_SIGNING.has(k)) throw new Error(`aps config: unrecognized signing field: ${k}`)
  }
  const rawCallers = obj.allowedCallers
  if (rawCallers !== undefined && !Array.isArray(rawCallers)) {
    throw new Error('aps config: signing.allowedCallers must be an array of strings')
  }
  const allowedCallers = (rawCallers ?? []).map((item, i) => {
    if (typeof item !== 'string' || item.trim().length === 0) {
      throw new Error(`aps config: signing.allowedCallers[${i}] must be a non-empty string`)
    }
    return item.trim()
  })
  const auditLogPath = normalizeAbsolutePath(
    'signing.auditLogPath',
    obj.auditLogPath,
    DEFAULT_CONFIG.signing.auditLogPath,
  )
  return {
    enabled: obj.enabled === true,
    allowedCallers,
    requireApproval: obj.requireApproval === true,
    auditLogPath,
  }
}

/** A malformed trust input is neither "no anchors" nor "all anchors": it is a
 *  configuration error, and it fails closed. Mirrors the SDK 5.0.0 fix where
 *  `?? []` let every non-null malformed shape through as an empty anchor list. */
function normalizeDelegationPolicy(raw: unknown): APSPluginConfig['policy']['delegation'] {
  if (raw === undefined || raw === null) return { ...DEFAULT_CONFIG.policy.delegation }
  if (typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('aps config: policy.delegation must be an object')
  }
  const obj = raw as Record<string, unknown>
  const allowSelfSignedRoot = obj.allowSelfSignedRoot === true
  const rawIssuers = obj.trustedIssuers
  if (rawIssuers === undefined) return { trustedIssuers: [], allowSelfSignedRoot }
  if (!Array.isArray(rawIssuers)) {
    throw new Error('aps config: policy.delegation.trustedIssuers must be an array')
  }
  const trustedIssuers: TrustedIssuer[] = rawIssuers.map((item, i) => {
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      throw new Error(`aps config: trustedIssuers[${i}] must be an object`)
    }
    const rec = item as Record<string, unknown>
    if (typeof rec.issuer !== 'string' || rec.issuer.length === 0) {
      throw new Error(`aps config: trustedIssuers[${i}].issuer must be a non-empty string`)
    }
    if (typeof rec.publicKey !== 'string' || !/^[0-9a-f]{64}$/.test(rec.publicKey)) {
      throw new Error(`aps config: trustedIssuers[${i}].publicKey must be 64 lowercase hex characters`)
    }
    const vm = rec.verificationMethod
    if (vm !== undefined && typeof vm !== 'string') {
      throw new Error(`aps config: trustedIssuers[${i}].verificationMethod must be a string`)
    }
    return { issuer: rec.issuer, publicKey: rec.publicKey, ...(typeof vm === 'string' ? { verificationMethod: vm } : {}) }
  })
  return { trustedIssuers, allowSelfSignedRoot }
}

/** Custom paths go straight to Node filesystem APIs, which do not expand `~`.
 *  A path like `~/x` was silently created as a literal `./~/x`, so a relative
 *  or tilde path is a configuration error rather than a surprise location.
 *  The defaults still resolve through homedir(). */
function normalizeAbsolutePath(field: string, raw: unknown, fallback: string): string {
  if (raw === undefined) return fallback
  if (typeof raw !== 'string' || raw.trim().length === 0) {
    throw new Error(`aps config: ${field} must be a non-empty string`)
  }
  const value = raw.trim()
  if (value.startsWith('~')) {
    throw new Error(`aps config: ${field} must be an absolute path; '~' is not expanded (received ${value})`)
  }
  if (!isAbsolute(value)) {
    throw new Error(`aps config: ${field} must be an absolute path (received ${value})`)
  }
  return value
}

function normalizeVerifierUrl(raw: unknown): string {
  if (raw === undefined) return DEFAULT_CONFIG.endpoints.verifier
  if (typeof raw !== 'string' || raw.trim().length === 0) {
    throw new Error('aps config: endpoints.verifier must be a non-empty string')
  }
  const value = raw.trim()
  let parsed: URL
  try {
    parsed = new URL(value)
  } catch {
    throw new Error(`aps config: endpoints.verifier must be an absolute URL (received ${value})`)
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new Error(`aps config: endpoints.verifier must be http or https (received ${parsed.protocol})`)
  }
  return value
}

const KNOWN_SKILL_AUTHOR = new Set(['warnBelow', 'blockBelow'])
const GRADE_THRESHOLD_MAX = 4

/** APS grades are 0 to 3, so a threshold is an integer 0 to 4: 0 never fires
 *  and 4 fires for every grade. Anything else is a configuration error, not a
 *  value to clamp, because a mistyped threshold silently disables a gate. */
function normalizeGradeThreshold(field: string, raw: unknown, fallback: number): number {
  if (raw === undefined) return fallback
  if (typeof raw !== 'number' || !Number.isInteger(raw) || raw < 0 || raw > GRADE_THRESHOLD_MAX) {
    throw new Error(`aps config: ${field} must be an integer between 0 and ${GRADE_THRESHOLD_MAX} (received ${JSON.stringify(raw)})`)
  }
  return raw
}

function normalizeSkillAuthorPolicy(raw: unknown): APSPluginConfig['policy']['skillAuthor'] {
  if (raw === undefined || raw === null) return { ...DEFAULT_CONFIG.policy.skillAuthor }
  if (typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('aps config: policy.skillAuthor must be an object')
  }
  const obj = raw as Record<string, unknown>
  for (const k of Object.keys(obj)) {
    rejectIfRemovedSecurityControl(`policy.skillAuthor.${k}`)
    if (!KNOWN_SKILL_AUTHOR.has(k)) throw new Error(`aps config: unrecognized policy.skillAuthor field: ${k}`)
  }
  // null is the documented "blocking disabled" value and must stay distinct
  // from an absent key, which takes the default.
  let blockBelow: number | null
  if (obj.blockBelow === null) blockBelow = null
  else if (obj.blockBelow === undefined) blockBelow = DEFAULT_CONFIG.policy.skillAuthor.blockBelow
  else blockBelow = normalizeGradeThreshold('policy.skillAuthor.blockBelow', obj.blockBelow, 0)
  return {
    warnBelow: normalizeGradeThreshold('policy.skillAuthor.warnBelow', obj.warnBelow, DEFAULT_CONFIG.policy.skillAuthor.warnBelow),
    blockBelow,
  }
}

const KNOWN_TOOL_CALLS = new Set(['highRiskTools', 'highRiskBehavior'])
const HIGH_RISK_BEHAVIORS: readonly HighRiskBehavior[] = ['approval', 'block']

function normalizeToolCallsPolicy(raw: unknown): APSPluginConfig['policy']['toolCalls'] {
  if (raw === undefined || raw === null) return { ...DEFAULT_CONFIG.policy.toolCalls, highRiskTools: [...DEFAULT_CONFIG.policy.toolCalls.highRiskTools] }
  if (typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('aps config: policy.toolCalls must be an object')
  }
  const obj = raw as Record<string, unknown>
  for (const k of Object.keys(obj)) {
    rejectIfRemovedSecurityControl(`policy.toolCalls.${k}`)
    if (!KNOWN_TOOL_CALLS.has(k)) throw new Error(`aps config: unrecognized policy.toolCalls field: ${k}`)
  }
  const rawTools = obj.highRiskTools
  if (rawTools !== undefined && !Array.isArray(rawTools)) {
    throw new Error('aps config: policy.toolCalls.highRiskTools must be an array of strings')
  }
  const highRiskTools = rawTools === undefined
    ? [...DEFAULT_CONFIG.policy.toolCalls.highRiskTools]
    : rawTools.map((item, i) => {
        if (typeof item !== 'string' || item.trim().length === 0) {
          throw new Error(`aps config: policy.toolCalls.highRiskTools[${i}] must be a non-empty string`)
        }
        return item.trim()
      })
  const rawBehavior = obj.highRiskBehavior
  if (rawBehavior === undefined) {
    return { highRiskTools, highRiskBehavior: DEFAULT_CONFIG.policy.toolCalls.highRiskBehavior }
  }
  if (typeof rawBehavior !== 'string' || !HIGH_RISK_BEHAVIORS.includes(rawBehavior as HighRiskBehavior)) {
    const removedNote = rawBehavior === 'warn'
      ? ' The "warn" behaviour was removed: it was accepted and then emitted nothing.'
      : ''
    throw new Error(`aps config: policy.toolCalls.highRiskBehavior must be one of ${HIGH_RISK_BEHAVIORS.join(', ')} (received ${JSON.stringify(rawBehavior)}).${removedNote}`)
  }
  return { highRiskTools, highRiskBehavior: rawBehavior as HighRiskBehavior }
}
