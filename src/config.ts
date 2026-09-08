// Agent Passport System OpenClaw plugin — config schema + loader.
// Schema mirrors section 8 of Agent Trust Verification Provider Pattern v0.1.

import { readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

export type HighRiskBehavior = 'approval' | 'block' | 'warn'

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
  endpoints: { verifier: string; jwks: string }
  credentials: { passportPath: string }
  signing: SigningConfig
  policy: {
    skillAuthor: { minGrade: number; warnBelow: number; blockBelow: number | null }
    toolCalls: { enforceScope: boolean; highRiskTools: string[]; highRiskBehavior: HighRiskBehavior }
    inboundMessages: { requireSignature: boolean; warnUnsigned: boolean }
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
    jwks: 'https://gateway.aeoess.com/.well-known/jwks.json',
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
    skillAuthor: { minGrade: 0, warnBelow: 1, blockBelow: null },
    toolCalls: { enforceScope: true, highRiskTools: ['bash', 'exec', 'fetch'], highRiskBehavior: 'approval' },
    inboundMessages: { requireSignature: false, warnUnsigned: true },
    // No anchors and no self-signed roots by default. An operator who wants
    // delegation verification configures the issuers they actually trust.
    delegation: { trustedIssuers: [], allowSelfSignedRoot: false },
  },
}

const KNOWN_TOP_LEVEL = new Set(['provider', 'endpoints', 'credentials', 'signing', 'policy'])
const KNOWN_POLICY = new Set(['skillAuthor', 'toolCalls', 'inboundMessages', 'delegation'])

export function loadConfig(): APSPluginConfig {
  const envPath = process.env.OPENCLAW_APS_CONFIG_PATH
  const homePath = join(homedir(), '.openclaw', 'aps.config.json')
  const path = envPath ?? (existsAsFile(homePath) ? homePath : null)
  if (!path) return DEFAULT_CONFIG
  const raw: unknown = JSON.parse(readFileSync(path, 'utf8'))
  return validate(raw)
}

function existsAsFile(p: string): boolean {
  try { readFileSync(p, 'utf8'); return true } catch { return false }
}

function validate(raw: unknown): APSPluginConfig {
  if (!raw || typeof raw !== 'object') throw new Error('aps config: expected object')
  const obj = raw as Record<string, unknown>
  for (const k of Object.keys(obj)) {
    if (!KNOWN_TOP_LEVEL.has(k)) console.warn(`[aps-plugin] unknown top-level config key: ${k}`)
  }
  const policy = (obj.policy ?? {}) as Record<string, unknown>
  for (const k of Object.keys(policy)) {
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
    endpoints: { ...DEFAULT_CONFIG.endpoints, ...endpoints },
    credentials: { ...DEFAULT_CONFIG.credentials, ...credentials },
    signing: normalizeSigningConfig(obj.signing),
    policy: {
      skillAuthor: { ...DEFAULT_CONFIG.policy.skillAuthor, ...(policy.skillAuthor ?? {}) },
      toolCalls: { ...DEFAULT_CONFIG.policy.toolCalls, ...(policy.toolCalls ?? {}) },
      inboundMessages: { ...DEFAULT_CONFIG.policy.inboundMessages, ...(policy.inboundMessages ?? {}) },
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
  const auditLogPath = obj.auditLogPath
  if (auditLogPath !== undefined && (typeof auditLogPath !== 'string' || auditLogPath.length === 0)) {
    throw new Error('aps config: signing.auditLogPath must be a non-empty string')
  }
  return {
    enabled: obj.enabled === true,
    allowedCallers,
    requireApproval: obj.requireApproval === true,
    auditLogPath: auditLogPath ?? DEFAULT_CONFIG.signing.auditLogPath,
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
