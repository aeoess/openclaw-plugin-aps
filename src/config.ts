// Agent Passport System OpenClaw plugin — config schema + loader.
// Schema mirrors section 8 of Agent Trust Verification Provider Pattern v0.1.

import { readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

export type HighRiskBehavior = 'approval' | 'block' | 'warn'

export interface APSPluginConfig {
  provider: 'aps'
  endpoints: { verifier: string; jwks: string }
  credentials: { passportPath: string }
  policy: {
    skillAuthor: { minGrade: number; warnBelow: number; blockBelow: number | null }
    toolCalls: { enforceScope: boolean; highRiskTools: string[]; highRiskBehavior: HighRiskBehavior }
    inboundMessages: { requireSignature: boolean; warnUnsigned: boolean }
  }
}

export const DEFAULT_CONFIG: APSPluginConfig = {
  provider: 'aps',
  endpoints: {
    verifier: 'https://gateway.aeoess.com/api/v1/public/trust',
    jwks: 'https://gateway.aeoess.com/.well-known/jwks.json',
  },
  credentials: { passportPath: join(homedir(), '.openclaw', 'aps-credentials.json') },
  policy: {
    skillAuthor: { minGrade: 0, warnBelow: 1, blockBelow: null },
    toolCalls: { enforceScope: true, highRiskTools: ['bash', 'exec', 'fetch'], highRiskBehavior: 'approval' },
    inboundMessages: { requireSignature: false, warnUnsigned: true },
  },
}

const KNOWN_TOP_LEVEL = new Set(['provider', 'endpoints', 'credentials', 'policy'])
const KNOWN_POLICY = new Set(['skillAuthor', 'toolCalls', 'inboundMessages'])

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
    policy: {
      skillAuthor: { ...DEFAULT_CONFIG.policy.skillAuthor, ...(policy.skillAuthor ?? {}) },
      toolCalls: { ...DEFAULT_CONFIG.policy.toolCalls, ...(policy.toolCalls ?? {}) },
      inboundMessages: { ...DEFAULT_CONFIG.policy.inboundMessages, ...(policy.inboundMessages ?? {}) },
    },
  }
}
