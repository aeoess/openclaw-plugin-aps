// Thin fetch wrapper for the public APS gateway. No retries, no caching layer
// (caller's responsibility). JWKS is module-cached with a 1h TTL.

import * as ed from '@noble/ed25519'

export interface TrustProfile {
  agentId: string
  grade: number
  attestations?: unknown[]
  envelope?: { protected: string; payload: string; signature: string; kid?: string }
  [k: string]: unknown
}

export interface JWK {
  kid: string
  kty: string
  alg?: string
  crv?: string
  x?: string
}

export interface JWKS {
  keys: JWK[]
}

let jwksCache: { url: string; jwks: JWKS; expiresAt: number } | null = null
const JWKS_TTL_MS = 60 * 60 * 1000

export async function checkGrade(verifierUrl: string, agentId: string): Promise<TrustProfile | null> {
  const res = await fetch(`${verifierUrl}/${encodeURIComponent(agentId)}`)
  if (res.status === 404) return null
  if (!res.ok) throw new Error(`aps gateway error ${res.status}: ${await res.text().catch(() => '')}`)
  return (await res.json()) as TrustProfile
}

export async function fetchJWKS(jwksUrl: string): Promise<JWKS> {
  const now = Date.now()
  if (jwksCache && jwksCache.url === jwksUrl && jwksCache.expiresAt > now) return jwksCache.jwks
  const res = await fetch(jwksUrl)
  if (!res.ok) throw new Error(`aps jwks fetch failed ${res.status}`)
  const jwks = (await res.json()) as JWKS
  jwksCache = { url: jwksUrl, jwks, expiresAt: now + JWKS_TTL_MS }
  return jwks
}

/** Reset cache for tests. */
export function _resetJWKSCache(): void { jwksCache = null }

export async function verifyJWS(profile: TrustProfile, jwks: JWKS): Promise<boolean> {
  const env = profile.envelope
  if (!env) return false
  const key = jwks.keys.find(k => k.kid === env.kid) ?? jwks.keys[0]
  if (!key || key.kty !== 'OKP' || key.crv !== 'Ed25519' || !key.x) return false
  const signingInput = new TextEncoder().encode(`${env.protected}.${env.payload}`)
  try {
    const sig = b64urlDecode(env.signature)
    const pub = b64urlDecode(key.x)
    return await ed.verifyAsync(sig, signingInput, pub)
  } catch { return false }
}

function b64urlDecode(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4))
  const b64 = (s + pad).replace(/-/g, '+').replace(/_/g, '/')
  return new Uint8Array(Buffer.from(b64, 'base64'))
}
