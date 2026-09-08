// Thin fetch wrapper for the public APS gateway. No retries, no caching layer
// (caller's responsibility). JWKS is module-cached with a 1h TTL.

import * as ed from '@noble/ed25519'

export interface TrustProfile {
  agentId: string
  grade: number
  /** The gateway answers 200 with found:false for an agent it does not know.
   *  Absent on older responses, where a 404 carried the same meaning. */
  found?: boolean
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

/** Null means "this gateway does not know that agent", which is not the same
 *  answer as "that agent is graded 0".
 *
 *  The live gateway answers 200 with `found: false` and `grade: 0` for an
 *  unknown agent, so reading the body as a profile reported an unverified
 *  identity as a verified one holding the lowest grade. An operator with
 *  blockBelow set would have blocked unknown authors as though the registry had
 *  graded them. A 404 still means the same thing on older deployments. */
export async function checkGrade(verifierUrl: string, agentId: string): Promise<TrustProfile | null> {
  const res = await fetch(`${verifierUrl}/${encodeURIComponent(agentId)}`)
  if (res.status === 404) return null
  if (!res.ok) throw new Error(`aps gateway error ${res.status}: ${await res.text().catch(() => '')}`)
  const profile = (await res.json()) as TrustProfile
  if (profile?.found === false) return null
  return profile
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
  // The kid binds the envelope to one key. Falling back to keys[0] when the kid
  // does not match meant an envelope naming an unknown key was checked against
  // whichever key happened to be first, so the kid decided nothing. An envelope
  // that names a key must be checked against that key or refused.
  const key = env.kid === undefined
    ? (jwks.keys.length === 1 ? jwks.keys[0] : undefined)
    : jwks.keys.find(k => k.kid === env.kid)
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
