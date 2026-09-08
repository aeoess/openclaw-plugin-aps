// Authority-aware delegation verification: the trust inputs are the operator's,
// never the artifact's. These tests mint a real v1 authority delegation with the
// SDK's own writer, then attack it.
//
// The canonical helpers are reached by file path because the package exports map
// publishes only "." and "./core". That path is used HERE ONLY, to mint fixtures;
// the plugin itself imports from the package root.

import { describe, expect, it, vi } from 'vitest'
import { generateKeyPair } from 'agent-passport-system'
import {
  computeAuthorityDelegationIdForWrite,
  signAuthorityDelegation,
} from '../node_modules/agent-passport-system/dist/src/v2/authority-delegation/canonical.js'
import { DEFAULT_CONFIG, type APSPluginConfig, type TrustedIssuer } from '../src/config.js'
import { verifyChain } from '../src/index.js'

const ISSUER = 'did:key:issuer'
const SUBJECT = 'did:key:subject'
const VM = 'did:key:issuer#k1'

function mintRoot(privateKey: string, over: Record<string, unknown> = {}): Record<string, unknown> {
  const now = new Date()
  const body = {
    record_type: 'aps:authority-delegation:v1',
    version: '1.0',
    parent_delegation_id: null,
    issuer: ISSUER,
    subject: SUBJECT,
    verification_method: VM,
    issued_at: now.toISOString(),
    nonce: 'a'.repeat(32),
    authority: {
      scope: { profile: 'aps-hierarchical-v1', grants: ['tools.read'] },
      spend: { mode: 'unbounded' },
      depth: { remaining: 1 },
      time: { not_before: now.toISOString(), not_after: new Date(Date.now() + 864e5).toISOString() },
      reputation: { profile: 'aps-score-0-100-v1', ceiling: 100 },
      values: { profile: 'aps-values-identifiers-v1', required: [] },
      reversibility: { profile: 'aps-tci-v1', ceiling: 'compensable' },
    },
    ...over,
  }
  const delegation_id = computeAuthorityDelegationIdForWrite(body as never)
  const unsigned = { ...body, delegation_id }
  return { ...unsigned, signature: signAuthorityDelegation(unsigned as never, privateKey) }
}

function configWith(trustedIssuers: TrustedIssuer[], allowSelfSignedRoot = false): APSPluginConfig {
  return {
    ...DEFAULT_CONFIG,
    policy: { ...DEFAULT_CONFIG.policy, delegation: { trustedIssuers, allowSelfSignedRoot } },
  }
}

const codes = (r: { failures: { code: string }[] }): string[] => r.failures.map(f => f.code)

describe('authority-aware delegation verification', () => {
  it('rejects a delegation whose body was tampered with after signing', () => {
    const keys = generateKeyPair()
    const root = mintRoot(keys.privateKey)
    const config = configWith([{ issuer: ISSUER, publicKey: keys.publicKey, verificationMethod: VM }])

    // Widen the scope the principal actually granted.
    const tampered = {
      ...root,
      authority: {
        ...(root.authority as Record<string, unknown>),
        scope: { profile: 'aps-hierarchical-v1', grants: ['tools.read', 'tools.write'] },
      },
    }
    const result = verifyChain(config, [tampered])
    expect(result.valid).toBe(false)
    expect(codes(result)).toContain('ID_MISMATCH')
  })

  it('rejects a delegation whose signature was replaced', () => {
    const keys = generateKeyPair()
    const attacker = generateKeyPair()
    const root = mintRoot(keys.privateKey)
    const config = configWith([{ issuer: ISSUER, publicKey: keys.publicKey, verificationMethod: VM }])

    // Same body, signed by a key the operator never trusted.
    const { signature: _drop, ...unsigned } = root as Record<string, unknown> & { signature: string }
    const forged = { ...unsigned, signature: signAuthorityDelegation(unsigned as never, attacker.privateKey) }
    const result = verifyChain(config, [forged])
    expect(result.valid).toBe(false)
    expect(codes(result)).toContain('SIGNATURE_INVALID')
  })

  it('rejects a self-signed root by default', () => {
    const keys = generateKeyPair()
    // issuer delegating to itself: the artifact vouches for itself.
    const root = mintRoot(keys.privateKey, { subject: ISSUER })
    const config = configWith([{ issuer: ISSUER, publicKey: keys.publicKey, verificationMethod: VM }])

    const result = verifyChain(config, [root])
    expect(result.valid).toBe(false)
    expect(codes(result)).toContain('ROOT_UNTRUSTED')
  })

  it('accepts a self-signed root only on the explicit opt-in, and still needs a configured key', () => {
    const keys = generateKeyPair()
    const root = mintRoot(keys.privateKey, { subject: ISSUER })

    const optedIn = verifyChain(
      configWith([{ issuer: ISSUER, publicKey: keys.publicKey, verificationMethod: VM }], true),
      [root],
    )
    expect(codes(optedIn)).not.toContain('ROOT_UNTRUSTED')

    // The opt-in is not a substitute for issuer trust: with no anchor it still
    // fails. The refusal lands on key resolution rather than root trust, because
    // an unconfigured issuer has no key to check the signature with and the
    // verifier stops there. Either code is a refusal; what matters is that no
    // opt-in makes an unanchored root verify.
    const noAnchor = verifyChain(configWith([], true), [root])
    expect(noAnchor.valid).toBe(false)
    expect(codes(noAnchor).some(c => c === 'ROOT_UNTRUSTED' || c === 'KEY_RESOLUTION_FAILED')).toBe(true)
  })

  it('fails closed with no trust anchors configured, which is the default', () => {
    const keys = generateKeyPair()
    const root = mintRoot(keys.privateKey)

    expect(DEFAULT_CONFIG.policy.delegation.trustedIssuers).toEqual([])
    expect(DEFAULT_CONFIG.policy.delegation.allowSelfSignedRoot).toBe(false)

    const result = verifyChain(DEFAULT_CONFIG, [root])
    expect(result.valid).toBe(false)
    // Refused before a signature is even checked: there is no configured key.
    expect(codes(result).some(c => c === 'ROOT_UNTRUSTED' || c === 'KEY_RESOLUTION_FAILED')).toBe(true)
  })

  it('never resolves a verification key from the artifact itself', () => {
    const attacker = generateKeyPair()
    // A chain signed entirely by the attacker, naming an issuer nobody trusts.
    const root = mintRoot(attacker.privateKey, { issuer: 'did:key:attacker', verification_method: 'did:key:attacker#k1' })
    const result = verifyChain(configWith([{ issuer: ISSUER, publicKey: generateKeyPair().publicKey }]), [root])
    expect(result.valid).toBe(false)
    expect(codes(result).some(c => c === 'ROOT_UNTRUSTED' || c === 'KEY_RESOLUTION_FAILED')).toBe(true)
  })

  it('reports unknown revocation rather than assuming the delegation is live', () => {
    const keys = generateKeyPair()
    const root = mintRoot(keys.privateKey)
    const result = verifyChain(
      configWith([{ issuer: ISSUER, publicKey: keys.publicKey, verificationMethod: VM }]),
      [root],
    )
    // Cryptography and trust both pass; the plugin has no revocation feed, so
    // the honest answer is indeterminate, not valid.
    expect(codes(result)).toContain('REVOCATION_UNKNOWN')
    expect(result.state).toBe('indeterminate')
    expect(result.valid).toBe(false)
  })
})

describe('gateway trust lookup', () => {
  it('reads found:false as "not known", not as a grade of 0', async () => {
    const { checkGrade } = await vi.importActual<typeof import('../src/aps-client.js')>('../src/aps-client.js')
    const original = globalThis.fetch
    // Exactly what gateway.aeoess.com returns today for an unknown agent.
    globalThis.fetch = (async () => new Response(
      JSON.stringify({ agent_id: 'nobody', grade: 0, grade_label: 'unknown', found: false, queried_at: new Date().toISOString() }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    )) as typeof fetch
    try {
      expect(await checkGrade('https://gateway.example/api/v1/public/trust', 'nobody')).toBeNull()
    } finally {
      globalThis.fetch = original
    }
  })
})
