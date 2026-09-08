import { describe, expect, it } from 'vitest'
import { generateKeyPair, verify } from 'agent-passport-system'
import { DEFAULT_CONFIG, type APSPluginConfig } from '../src/config.js'
import {
  GATEWAY_CLIENT_CALLER,
  SIGN_MESSAGE_SIGNATURE_DOMAIN,
  makeSignMessage,
  messageDigest,
  resolveApprover,
  resolveCaller,
  signMessageSignatureInput,
  type SigningAuditRecord,
} from '../src/signing.js'

const KEYS = generateKeyPair()
const MESSAGE = 'ship it'

/** Records every passport read so a test can assert the key was never loaded. */
function passportReader() {
  const calls: string[] = []
  return {
    calls,
    read: (path: string) => {
      calls.push(path)
      return { privateKey: KEYS.privateKey }
    },
  }
}

function audit() {
  const records: SigningAuditRecord[] = []
  return { records, write: (r: SigningAuditRecord) => { records.push(r) } }
}

function config(signing: Partial<APSPluginConfig['signing']>): APSPluginConfig {
  return { ...DEFAULT_CONFIG, signing: { ...DEFAULT_CONFIG.signing, ...signing } }
}

const PLUGIN_CALLER = { internal: { pluginRuntimeOwnerId: 'trusted-peer' } }
const NETWORK_CALLER = { connect: { role: 'operator', scopes: ['operator.admin'] } }

describe('aps.signMessage gate', () => {
  it('refuses and never reads the passport when signing is disabled', async () => {
    const passport = passportReader()
    const log = audit()
    // Everything else is wide open on purpose: only signing.enabled stands
    // between this caller and the passport key.
    const handler = makeSignMessage(
      config({ enabled: false, allowedCallers: ['trusted-peer'], requireApproval: false }),
      { readPassport: passport.read, writeAudit: log.write, approver: async () => true },
    )
    await expect(handler({ params: { message: MESSAGE }, client: PLUGIN_CALLER })).rejects.toThrow(
      /signing is disabled/,
    )
    expect(passport.calls).toEqual([])
    expect(log.records[0]?.outcome).toBe('refused:signing-disabled')
  })

  it('refuses a caller that is not on the allowlist', async () => {
    const passport = passportReader()
    const log = audit()
    const handler = makeSignMessage(
      config({ enabled: true, allowedCallers: ['trusted-peer'], requireApproval: false }),
      { readPassport: passport.read, writeAudit: log.write },
    )
    await expect(handler({ params: { message: MESSAGE }, client: { internal: { pluginRuntimeOwnerId: 'other-plugin' } } }))
      .rejects.toThrow(/'other-plugin' is not in signing.allowedCallers/)
    await expect(handler({ params: { message: MESSAGE }, client: NETWORK_CALLER }))
      .rejects.toThrow(/'gateway-client' is not in signing.allowedCallers/)
    await expect(handler({ params: { message: MESSAGE }, client: null }))
      .rejects.toThrow(/'unknown' is not in signing.allowedCallers/)
    expect(passport.calls).toEqual([])
    expect(log.records.map(r => r.outcome)).toEqual([
      'refused:caller-not-allowed',
      'refused:caller-not-allowed',
      'refused:caller-not-allowed',
    ])
  })

  it('runs an allowlisted caller through the approval path', async () => {
    const passport = passportReader()
    const seen: Array<{ caller: string; digest: string; domain: string }> = []
    const cfg = config({ enabled: true, allowedCallers: ['trusted-peer'], requireApproval: true })

    const approved = makeSignMessage(cfg, {
      readPassport: passport.read,
      writeAudit: () => {},
      approver: async req => { seen.push(req); return true },
    })
    const result = await approved({ params: { message: MESSAGE }, client: PLUGIN_CALLER })
    expect(result.signature).toMatch(/^[0-9a-f]+$/)
    expect(seen).toEqual([
      { caller: 'trusted-peer', digest: messageDigest(MESSAGE), domain: SIGN_MESSAGE_SIGNATURE_DOMAIN },
    ])

    const denied = makeSignMessage(cfg, {
      readPassport: passport.read,
      writeAudit: () => {},
      approver: async () => false,
    })
    await expect(denied({ params: { message: MESSAGE }, client: PLUGIN_CALLER })).rejects.toThrow(
      /denied/,
    )
  })

  it('refuses when approval is required and this host offers no approval channel', async () => {
    const passport = passportReader()
    const log = audit()
    // deps.approver omitted, so the handler falls back to resolveApprover(),
    // which is null on OpenClaw 2026.9.2. See src/signing.ts header.
    const handler = makeSignMessage(
      config({ enabled: true, allowedCallers: ['trusted-peer'], requireApproval: true }),
      { readPassport: passport.read, writeAudit: log.write },
    )
    await expect(handler({ params: { message: MESSAGE }, client: PLUGIN_CALLER })).rejects.toThrow(
      /no approval channel/,
    )
    expect(passport.calls).toEqual([])
    expect(log.records[0]?.outcome).toBe('refused:approval-unavailable')
    expect(resolveApprover()).toBeNull()
  })

  it('puts the domain prefix on every signature it produces', async () => {
    const handler = makeSignMessage(
      config({ enabled: true, allowedCallers: ['trusted-peer', GATEWAY_CLIENT_CALLER], requireApproval: false }),
      { readPassport: passportReader().read, writeAudit: () => {} },
    )
    for (const client of [PLUGIN_CALLER, NETWORK_CALLER]) {
      for (const message of [MESSAGE, 'another payload', '{"a":1}']) {
        const result = await handler({ params: { message }, client })
        expect(result.domain).toBe(SIGN_MESSAGE_SIGNATURE_DOMAIN)
        // The signature verifies over the domain-prefixed input and only over it,
        // so it cannot be replayed as a passport signature over the bare message.
        expect(verify(signMessageSignatureInput(message), result.signature, KEYS.publicKey)).toBe(true)
        expect(verify(message, result.signature, KEYS.publicKey)).toBe(false)
      }
    }
  })

  it('logs the caller, prefix and digest and never the message body', async () => {
    const log = audit()
    const handler = makeSignMessage(
      config({ enabled: true, allowedCallers: ['trusted-peer'], requireApproval: false }),
      { readPassport: passportReader().read, writeAudit: log.write },
    )
    await handler({ params: { message: MESSAGE }, client: PLUGIN_CALLER })
    const record = log.records[0]
    expect(record?.outcome).toBe('signed')
    expect(record?.caller).toBe('trusted-peer')
    expect(record?.callerKind).toBe('plugin')
    expect(record?.domain).toBe(SIGN_MESSAGE_SIGNATURE_DOMAIN)
    expect(record?.digest).toBe(messageDigest(MESSAGE))
    expect(JSON.stringify(log.records)).not.toContain(MESSAGE)
  })

  it('names the caller identity the host actually supplies', () => {
    expect(resolveCaller(PLUGIN_CALLER)).toEqual({ kind: 'plugin', id: 'trusted-peer' })
    expect(resolveCaller(NETWORK_CALLER)).toEqual({ kind: 'gateway-client', id: GATEWAY_CLIENT_CALLER })
    expect(resolveCaller(null)).toEqual({ kind: 'unknown', id: 'unknown' })
  })
})

describe('signing config', () => {
  it('defaults to off, no allowed callers, allowlist as the gate', () => {
    expect(DEFAULT_CONFIG.signing.enabled).toBe(false)
    expect(DEFAULT_CONFIG.signing.allowedCallers).toEqual([])
    expect(DEFAULT_CONFIG.signing.requireApproval).toBe(false)
    expect(DEFAULT_CONFIG.signing.auditLogPath).toMatch(/aps-signing-audit\.log$/)
  })
})
