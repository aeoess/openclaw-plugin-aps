import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mkdtempSync, writeFileSync, rmSync, chmodSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DEFAULT_CONFIG, loadConfig } from '../src/config.js'
import definePlugin, { makeBeforeInstall, makeBeforeToolCall, reportSigningState, type PluginAPI } from '../src/index.js'

vi.mock('../src/aps-client.js', async () => {
  const actual = await vi.importActual<typeof import('../src/aps-client.js')>('../src/aps-client.js')
  return {
    ...actual,
    checkGrade: vi.fn(),
    fetchJWKS: vi.fn(async () => ({ keys: [] })),
  }
})
import { checkGrade } from '../src/aps-client.js'

const mockedCheckGrade = checkGrade as unknown as ReturnType<typeof vi.fn>

// Test double for the host API. Only the members this plugin touches are
// implemented; the host type has many more, so the partial is cast once here
// rather than restated. src/index.ts itself is bound to the real host type.
const stubLogger = { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} }
const noopApi = {
  on: () => {},
  registerHook: () => {},
  registerGatewayMethod: () => {},
  logger: stubLogger,
} as unknown as PluginAPI

describe('config', () => {
  let tmp: string
  beforeEach(() => { tmp = mkdtempSync(join(tmpdir(), 'aps-cfg-')) })
  afterEach(() => { rmSync(tmp, { recursive: true, force: true }); delete process.env.OPENCLAW_APS_CONFIG_PATH })

  it('returns defaults when no config file present', () => {
    delete process.env.OPENCLAW_APS_CONFIG_PATH
    const cfg = loadConfig()
    // Note: loadConfig also probes ~/.openclaw/aps.config.json. We assert
    // shape, not strict identity, so a real file there does not break the test.
    expect(cfg.provider).toBe('aps')
    expect(cfg.endpoints.verifier).toContain('aeoess.com')
    expect(cfg.policy.toolCalls.highRiskTools).toContain('bash')
  })

  it('reads from OPENCLAW_APS_CONFIG_PATH env var when set', () => {
    const path = join(tmp, 'aps.json')
    writeFileSync(path, JSON.stringify({ provider: 'aps', policy: { skillAuthor: { warnBelow: 2, blockBelow: 1 } } }))
    process.env.OPENCLAW_APS_CONFIG_PATH = path
    const cfg = loadConfig()
    expect(cfg.policy.skillAuthor.warnBelow).toBe(2)
    expect(cfg.policy.skillAuthor.blockBelow).toBe(1)
  })

  it('loads the signing block and keeps it fail-closed', () => {
    const path = join(tmp, 'signing.json')
    writeFileSync(path, JSON.stringify({ signing: { enabled: true, allowedCallers: ['peer'] } }))
    process.env.OPENCLAW_APS_CONFIG_PATH = path
    const cfg = loadConfig()
    expect(cfg.signing.enabled).toBe(true)
    expect(cfg.signing.allowedCallers).toEqual(['peer'])
    // Not stated in the file: the allowlist is the gate; the hard-stop is opt-in.
    expect(cfg.signing.requireApproval).toBe(false)
  })

  it('rejects malformed config (unrecognized signing field)', () => {
    const path = join(tmp, 'bad-signing.json')
    writeFileSync(path, JSON.stringify({ signing: { enable: true } }))
    process.env.OPENCLAW_APS_CONFIG_PATH = path
    expect(() => loadConfig()).toThrow(/unrecognized signing field/)
  })

  it('rejects malformed config (unrecognized policy field)', () => {
    const path = join(tmp, 'bad.json')
    writeFileSync(path, JSON.stringify({ policy: { wat: {} } }))
    process.env.OPENCLAW_APS_CONFIG_PATH = path
    expect(() => loadConfig()).toThrow(/unrecognized policy field/)
  })
})

describe('before_install handler', () => {
  beforeEach(() => { mockedCheckGrade.mockReset() })

  const event = { targetType: 'plugin' as const, targetName: 'foo', plugin: { pluginId: 'p1', packageName: '@acme/foo', author: 'acme' } }

  it('returns block when grade < blockBelow', async () => {
    mockedCheckGrade.mockResolvedValueOnce({ state: 'found', profile: { agentId: 'acme', grade: 0 } })
    const cfg = { ...DEFAULT_CONFIG, policy: { ...DEFAULT_CONFIG.policy, skillAuthor: { warnBelow: 1, blockBelow: 1 } } }
    const handler = makeBeforeInstall(cfg, noopApi)
    const r = await handler(event)
    expect(r && 'block' in r ? r.block : false).toBe(true)
  })

  it('returns findings when grade < warnBelow but >= blockBelow', async () => {
    mockedCheckGrade.mockResolvedValueOnce({ state: 'found', profile: { agentId: 'acme', grade: 0 } })
    const cfg = { ...DEFAULT_CONFIG, policy: { ...DEFAULT_CONFIG.policy, skillAuthor: { warnBelow: 1, blockBelow: null } } }
    const handler = makeBeforeInstall(cfg, noopApi)
    const r = await handler(event)
    expect(r && 'findings' in r && r.findings?.[0]?.severity).toBe('warn')
  })

  it('passes through (returns undefined) when grade >= warnBelow', async () => {
    mockedCheckGrade.mockResolvedValueOnce({ state: 'found', profile: { agentId: 'acme', grade: 2 } })
    const handler = makeBeforeInstall(DEFAULT_CONFIG, noopApi)
    expect(await handler(event)).toBeUndefined()
  })

  it('warns on unknown author (registry answers not-found)', async () => {
    mockedCheckGrade.mockResolvedValueOnce({ state: 'unknown' })
    const handler = makeBeforeInstall(DEFAULT_CONFIG, noopApi)
    const r = await handler(event)
    expect(r && 'findings' in r && r.findings?.[0]?.ruleId).toBe('aps.author.unknown')
  })

  it('warns on missing author identifier', async () => {
    const handler = makeBeforeInstall(DEFAULT_CONFIG, noopApi)
    const r = await handler({ targetType: 'skill', targetName: 'local', skill: { installId: 'x' } })
    expect(r && 'findings' in r && r.findings?.[0]?.ruleId).toBe('aps.author.missing')
    expect(mockedCheckGrade).not.toHaveBeenCalled()
  })
})

describe('before_tool_call handler', () => {
  it('returns requireApproval for high-risk tools when policy is approval', () => {
    const handler = makeBeforeToolCall(DEFAULT_CONFIG)
    const r = handler({ toolName: 'bash', params: {} })
    expect(r && 'requireApproval' in r && r.requireApproval?.severity).toBe('warning')
  })

  it('returns block for high-risk tools when policy is block', () => {
    const cfg = { ...DEFAULT_CONFIG, policy: { ...DEFAULT_CONFIG.policy, toolCalls: { ...DEFAULT_CONFIG.policy.toolCalls, highRiskBehavior: 'block' as const } } }
    const handler = makeBeforeToolCall(cfg)
    const r = handler({ toolName: 'exec', params: {} })
    expect(r && 'block' in r ? r.block : false).toBe(true)
  })

  it('passes through (returns undefined) for non-high-risk tools', () => {
    const handler = makeBeforeToolCall(DEFAULT_CONFIG)
    expect(handler({ toolName: 'read_file', params: {} })).toBeUndefined()
  })
})

describe('gateway methods receive the host options object', () => {
  // The host calls a registered method with ONE object ({ params, respond, client, ... })
  // and delivers a returned value as respond(true, value). 0.2.0 read positional args
  // and so answered every call with "[object Object]" or a thrown error.
  function capture() {
    const methods = new Map<string, (request: Record<string, unknown>) => Promise<unknown>>()
    const api = {
      on: () => {},
      registerHook: () => {},
      registerGatewayMethod: (name: string, handler: unknown) => { methods.set(name, handler as (request: Record<string, unknown>) => Promise<unknown>) },
      logger: stubLogger,
    } as unknown as PluginAPI
    definePlugin(api)
    return methods
  }

  // The exported GatewayRequestHandler type is (opts) => void | Promise<void>.
  // The host's runtime adapter would also deliver a returned value, but this
  // plugin responds explicitly to satisfy the published type, so these assert
  // respond rather than a return value.
  it('aps.checkGrade reads params.agentId and responds with the profile', async () => {
    mockedCheckGrade.mockResolvedValueOnce({ state: 'found', profile: { agentId: 'agent-x', found: true, grade: 2 } } as unknown as never)
    const methods = capture()
    const respond = vi.fn()
    await methods.get('aps.checkGrade')!({ params: { agentId: 'agent-x' }, respond })
    expect(mockedCheckGrade).toHaveBeenCalledWith(expect.any(String), 'agent-x')
    // Published contract is TrustProfile | null; TrustLookup stays internal.
    expect(respond).toHaveBeenCalledWith(true, expect.objectContaining({ grade: 2 }))
  })

  it('aps.checkGrade responds with an error when params.agentId is missing', async () => {
    const methods = capture()
    const respond = vi.fn()
    await methods.get('aps.checkGrade')!({ params: {}, respond })
    expect(respond).toHaveBeenCalledWith(
      false,
      undefined,
      expect.objectContaining({ message: expect.stringMatching(/params\.agentId/) }),
    )
  })

  it('aps.verifyDelegation reads params.chain and refuses an empty one', async () => {
    const methods = capture()
    const respond = vi.fn()
    await methods.get('aps.verifyDelegation')!({ params: { chain: [] }, respond })
    await methods.get('aps.verifyDelegation')!({ respond })
    expect(respond).toHaveBeenCalledTimes(2)
    for (const call of respond.mock.calls) {
      expect(call[0]).toBe(false)
      expect((call[2] as { message: string }).message).toMatch(/params\.chain/)
    }
  })
})

// Item 1 proof. An early return in the source is not evidence that the file was
// left alone, so the filesystem boundary is injected and observed directly:
// with signing disabled, neither the existence check nor the read may run.
describe('passport file is not opened while signing is disabled', () => {
  const cfgWith = (enabled: boolean) => ({
    ...DEFAULT_CONFIG,
    credentials: { passportPath: '/nonexistent/aps-credentials.json' },
    signing: { ...DEFAULT_CONFIG.signing, enabled },
  })

  it('makes zero filesystem calls to the passport path when signing is off', () => {
    const exists = vi.fn(() => true)
    const read = vi.fn(() => '{}')
    const logged: string[] = []
    const api = {
      logger: { debug: () => {}, info: (m: string) => logged.push(m), warn: (m: string) => logged.push(m), error: () => {} },
    } as unknown as PluginAPI

    reportSigningState(cfgWith(false), api, { exists, read })

    expect(exists).not.toHaveBeenCalled()
    expect(read).not.toHaveBeenCalled()
    // and nothing may claim the file was inspected
    expect(logged.join('\n')).not.toMatch(/passport file present|did not parse|no local passport/)
  })

  it('does probe the passport path when signing is on, so the check above is not vacuous', () => {
    const exists = vi.fn(() => true)
    const read = vi.fn(() => '{"privateKey":"x"}')
    const api = {
      logger: { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} },
    } as unknown as PluginAPI

    reportSigningState(cfgWith(true), api, { exists, read })

    expect(exists).toHaveBeenCalledWith('/nonexistent/aps-credentials.json')
    expect(read).toHaveBeenCalledWith('/nonexistent/aps-credentials.json')
  })
})

// Item 7. A malformed security policy must fail, never become the permissive
// branch, and unreadable must not be mistaken for absent.
describe('config validation', () => {
  let tmp: string
  beforeEach(() => { tmp = mkdtempSync(join(tmpdir(), 'aps-val-')) })
  afterEach(() => { rmSync(tmp, { recursive: true, force: true }); delete process.env.OPENCLAW_APS_CONFIG_PATH })

  const withConfig = (value: unknown) => {
    const path = join(tmp, 'aps.config.json')
    writeFileSync(path, JSON.stringify(value))
    process.env.OPENCLAW_APS_CONFIG_PATH = path
    return path
  }

  it('rejects an unknown highRiskBehavior instead of falling back', () => {
    withConfig({ policy: { toolCalls: { highRiskBehavior: 'warn' } } })
    expect(() => loadConfig()).toThrow(/highRiskBehavior/)
  })

  it('rejects an out-of-range grade threshold', () => {
    withConfig({ policy: { skillAuthor: { warnBelow: 99 } } })
    expect(() => loadConfig()).toThrow(/warnBelow/)
  })

  it('rejects a non-integer grade threshold', () => {
    withConfig({ policy: { skillAuthor: { warnBelow: 1.5 } } })
    expect(() => loadConfig()).toThrow(/warnBelow/)
  })

  it('keeps blockBelow null distinct from an absent key', () => {
    withConfig({ policy: { skillAuthor: { blockBelow: null } } })
    expect(loadConfig().policy.skillAuthor.blockBelow).toBeNull()
  })

  it('rejects a tilde path, which Node never expands', () => {
    withConfig({ credentials: { passportPath: '~/aps-credentials.json' } })
    expect(() => loadConfig()).toThrow(/absolute path/)
  })

  it('rejects a relative passport path', () => {
    withConfig({ credentials: { passportPath: 'creds.json' } })
    expect(() => loadConfig()).toThrow(/absolute path/)
  })

  it('rejects a non-http verifier URL', () => {
    withConfig({ endpoints: { verifier: 'file:///etc/passwd' } })
    expect(() => loadConfig()).toThrow(/endpoints\.verifier/)
  })

  it('treats an unreadable config file as an error, not as absent', () => {
    const path = join(tmp, 'unreadable.json')
    writeFileSync(path, JSON.stringify({ provider: 'aps' }))
    chmodSync(path, 0o000)
    process.env.OPENCLAW_APS_CONFIG_PATH = path
    try {
      expect(() => loadConfig()).toThrow(/could not be read/)
    } finally { chmodSync(path, 0o600) }
  })
})

// Removing documented config keys is a breaking change, so the loader's
// treatment of each class is pinned. The asymmetry is the point: a removed
// endpoint is benign and warns, a removed security control fails loudly rather
// than being accepted and ignored, which is the defect this release fixes.
describe('removed configuration keys', () => {
  let tmp: string
  beforeEach(() => { tmp = mkdtempSync(join(tmpdir(), 'aps-removed-')) })
  afterEach(() => { rmSync(tmp, { recursive: true, force: true }); delete process.env.OPENCLAW_APS_CONFIG_PATH })

  const withConfig = (value: unknown) => {
    const path = join(tmp, 'aps.config.json')
    writeFileSync(path, JSON.stringify(value))
    process.env.OPENCLAW_APS_CONFIG_PATH = path
  }

  it('loads and warns for the removed endpoints.jwks, ignoring the value', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      withConfig({ endpoints: { verifier: 'https://example.test/trust', jwks: 'https://example.test/jwks' } })
      const cfg = loadConfig()
      expect(cfg.endpoints.verifier).toBe('https://example.test/trust')
      expect(cfg.endpoints as Record<string, unknown>).not.toHaveProperty('jwks')
      expect(warn).toHaveBeenCalledWith(expect.stringContaining('endpoints.jwks'))
    } finally { warn.mockRestore() }
  })

  it.each([
    ['policy.toolCalls.enforceScope', { policy: { toolCalls: { enforceScope: true } } }],
    ['policy.skillAuthor.minGrade', { policy: { skillAuthor: { minGrade: 0 } } }],
    ['policy.inboundMessages', { policy: { inboundMessages: { requireSignature: true } } }],
  ])('fails loudly for the removed security control %s', (field, value) => {
    withConfig(value)
    expect(() => loadConfig()).toThrow(new RegExp(field.replace(/\./g, '\\.')))
  })

  it('fails loudly for the removed highRiskBehavior "warn"', () => {
    withConfig({ policy: { toolCalls: { highRiskBehavior: 'warn' } } })
    expect(() => loadConfig()).toThrow(/"warn" behaviour was removed/)
  })

  it('fails for an arbitrary unknown key rather than warning', () => {
    withConfig({ notAField: true })
    expect(() => loadConfig()).toThrow(/unrecognized top-level field: notAField/)
  })
})

// The RPC keeps its published TrustProfile | null contract. The internal
// TrustLookup states are mapped at the boundary, and the two failure states
// travel through the host error channel rather than being flattened to null.
describe('aps.checkGrade preserves its published contract', () => {
  function capture() {
    const methods = new Map<string, (request: Record<string, unknown>) => Promise<unknown>>()
    const api = {
      on: () => {},
      registerHook: () => {},
      registerGatewayMethod: (name: string, handler: unknown) => { methods.set(name, handler as (request: Record<string, unknown>) => Promise<unknown>) },
      logger: stubLogger,
    } as unknown as PluginAPI
    definePlugin(api)
    return methods
  }

  it('responds with null for an author the registry does not know', async () => {
    mockedCheckGrade.mockResolvedValueOnce({ state: 'unknown' } as unknown as never)
    const respond = vi.fn()
    await capture().get('aps.checkGrade')!({ params: { agentId: 'nobody' }, respond })
    expect(respond).toHaveBeenCalledWith(true, null)
  })

  it('reports an unavailable verifier as a Gateway error, not as null', async () => {
    mockedCheckGrade.mockResolvedValueOnce({ state: 'unavailable', reason: 'ECONNREFUSED' } as unknown as never)
    const respond = vi.fn()
    await capture().get('aps.checkGrade')!({ params: { agentId: 'acme' }, respond })
    expect(respond).toHaveBeenCalledWith(false, undefined, expect.objectContaining({ code: 'aps_verifier_unavailable' }))
    expect(respond).not.toHaveBeenCalledWith(true, null)
  })

  it('reports a malformed profile as a Gateway error, not as null', async () => {
    mockedCheckGrade.mockResolvedValueOnce({ state: 'malformed', reason: 'grade missing' } as unknown as never)
    const respond = vi.fn()
    await capture().get('aps.checkGrade')!({ params: { agentId: 'acme' }, respond })
    expect(respond).toHaveBeenCalledWith(false, undefined, expect.objectContaining({ code: 'aps_verifier_malformed' }))
  })
})
