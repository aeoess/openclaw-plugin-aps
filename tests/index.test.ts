import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DEFAULT_CONFIG, loadConfig } from '../src/config.js'
import definePlugin, { makeBeforeInstall, makeBeforeToolCall, type PluginAPI } from '../src/index.js'

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

const noopApi: PluginAPI = {
  registerHook: () => {},
  registerGatewayMethod: () => {},
  log: () => {},
}

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
    writeFileSync(path, JSON.stringify({ provider: 'aps', policy: { skillAuthor: { warnBelow: 2, blockBelow: 1, minGrade: 0 } } }))
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
    mockedCheckGrade.mockResolvedValueOnce({ agentId: 'acme', grade: 0 })
    const cfg = { ...DEFAULT_CONFIG, policy: { ...DEFAULT_CONFIG.policy, skillAuthor: { minGrade: 0, warnBelow: 1, blockBelow: 1 } } }
    const handler = makeBeforeInstall(cfg, noopApi)
    const r = await handler(event)
    expect(r && 'block' in r ? r.block : false).toBe(true)
  })

  it('returns findings when grade < warnBelow but >= blockBelow', async () => {
    mockedCheckGrade.mockResolvedValueOnce({ agentId: 'acme', grade: 0 })
    const cfg = { ...DEFAULT_CONFIG, policy: { ...DEFAULT_CONFIG.policy, skillAuthor: { minGrade: 0, warnBelow: 1, blockBelow: null } } }
    const handler = makeBeforeInstall(cfg, noopApi)
    const r = await handler(event)
    expect(r && 'findings' in r && r.findings?.[0]?.severity).toBe('warn')
  })

  it('passes through (returns undefined) when grade >= warnBelow', async () => {
    mockedCheckGrade.mockResolvedValueOnce({ agentId: 'acme', grade: 2 })
    const handler = makeBeforeInstall(DEFAULT_CONFIG, noopApi)
    expect(await handler(event)).toBeUndefined()
  })

  it('warns on unknown author (gateway returns null)', async () => {
    mockedCheckGrade.mockResolvedValueOnce(null)
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
    const api: PluginAPI = {
      registerHook: () => {},
      registerGatewayMethod: (name: string, handler: unknown) => { methods.set(name, handler as (request: Record<string, unknown>) => Promise<unknown>) },
      log: () => {},
    }
    definePlugin(api)
    return methods
  }

  it('aps.checkGrade reads params.agentId and forwards it', async () => {
    mockedCheckGrade.mockResolvedValueOnce({ found: true, grade: 2 } as unknown as never)
    const methods = capture()
    const result = await methods.get('aps.checkGrade')!({ params: { agentId: 'agent-x' } })
    expect(mockedCheckGrade).toHaveBeenCalledWith(expect.any(String), 'agent-x')
    expect(result).toMatchObject({ grade: 2 })
  })

  it('aps.checkGrade refuses when params.agentId is missing', async () => {
    const methods = capture()
    await expect(methods.get('aps.checkGrade')!({ params: {} })).rejects.toThrow(/params\.agentId/)
  })

  it('aps.verifyDelegation reads params.chain and refuses an empty one', async () => {
    const methods = capture()
    await expect(methods.get('aps.verifyDelegation')!({ params: { chain: [] } })).rejects.toThrow(/params\.chain/)
    await expect(methods.get('aps.verifyDelegation')!({})).rejects.toThrow(/params\.chain/)
  })
})
