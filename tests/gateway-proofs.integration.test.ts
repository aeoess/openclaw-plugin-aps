// Repository-owned runtime proofs for the four invariants this plugin claims.
//
// Everything runs against the exact-pinned openclaw dependency, with loopback
// fixtures and external network denied. Set APS_TARBALL_PATH to prove a
// specific packed artifact; otherwise the repo is packed on demand.
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readdirSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeAll, describe, expect, it } from 'vitest'
import {
  bootGateway,
  CH_PACKAGE,
  CH_VERSION,
  countExecutions,
  type GatewayHandle,
  readNetworkAttempts,
  REPO_ROOT,
  startClawHubFixture,
  startMockModel,
  startVerifierFixture,
} from './helpers/aps-gateway-harness.js'

const TIMEOUT = 300_000
const TOOL = 'exec'
let tarball = ''

const open: GatewayHandle[] = []
const closers: Array<() => Promise<void>> = []

beforeAll(() => {
  tarball = process.env.APS_TARBALL_PATH ?? packRepo()
}, 180_000)

afterEach(async () => {
  for (const h of open.splice(0)) {
    await h.stop()
    h.cleanup()
  }
  await Promise.allSettled(closers.splice(0).map((c) => c()))
})

function packRepo(): string {
  const out = mkdtempSync(join(tmpdir(), 'aps-pack-'))
  execFileSync('npm', ['pack', REPO_ROOT], { cwd: out, stdio: 'ignore' })
  const file = readdirSync(out).find((f) => f.endsWith('.tgz'))
  if (!file) throw new Error('npm pack produced no tarball')
  return join(out, file)
}

async function boot(params: {
  apsPolicy: Record<string, unknown>
  verifierUrl: string
  execCommand: string
  clawhubUrl?: string
}) {
  const model = await startMockModel({ execCommand: params.execCommand, toolName: TOOL })
  closers.push(model.close)
  const handle = await bootGateway({
    apsConfig: { provider: 'aps', endpoints: { verifier: params.verifierUrl }, policy: params.apsPolicy },
    modelBaseUrl: model.baseUrl,
    ...(params.clawhubUrl ? { clawhubUrl: params.clawhubUrl } : {}),
  })
  open.push(handle)
  // Install BEFORE the Gateway starts: plugin source changes take effect only
  // on the next Gateway start, so installing afterwards leaves it unloaded.
  const install = await handle.run(['plugins', 'install', tarball, '--accept-capabilities', '--force'])
  await handle.start()
  return { handle, install }
}

describe('APS runtime invariants', () => {
  it('gates a high-risk tool call and the tool never runs', { timeout: TIMEOUT }, async () => {
    const verifier = await startVerifierFixture({})
    closers.push(verifier.close)
    const counter = join(mkdtempSync(join(tmpdir(), 'aps-counter-')), 'exec.log')
    writeFileSync(counter, '', 'utf8')
    const { handle } = await boot({
      apsPolicy: { toolCalls: { highRiskTools: [TOOL], highRiskBehavior: 'block' } },
      verifierUrl: verifier.baseUrl,
      execCommand: `echo ran >> ${counter}`,
    })
    await handle.run(['agent', '-m', `Run the ${TOOL} tool, then report the result.`, '--json'])

    const logs = handle.logs()
    expect(logs).toContain('[aps] aps plugin ready')
    expect(countExecutions(counter)).toBe(0)
    expect(readNetworkAttempts(handle)).toBe('')
  })

  it('answers all three gateway RPC methods through the Gateway', { timeout: TIMEOUT }, async () => {
    const verifier = await startVerifierFixture({
      'known-good': { agentId: 'known-good', grade: 3, found: true },
    })
    closers.push(verifier.close)
    const { handle } = await boot({
      apsPolicy: { toolCalls: { highRiskTools: [TOOL], highRiskBehavior: 'block' } },
      verifierUrl: verifier.baseUrl,
      execCommand: 'true',
    })
    const call = async (method: string, params: unknown) =>
      await handle.run(['gateway', 'call', method, '--params', JSON.stringify(params), '--json'])

    const found = await call('aps.checkGrade', { agentId: 'known-good' })
    const unknown = await call('aps.checkGrade', { agentId: 'nobody' })
    const delegation = await call('aps.verifyDelegation', { chain: [{ not: 'real' }] })
    const signing = await call('aps.signMessage', { message: 'hello' })

    // found -> a TrustProfile; unknown -> null; both over the Gateway.
    expect(`${found.stdout}${found.stderr}`).toContain('"grade": 3')
    expect(`${unknown.stdout}${unknown.stderr}`).toMatch(/null/)
    // a structured delegation result; indeterminate or invalid are both fine
    expect(`${delegation.stdout}${delegation.stderr}`).toMatch(/state|valid|failures/)
    // signing disabled: the refusal arrives through the response channel
    expect(`${signing.stdout}${signing.stderr}`).toMatch(/disabled|refus/i)
    expect(readNetworkAttempts(handle)).toBe('')
  })

  it('blocks a Gateway plugin install and surfaces our own decision', { timeout: TIMEOUT }, async () => {
    // A known author holding the lowest grade, so blockBelow bites and the host
    // must surface OUR block rather than a finding buried in a log.
    const verifier = await startVerifierFixture({
      apsfixture: { agentId: 'apsfixture', grade: 0, found: true },
    })
    closers.push(verifier.close)
    const clawhub = await startClawHubFixture()
    closers.push(clawhub.close)
    const { handle } = await boot({
      apsPolicy: {
        skillAuthor: { warnBelow: 1, blockBelow: 1 },
        toolCalls: { highRiskTools: [TOOL], highRiskBehavior: 'block' },
      },
      verifierUrl: verifier.baseUrl,
      execCommand: 'true',
      clawhubUrl: clawhub.registry,
    })

    const install = await handle.run([
      'gateway', 'call', 'plugins.install',
      '--params',
      JSON.stringify({ source: 'clawhub', packageName: CH_PACKAGE, version: CH_VERSION, acknowledgeInstallPolicyWarning: true }),
      '--timeout', '120000', '--json',
    ])
    const output = `${install.stdout}${install.stderr}`

    // the handler ran: it resolved the npm scope and asked the loopback verifier
    expect(verifier.hits.join(' ')).toContain('apsfixture')
    // and the host surfaced our handler's own decision
    expect(output).toContain('APS grade 0 below blockBelow 1')
    expect(readNetworkAttempts(handle)).toBe('')
  })
})
