// Permanent guard for the activation.onStartup defect.
//
// The invariant is STARTUP SELECTION and GATE ABSENCE, not a plugin-listing
// string: OpenClaw can report a plugin as loaded on one surface while it is not
// participating in the Gateway runtime, which is how this defect hid.
//
// Two jobs have now ended with a live mutation in the tree, so restoration here
// is mechanical: a finally block plus process traps. That is necessary and NOT
// sufficient, because no trap survives SIGKILL, so the suite also asserts the
// manifest independently at the end.
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import {
  bootGateway,
  countExecutions,
  type GatewayHandle,
  readNetworkAttempts,
  REPO_ROOT,
  startMockModel,
  startVerifierFixture,
} from './helpers/aps-gateway-harness.js'

const TIMEOUT = 300_000
const TOOL = 'exec'
const MANIFEST = join(REPO_ROOT, 'openclaw.plugin.json')

function readManifest(): Record<string, unknown> {
  return JSON.parse(readFileSync(MANIFEST, 'utf8')) as Record<string, unknown>
}

function activationPresent(): boolean {
  const manifest = readManifest()
  const activation = manifest.activation as { onStartup?: unknown } | undefined
  return activation?.onStartup === true
}

const pristineManifest = readFileSync(MANIFEST, 'utf8')
let restored = true

function restoreManifest(): void {
  if (restored) return
  writeFileSync(MANIFEST, pristineManifest, 'utf8')
  execFileSync('npm', ['run', 'build'], { cwd: REPO_ROOT, stdio: 'ignore' })
  restored = true
}

// Traps: a crash or a signal must not leave the mutation behind.
for (const signal of ['SIGINT', 'SIGTERM', 'uncaughtException'] as const) {
  process.once(signal, () => {
    restoreManifest()
  })
}

afterAll(() => {
  restoreManifest()
  // Independent of any diff: parse the working tree and assert the value.
  expect(activationPresent()).toBe(true)
})

async function runCase(counter: string) {
  const verifier = await startVerifierFixture({})
  const model = await startMockModel({ execCommand: `echo ran >> ${counter}`, toolName: TOOL })
  const tarballDir = mkdtempSync(join(tmpdir(), 'aps-mut-pack-'))
  execFileSync('npm', ['pack', REPO_ROOT], { cwd: tarballDir, stdio: 'ignore' })
  const tgz = join(
    tarballDir,
    execFileSync('ls', [tarballDir], { encoding: 'utf8' }).split('\n').find((f) => f.endsWith('.tgz')) ?? '',
  )
  const handle: GatewayHandle = await bootGateway({
    apsConfig: {
      provider: 'aps',
      policy: { toolCalls: { highRiskTools: [TOOL], highRiskBehavior: 'block' } },
    },
    modelBaseUrl: model.baseUrl,
  })
  await handle.run(['plugins', 'install', tgz, '--accept-capabilities', '--force'])
  await handle.start()
  await handle.run(['agent', '-m', `Run the ${TOOL} tool, then report the result.`, '--json'])

  const logs = handle.logs()
  const startupLine = logs.split('\n').find((l) => l.includes('http server listening')) ?? ''
  const result = {
    startupLine: startupLine.trim(),
    selectedForStartup: /plugins:[^)]*\baps\b/.test(startupLine),
    gatewayStartRan: logs.includes('[aps] aps plugin ready'),
    startHooks: /gateway-start-hooks=([a-z-]+)/.exec(logs)?.[1] ?? '(absent)',
    executions: countExecutions(counter),
    attempts: readNetworkAttempts(handle),
  }
  await handle.stop()
  handle.cleanup()
  await verifier.close()
  await model.close()
  return result
}

describe('activation.onStartup is load bearing', () => {
  it(
    'removing it removes startup selection and the gate itself',
    { timeout: TIMEOUT * 3 },
    async () => {
      expect(activationPresent()).toBe(true)

      const counterA = join(mkdtempSync(join(tmpdir(), 'aps-mut-a-')), 'exec.log')
      writeFileSync(counterA, '', 'utf8')
      const baseline = await runCase(counterA)
      expect(baseline.selectedForStartup).toBe(true)
      expect(baseline.gatewayStartRan).toBe(true)
      expect(baseline.executions).toBe(0)
      expect(baseline.attempts).toBe('')

      let mutated: Awaited<ReturnType<typeof runCase>> | undefined
      try {
        const manifest = readManifest()
        delete manifest.activation
        writeFileSync(MANIFEST, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8')
        restored = false
        // Print the patched file back: a patch that changed nothing is a null
        // result, not a control.
        // eslint-disable-next-line no-console
        console.log('[mutation] manifest under test:\n', readFileSync(MANIFEST, 'utf8'))
        expect(activationPresent()).toBe(false)
        execFileSync('npm', ['run', 'build'], { cwd: REPO_ROOT, stdio: 'ignore' })

        const counterB = join(mkdtempSync(join(tmpdir(), 'aps-mut-b-')), 'exec.log')
        writeFileSync(counterB, '', 'utf8')
        mutated = await runCase(counterB)
      } finally {
        restoreManifest()
      }

      // The invariant: startup selection and the gate both disappear.
      expect(mutated?.selectedForStartup).toBe(false)
      expect(mutated?.gatewayStartRan).toBe(false)
      expect(mutated?.executions).toBe(1)
      // observation, not the invariant
      expect(typeof mutated?.startHooks).toBe('string')

      // restored, and green again
      expect(activationPresent()).toBe(true)
      const counterC = join(mkdtempSync(join(tmpdir(), 'aps-mut-c-')), 'exec.log')
      writeFileSync(counterC, '', 'utf8')
      const again = await runCase(counterC)
      expect(again.selectedForStartup).toBe(true)
      expect(again.gatewayStartRan).toBe(true)
      expect(again.executions).toBe(0)
    },
  )
})
