// Repository-owned harness for the runtime proofs.
//
// These proofs used to live in a scratch OpenClaw checkout, so nothing tracked
// here would have caught a regression in them. Everything below runs against
// the exact-pinned openclaw dependency this repository already declares, using
// only loopback fixtures, with external network access denied. A developer who
// clones the repo and runs the suite reproduces them.
import { type ChildProcess, spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, rmSync } from 'node:fs'
import { createServer, type IncomingMessage, type ServerResponse, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createStoredZip } from './stored-zip.js'

const HERE = dirname(fileURLToPath(import.meta.url))
export const REPO_ROOT = resolve(HERE, '..', '..')
export const OPENCLAW_CLI = join(REPO_ROOT, 'node_modules', 'openclaw', 'openclaw.mjs')
export const DENY_NETWORK_PRELOAD = join(HERE, 'deny-external-network.mjs')

export const CH_PACKAGE = '@apsfixture/demo-plugin'
export const CH_VERSION = '1.0.0'
export const CH_PLUGIN_ID = 'aps-scoped-fixture'

async function listen(server: Server): Promise<number> {
  await new Promise<void>((res, rej) => {
    server.once('error', rej)
    server.listen(0, '127.0.0.1', res)
  })
  return (server.address() as AddressInfo).port
}

function closer(server: Server) {
  return async () => {
    server.closeAllConnections()
    await new Promise<void>((res) => server.close(() => res()))
  }
}

/** Loopback stand-in for the public APS trust registry. Production cannot be
 *  used: the network guard denies it, so the only reachable state would be
 *  `unavailable`, which is the wrong proof for a known or unknown author. */
export async function startVerifierFixture(profiles: Record<string, unknown>) {
  const hits: string[] = []
  const server = createServer((req, res) => {
    const url = req.url ?? ''
    hits.push(url)
    const key = Object.keys(profiles).find((k) => url.includes(k))
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify(key ? profiles[key] : { found: false, grade: 0 }))
  })
  const port = await listen(server)
  return { baseUrl: `http://127.0.0.1:${port}/trust`, hits, close: closer(server) }
}

/** Local ClawHub. Gateway plugins.install accepts only `clawhub` and `official`
 *  sources, and the install must run in the Gateway process for the plugin's
 *  before_install hook to be registered at all. The package name is SCOPED so
 *  the author gate has a real npm scope to resolve. */
export async function startClawHubFixture() {
  const archive = createStoredZip({
    'package/package.json': JSON.stringify({
      name: CH_PACKAGE,
      version: CH_VERSION,
      type: 'module',
      openclaw: { extensions: ['./dist/index.js'] },
    }),
    'package/openclaw.plugin.json': JSON.stringify({
      id: CH_PLUGIN_ID,
      configSchema: { type: 'object', properties: {} },
    }),
    'package/dist/index.js': 'export default function register() {}\n',
  })
  const sha256 = createHash('sha256').update(archive).digest('hex')
  const apiPath = `/api/v1/packages/${encodeURIComponent(CH_PACKAGE)}`
  let registry = ''
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const send = (body: unknown) => {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify(body))
    }
    const pkg = { name: CH_PACKAGE, displayName: 'APS Fixture', family: 'code-plugin' }
    if (req.method === 'GET' && url.pathname === apiPath) {
      send({
        package: { ...pkg, runtimeId: CH_PLUGIN_ID, channel: 'community', isOfficial: false, latestVersion: CH_VERSION, tags: { latest: CH_VERSION }, compatibility: {} },
        owner: { handle: 'apsfixture' },
      })
      return
    }
    if (req.method === 'GET' && url.pathname === `${apiPath}/versions/${CH_VERSION}/artifact`) {
      send({ package: pkg, version: { version: CH_VERSION, createdAt: 1, changelog: 'fixture', sha256hash: sha256, compatibility: {} } })
      return
    }
    if (req.method === 'GET' && url.pathname === `${apiPath}/versions/${CH_VERSION}/security`) {
      send({
        package: pkg,
        release: { version: CH_VERSION },
        overview: 'Synthetic fixture.',
        securityAuditUrl: `${registry}/audit`,
        trust: { scanStatus: 'clean', moderationState: null, blockedFromDownload: false, reasons: [], pending: false, stale: false },
      })
      return
    }
    if (req.method === 'GET' && url.pathname === `${apiPath}/download`) {
      res.writeHead(200, { 'content-type': 'application/zip' })
      res.end(archive)
      return
    }
    if (req.method === 'POST' && url.pathname === '/api/cli/telemetry/install') {
      send({ ok: true })
      return
    }
    res.writeHead(404).end('not found')
  })
  const port = await listen(server)
  registry = `http://127.0.0.1:${port}`
  return { registry, close: closer(server) }
}

/** Minimal openai-responses model. First turn calls the high-risk tool, second
 *  turn answers, so a real tool call reaches the host's before_tool_call. */
export async function startMockModel(params: { execCommand: string; toolName: string }) {
  let turn = 0
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (req.method === 'GET' && url.pathname === '/v1/models') {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ data: [{ id: 'aps-proof', object: 'model' }] }))
      return
    }
    if (req.method !== 'POST' || url.pathname !== '/v1/responses') {
      res.writeHead(404).end()
      return
    }
    const chunks: Buffer[] = []
    req.on('data', (c: Buffer) => chunks.push(c))
    req.on('end', () => {
      turn += 1
      res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' })
      const write = (events: unknown[]) => {
        for (const e of events) res.write(`data: ${JSON.stringify(e)}\n\n`)
        res.end()
      }
      if (turn === 1) {
        const item = {
          type: 'function_call', id: 'fc_1', call_id: 'call_1',
          name: params.toolName, arguments: JSON.stringify({ command: params.execCommand }),
          status: 'completed',
        }
        write([
          { type: 'response.output_item.added', output_index: 0, item: { ...item, status: 'in_progress', arguments: '' } },
          { type: 'response.function_call_arguments.done', item_id: item.id, output_index: 0, arguments: item.arguments },
          { type: 'response.output_item.done', output_index: 0, item },
          { type: 'response.completed', response: { id: 'r1', status: 'completed', output: [item], usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2 } } },
        ])
        return
      }
      const msg = { type: 'message', id: 'm', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text: 'APS_PROOF_DONE', annotations: [] }] }
      write([
        { type: 'response.output_item.added', output_index: 0, item: { ...msg, status: 'in_progress', content: [] } },
        { type: 'response.output_text.done', item_id: 'm', output_index: 0, content_index: 0, text: 'APS_PROOF_DONE' },
        { type: 'response.output_item.done', output_index: 0, item: msg },
        { type: 'response.completed', response: { id: 'r2', status: 'completed', output: [msg], usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2 } } },
      ])
    })
  })
  const port = await listen(server)
  return { baseUrl: `http://127.0.0.1:${port}`, close: closer(server) }
}

export type GatewayHandle = {
  stateDir: string
  root: string
  token: string
  port: number
  networkAttemptsFile: string
  run: (args: string[]) => Promise<{ code: number | null; stdout: string; stderr: string }>
  /** Starts the Gateway. Install plugins BEFORE calling this: plugin source
   *  changes take effect only on the next Gateway start, so a plugin installed
   *  after startup is simply not loaded. */
  start: () => Promise<void>
  logs: () => string
  stop: () => Promise<void>
  cleanup: () => void
}

/** Ask the OS for a free port rather than counting upward: a fixed counter
 *  collides with a gateway left listening by an earlier run. */
async function freePort(): Promise<number> {
  const probe = createServer()
  const port = await listen(probe)
  await new Promise<void>((res) => probe.close(() => res()))
  return port
}

export async function bootGateway(params: {
  apsConfig: Record<string, unknown>
  modelBaseUrl: string
  clawhubUrl?: string
}): Promise<GatewayHandle> {
  const root = mkdtempSync(join(tmpdir(), 'aps-proof-'))
  const stateDir = join(root, 'state')
  mkdirSync(stateDir, { recursive: true })
  const token = 'aps-proof-token'
  const port = await freePort()
  const apsConfigPath = join(root, 'aps.config.json')
  const networkAttemptsFile = join(root, 'external-network-attempts.log')
  writeFileSync(networkAttemptsFile, '', 'utf8')
  writeFileSync(apsConfigPath, JSON.stringify(params.apsConfig), 'utf8')
  const configPath = join(stateDir, 'openclaw.json')
  writeFileSync(configPath, JSON.stringify({
    gateway: { mode: 'local', bind: 'loopback', port, auth: { mode: 'token', token } },
    update: { checkOnStart: false },
    plugins: { slots: { memory: 'none' } },
    agents: {
      defaults: {
        heartbeat: { every: '0m' }, skipBootstrap: true, skills: [],
        model: { primary: 'aps-proof/aps-proof' },
        models: { 'aps-proof/aps-proof': { agentRuntime: { id: 'openclaw' } } },
      },
    },
    tools: { profile: 'coding' },
    models: {
      mode: 'replace',
      providers: {
        'aps-proof': {
          baseUrl: `${params.modelBaseUrl}/v1`, apiKey: 'test-token-placeholder',
          api: 'openai-responses', request: { allowPrivateNetwork: true },
          models: [{ id: 'aps-proof', name: 'aps-proof', api: 'openai-responses', reasoning: false, input: ['text'], cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 }, contextWindow: 128000, maxTokens: 4096 }],
        },
      },
    },
  }), 'utf8')

  // OpenClaw's own e2e helpers strip these before spawning the CLI: the child
  // changes behaviour when it believes it is inside a Vitest run, and inherits
  // silence instead of starting. Without this the Gateway produces no output at
  // all and the boot times out.
  const inherited: NodeJS.ProcessEnv = { ...process.env }
  for (const key of [
    'VITEST',
    'VITEST_POOL_ID',
    'VITEST_WORKER_ID',
    'VITEST_MODE',
    'NODE_ENV',
    'OPENCLAW_HOME',
    'OPENCLAW_PROFILE',
  ]) {
    delete inherited[key]
  }

  const env: NodeJS.ProcessEnv = {
    ...inherited,
    HOME: root,
    OPENCLAW_STATE_DIR: stateDir,
    OPENCLAW_CONFIG_PATH: configPath,
    OPENCLAW_APS_CONFIG_PATH: apsConfigPath,
    APS_NETWORK_ATTEMPTS_FILE: networkAttemptsFile,
    OPENCLAW_SKIP_CHANNELS: '1',
    // Suppress the host's OWN startup version check in every spawned process.
    // The network guard stays absolute: it fails on ANY non-loopback request.
    // Configuring the host not to phone home is what makes a failure mean that
    // THIS plugin reached out, rather than that OpenClaw did.
    OPENCLAW_NO_AUTO_UPDATE: '1',
    DO_NOT_TRACK: '1',
    NODE_OPTIONS: `--import ${JSON.stringify(DENY_NETWORK_PRELOAD)}`,
    ...(params.clawhubUrl ? { OPENCLAW_CLAWHUB_URL: params.clawhubUrl, CLAWHUB_TOKEN: 'test-token' } : {}),
  }

  const run = (args: string[]) =>
    new Promise<{ code: number | null; stdout: string; stderr: string }>((res, rej) => {
      const child = spawn(process.execPath, [OPENCLAW_CLI, ...args], { env, stdio: ['ignore', 'pipe', 'pipe'] })
      let stdout = ''
      let stderr = ''
      child.stdout.setEncoding('utf8')
      child.stderr.setEncoding('utf8')
      child.stdout.on('data', (c: string) => { stdout += c })
      child.stderr.on('data', (c: string) => { stderr += c })
      child.on('error', rej)
      child.on('close', (code) => res({ code, stdout, stderr }))
    })

  let log = ''
  let gw: ChildProcess | undefined

  const start = async (): Promise<void> => {
    const child = spawn(process.execPath, [OPENCLAW_CLI, 'gateway', '--allow-unconfigured'], { env, stdio: ['ignore', 'pipe', 'pipe'] })
    gw = child
    let spawnError: Error | undefined
    child.on('error', (err: Error) => { spawnError = err })
    child.on('exit', (code, signal) => { log += `\n[harness] gateway exited code=${code} signal=${signal}\n` })
    child.stdout?.setEncoding('utf8')
    child.stderr?.setEncoding('utf8')
    child.stdout?.on('data', (c: string) => { log += c })
    child.stderr?.on('data', (c: string) => { log += c })

    const deadline = Date.now() + 90_000
    while (Date.now() < deadline && !/\[gateway\] ready/.test(log) && !spawnError) {
      await new Promise((r) => setTimeout(r, 250))
    }
    if (spawnError) {
      child.kill('SIGKILL')
      throw new Error(`gateway failed to spawn: ${spawnError.message}`)
    }
    if (!/\[gateway\] ready/.test(log)) {
      child.kill('SIGKILL')
      throw new Error(`gateway did not become ready. captured output:\n${log || '(nothing)'}`)
    }
  }

  return {
    stateDir, root, token, port, networkAttemptsFile, run, start,
    logs: () => log,
    stop: async () => {
      gw?.kill('SIGTERM')
      await new Promise((r) => setTimeout(r, 500))
      gw?.kill('SIGKILL')
    },
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  }
}

export function readNetworkAttempts(handle: GatewayHandle): string {
  return readFileSync(handle.networkAttemptsFile, 'utf8').trim()
}

/** Counts executions by APPENDED lines. File existence cannot prove "once":
 *  two runs of the same redirect leave exactly one file. */
export function countExecutions(counterPath: string): number {
  try {
    return readFileSync(counterPath, 'utf8').split('\n').filter((l) => l.trim().length > 0).length
  } catch {
    return 0
  }
}
