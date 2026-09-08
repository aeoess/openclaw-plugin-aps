// Agent Passport System OpenClaw plugin — signing gate for aps.signMessage.
//
// Citations below name SYMBOLS, not line numbers. An earlier version cited line
// numbers and they drifted between host releases; the symbols did not. Verified
// against OpenClaw 2026.9.3, the exact version this plugin is pinned to and the
// only host it has been exercised on.
//
// Why this file exists: aps.signMessage hands a configured local passport
// private key to whoever can reach the gateway method. A plugin-registered
// gateway method is reachable by network gateway clients, because the host
// merges the plugin registry's gatewayHandlers into the gateway method registry
// (src/gateway/server-methods.ts, buildGatewayMethodRegistry via
// gatewayPluginHandlers), and by other plugins through the trusted in-process
// runtime (src/gateway/server-plugins.ts, dispatchTrustedPluginGatewayMethod).
// So signing is off by default, gated on caller identity when on, and every
// signature carries a domain-separation prefix.
//
// Caller identity IS available: the host passes its GatewayClient to the handler
// as `client` (GatewayRequestHandlerOptions in
// src/gateway/server-methods/shared-types.ts), forwarded verbatim by
// adaptPluginGatewayMethodHandler in
// src/plugins/registry-registrars-network.ts. A plugin caller is named by
// client.internal.pluginRuntimeOwnerId (declared in
// src/gateway/server-methods/client-types.ts), which the host stamps from its
// own AsyncLocalStorage plugin scope and never from wire params
// (src/gateway/server-plugin-runtime-client.ts).
//
// Approval is NOT available to this handler. requireApproval is a return value
// of the before_tool_call hook (src/plugins/hook-before-tool-call-result.ts),
// consumed by the agent tool pipeline
// (src/agents/agent-tools.before-tool-call.approval.ts). A gateway RPC handler
// has no equivalent return channel, and the one SDK seam that could reach the
// core plugin.approval.request method refuses unless the request scope sets
// gatewayMethodDispatchAllowed (src/plugin-sdk/gateway-method-runtime.ts),
// which only plugin HTTP routes ever get (src/gateway/server/plugins-http.ts).
// So the default approver here is absent and an approval-gated request is
// refused, not waved through.

import { createHash } from 'node:crypto'
import { appendFileSync, mkdirSync, readFileSync } from 'node:fs'
import { dirname } from 'node:path'
import { sign } from 'agent-passport-system'
import type { APSPluginConfig } from './config.js'
import type { OpenClawPluginApi } from 'openclaw/plugin-sdk/plugin-entry'

/** Domain separation for every signature this plugin produces.
 *
 *  Same shape as the SDK's own domains, for example
 *  AUTHORITY_DELEGATION_SIGNATURE_DOMAIN in
 *  agent-passport-system src/v2/authority-delegation/canonical.ts:10: an ASCII
 *  label, a version, a NUL terminator, prepended to the exact signing input.
 *  A signature minted here therefore cannot be replayed as a passport,
 *  attestation or authority-delegation signature over a different context. */
export const SIGN_MESSAGE_SIGNATURE_DOMAIN = 'APS-OPENCLAW-PLUGIN-SIGN-MESSAGE-V1\0'

/** Exact Ed25519 input: domain plus the caller's message. */
export function signMessageSignatureInput(message: string): string {
  return SIGN_MESSAGE_SIGNATURE_DOMAIN + message
}

/** Allowlist token standing for any authenticated gateway client that is not a
 *  named plugin. It is one token because OpenClaw does not give the handler a
 *  stable per-client name; see resolveCaller. */
export const GATEWAY_CLIENT_CALLER = 'gateway-client'

/** The caller identity the host supplies, derived from the host's own gateway
 *  handler options rather than restated here. This one is security-bearing:
 *  resolveCaller reads internal.pluginRuntimeOwnerId out of it to decide who
 *  may sign, so a local mirror that drifted from the host shape would be a
 *  silent authorization change. */
export type GatewayCallerClient = NonNullable<
  Parameters<Parameters<OpenClawPluginApi['registerGatewayMethod']>[1]>[0]['client']
>

export type SigningCaller = { kind: 'plugin' | 'gateway-client' | 'unknown'; id: string }

/** Resolve the caller the host actually named.
 *
 *  A plugin dispatching through the trusted in-process runtime is named
 *  exactly; anything else that arrives with a completed handshake is one
 *  anonymous 'gateway-client'; a handler invoked with no client at all is
 *  'unknown' and is never on an allowlist. */
export function resolveCaller(client: GatewayCallerClient | null | undefined): SigningCaller {
  const pluginId = client?.internal?.pluginRuntimeOwnerId
  if (typeof pluginId === 'string' && pluginId.trim().length > 0) {
    return { kind: 'plugin', id: pluginId.trim() }
  }
  if (client?.connect) return { kind: 'gateway-client', id: GATEWAY_CLIENT_CALLER }
  return { kind: 'unknown', id: 'unknown' }
}

/** sha256 of the message. The audit log records this and never the body. */
export function messageDigest(message: string): string {
  return `sha256:${createHash('sha256').update(message, 'utf8').digest('hex')}`
}

export type SigningOutcome =
  | 'signed'
  | 'refused:signing-disabled'
  | 'refused:caller-not-allowed'
  | 'refused:approval-unavailable'
  | 'refused:approval-denied'
  | 'refused:invalid-params'
  | 'refused:no-passport'

export interface SigningAuditRecord {
  ts: string
  outcome: SigningOutcome
  caller: string
  callerKind: SigningCaller['kind']
  domain: string
  digest: string | null
}

/** Asks a human to approve one signing request. */
export type SigningApprover = (request: {
  caller: string
  digest: string
  domain: string
}) => Promise<boolean>

/** OpenClaw 2026.9.3 exposes no approval channel to a gateway RPC handler
 *  (see the file header for the exact citations), so there is nothing to
 *  return here. When signing.requireApproval is on, requests are refused
 *  rather than signed without a decision. */
export function resolveApprover(): SigningApprover | null {
  return null
}

export interface SignMessageDeps {
  approver?: SigningApprover | null
  readPassport?: (path: string) => unknown
  writeAudit?: (record: SigningAuditRecord) => void
}

/** Append one JSON line to the local signing audit log. Never the message body. */
export function appendAudit(path: string, record: SigningAuditRecord): void {
  try {
    mkdirSync(dirname(path), { recursive: true })
    appendFileSync(path, `${JSON.stringify(record)}\n`, 'utf8')
  } catch (e) {
    console.warn(`[aps] signing audit log write failed at ${path}: ${(e as Error).message}`)
  }
}

class SigningRefusal extends Error {
  readonly outcome: SigningOutcome
  constructor(outcome: SigningOutcome, message: string) {
    super(message)
    this.name = 'SigningRefusal'
    this.outcome = outcome
  }
}

export interface SignMessageRequest {
  params?: Record<string, unknown>
  client?: GatewayCallerClient | null
}

export interface SignMessageResult {
  signature: string
  domain: string
  digest: string
}

/** Build the aps.signMessage handler.
 *
 *  Check order matters: the passport file is not read, and its private key is
 *  not loaded, until the request has passed the enabled switch, the caller
 *  allowlist and the approval gate. */
export function makeSignMessage(config: APSPluginConfig, deps: SignMessageDeps = {}) {
  const readPassport = deps.readPassport ?? ((p: string) => JSON.parse(readFileSync(p, 'utf8')) as unknown)
  const approver = deps.approver === undefined ? resolveApprover() : deps.approver
  const writeAudit =
    deps.writeAudit ?? ((record: SigningAuditRecord) => appendAudit(config.signing.auditLogPath, record))

  return async (request: SignMessageRequest = {}): Promise<SignMessageResult> => {
    const caller = resolveCaller(request.client)
    const raw = request.params?.message
    const digest = typeof raw === 'string' ? messageDigest(raw) : null
    const audit = (outcome: SigningOutcome): void => {
      writeAudit({
        ts: new Date().toISOString(),
        outcome,
        caller: caller.id,
        callerKind: caller.kind,
        domain: SIGN_MESSAGE_SIGNATURE_DOMAIN,
        digest,
      })
    }

    try {
      if (config.signing.enabled !== true) {
        throw new SigningRefusal(
          'refused:signing-disabled',
          'aps.signMessage: signing is disabled. Set signing.enabled to true only if every plugin and gateway client that can reach this method is trusted with the configured passport key.',
        )
      }
      if (typeof raw !== 'string' || raw.length === 0) {
        throw new SigningRefusal(
          'refused:invalid-params',
          'aps.signMessage: params.message must be a non-empty string',
        )
      }
      if (!config.signing.allowedCallers.includes(caller.id)) {
        throw new SigningRefusal(
          'refused:caller-not-allowed',
          `aps.signMessage: caller '${caller.id}' is not in signing.allowedCallers`,
        )
      }
      if (config.signing.requireApproval) {
        if (!approver) {
          throw new SigningRefusal(
            'refused:approval-unavailable',
            'aps.signMessage: signing.requireApproval is on and this OpenClaw host offers no approval channel to a gateway RPC handler, so the request is refused. See the Signing section of the plugin README.',
          )
        }
        const approved = await approver({
          caller: caller.id,
          digest: digest as string,
          domain: SIGN_MESSAGE_SIGNATURE_DOMAIN,
        })
        if (!approved) {
          throw new SigningRefusal('refused:approval-denied', 'aps.signMessage: signing request denied')
        }
      }

      const passport = readPassport(config.credentials.passportPath)
      if (!passport || typeof passport !== 'object' || !('privateKey' in passport)) {
        throw new SigningRefusal(
          'refused:no-passport',
          'aps.signMessage: passport file missing privateKey',
        )
      }
      const signature = sign(
        signMessageSignatureInput(raw),
        (passport as { privateKey: string }).privateKey,
      )
      audit('signed')
      return { signature, domain: SIGN_MESSAGE_SIGNATURE_DOMAIN, digest: digest as string }
    } catch (e) {
      if (e instanceof SigningRefusal) {
        audit(e.outcome)
        throw new Error(e.message)
      }
      // A passport that is absent or unreadable is also a refusal to record.
      audit('refused:no-passport')
      throw e
    }
  }
}
