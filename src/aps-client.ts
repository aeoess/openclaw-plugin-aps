// Thin fetch wrapper for the public APS gateway. No retries, no caching layer
// (caller's responsibility).

/** APS defines exactly four grades. A response carrying anything else is
 *  malformed, not a low grade. */
export type PassportGrade = 0 | 1 | 2 | 3

export interface TrustProfile {
  agentId?: string
  grade: PassportGrade
  /** The gateway answers 200 with found:false for an agent it does not know.
   *  Absent on older responses, where a 404 carried the same meaning. */
  found?: boolean
  attestations?: unknown[]
  [k: string]: unknown
}

/** Three distinct outcomes that must never be represented as one another.
 *
 *  `unknown` means the registry answered and does not know this author.
 *  `unavailable` means we never got a usable answer: transport failure, a
 *  non-2xx status, or a timeout applied by the caller.
 *  `malformed` means the registry answered 200 with a body we cannot trust.
 *
 *  All three currently fail open at the install gate, but each carries its own
 *  reason so the finding and the log say what actually happened. Collapsing
 *  them to a single null is what previously reported a network failure as
 *  "author not found". */
export type TrustLookup =
  | { state: 'found'; profile: TrustProfile }
  | { state: 'unknown' }
  | { state: 'unavailable'; reason: string }
  | { state: 'malformed'; reason: string }

function isPassportGrade(value: unknown): value is PassportGrade {
  return value === 0 || value === 1 || value === 2 || value === 3
}

/** Never throws. A caller cannot accidentally turn a transport failure into a
 *  permissive branch, because every failure is a named state. */
export async function checkGrade(verifierUrl: string, agentId: string): Promise<TrustLookup> {
  let res: Response
  try {
    res = await fetch(`${verifierUrl}/${encodeURIComponent(agentId)}`)
  } catch (e) {
    return { state: 'unavailable', reason: `request failed: ${(e as Error).message}` }
  }
  if (res.status === 404) return { state: 'unknown' }
  if (!res.ok) return { state: 'unavailable', reason: `gateway returned ${res.status}` }

  let body: unknown
  try {
    body = await res.json()
  } catch (e) {
    return { state: 'malformed', reason: `response was not JSON: ${(e as Error).message}` }
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { state: 'malformed', reason: 'response was not a JSON object' }
  }
  const rec = body as Record<string, unknown>
  if (rec.found === false) return { state: 'unknown' }
  // Validate before use. `{found:true}` with no grade previously made both
  // numeric comparisons in the install gate false, so the install passed with
  // neither a warning nor a block: fail-open by accident of `undefined < 1`.
  if (!isPassportGrade(rec.grade)) {
    return {
      state: 'malformed',
      reason: `grade must be 0, 1, 2 or 3; received ${JSON.stringify(rec.grade)}`,
    }
  }
  return { state: 'found', profile: rec as TrustProfile }
}
