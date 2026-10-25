import { AidError, assertAlgorithm, decodeJwt, verifySignature } from './verifier.js'

/**
 * Security Event Tokens from an issuer (RFC 8417 shape, delivered like RFC 8935 push): a signed JWT whose `events` claim
 * says an agent was suspended or deleted or reactivated, or that one token was revoked. The gateway verifies the
 * signature with the issuer's own configured keys, the issuer and audience exactly, and refuses an old or replayed event.
 */

export const EVENT_TYPES = {
  'urn:aid:event:agent-suspended': 'agent-suspended',
  'urn:aid:event:agent-deleted': 'agent-deleted',
  'urn:aid:event:agent-reactivated': 'agent-reactivated',
  'urn:aid:event:token-revoked': 'token-revoked',
}

export class SetError extends Error {
  /** @param {'invalid_request'|'invalid_issuer'|'invalid_audience'|'invalid_key'} err */
  constructor(err, description) { super(description); this.err = err; this.description = description }
}

/**
 * @param {string} jwt
 * @param {{ issuers: Map<string, {issuer: string, jwksUri: string}>, jwks: { keyFor(uri: string, kid?: string): Promise<object> }, audience: string, maxAgeSec: number, now: () => number, seen: Map<string, number>, clockSkewSec?: number }} ctx
 * @returns {Promise<Array<{ issuer: string, type: string, agentId?: string, jti?: string }>>}
 */
export async function verifySecurityEvent(jwt, { issuers, jwks, audience, maxAgeSec, now, seen, clockSkewSec = 60 }) {
  let decoded
  try { decoded = decodeJwt(jwt); assertAlgorithm(decoded.header) } catch (e) {
    throw new SetError('invalid_request', e instanceof AidError ? e.message : 'not a token')
  }
  const { payload } = decoded
  const issuer = typeof payload.iss === 'string' ? issuers.get(payload.iss) : undefined
  if (!issuer) throw new SetError('invalid_issuer', 'the issuer is not one this tenant trusts')
  let good = false
  try { good = verifySignature(decoded, await jwks.keyFor(issuer.jwksUri, decoded.header.kid)) } catch { throw new SetError('invalid_key', 'the issuer\'s key could not be used') }
  if (!good) throw new SetError('invalid_key', 'the signature does not match')
  const aud = Array.isArray(payload.aud) ? payload.aud : typeof payload.aud === 'string' ? [payload.aud] : []
  if (!aud.includes(audience)) throw new SetError('invalid_audience', 'the event is not for this tenant')

  const nowSec = Math.floor(now() / 1000)
  if (typeof payload.iat !== 'number') throw new SetError('invalid_request', 'iat is required')
  if (payload.iat - clockSkewSec > nowSec) throw new SetError('invalid_request', 'iat is in the future')
  if (nowSec - payload.iat > maxAgeSec) throw new SetError('invalid_request', 'the event is too old')
  if (typeof payload.exp === 'number' && payload.exp + clockSkewSec <= nowSec) throw new SetError('invalid_request', 'the event has expired')
  if (typeof payload.jti !== 'string' || !payload.jti) throw new SetError('invalid_request', 'jti is required')

  const events = payload.events
  if (!events || typeof events !== 'object' || Array.isArray(events) || Object.keys(events).length === 0) throw new SetError('invalid_request', 'no events')
  const out = []
  for (const [uri, body] of Object.entries(events)) {
    const type = EVENT_TYPES[uri]
    if (!type) throw new SetError('invalid_request', 'an event type is not supported')
    if (!body || typeof body !== 'object') throw new SetError('invalid_request', 'an event has no subject')
    if (type === 'token-revoked') {
      if (typeof body.jti !== 'string' || !body.jti) throw new SetError('invalid_request', 'token-revoked needs a jti')
      out.push({ issuer: issuer.issuer, type, jti: body.jti })
    } else {
      if (typeof body.agent_id !== 'string' || !body.agent_id) throw new SetError('invalid_request', `${type} needs an agent_id`)
      out.push({ issuer: issuer.issuer, type, agentId: body.agent_id })
    }
  }

  // Replay: remember the event id for as long as an event of that age could still be accepted
  for (const [k, until] of seen) if (until <= now()) seen.delete(k)
  const key = `${issuer.issuer}\u0000${payload.jti}`
  if (seen.has(key)) throw new SetError('invalid_request', 'this event was already received')
  seen.set(key, now() + (maxAgeSec + clockSkewSec) * 1000)
  return out
}
