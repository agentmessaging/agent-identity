import { createHash } from 'node:crypto'
import { outboundRequest } from './outbound.js'

/**
 * Access tokens for oauth2_client_credentials agents. One token per agent, fetched from the tenant's fixed token URL,
 * kept until shortly before it expires, never longer than an hour. Concurrent requests share one fetch.
 */
export class OAuthTokenCache {
  constructor({ now = () => Date.now(), allowPrivate = false, earlyMs = 30_000 } = {}) {
    this.now = now
    this.allowPrivate = allowPrivate
    this.earlyMs = earlyMs
    this.tokens = new Map()
    this.inflight = new Map()
    this.fetches = 0
  }

  invalidate(name) { this.tokens.delete(name) }

  /** @returns {Promise<string>} the access token; throws on any failure (the caller says only "credential unavailable") */
  async get(name, cred, { tokenUrl, tokenAuth = 'basic' }) {
    const fingerprint = createHash('sha256').update(`${cred.clientId}\u0000${cred.clientSecret}\u0000${cred.scope ?? ''}\u0000${tokenUrl}`).digest('hex')
    const hit = this.tokens.get(name)
    if (hit && hit.fingerprint === fingerprint && hit.expiresAt - this.earlyMs > this.now()) return hit.token
    const pending = this.inflight.get(name)
    if (pending && pending.fingerprint === fingerprint) return pending.promise
    const promise = this.#fetch(name, cred, tokenUrl, tokenAuth, fingerprint).finally(() => { if (this.inflight.get(name)?.promise === promise) this.inflight.delete(name) })
    this.inflight.set(name, { fingerprint, promise })
    return promise
  }

  async #fetch(name, cred, tokenUrl, tokenAuth, fingerprint) {
    this.fetches++
    const form = new URLSearchParams({ grant_type: 'client_credentials' })
    if (cred.scope) form.set('scope', cred.scope)
    const headers = { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' }
    if (tokenAuth === 'body') { form.set('client_id', cred.clientId); form.set('client_secret', cred.clientSecret) } else {
      headers.authorization = `Basic ${Buffer.from(`${encodeURIComponent(cred.clientId)}:${encodeURIComponent(cred.clientSecret)}`).toString('base64')}`
    }
    const res = await outboundRequest(new URL(tokenUrl), { method: 'POST', headers, body: form.toString(), timeoutMs: 10_000, maxBytes: 64 * 1024, allowPrivate: this.allowPrivate })
    if (res.status !== 200) throw new Error('token endpoint refused')
    const body = JSON.parse(res.body.toString('utf8'))
    if (typeof body.access_token !== 'string' || !/^[\x21-\x7e]+$/.test(body.access_token)) throw new Error('no usable token')
    if (body.token_type !== undefined && String(body.token_type).toLowerCase() !== 'bearer') throw new Error('not a bearer token')
    const lifetimeSec = Number.isFinite(body.expires_in) ? Math.min(Math.max(body.expires_in, 0), 3600) : 300
    if (lifetimeSec * 1000 > this.earlyMs) this.tokens.set(name, { token: body.access_token, expiresAt: this.now() + lifetimeSec * 1000, fingerprint })
    return body.access_token
  }
}
