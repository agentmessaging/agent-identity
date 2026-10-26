import { AidError } from './errors.js'

/**
 * Keys for each trusted issuer, from the JWKS address configured for it. Cached; an unknown `kid` triggers one refresh
 * (a key rotation), no more often than `minRefreshMs`, so a stream of tokens with made-up kids cannot make the
 * verifier hammer the issuer. If the issuer cannot be reached the verifier fails closed: a stale key set is used only
 * when `staleIfErrorMs` says so.
 */
export class JwksCache {
  constructor({ fetch: fetchImpl = globalThis.fetch, now = () => Date.now(), ttlMs = 10 * 60_000, minRefreshMs = 30_000, staleIfErrorMs = 0, allowInsecureHttp = false } = {}) {
    this.fetch = fetchImpl
    this.now = now
    this.ttlMs = ttlMs
    this.minRefreshMs = minRefreshMs
    this.staleIfErrorMs = staleIfErrorMs
    this.allowInsecureHttp = allowInsecureHttp
    /** @type {Map<string, { keys: object[], at: number }>} */
    this.cache = new Map()
    /** @type {Map<string, number>} */
    this.lastRefresh = new Map()
  }

  async #load(uri) {
    if (!this.allowInsecureHttp && !uri.startsWith('https://')) throw new AidError('jwks_unavailable', 'The JWKS address must be https')
    let res
    try {
      res = await this.fetch(uri, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(5000) })
    } catch {
      throw new AidError('jwks_unavailable', 'The issuer\'s keys could not be fetched')
    }
    if (!res.ok) throw new AidError('jwks_unavailable', `The issuer's keys returned ${res.status}`)
    let body
    try { body = await res.json() } catch { throw new AidError('jwks_unavailable', 'The issuer\'s keys are not JSON') }
    if (!body || !Array.isArray(body.keys)) throw new AidError('jwks_unavailable', 'The issuer\'s keys have no "keys"')
    return body.keys
  }

  async #refresh(uri) {
    this.lastRefresh.set(uri, this.now())
    try {
      const keys = await this.#load(uri)
      this.cache.set(uri, { keys, at: this.now() })
      return keys
    } catch (e) {
      const cached = this.cache.get(uri)
      if (cached && this.now() - cached.at <= this.staleIfErrorMs) return cached.keys
      throw e
    }
  }

  /** The JWK that signed a token with this `kid` (or, with no kid, the only signing key the issuer has) */
  async keyFor(uri, kid) {
    let entry = this.cache.get(uri)
    let keys = entry && this.now() - entry.at < this.ttlMs ? entry.keys : await this.#refresh(uri)
    const pick = list => {
      const usable = list.filter(k => k.kty === 'RSA' && (!k.use || k.use === 'sig') && (!k.alg || k.alg === 'RS256'))
      if (kid) return usable.find(k => k.kid === kid)
      return usable.length === 1 ? usable[0] : undefined
    }
    let key = pick(keys)
    if (!key && this.now() - (this.lastRefresh.get(uri) ?? 0) >= this.minRefreshMs) {
      keys = await this.#refresh(uri)
      key = pick(keys)
    }
    if (!key) throw new AidError('key_not_found', 'No key of the issuer matches this token')
    return key
  }
}
