import { inspect } from 'node:util'
import { Buffer } from 'node:buffer'

/**
 * The credential the gateway holds for one agent's user in the old system. Four kinds:
 *   header                       a static header, e.g. X-API-Key: <value>
 *   bearer                       Authorization: Bearer <token>
 *   basic                        Authorization: Basic <user:password>
 *   oauth2_client_credentials    the agent user's own OAuth client; the gateway fetches and caches a short-lived access
 *                                token (the token endpoint is the tenant's fixed `upstream.tokenUrl`)
 */

export const CREDENTIAL_TYPES = ['header', 'bearer', 'basic', 'oauth2_client_credentials']

const FORBIDDEN_HEADER_NAMES = new Set(['host', 'content-length', 'content-type', 'transfer-encoding', 'connection', 'upgrade', 'te', 'trailer', 'keep-alive',
  'proxy-authorization', 'proxy-connection', 'cookie', 'set-cookie', 'expect', 'x-request-id'])
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$/
const PRINTABLE_VALUE = /^[\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?$/

/** Wraps a credential so that logging, JSON.stringify or util.inspect of it can never show the secret */
export class Credential {
  #value
  constructor(value) { this.#value = Object.freeze({ ...value }); Object.defineProperty(this, 'type', { value: value.type, enumerable: true }) }
  /** Only the gateway's own proxy code calls this */
  reveal() { return this.#value }
  toJSON() { return { type: this.type, secret: '[redacted]' } }
  toString() { return `[Credential ${this.type}]` }
  [inspect.custom]() { return `[Credential ${this.type} redacted]` }
}

function need(obj, key, re) {
  const v = obj[key]
  if (typeof v !== 'string' || v.length === 0 || v.length > 4096 || (re && !re.test(v))) throw new TypeError(`credential: "${key}" is missing or not acceptable`)
  return v
}

/** Validate a credential from an admin or the CLI; the error never contains the value */
export function validateCredential(raw, { tokenUrlConfigured = true } = {}) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new TypeError('credential must be an object')
  const allowed = {
    header: ['type', 'name', 'value'], bearer: ['type', 'token'], basic: ['type', 'username', 'password'],
    oauth2_client_credentials: ['type', 'clientId', 'clientSecret', 'scope'],
  }[raw.type]
  if (!allowed) throw new TypeError(`credential: type must be one of ${CREDENTIAL_TYPES.join(', ')}`)
  for (const k of Object.keys(raw)) if (!allowed.includes(k)) throw new TypeError(`credential: unknown field "${k}" for type ${raw.type}`)
  switch (raw.type) {
    case 'header': {
      const name = need(raw, 'name', HEADER_NAME)
      const lower = name.toLowerCase()
      if (FORBIDDEN_HEADER_NAMES.has(lower) || lower.startsWith('x-aid-')) throw new TypeError('credential: that header name is reserved')
      return { type: 'header', name, value: need(raw, 'value', PRINTABLE_VALUE) }
    }
    case 'bearer': return { type: 'bearer', token: need(raw, 'token', /^[\x21-\x7e]+$/) }
    case 'basic': {
      const username = need(raw, 'username', /^[^:\u0000-\u001f\u007f]+$/)
      return { type: 'basic', username, password: need(raw, 'password', /^[^\u0000-\u001f\u007f]+$/) }
    }
    default: {
      if (!tokenUrlConfigured) throw new TypeError('credential: this tenant has no upstream.tokenUrl, so an OAuth2 client credential cannot be used')
      const scope = raw.scope === undefined ? undefined : need(raw, 'scope', /^[\x21-\x7e]+(?: [\x21-\x7e]+)*$/)
      return { type: 'oauth2_client_credentials', clientId: need(raw, 'clientId', /^[\x21-\x7e]+$/), clientSecret: need(raw, 'clientSecret', /^[\x21-\x7e]+$/), ...(scope ? { scope } : {}) }
    }
  }
}

/** The outbound header for a credential (for oauth2, pass the access token). Lower-case names. */
export function authHeader(cred, accessToken) {
  switch (cred.type) {
    case 'header': return { [cred.name.toLowerCase()]: cred.value }
    case 'bearer': return { authorization: `Bearer ${cred.token}` }
    case 'basic': return { authorization: `Basic ${Buffer.from(`${cred.username}:${cred.password}`).toString('base64')}` }
    default: return { authorization: `Bearer ${accessToken}` }
  }
}

/** Every string that must never come back out in a response: used to refuse an upstream that echoes its credentials */
export function secretStrings(cred, accessToken) {
  const out = []
  switch (cred.type) {
    case 'header': out.push(cred.value); break
    case 'bearer': out.push(cred.token); break
    case 'basic': out.push(cred.password, Buffer.from(`${cred.username}:${cred.password}`).toString('base64')); break
    default: out.push(cred.clientSecret); if (accessToken) out.push(accessToken)
  }
  return out.filter(s => typeof s === 'string' && s.length >= 4)
}
