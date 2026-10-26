import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, unlinkSync } from 'node:fs'
import net from 'node:net'
import { join } from 'node:path'
import { atomicWriteFile } from './fsutil.js'
import { compileCatalog, validateCatalog } from './catalog.js'
import { isBlockedAddress } from './outbound.js'
import { TENANT_NAME } from './paths.js'
import { normalizeConfig } from './verifier.js'

export const REDACTED = '[redacted]'

const TOP_LEVEL = new Set(['displayName', 'disabled', 'issuers', 'grants', 'clockSkewSec', 'events', 'upstream', 'catalog', 'agents', 'limits'])
const GENERIC_AUDIENCES = new Set(['client_app', 'api_service'])
const DEFAULT_LIMITS = { maxBodyBytes: 1024 * 1024, timeoutMs: 15_000, maxResponseBytes: 5 * 1024 * 1024, ratePerMinute: 120, burst: 30 }
const LIMIT_BOUNDS = { maxBodyBytes: [0, 16 * 1024 * 1024], timeoutMs: [100, 60_000], maxResponseBytes: [1024, 64 * 1024 * 1024], ratePerMinute: [1, 100_000], burst: [1, 10_000] }
const FORWARDABLE = /^[a-z][a-z0-9-]{0,40}$/
const NEVER_FORWARD = new Set(['authorization', 'cookie', 'proxy-authorization', 'x-api-key', 'host', 'content-length', 'transfer-encoding', 'connection', 'upgrade', 'te', 'trailer', 'x-request-id', 'set-cookie'])

/** The vault entry for one agent of one tenant */
export const credentialName = (tenant, agentKey, entry) => `${tenant}/${(entry?.credentialRef ?? agentKey).toLowerCase()}`

export function assertTenantName(name) {
  if (typeof name !== 'string' || !TENANT_NAME.test(name)) throw new TypeError('a tenant name is 1-63 characters: lower-case letters, digits, - and _, starting with a letter or digit')
}

function checkUrl(value, label, { allowInsecure, allowPrivate }) {
  let u
  try { u = new URL(value) } catch { throw new TypeError(`${label} is not a URL`) }
  if (u.protocol !== 'https:' && !(allowInsecure && u.protocol === 'http:')) throw new TypeError(`${label} must be https`)
  if (u.username || u.password || u.hash) throw new TypeError(`${label} must not carry credentials or a fragment`)
  const host = u.hostname.replace(/^\[|\]$/g, '')
  if (!allowPrivate && net.isIP(host) && isBlockedAddress(host)) throw new TypeError(`${label} points at an internal address`)
  return u
}

/**
 * Validate a tenant's configuration and return the normalized form (a plain object; no secrets are added or removed).
 * Unknown fields are refused, so a typo cannot silently disable a control.
 * @param {object} raw
 * @param {{ allowInsecureHttp?: boolean, allowInsecureUpstream?: boolean, allowPrivateUpstream?: boolean }} [opts]
 */
export function validateTenantConfig(raw, { allowInsecureHttp = false, allowInsecureUpstream = false, allowPrivateUpstream = false } = {}) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new TypeError('the tenant config must be an object')
  for (const k of Object.keys(raw)) if (!TOP_LEVEL.has(k)) throw new TypeError(`unknown field "${k}" in the tenant config`)
  const warnings = []

  if (!Array.isArray(raw.issuers) || raw.issuers.length === 0) throw new TypeError('at least one issuer is required')
  const verifierView = normalizeConfig({ issuers: raw.issuers, grants: raw.grants ?? [], clockSkewSec: raw.clockSkewSec })   // throws for the profile's rules
  warnings.push(...verifierView.warnings)
  for (const i of raw.issuers) {
    if (i.audience.every(a => GENERIC_AUDIENCES.has(a))) throw new TypeError(`issuer ${i.issuer}: the gateway refuses a generic audience; use a value specific to this tenant's service`)
    checkUrl(i.jwksUri, `issuer ${i.issuer} jwksUri`, { allowInsecure: allowInsecureHttp, allowPrivate: allowPrivateUpstream })
    if (i.introspection) checkUrl(i.introspection.endpoint, `issuer ${i.issuer} introspection endpoint`, { allowInsecure: allowInsecureHttp, allowPrivate: allowPrivateUpstream })
  }

  const up = raw.upstream
  if (!up || typeof up !== 'object') throw new TypeError('upstream is required')
  for (const k of Object.keys(up)) if (!['baseUrl', 'tokenUrl', 'tokenAuth', 'forwardHeaders'].includes(k)) throw new TypeError(`unknown field "upstream.${k}"`)
  const base = checkUrl(up.baseUrl, 'upstream.baseUrl', { allowInsecure: allowInsecureUpstream, allowPrivate: allowPrivateUpstream })
  if (base.search) throw new TypeError('upstream.baseUrl must not have a query')
  if (up.tokenUrl !== undefined) {
    const t = checkUrl(up.tokenUrl, 'upstream.tokenUrl', { allowInsecure: allowInsecureUpstream, allowPrivate: allowPrivateUpstream })
    if (t.hash) throw new TypeError('upstream.tokenUrl must not have a fragment')
  }
  if (up.tokenAuth !== undefined && !['basic', 'body'].includes(up.tokenAuth)) throw new TypeError('upstream.tokenAuth must be "basic" or "body"')
  const forwardHeaders = (up.forwardHeaders ?? []).map(h => String(h).toLowerCase())
  for (const h of forwardHeaders) if (!FORWARDABLE.test(h) || NEVER_FORWARD.has(h) || h.startsWith('x-aid-') || /cookie|auth|token|key|secret/.test(h)) throw new TypeError(`upstream.forwardHeaders: "${h}" cannot be forwarded`)

  const catalog = validateCatalog(raw.catalog ?? [])
  compileCatalog(catalog)
  if (catalog.length === 0) warnings.push('the catalog is empty, so every request is refused')

  const agents = {}
  for (const [key, a] of Object.entries(raw.agents ?? {})) {
    if (!/^[\x21-\x7e]{1,254}$/.test(key)) throw new TypeError('an agents key is an agent address or id')
    if (!a || typeof a !== 'object') throw new TypeError(`agents["${key}"] must be an object`)
    for (const k of Object.keys(a)) if (!['credentialRef', 'issuer', 'disabled', 'note', 'upstreamUser'].includes(k)) throw new TypeError(`unknown field "${k}" in agents["${key}"]`)
    if (a.credentialRef !== undefined && !/^[A-Za-z0-9@._:+-]{1,254}$/.test(a.credentialRef)) throw new TypeError(`agents["${key}"].credentialRef is not acceptable`)
    if (a.issuer !== undefined && !verifierView.issuers.has(a.issuer)) throw new TypeError(`agents["${key}"].issuer is not a configured issuer`)
    if (raw.issuers.length > 1 && !a.issuer) throw new TypeError(`agents["${key}"] needs an "issuer": with several issuers the same address from another issuer must not reach this credential`)
    agents[key] = { ...(a.credentialRef ? { credentialRef: a.credentialRef } : {}), ...(a.issuer ? { issuer: a.issuer } : {}), ...(a.disabled ? { disabled: true } : {}), ...(a.note ? { note: String(a.note).slice(0, 300) } : {}), ...(a.upstreamUser ? { upstreamUser: String(a.upstreamUser).slice(0, 100) } : {}) }
  }

  let events
  if (raw.events !== undefined) {
    if (!raw.events || typeof raw.events.audience !== 'string' || !raw.events.audience) throw new TypeError('events needs an "audience"')
    for (const k of Object.keys(raw.events)) if (!['audience', 'maxAgeSec'].includes(k)) throw new TypeError(`unknown field "events.${k}"`)
    const maxAgeSec = raw.events.maxAgeSec ?? 300
    if (!Number.isInteger(maxAgeSec) || maxAgeSec < 10 || maxAgeSec > 3600) throw new TypeError('events.maxAgeSec must be 10-3600')
    events = { audience: raw.events.audience, maxAgeSec }
  } else {
    warnings.push('no "events" block: the status-event receiver is off, so only token lifetime and introspection stop a suspended agent')
  }

  const limits = { ...DEFAULT_LIMITS }
  for (const [k, v] of Object.entries(raw.limits ?? {})) {
    if (!LIMIT_BOUNDS[k]) throw new TypeError(`unknown limit "${k}"`)
    if (!Number.isFinite(v) || v < LIMIT_BOUNDS[k][0] || v > LIMIT_BOUNDS[k][1]) throw new TypeError(`limits.${k} must be between ${LIMIT_BOUNDS[k][0]} and ${LIMIT_BOUNDS[k][1]}`)
    limits[k] = v
  }

  const config = {
    ...(raw.displayName ? { displayName: String(raw.displayName).slice(0, 100) } : {}),
    ...(raw.disabled ? { disabled: true } : {}),
    issuers: raw.issuers, grants: raw.grants ?? [], ...(raw.clockSkewSec !== undefined ? { clockSkewSec: raw.clockSkewSec } : {}),
    ...(events ? { events } : {}),
    upstream: { baseUrl: base.href.replace(/\/$/, ''), ...(up.tokenUrl ? { tokenUrl: up.tokenUrl } : {}), ...(up.tokenAuth ? { tokenAuth: up.tokenAuth } : {}), ...(forwardHeaders.length ? { forwardHeaders } : {}) },
    catalog, agents, limits,
  }
  return { config, warnings }
}

/** The config as an API may show it: introspection secrets replaced */
export function redactTenant(cfg) {
  const copy = structuredClone(cfg)
  for (const i of copy.issuers ?? []) {
    if (i.introspection) for (const k of ['clientSecret', 'bearer']) if (i.introspection[k] !== undefined) i.introspection[k] = REDACTED
  }
  return copy
}

/** A config sent back with "[redacted]" in a secret field keeps the stored secret; one with no stored secret to keep is refused */
export function restoreSecrets(incoming, existing) {
  const copy = structuredClone(incoming)
  for (const i of copy.issuers ?? []) {
    if (!i.introspection) continue
    const old = existing?.issuers?.find(o => o.issuer === i.issuer)?.introspection
    for (const k of ['clientSecret', 'bearer']) {
      if (i.introspection[k] === REDACTED) {
        if (old?.[k] === undefined) throw new TypeError(`issuer ${i.issuer}: "${REDACTED}" is not a secret; send the real value`)
        i.introspection[k] = old[k]
      }
    }
  }
  return copy
}

/** One JSON file per tenant, mode 600, replaced atomically. Re-read when the file changes on disk (the CLI may edit it). */
export class TenantStore {
  constructor(dir) {
    this.dir = join(dir, 'tenants')
    mkdirSync(this.dir, { recursive: true, mode: 0o700 })
    /** @type {Map<string, { mtimeMs: number, config: object }>} */
    this.cache = new Map()
  }

  #file(name) { assertTenantName(name); return join(this.dir, `${name}.json`) }

  list() {
    return readdirSync(this.dir).filter(f => f.endsWith('.json')).map(f => f.slice(0, -5)).filter(n => TENANT_NAME.test(n)).sort()
  }

  get(name) {
    if (typeof name !== 'string' || !TENANT_NAME.test(name)) return null
    const file = this.#file(name)
    if (!existsSync(file)) { this.cache.delete(name); return null }
    const { mtimeMs } = statSync(file)
    const hit = this.cache.get(name)
    if (hit && hit.mtimeMs === mtimeMs) return hit.config
    const config = JSON.parse(readFileSync(file, 'utf8'))
    this.cache.set(name, { mtimeMs, config })
    return config
  }

  put(name, config) {
    const file = this.#file(name)
    atomicWriteFile(file, `${JSON.stringify(config, null, 2)}\n`)
    this.cache.set(name, { mtimeMs: statSync(file).mtimeMs, config })
  }

  delete(name) {
    const file = this.#file(name)
    if (existsSync(file)) unlinkSync(file)
    this.cache.delete(name)
  }
}
