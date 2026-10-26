/**
 * What the relying party (Acme) decides for itself. The issuer proves WHO an agent is and caps what it may claim;
 * Acme alone decides whether to let that agent in and what it may do here. Everything below is Acme's configuration.
 *
 *   issuers  who Acme trusts to name agents, each with its keys, its audience and how often to ask it whether the
 *            agent is still active. kind "own" is Acme's own tenant at the provider; "external" is anyone else.
 *   grants   the agents Acme has authorized to work in it. An "own" issuer may let every active agent of the tenant
 *            in (allowAllActiveAgents); an "external" issuer lets in only the agents named by a grant, each with a
 *            ceiling of local permissions, a human sponsor at Acme and, optionally, an expiry.
 *
 * Deny by default: no issuer, no grant, no permission means no.
 */

const GENERIC_AUDIENCES = new Set(['client_app', 'api_service'])
const INTROSPECT_MODES = new Set(['always', 'never', 'for-permissions'])

/** @typedef {{ endpoint: string, clientId?: string, clientSecret?: string, bearer?: string }} IntrospectionConfig */

/**
 * @typedef {object} IssuerConfig
 * @property {string} issuer exact `iss` value
 * @property {string} jwksUri where its keys are published
 * @property {'own'|'external'} kind
 * @property {string[]} audience the `aud` values Acme accepts (at least one must be in the token)
 * @property {boolean} [allowAllActiveAgents] own tenants only: every active agent of the tenant may work here
 * @property {IntrospectionConfig} [introspection]
 * @property {'always'|'never'|'for-permissions'} [introspect] default 'always' when introspection is configured
 * @property {string[]} [sensitivePermissions] with 'for-permissions': introspect only when one of these is asked for or held
 * @property {Record<string, string[]>} [scopeMap] issuer scope -> Acme permissions (a scope with no entry grants nothing)
 * @property {number} [maxTokenAgeSec] refuse a token issued longer ago than this
 */

/**
 * @typedef {object} Grant
 * @property {string} issuer
 * @property {string} [agentId] the issuer's stable id for the agent
 * @property {string} [address] or its address (name@tenant.provider)
 * @property {string[]|'*'} [permissions] ceiling of Acme permissions (omitted = only what the scope map yields, no extra cap)
 * @property {string} sponsor the person at Acme who approved it
 * @property {string} [expiresAt] ISO time; the grant stops working then
 * @property {string} [note]
 */

export function normalizeConfig(raw, { strictAudience = false } = {}) {
  const warnings = []
  if (!raw || typeof raw !== 'object') throw new TypeError('config must be an object')
  const issuers = new Map()
  for (const i of raw.issuers ?? []) {
    if (!i.issuer || typeof i.issuer !== 'string') throw new TypeError('every issuer needs an "issuer"')
    if (!i.jwksUri || typeof i.jwksUri !== 'string') throw new TypeError(`issuer ${i.issuer} needs a "jwksUri"`)
    if (i.kind !== 'own' && i.kind !== 'external') throw new TypeError(`issuer ${i.issuer} needs kind "own" or "external"`)
    if (!Array.isArray(i.audience) || i.audience.length === 0) {
      throw new TypeError(`issuer ${i.issuer} needs a non-empty "audience": without one, a token meant for another service would be accepted here`)
    }
    if (i.audience.every(a => GENERIC_AUDIENCES.has(a))) {
      if (strictAudience) throw new TypeError(`issuer ${i.issuer}: audience ${JSON.stringify(i.audience)} is shared by every tenant of the provider and says nothing about this service (strictAudience refuses it)`)
      warnings.push(`issuer ${i.issuer}: audience ${JSON.stringify(i.audience)} is shared by every tenant of the provider and says nothing about Acme; use a value specific to Acme`)
    }
    if (i.allowAllActiveAgents && i.kind !== 'own') throw new TypeError(`issuer ${i.issuer}: allowAllActiveAgents is for an "own" issuer only`)
    const introspect = i.introspect ?? (i.introspection ? 'always' : 'never')
    if (!INTROSPECT_MODES.has(introspect)) throw new TypeError(`issuer ${i.issuer}: introspect must be one of ${[...INTROSPECT_MODES].join(', ')}`)
    if (introspect !== 'never' && !i.introspection?.endpoint) throw new TypeError(`issuer ${i.issuer}: introspect "${introspect}" needs an introspection endpoint`)
    if (introspect === 'never') warnings.push(`issuer ${i.issuer}: no introspection, so a suspended agent keeps working until its token expires (or until a status event arrives)`)
    issuers.set(i.issuer, { ...i, introspect, sensitivePermissions: i.sensitivePermissions ?? [], scopeMap: i.scopeMap ?? null })
  }
  const grants = (raw.grants ?? []).map(g => {
    if (!issuers.has(g.issuer)) throw new TypeError(`a grant names an issuer that is not configured: ${g.issuer}`)
    if (!g.agentId && !g.address) throw new TypeError('a grant needs an agentId or an address')
    if (!g.sponsor) throw new TypeError('a grant needs a sponsor: the person at Acme who approved it')
    if (g.expiresAt && Number.isNaN(Date.parse(g.expiresAt))) throw new TypeError('a grant\'s expiresAt must be a date')
    return { ...g }
  })
  return { issuers, grants, clockSkewSec: raw.clockSkewSec ?? 60, warnings }
}

/** The grant that authorizes this agent, if any (by id, else by address, case-insensitive) */
export function findGrant(grants, issuer, agentId, address, nowMs) {
  const hit = grants.find(g => g.issuer === issuer
    && ((g.agentId && agentId && g.agentId === agentId) || (g.address && address && g.address.toLowerCase() === address.toLowerCase())))
  if (!hit) return { grant: null, expired: false }
  if (hit.expiresAt && Date.parse(hit.expiresAt) <= nowMs) return { grant: hit, expired: true }
  return { grant: hit, expired: false }
}

/** The scopes in a token, from `scope` (a string, RFC 9068) or `scopes` (an array, what the 23blocks server issues today) */
export function scopesOf(payload) {
  if (typeof payload.scope === 'string') return payload.scope.split(' ').filter(Boolean)
  if (Array.isArray(payload.scopes)) return payload.scopes.filter(s => typeof s === 'string')
  return []
}

/** Issuer scopes -> Acme permissions. With no scope map the scopes are the permissions; with one, a scope it does not name grants nothing. */
export function mapScopes(scopes, scopeMap) {
  if (!scopeMap) return [...new Set(scopes)]
  const out = new Set()
  for (const s of scopes) for (const p of scopeMap[s] ?? []) out.add(p)
  return [...out]
}

/** What the agent may do here: the mapped permissions, capped by the grant's ceiling (which can only narrow) */
export function effectivePermissions(mapped, grant) {
  if (!grant || grant.permissions === undefined || grant.permissions === '*') return mapped
  const cap = new Set(grant.permissions)
  return mapped.filter(p => cap.has(p))
}
