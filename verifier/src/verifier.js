import { AidError } from './errors.js'
import { assertAlgorithm, decodeJwt, verifySignature } from './jwt.js'
import { JwksCache } from './jwks.js'
import { effectivePermissions, findGrant, mapScopes, normalizeConfig, scopesOf } from './policy.js'
import { introspect as askIssuer } from './introspect.js'
import { RevocationList } from './revocation.js'

/**
 * @typedef {object} Principal
 * @property {string} issuer
 * @property {'own'|'external'} kind
 * @property {string} agentId
 * @property {string|undefined} address
 * @property {string|undefined} name
 * @property {string} jti
 * @property {string[]} issuerScopes what the token carries
 * @property {string[]} permissions what the agent may do HERE (mapped, then capped by its grant)
 * @property {string|undefined} role the issuer's role for the agent, when it was asked
 * @property {object|null} grant the Acme grant that let it in, if the issuer is external
 * @property {number} expiresAt epoch seconds
 */

/**
 * The relying party's verifier. `verify(token, { permissions })` answers one question: may this bearer of an AID token
 * work here, and as whom? The order is the order of trust, cheapest and safest first:
 *   1. read the token (nothing in it is trusted);  2. the issuer must be one Acme configured;  3. the signature, from that
 *   issuer's own keys;  4. time, audience and kind;  5. Acme's authorization (own tenant, or a grant);  6. what the issuer
 *   has told Acme since;  7. introspection, as often as the policy says;  8. permissions, mapped and capped.
 * Every refusal is an AidError with a code, and `onDecision` hears every outcome (never the token).
 */
export function createVerifier(rawConfig, { fetch: fetchImpl = globalThis.fetch, now = () => Date.now(), onDecision, jwks, revocations, allowInsecureHttp = false } = {}) {
  const config = normalizeConfig(rawConfig)
  const keys = jwks ?? new JwksCache({ fetch: fetchImpl, now, allowInsecureHttp })
  const revoked = revocations ?? new RevocationList({ now })

  async function check(token, requiredPermissions) {
    const decoded = decodeJwt(token)
    assertAlgorithm(decoded.header)
    const { payload } = decoded

    // The issuer, before any network call: an unknown issuer costs Acme nothing
    const issuer = typeof payload.iss === 'string' ? config.issuers.get(payload.iss) : undefined
    if (!issuer) throw new AidError('untrusted_issuer', 'The issuer is not one this service trusts')

    const jwk = await keys.keyFor(issuer.jwksUri, decoded.header.kid)
    let good = false
    try { good = verifySignature(decoded, jwk) } catch (e) { if (e instanceof AidError) throw e }
    if (!good) throw new AidError('bad_signature', 'The signature does not match the issuer\'s key')

    const nowSec = Math.floor(now() / 1000)
    const skew = config.clockSkewSec
    if (typeof payload.exp !== 'number') throw new AidError('malformed_token', 'The token has no expiry')
    if (payload.exp + skew <= nowSec) throw new AidError('token_expired', 'The token has expired')
    if (typeof payload.nbf === 'number' && payload.nbf - skew > nowSec) throw new AidError('token_not_yet_valid', 'The token is not valid yet')
    if (typeof payload.iat === 'number') {
      if (payload.iat - skew > nowSec) throw new AidError('token_not_yet_valid', 'The token was issued in the future')
      if (issuer.maxTokenAgeSec && nowSec - payload.iat > issuer.maxTokenAgeSec) throw new AidError('token_expired', 'The token is older than this service accepts')
    }

    const aud = Array.isArray(payload.aud) ? payload.aud : typeof payload.aud === 'string' ? [payload.aud] : []
    if (!aud.some(a => issuer.audience.includes(a))) throw new AidError('bad_audience', 'The token is not meant for this service')

    const agentId = typeof payload.agent_id === 'string' ? payload.agent_id : typeof payload.sub === 'string' && payload.sub.startsWith('agent:') ? payload.sub.slice(6) : undefined
    if (payload.token_type !== 'agent' || !agentId) throw new AidError('not_an_agent_token', 'The token does not name an agent')
    const address = typeof payload.agent_address === 'string' ? payload.agent_address : undefined

    // Acme's own authorization: an own tenant's agents, or a grant
    let grant = null
    const alreadyIn = issuer.kind === 'own' && issuer.allowAllActiveAgents
    if (!alreadyIn) {
      const found = findGrant(config.grants, issuer.issuer, agentId, address, now())
      if (!found.grant) throw new AidError('agent_not_authorized', 'No one at this service has authorized this agent')
      if (found.expired) throw new AidError('agent_not_authorized', 'The authorization for this agent has expired')
      grant = found.grant
    } else {
      // An own tenant may still narrow one agent with a grant (a ceiling), and a grant never widens
      const found = findGrant(config.grants, issuer.issuer, agentId, address, now())
      if (found.grant && !found.expired) grant = found.grant
    }

    if (revoked.isRevoked(issuer.issuer, agentId, payload.jti)) throw new AidError('agent_revoked', 'The issuer has revoked this agent or token')

    const issuerScopes = scopesOf(payload)
    const mapped = mapScopes(issuerScopes, issuer.scopeMap)
    const permissions = effectivePermissions(mapped, grant)

    let role
    const needAsk = issuer.introspect === 'always'
      || (issuer.introspect === 'for-permissions' && [...requiredPermissions, ...permissions].some(p => issuer.sensitivePermissions.includes(p)))
    if (needAsk) {
      const answer = await askIssuer(issuer.introspection, token, { fetch: fetchImpl })
      if (!answer.active) throw new AidError('agent_inactive', `The issuer says the agent is not active${answer.reason ? ` (${answer.reason})` : ''}`)
      if (answer.agent_status && answer.agent_status !== 'active') throw new AidError('agent_inactive', 'The issuer says the agent is not active')
      if (answer.sub && answer.sub !== payload.sub) throw new AidError('introspection_failed', 'The issuer\'s answer is about a different subject')
      role = typeof answer.agent_role === 'string' ? answer.agent_role : undefined
    }

    const missing = requiredPermissions.filter(p => !permissions.includes(p))
    if (missing.length > 0) throw new AidError('insufficient_permissions', `The agent may not do: ${missing.join(', ')}`)

    /** @type {Principal} */
    const principal = {
      issuer: issuer.issuer, kind: issuer.kind, agentId, address, name: typeof payload.agent_name === 'string' ? payload.agent_name : undefined,
      jti: typeof payload.jti === 'string' ? payload.jti : '', issuerScopes, permissions, role,
      grant: grant ? { sponsor: grant.sponsor, expiresAt: grant.expiresAt, note: grant.note } : null, expiresAt: payload.exp,
    }
    return principal
  }

  return {
    /** The notes about weak configuration (a generic audience, no introspection) to show the operator at start-up */
    warnings: config.warnings,
    revocations: revoked,
    /**
     * @param {string} token
     * @param {{ permissions?: string[] }} [opts] what this request needs; the agent must hold all of them here
     * @returns {Promise<{ ok: true, principal: Principal } | { ok: false, code: string, message: string }>}
     */
    async verify(token, { permissions = [] } = {}) {
      try {
        const principal = await check(token, permissions)
        onDecision?.({ ok: true, issuer: principal.issuer, agentId: principal.agentId, jti: principal.jti, permissions: principal.permissions })
        return { ok: true, principal }
      } catch (e) {
        const err = e instanceof AidError ? e : new AidError('internal_error', 'The token could not be checked')
        onDecision?.({ ok: false, code: err.code, message: err.message })
        return { ok: false, code: err.code, message: err.message }
      }
    },
  }
}
