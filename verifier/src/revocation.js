/**
 * What the issuer has told Acme since it signed the token: an agent was suspended or deleted, or one token was revoked.
 * A short token lifetime is the fallback when events are lost; this is the fast path. In memory: a process that
 * restarts forgets, which is why introspection (or short tokens) stays the source of truth.
 */
export class RevocationList {
  constructor({ now = () => Date.now() } = {}) {
    this.now = now
    /** @type {Map<string, number|null>} key -> revoked until (ms), null = until restored */
    this.agents = new Map()
    this.tokens = new Map()
  }

  #key(issuer, id) { return `${issuer}\u0000${id}` }

  revokeAgent(issuer, agentId, { untilMs = null } = {}) { this.agents.set(this.#key(issuer, agentId), untilMs) }
  restoreAgent(issuer, agentId) { this.agents.delete(this.#key(issuer, agentId)) }
  revokeToken(issuer, jti, { untilMs = null } = {}) { this.tokens.set(this.#key(issuer, jti), untilMs) }

  #active(map, key) {
    if (!map.has(key)) return false
    const until = map.get(key)
    if (until !== null && until <= this.now()) { map.delete(key); return false }
    return true
  }

  isRevoked(issuer, agentId, jti) {
    return this.#active(this.agents, this.#key(issuer, agentId)) || (!!jti && this.#active(this.tokens, this.#key(issuer, jti)))
  }

  /** Apply an event from an issuer: { issuer, type: 'agent-suspended'|'agent-deleted'|'agent-reactivated'|'token-revoked', agentId?, jti? } */
  apply(event) {
    switch (event?.type) {
      case 'agent-suspended':
      case 'agent-deleted': if (event.agentId) this.revokeAgent(event.issuer, event.agentId); return true
      case 'agent-reactivated': if (event.agentId) this.restoreAgent(event.issuer, event.agentId); return true
      case 'token-revoked': if (event.jti) this.revokeToken(event.issuer, event.jti); return true
      default: return false
    }
  }
}
