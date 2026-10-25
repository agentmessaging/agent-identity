/** A refusal, with a code that is safe to log and a message for the operator. Never carries the token. */
export class AidError extends Error {
  /** @param {string} code @param {string} message */
  constructor(code, message, extra = {}) {
    super(message)
    this.name = 'AidError'
    this.code = code
    /** For a refusal after the agent was identified (insufficient_permissions): who it is, so the caller can audit "X was refused Y" */
    this.principal = extra.principal
  }
}

/** Codes that mean "the token is not good" (401) as against "the agent is known but may not do this" (403) */
export const AUTHENTICATION_CODES = new Set([
  'malformed_token', 'unsupported_alg', 'untrusted_issuer', 'key_not_found', 'bad_signature', 'token_expired',
  'token_not_yet_valid', 'bad_audience', 'not_an_agent_token', 'jwks_unavailable', 'agent_revoked', 'agent_inactive', 'introspection_failed',
])
