import { AUTHENTICATION_CODES } from './errors.js'

/** The bearer token from an Authorization header value, or null */
export function bearerToken(header) {
  if (typeof header !== 'string') return null
  const m = /^Bearer ([A-Za-z0-9._~+/=-]+)$/.exec(header.trim())
  return m ? m[1] : null
}

/**
 * Express/Connect-style middleware. A failed token is a 401 with `WWW-Authenticate: Bearer error="invalid_token"`; a
 * known agent that may not do this is a 403 with `error="insufficient_scope"`. The body says only that, never why:
 * the reason goes to the verifier's onDecision, not to the caller. On success `req.aid` is the principal.
 */
export function aidMiddleware(verifier, { permissions = [] } = {}) {
  return async (req, res, next) => {
    const token = bearerToken(req.headers?.authorization)
    if (!token) {
      res.setHeader?.('WWW-Authenticate', 'Bearer')
      return res.status(401).json({ error: 'invalid_request' })
    }
    const result = await verifier.verify(token, { permissions })
    if (result.ok) {
      req.aid = result.principal
      return next()
    }
    if (AUTHENTICATION_CODES.has(result.code)) {
      res.setHeader?.('WWW-Authenticate', 'Bearer error="invalid_token"')
      return res.status(401).json({ error: 'invalid_token' })
    }
    if (result.code === 'internal_error') return res.status(500).json({ error: 'server_error' })
    res.setHeader?.('WWW-Authenticate', 'Bearer error="insufficient_scope"')
    return res.status(403).json({ error: 'insufficient_scope' })
  }
}
