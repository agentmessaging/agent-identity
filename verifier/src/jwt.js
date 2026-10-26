import { createPublicKey, verify as cryptoVerify } from 'node:crypto'
import { AidError } from './errors.js'

const MAX_TOKEN_BYTES = 8192
const MIN_RSA_BITS = 2048

/** Split and decode a compact JWT. Nothing in it is trusted yet: that comes only after the signature. */
export function decodeJwt(token) {
  if (typeof token !== 'string' || token.length === 0 || token.length > MAX_TOKEN_BYTES) {
    throw new AidError('malformed_token', 'The token is missing or too large')
  }
  const parts = token.split('.')
  if (parts.length !== 3 || parts.some(p => p.length === 0)) throw new AidError('malformed_token', 'A token has three parts')
  try {
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'))
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'))
    if (!header || typeof header !== 'object' || !payload || typeof payload !== 'object' || Array.isArray(payload)) throw new Error('not objects')
    return { header, payload, signingInput: `${parts[0]}.${parts[1]}`, signature: Buffer.from(parts[2], 'base64url') }
  } catch {
    throw new AidError('malformed_token', 'The token is not valid JSON')
  }
}

/**
 * Only RS256 is accepted, exactly: never `none`, never an HMAC (which would let an attacker sign with the public key),
 * never an algorithm the issuer did not publish. Headers that tell a verifier where to fetch a key (jku, x5u, jwk) are
 * ignored: keys come only from the trusted issuer's own configured JWKS.
 */
export function assertAlgorithm(header) {
  if (header.alg !== 'RS256') throw new AidError('unsupported_alg', 'Only RS256 is accepted')
}

/** A public key from an RSA JWK, refusing a modulus under 2048 bits */
export function keyFromJwk(jwk) {
  if (!jwk || jwk.kty !== 'RSA' || typeof jwk.n !== 'string' || typeof jwk.e !== 'string') throw new AidError('key_not_found', 'The key is not an RSA JWK')
  if (jwk.n && Buffer.from(jwk.n, 'base64url').length * 8 < MIN_RSA_BITS) throw new AidError('key_not_found', 'The key is too small')
  try {
    return createPublicKey({ key: jwk, format: 'jwk' })
  } catch {
    throw new AidError('key_not_found', 'The key could not be read')
  }
}

export function verifySignature(decoded, jwk) {
  const key = keyFromJwk(jwk)
  return cryptoVerify('RSA-SHA256', Buffer.from(decoded.signingInput), key, decoded.signature)
}
