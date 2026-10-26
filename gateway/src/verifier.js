// The one place the gateway reaches into the reference verifier. If this package is ever shipped on its own,
// change these paths (or depend on the verifier package) and nothing else.
export { createVerifier, normalizeConfig, JwksCache, RevocationList, AUTHENTICATION_CODES, AidError, bearerToken } from '../../verifier/src/index.js'
export { decodeJwt, assertAlgorithm, verifySignature } from '../../verifier/src/jwt.js'
