import { createSign, generateKeyPairSync } from 'node:crypto'

const b64 = x => Buffer.from(typeof x === 'string' ? x : JSON.stringify(x)).toString('base64url')

/** A pretend issuer: its own RSA key, its JWKS, and a way to sign tokens as it would */
export function makeIssuer(issuer, { kid = 'k1', bits = 2048 } = {}) {
  let pair = generateKeyPairSync('rsa', { modulusLength: bits })
  const state = { kid, jwks: null }
  const publish = () => { state.jwks = { keys: [{ ...pair.publicKey.export({ format: 'jwk' }), kid: state.kid, use: 'sig', alg: 'RS256' }] } }
  publish()
  return {
    issuer,
    jwksUri: `${issuer}/.well-known/jwks.json`,
    get jwks() { return state.jwks },
    /** Rotate: a new key under a new kid */
    rotate(newKid) { pair = generateKeyPairSync('rsa', { modulusLength: bits }); state.kid = newKid; publish() },
    sign(payload, header = {}) {
      const h = { alg: 'RS256', typ: 'JWT', kid: state.kid, ...header }
      const input = `${b64(h)}.${b64(payload)}`
      const sig = createSign('RSA-SHA256').update(input).sign(pair.privateKey).toString('base64url')
      return `${input}.${sig}`
    },
  }
}

export const nowSec = () => Math.floor(Date.now() / 1000)

/** An agent token as the 23blocks server issues them today (scopes array, generic audience plus the tenant key) */
export function agentPayload(issuer, over = {}) {
  const t = nowSec()
  return {
    iss: issuer, sub: 'agent:ag-1', aud: ['client_app', 'api_service', 'acme-key'], exp: t + 3600, nbf: t, iat: t, jti: `j-${Math.random()}`,
    scopes: ['files:read', 'tickets:write'], token_type: 'agent', agent_id: 'ag-1', agent_address: 'bot@acme.example', agent_name: 'bot', ...over,
  }
}

/** A fetch that serves the given issuers' JWKS and, optionally, an introspection handler; it counts calls */
export function makeFetch(issuers, { introspect } = {}) {
  const calls = { jwks: 0, introspect: 0, fail: false }
  const f = async (url, init = {}) => {
    const u = String(url)
    if (calls.fail) throw new Error('network down')
    const iss = issuers.find(i => i.jwksUri === u)
    if (iss) { calls.jwks++; return new Response(JSON.stringify(iss.jwks), { status: 200 }) }
    if (introspect && u.endsWith('/introspect')) {
      calls.introspect++
      const token = new URLSearchParams(init.body).get('token')
      const out = await introspect(token, init)
      return new Response(JSON.stringify(out.body ?? out), { status: out.status ?? 200 })
    }
    return new Response('not found', { status: 404 })
  }
  f.calls = calls
  return f
}
