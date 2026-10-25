import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto'

/**
 * The agent. It owns an Ed25519 key and never sees any password or API key of the system it works in: it proves it holds
 * the key to the issuer, gets a token meant for one service, and presents that. (Simplified from the real AID client.)
 */
export function createAgent({ name, address }) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' })
  return {
    name,
    address,
    publicKeyPem,
    async requestToken(issuer, { resource, scope } = {}) {
      const ts = Math.floor(Date.now() / 1000)
      const identity = Buffer.from(JSON.stringify({ address, public_key: publicKeyPem })).toString('base64url')
      const proof = cryptoSign(null, Buffer.from(`aid-token-exchange\n${ts}\n${issuer}`), privateKey).toString('base64url')
      const body = new URLSearchParams({ grant_type: 'urn:aid:agent-identity', agent_identity: identity, proof, timestamp: String(ts) })
      if (resource) body.set('resource', resource)
      if (scope) body.set('scope', scope)
      const res = await fetch(`${issuer}/oauth/token`, { method: 'POST', body })
      const json = await res.json()
      if (!res.ok) throw Object.assign(new Error(json.error_description || json.error), { status: res.status, body: json })
      return json.access_token
    },
    async call(base, path, token, init = {}) {
      const res = await fetch(`${base}${path}`, { ...init, headers: { Authorization: `Bearer ${token}`, ...(init.headers ?? {}) } })
      let body = null
      try { body = await res.json() } catch { /* 204 has none */ }
      return { status: res.status, body }
    },
  }
}
