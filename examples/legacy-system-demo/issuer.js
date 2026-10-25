/**
 * A PRETEND AID issuer for the demo. It stands in for the 23blocks auth server so the demo runs anywhere with no
 * account. It follows the shape of the real one (per-tenant issuer, JWKS, the `urn:aid:agent-identity` grant with an
 * Ed25519 proof, introspection) and adds the two things the real server does not do yet and the profile requires
 * (docs/federation.md §7): an audience specific to the service the token is for (`resource`), and a `scope` string.
 * Simplified: registration is a function call here, not the real approval flow.
 */
import { createHash, createPrivateKey, createPublicKey, createSign, generateKeyPairSync, randomUUID, verify as cryptoVerify } from 'node:crypto'
import { createServer } from 'node:http'

const b64 = x => Buffer.from(typeof x === 'string' ? x : JSON.stringify(x)).toString('base64url')

async function readBody(req) {
  const chunks = []
  for await (const c of req) chunks.push(c)
  const raw = Buffer.concat(chunks).toString('utf8')
  if ((req.headers['content-type'] || '').includes('json')) return JSON.parse(raw || '{}')
  return Object.fromEntries(new URLSearchParams(raw))
}

export async function startIssuer({ tenant = 'acme', tokenLifetimeSec = 60, introspectionClient = { id: 'legacy', secret: 'legacy-secret' } } = {}) {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const kid = 'demo-1'
  const jwks = { keys: [{ ...publicKey.export({ format: 'jwk' }), kid, use: 'sig', alg: 'RS256' }] }
  /** @type {Map<string, { id: string, address: string, name: string, publicKey: string, scopes: string[], status: string }>} */
  const agents = new Map()
  const sign = payload => {
    const input = `${b64({ alg: 'RS256', typ: 'JWT', kid })}.${b64(payload)}`
    return `${input}.${createSign('RSA-SHA256').update(input).sign(privateKey).toString('base64url')}`
  }

  let issuer = ''
  const server = createServer(async (req, res) => {
    const send = (code, body) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)) }
    const url = new URL(req.url, 'http://x')
    try {
      if (req.method === 'GET' && url.pathname === `/${tenant}/.well-known/jwks.json`) return send(200, jwks)
      if (req.method === 'GET' && url.pathname === `/${tenant}/.well-known/oauth-authorization-server`) {
        return send(200, { issuer, jwks_uri: `${issuer}/.well-known/jwks.json`, token_endpoint: `${issuer}/oauth/token`, introspection_endpoint: `${issuer}/oauth/introspect`, grant_types_supported: ['urn:aid:agent-identity'] })
      }
      if (req.method === 'POST' && url.pathname === `/${tenant}/oauth/token`) {
        const p = await readBody(req)
        if (p.grant_type !== 'urn:aid:agent-identity') return send(400, { error: 'unsupported_grant_type' })
        let doc
        try { doc = JSON.parse(Buffer.from(p.agent_identity, 'base64url').toString('utf8')) } catch { return send(400, { error: 'invalid_request' }) }
        const agent = agents.get(String(doc.address).toLowerCase())
        if (!agent) return send(401, { error: 'invalid_client', error_description: 'unknown agent' })
        if (agent.status !== 'active') return send(403, { error: 'access_denied', error_description: `agent is ${agent.status}` })
        // Proof of possession: the agent signs "aid-token-exchange\n<unix time>\n<issuer>" with its Ed25519 key
        const ts = Number(p.timestamp)
        if (!Number.isFinite(ts) || Math.abs(Date.now() / 1000 - ts) > 300) return send(401, { error: 'invalid_grant', error_description: 'stale proof' })
        const ok = doc.public_key === agent.publicKey
          && cryptoVerify(null, Buffer.from(`aid-token-exchange\n${ts}\n${issuer}`), createPublicKey(agent.publicKey), Buffer.from(p.proof, 'base64url'))
        if (!ok) return send(401, { error: 'invalid_grant', error_description: 'bad proof' })
        const requested = p.scope ? String(p.scope).split(' ').filter(Boolean) : agent.scopes
        const bad = requested.filter(s => !agent.scopes.includes(s))
        if (bad.length) return send(400, { error: 'invalid_scope', error_description: bad.join(', ') })
        const now = Math.floor(Date.now() / 1000)
        const token = sign({
          iss: issuer, sub: `agent:${agent.id}`,
          // What the real server does not do yet (R1): a token meant for one service. Without `resource` it falls back to the generic audience
          aud: p.resource ? [p.resource] : ['client_app', 'api_service'],
          exp: now + tokenLifetimeSec, nbf: now, iat: now, jti: randomUUID(), scope: requested.join(' '), scopes: requested,
          token_type: 'agent', agent_id: agent.id, agent_address: agent.address, agent_name: agent.name,
        })
        return send(200, { access_token: token, token_type: 'Bearer', expires_in: tokenLifetimeSec, scope: requested.join(' ') })
      }
      if (req.method === 'POST' && url.pathname === `/${tenant}/oauth/introspect`) {
        const auth = /^Basic (.+)$/.exec(req.headers.authorization || '')
        const [id, secret] = auth ? Buffer.from(auth[1], 'base64').toString('utf8').split(':') : []
        if (id !== introspectionClient.id || secret !== introspectionClient.secret) return send(401, { error: 'invalid_client' })
        const { token } = await readBody(req)
        let claims
        try { claims = JSON.parse(Buffer.from(String(token).split('.')[1], 'base64url').toString('utf8')) } catch { return send(200, { active: false }) }
        const agent = [...agents.values()].find(a => a.id === claims.agent_id)
        if (!agent) return send(200, { active: false, reason: 'agent_not_found' })
        if (agent.status !== 'active') return send(200, { active: false, reason: `agent_${agent.status}` })
        return send(200, { active: true, sub: claims.sub, scope: claims.scope, exp: claims.exp, agent_id: agent.id, agent_address: agent.address, agent_status: agent.status })
      }
      send(404, { error: 'not_found' })
    } catch {
      send(500, { error: 'server_error' })
    }
  })
  await new Promise(r => server.listen(0, '127.0.0.1', r))
  const port = server.address().port
  issuer = `http://127.0.0.1:${port}/${tenant}`

  return {
    issuer,
    jwksUri: `${issuer}/.well-known/jwks.json`,
    introspectionEndpoint: `${issuer}/oauth/introspect`,
    introspectionClient,
    /** Register an agent (the real server does this through an approval flow) */
    register({ name, address, publicKeyPem, scopes }) {
      const agent = { id: `ag_${createHash('sha256').update(address).digest('hex').slice(0, 8)}`, address: address.toLowerCase(), name, publicKey: publicKeyPem, scopes, status: 'active' }
      agents.set(agent.address, agent)
      return agent
    },
    suspend(address) { agents.get(address.toLowerCase()).status = 'suspended' },
    reactivate(address) { agents.get(address.toLowerCase()).status = 'active' },
    /** A token signed by the issuer's key for any claims: for the demo's "expired token" case */
    signRaw: sign,
    stop: () => new Promise(r => server.close(r)),
  }
}
