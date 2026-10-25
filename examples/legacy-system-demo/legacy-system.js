/**
 * A PRETEND OLD SYSTEM (a CRM, an ERP, a till: it does not matter). It is built to look like a system that already has
 * the feature this demo needs, which is the "kind A" of docs/federation.md: it can be told to trust an outside OpenID
 * Connect / OAuth 2.0 identity provider on its API, it checks a signed token against that provider's published keys, and
 * it maps one claim in the token to one of ITS OWN users. Everything the agent may do comes from that user's permissions,
 * held here. There is no AID code in this file: the only thing that makes it work with an AID issuer is configuration.
 */
import { createServer } from 'node:http'
import { AidError } from '../../verifier/src/errors.js'
import { assertAlgorithm, decodeJwt, verifySignature } from '../../verifier/src/jwt.js'
import { JwksCache } from '../../verifier/src/jwks.js'

/**
 * @param {object} cfg
 * @param {{ issuer: string, jwksUri: string, audience: string, userClaim: string, introspection?: { endpoint: string, clientId: string, clientSecret: string } }} cfg.idp the "external identity provider" setting
 * @param {Array<{ id: string, name: string, kind: 'human'|'agent', externalId?: string, permissions: string[] }>} cfg.users this system's own users and their permissions
 */
export async function startLegacySystem({ idp, users }) {
  const keys = new JwksCache({ allowInsecureHttp: true })
  const contacts = [{ id: 1, name: 'Existing customer' }]
  const orders = [{ id: 100, total: 250 }, { id: 101, total: 90 }]
  /** this system's own audit log: who did what, as the system itself sees it */
  const audit = []

  async function authenticate(req) {
    const m = /^Bearer (.+)$/.exec(req.headers.authorization || '')
    if (!m) throw Object.assign(new Error('no token'), { status: 401 })
    const token = m[1]
    try {
      const d = decodeJwt(token)
      assertAlgorithm(d.header)
      if (d.payload.iss !== idp.issuer) throw new AidError('untrusted_issuer', 'issuer')
      if (!verifySignature(d, await keys.keyFor(idp.jwksUri, d.header.kid))) throw new AidError('bad_signature', 'signature')
      const now = Math.floor(Date.now() / 1000)
      if (typeof d.payload.exp !== 'number' || d.payload.exp <= now) throw new AidError('token_expired', 'expired')
      const aud = Array.isArray(d.payload.aud) ? d.payload.aud : [d.payload.aud]
      if (!aud.includes(idp.audience)) throw new AidError('bad_audience', 'audience')
      const who = d.payload[idp.userClaim]
      const user = users.find(u => u.externalId && u.externalId === who)
      if (!user) throw Object.assign(new Error('no local user'), { status: 403, code: 'no_local_user' })
      if (idp.introspection) {
        const r = await fetch(idp.introspection.endpoint, {
          method: 'POST',
          headers: { Authorization: `Basic ${Buffer.from(`${idp.introspection.clientId}:${idp.introspection.clientSecret}`).toString('base64')}`, 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ token }),
        })
        const a = await r.json()
        if (!a.active) throw Object.assign(new Error(`inactive: ${a.reason ?? ''}`), { status: 401 })
      }
      return user
    } catch (e) {
      if (e.status) throw e
      throw Object.assign(new Error(e.code ?? 'invalid token'), { status: 401, code: e.code })
    }
  }

  const server = createServer(async (req, res) => {
    const send = (code, body) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)) }
    let user
    try { user = await authenticate(req) } catch (e) {
      audit.push({ who: '(unauthenticated)', action: `${req.method} ${req.url}`, ok: false, why: e.code ?? e.message })
      return send(e.status ?? 401, { error: e.status === 403 ? 'forbidden' : 'unauthorized' })
    }
    const url = new URL(req.url, 'http://x')
    const need = (perm, run) => {
      if (!user.permissions.includes(perm)) {
        audit.push({ who: user.name, kind: user.kind, action: `${req.method} ${url.pathname}`, ok: false, why: `lacks ${perm}` })
        return send(403, { error: 'forbidden', message: `${user.name} may not ${perm}` })
      }
      const out = run()
      audit.push({ who: user.name, kind: user.kind, action: `${req.method} ${url.pathname}`, ok: true })
      return send(out.status ?? 200, out.body)
    }
    if (req.method === 'GET' && url.pathname === '/whoami') return send(200, { user: user.name, kind: user.kind, permissions: user.permissions })
    if (req.method === 'GET' && url.pathname === '/contacts') return need('contacts:read', () => ({ body: contacts }))
    if (req.method === 'POST' && url.pathname === '/contacts') {
      let body = ''
      for await (const c of req) body += c
      return need('contacts:create', () => { const c = { id: contacts.length + 1, name: JSON.parse(body || '{}').name ?? 'unnamed', createdBy: user.name }; contacts.push(c); return { status: 201, body: c } })
    }
    const del = /^\/orders\/(\d+)$/.exec(url.pathname)
    if (req.method === 'DELETE' && del) return need('orders:delete', () => { const i = orders.findIndex(o => o.id === Number(del[1])); if (i >= 0) orders.splice(i, 1); return { status: 204, body: {} } })
    send(404, { error: 'not_found' })
  })
  await new Promise(r => server.listen(0, '127.0.0.1', r))
  return { url: `http://127.0.0.1:${server.address().port}`, audit, orders, contacts, stop: () => new Promise(r => server.close(r)) }
}
