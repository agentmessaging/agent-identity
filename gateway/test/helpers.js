import { mkdtempSync, rmSync } from 'node:fs'
import { createServer } from 'node:http'
import net from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createAgent } from '../../examples/legacy-system-demo/agent.js'
import { startIssuer } from '../../examples/legacy-system-demo/issuer.js'
import { createGateway } from '../src/gateway.js'
import { MemoryVault } from '../src/vault.js'
import { validateTenantConfig } from '../src/tenants.js'

export const ADMIN_TOKEN = 'admin-token-for-tests-0123456789abcdef-xyz'
export const AUDIENCE = 'https://gw.test/acme'
export const ALL_SCOPES = ['contacts:read', 'contacts:create', 'orders:delete', 'misc:read']
/** The secrets the fake old system hands out. They must never reach an agent. */
export const KEYS = { lola: 'key-lola-9f8e7d6c5b4a', rex: 'key-rex-1a2b3c4d5e6f' }

/** A fake "old system": records every request it gets, serves a few routes, and some misbehaving ones */
export async function startUpstream(extra) {
  const requests = []
  const byKey = Object.fromEntries(Object.entries(KEYS).map(([u, k]) => [k, u]))
  const server = createServer(async (req, res) => {
    const chunks = []
    for await (const c of req) chunks.push(c)
    const rec = { method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString('utf8') }
    requests.push(rec)
    const send = (code, body, headers = {}) => { res.writeHead(code, { 'content-type': 'application/json', ...headers }); res.end(typeof body === 'string' ? body : JSON.stringify(body)) }
    if (extra) { const handled = await extra(req, res, rec, send); if (handled) return }
    const user = byKey[req.headers['x-api-key']] ?? (req.headers.authorization === 'Bearer oauth-token-lola' ? 'lola' : undefined)
    const path = req.url.split('?')[0]
    if (path === '/redirect-other') return send(302, {}, { location: 'http://evil.example/steal', 'set-cookie': 'sid=1', 'www-authenticate': 'Basic realm="x"' })
    if (path === '/redirect-same') return send(302, {}, { location: '/contacts' })
    if (path === '/set-cookie') return send(200, { ok: true }, { 'set-cookie': 'session=abc; Path=/', 'www-authenticate': 'ApiKey realm="x-api-key"', 'x-powered-by': 'old-system' })
    if (path === '/slow') { await new Promise(r => setTimeout(r, 600)); return send(200, { slow: true }) }
    if (path === '/big') return send(200, 'x'.repeat(200_000), { 'content-type': 'text/plain' })
    if (path === '/echo-key') return send(200, { you_sent: req.headers['x-api-key'] })
    if (path === '/echo-key-header') return send(200, { ok: true }, { 'x-debug': req.headers['x-api-key'] })
    if (!user) return send(401, { error: 'bad key' }, { 'www-authenticate': 'ApiKey realm="legacy"', 'set-cookie': 'a=b' })
    if (req.method === 'GET' && path === '/contacts') return send(200, { user, contacts: [{ id: 1 }] })
    if (req.method === 'GET' && /^\/contacts\/\d+$/.test(path)) return send(200, { user, id: path.split('/')[2] })
    if (req.method === 'POST' && path === '/contacts') return send(201, { user, created: JSON.parse(rec.body || '{}') })
    if (req.method === 'DELETE' && path.startsWith('/orders/')) return user === 'lola' ? send(403, { error: 'lola may not delete orders' }) : send(204, '')
    send(404, { error: 'nothing here' })
  })
  await new Promise(r => server.listen(0, '127.0.0.1', r))
  return { url: `http://127.0.0.1:${server.address().port}`, requests, stop: () => new Promise(r => { server.close(r); server.closeAllConnections() }) }
}

/**
 * Everything a proxy test needs: a pretend issuer, an old system, agents lola and rex (both known to the issuer), a gateway
 * with an in-memory vault holding lola's and rex's API keys, and one tenant "acme".
 */
export async function setup({ tenant = {}, introspect = 'always', upstreamExtra, gateway = {}, credentials = true, now } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'aid-gw-'))
  const issuer = await startIssuer({ tokenLifetimeSec: 300 })
  const upstream = await startUpstream(upstreamExtra)
  const lola = createAgent({ name: 'lola', address: 'lola@acme.example' })
  const rex = createAgent({ name: 'rex', address: 'rex@acme.example' })
  const lolaRec = issuer.register({ name: lola.name, address: lola.address, publicKeyPem: lola.publicKeyPem, scopes: ALL_SCOPES })
  const rexRec = issuer.register({ name: rex.name, address: rex.address, publicKeyPem: rex.publicKeyPem, scopes: ALL_SCOPES })
  const vault = new MemoryVault()
  if (credentials) {
    await vault.set('acme/lola@acme.example', { type: 'header', name: 'X-API-Key', value: KEYS.lola })
    await vault.set('acme/rex@acme.example', { type: 'header', name: 'X-API-Key', value: KEYS.rex })
  }
  const gw = createGateway({ dataDir: dir, vault, adminToken: ADMIN_TOKEN, allowInsecureHttp: true, allowInsecureUpstream: true, allowPrivateUpstream: true, now, ...gateway })
  const config = {
    issuers: [{
      issuer: issuer.issuer, kind: 'own', jwksUri: issuer.jwksUri, audience: [AUDIENCE], allowAllActiveAgents: true,
      introspection: { endpoint: issuer.introspectionEndpoint, clientId: issuer.introspectionClient.id, clientSecret: issuer.introspectionClient.secret }, introspect,
      scopeMap: { 'contacts:read': ['contacts.read'], 'contacts:create': ['contacts.create'], 'orders:delete': ['orders.delete'], 'misc:read': ['misc.read'] },
    }],
    events: { audience: `${AUDIENCE}/_events`, maxAgeSec: 300 },
    upstream: { baseUrl: upstream.url },
    catalog: [
      { permission: 'contacts.read', method: 'GET', pathTemplate: '/contacts' },
      { permission: 'contacts.read', method: 'GET', pathTemplate: '/contacts/{id}' },
      { permission: 'contacts.create', method: 'POST', pathTemplate: '/contacts' },
      { permission: 'orders.delete', method: 'DELETE', pathTemplate: '/orders/{id}' },
      { permission: 'misc.read', method: 'GET', pathTemplate: '/redirect-other' },
      { permission: 'misc.read', method: 'GET', pathTemplate: '/redirect-same' },
      { permission: 'misc.read', method: 'GET', pathTemplate: '/set-cookie' },
      { permission: 'misc.read', method: 'GET', pathTemplate: '/slow' },
      { permission: 'misc.read', method: 'GET', pathTemplate: '/big' },
      { permission: 'misc.read', method: 'GET', pathTemplate: '/echo-key' },
      { permission: 'misc.read', method: 'GET', pathTemplate: '/echo-key-header' },
    ],
    agents: { 'lola@acme.example': { upstreamUser: 'lola' }, 'rex@acme.example': { upstreamUser: 'rex' } },
    ...tenant,
  }
  const validated = validateTenantConfig(config, { allowInsecureHttp: true, allowInsecureUpstream: true, allowPrivateUpstream: true }).config
  gw.store.put('acme', validated)
  const addr = await gw.listen(0, '127.0.0.1')
  const base = `http://127.0.0.1:${addr.port}`
  const scopesAll = ALL_SCOPES.join(' ')

  const tokenFor = (agent, { resource = AUDIENCE, scope = scopesAll } = {}) => agent.requestToken(issuer.issuer, { resource, scope })
  /** a request through the gateway; JSON or text body parsed when possible */
  async function call(path, { token, method = 'GET', headers = {}, body } = {}) {
    const res = await fetch(`${base}${path}`, { method, redirect: 'manual', headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers }, body })
    const text = await res.text()
    let json
    try { json = JSON.parse(text) } catch { /* not json */ }
    return { status: res.status, headers: res.headers, text, json }
  }
  return {
    dir, issuer, upstream, lola, rex, lolaRec, rexRec, vault, gw, base, tokenFor, call, config: validated, tenantName: 'acme',
    async stop() { await gw.close(); await upstream.stop(); await issuer.stop(); rmSync(dir, { recursive: true, force: true }) },
  }
}

/** Send a raw request line (and headers) over a socket, so the client cannot "fix" the target first */
export function rawRequest(port, target, { method = 'GET', headers = {}, body = '' } = {}) {
  return new Promise(resolve => {
    const sock = net.connect(port, '127.0.0.1')
    const lines = [`${method} ${target} HTTP/1.1`, 'Host: gw.test', 'Connection: close', ...Object.entries(headers).map(([k, v]) => `${k}: ${v}`)]
    if (body) lines.push(`Content-Length: ${Buffer.byteLength(body)}`)
    sock.write(`${lines.join('\r\n')}\r\n\r\n${body}`)
    let data = ''
    sock.on('data', c => { data += c })
    sock.on('close', () => {
      const status = Number(/^HTTP\/1\.1 (\d+)/.exec(data)?.[1] ?? 0)
      resolve({ status, raw: data })
    })
    sock.on('error', () => resolve({ status: 0, raw: data }))
    setTimeout(() => sock.destroy(), 4000)
  })
}
