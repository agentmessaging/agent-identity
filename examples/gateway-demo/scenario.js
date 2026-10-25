import { randomBytes } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createAgent } from '../legacy-system-demo/agent.js'
import { startIssuer } from '../legacy-system-demo/issuer.js'
import { createGateway } from '../../gateway/src/gateway.js'
import { validateTenantConfig } from '../../gateway/src/tenants.js'
import { EncryptedFileVault } from '../../gateway/src/vault.js'
import { startOldSystem } from './old-system.js'

const SERVICE = 'https://gateway.acme.example/acme'          // what the gateway is called in a token's `aud`
const ADMIN_TOKEN = randomBytes(24).toString('base64url')
const SCOPES = ['contacts:read', 'contacts:create', 'orders:delete', 'reports:read']

const b64 = x => Buffer.from(JSON.stringify(x)).toString('base64url')

/**
 * Acme runs an old system that only knows API keys. Acme made a user "lola" in it (she may read and create contacts and
 * read reports), put her key in the gateway's vault, and uploaded a catalog that does NOT include reports. Lola holds
 * an AID token and never sees the key. Returns one entry per thing checked.
 */
export async function runScenario({ log = () => {} } = {}) {
  const results = []
  const check = (name, pass, detail = '') => { results.push({ name, pass: !!pass, detail }); log(pass ? '  ok  ' : '  FAIL', name, detail ? `(${detail})` : '') }
  const say = text => log(`\n${text}`)

  const dataDir = mkdtempSync(join(tmpdir(), 'aid-gateway-demo-'))
  const LOLA_KEY = `lola-${randomBytes(12).toString('hex')}`
  const REX_KEY = `rex-${randomBytes(12).toString('hex')}`
  const oldSystem = await startOldSystem({ users: [
    { name: 'ana', kind: 'human', apiKey: `ana-${randomBytes(12).toString('hex')}`, permissions: ['contacts:read', 'contacts:create', 'orders:delete', 'reports:read'] },
    // The users Acme created for the agents. Their permissions are THIS system's, and they are the limit.
    { name: 'lola', kind: 'agent', apiKey: LOLA_KEY, permissions: ['contacts:read', 'contacts:create', 'reports:read'] },
    { name: 'rex', kind: 'agent', apiKey: REX_KEY, permissions: ['contacts:read', 'orders:delete'] },
  ] })
  const issuer = await startIssuer({ tokenLifetimeSec: 300 })
  const lola = createAgent({ name: 'lola', address: 'lola@acme.example' })
  const rex = createAgent({ name: 'rex', address: 'rex@acme.example' })
  const lolaRec = issuer.register({ name: lola.name, address: lola.address, publicKeyPem: lola.publicKeyPem, scopes: SCOPES })
  issuer.register({ name: rex.name, address: rex.address, publicKeyPem: rex.publicKeyPem, scopes: SCOPES })

  const vault = new EncryptedFileVault(join(dataDir, 'vault.json'), randomBytes(32))
  await vault.set('acme/lola@acme.example', { type: 'header', name: 'X-API-Key', value: LOLA_KEY })
  await vault.set('acme/rex@acme.example', { type: 'header', name: 'X-API-Key', value: REX_KEY })

  const gateway = createGateway({ dataDir, vault, adminToken: ADMIN_TOKEN, allowInsecureHttp: true, allowInsecureUpstream: true, allowPrivateUpstream: true })
  const { config } = validateTenantConfig({
    displayName: 'Acme',
    issuers: [{
      issuer: issuer.issuer, kind: 'own', jwksUri: issuer.jwksUri, audience: [SERVICE], allowAllActiveAgents: true,
      // Freshness by status events only (no introspection), so the demo shows the push path
      introspect: 'never',
      scopeMap: { 'contacts:read': ['contacts.read'], 'contacts:create': ['contacts.create'], 'orders:delete': ['orders.delete'], 'reports:read': ['reports.read'] },
    }],
    events: { audience: `${SERVICE}/_events`, maxAgeSec: 300 },
    upstream: { baseUrl: oldSystem.url },
    // The catalog Acme uploaded. Note what is NOT here: reports.
    catalog: [
      { permission: 'contacts.read', method: 'GET', pathTemplate: '/contacts' },
      { permission: 'contacts.create', method: 'POST', pathTemplate: '/contacts' },
      { permission: 'orders.delete', method: 'DELETE', pathTemplate: '/orders/{id}' },
    ],
    agents: { 'lola@acme.example': { upstreamUser: 'lola' }, 'rex@acme.example': { upstreamUser: 'rex' } },
  }, { allowInsecureUpstream: true, allowInsecureHttp: true, allowPrivateUpstream: true })
  gateway.store.put('acme', config)
  const addr = await gateway.listen(0)
  const gw = `http://127.0.0.1:${addr.port}/acme`
  const admin = (path, method = 'POST') => fetch(`http://127.0.0.1:${addr.port}/_admin/${path}`, { method, headers: { authorization: `Bearer ${ADMIN_TOKEN}` } })
  /** everything Lola ever received, to prove the key is not in it */
  const received = []
  const call = async (agent, token, path, init = {}) => {
    const res = await fetch(`${gw}${path}`, { ...init, headers: { authorization: `Bearer ${token}`, ...(init.headers ?? {}) } })
    const text = await res.text()
    received.push(`${[...res.headers].join('\n')}\n${text}`)
    let body = null
    try { body = JSON.parse(text) } catch { /* no body */ }
    return { status: res.status, body, text, headers: res.headers }
  }

  try {
    say('1. The old system only knows API keys. It cannot read an AID token, and nobody can teach it.')
    const direct = await fetch(`${oldSystem.url}/contacts`, { headers: { authorization: `Bearer ${await lola.requestToken(issuer.issuer, { resource: SERVICE })}` } })
    check('the old system refuses a token (401): it is kind B, it needs the gateway', direct.status === 401)

    say('2. Lola proves she is Lola to the issuer, gets a token meant for the gateway, and works through it')
    const token = await lola.requestToken(issuer.issuer, { resource: SERVICE })
    const made = await call(lola, token, '/contacts', { method: 'POST', body: JSON.stringify({ name: 'New lead' }) })
    check('Lola creates a contact (201)', made.status === 201 && made.body.createdBy === 'lola', `status ${made.status}`)
    const list = await call(lola, token, '/contacts')
    check('and reads the list (200)', list.status === 200 && list.body.some(c => c.name === 'New lead'))
    check('the old system\'s own log says lola did it', oldSystem.audit.some(a => a.who === 'lola' && a.kind === 'agent' && a.action === 'POST /contacts' && a.ok))
    const rec = gateway.audit.query({ agent: 'lola@acme.example', decision: 'allow' })[0]
    check('the gateway\'s audit record names the agent, the permission and the template, not the raw path', rec.permission === 'contacts.read' && rec.pathTemplate === '/contacts' && rec.agentId === lolaRec.id)

    say('3. Something Lola\'s own user could do in the old system, but that Acme\'s catalog does not allow')
    const before = oldSystem.requests
    const report = await call(lola, token, '/reports/revenue')
    check('refused by the gateway (403): not in the catalog', report.status === 403 && report.body.code === 'not_in_catalog', `status ${report.status}`)
    check('the old system never saw the request', oldSystem.requests === before)
    check('and the old system would have allowed it: the gateway only narrows', oldSystem.users.find(u => u.name === 'lola').permissions.includes('reports:read'))

    say('4. Something in the catalog, and in her token, but beyond what the old system lets her user do')
    const del = await call(lola, token, '/orders/100', { method: 'DELETE' })
    check('refused by the OLD SYSTEM (403): its permissions are the ceiling', del.status === 403 && /lola may not orders:delete/.test(del.text), `status ${del.status}`)
    check('the order is still there', oldSystem.orders.some(o => o.id === 100))
    check('the gateway let it through and recorded the old system\'s answer', gateway.audit.query({ agent: 'lola@acme.example' })[0].upstreamStatus === 403)

    say('5. Lola can never read the key')
    await call(lola, token, '/contacts')
    await call(lola, token, '/nothing-here')
    const seen = oldSystem.audit.length
    await call(lola, token, '/contacts', { headers: { 'x-api-key': 'try-to-set-my-own', cookie: 'sid=mine' } })
    check('when she sends a key of her own, the old system still sees only her real one', oldSystem.audit.length === seen + 1 && oldSystem.audit.at(-1).who === 'lola' && oldSystem.audit.at(-1).ok)
    check('her key is in nothing the gateway ever sent her: no header, no body, no error', received.every(r => !r.includes(LOLA_KEY)), `${received.length} responses checked`)
    check('the gateway\'s audit log has no key and no token either', !JSON.stringify(gateway.audit.query({ limit: 1000 })).includes(LOLA_KEY) && !JSON.stringify(gateway.audit.query({ limit: 1000 })).includes(token))

    say('6. A token meant for another service')
    const other = await lola.requestToken(issuer.issuer, { resource: 'https://other.example' })
    const wrong = await call(lola, other, '/contacts')
    check('refused (401)', wrong.status === 401)
    check('for the right reason: the audience', gateway.audit.query({ decision: 'deny' })[0].reason === 'bad_audience')

    say('7. The issuer suspends Lola. The gateway is told by a signed status event and checks nothing else')
    issuer.suspend(lola.address)
    const still = await call(lola, token, '/contacts')
    check('before the event arrives, her token still works (the limit of signature-only checks)', still.status === 200)
    const now = Math.floor(Date.now() / 1000)
    const event = issuer.signRaw({ iss: issuer.issuer, aud: `${SERVICE}/_events`, iat: now, jti: `evt-${randomBytes(6).toString('hex')}`, events: { 'urn:aid:event:agent-suspended': { agent_id: lolaRec.id } } })
    const posted = await fetch(`${gw}/_events`, { method: 'POST', headers: { 'content-type': 'application/secevent+jwt' }, body: event })
    check('the gateway accepts the signed event (202)', posted.status === 202)
    const stopped = await call(lola, token, '/contacts')
    check('Lola is refused at once (401), with the token she already holds', stopped.status === 401)
    const forged = `${b64({ alg: 'RS256', kid: 'demo-1' })}.${b64({ iss: issuer.issuer, aud: `${SERVICE}/_events`, iat: now, jti: 'x', events: { 'urn:aid:event:agent-reactivated': { agent_id: lolaRec.id } } })}.${Buffer.from('not a signature').toString('base64url')}`
    check('a forged "reactivated" event is refused (400)', (await fetch(`${gw}/_events`, { method: 'POST', body: forged })).status === 400)
    check('and she stays stopped', (await call(lola, token, '/contacts')).status === 401)

    say('8. Acme\'s own kill switches, no issuer needed')
    const rexToken = await rex.requestToken(issuer.issuer, { resource: SERVICE })
    check('Rex works (200)', (await call(rex, rexToken, '/contacts')).status === 200)
    await admin('tenants/acme/agents/rex%40acme.example/disable')
    const off = await call(rex, rexToken, '/contacts')
    check('after Acme disables Rex he is refused at once (403)', off.status === 403 && off.body.code === 'agent_disabled')
    await admin('tenants/acme/agents/rex%40acme.example/enable')
    check('and works again when Acme enables him', (await call(rex, rexToken, '/contacts')).status === 200)
    await admin('tenants/acme/disable')
    const tenantOff = await call(rex, rexToken, '/contacts')
    check('disabling the whole tenant stops everyone at once (403)', tenantOff.status === 403)
    await admin('tenants/acme/enable')
    check('Rex, whose user may delete orders, deletes one: the permission is his, the attribution too', (await call(rex, rexToken, '/orders/101', { method: 'DELETE' })).status === 204 && oldSystem.audit.some(a => a.who === 'rex' && a.action === 'DELETE /orders/101' && a.ok))
  } finally {
    await gateway.close()
    await issuer.stop()
    await oldSystem.stop()
    rmSync(dataDir, { recursive: true, force: true })
  }
  return results
}
