// End to end with the REAL pieces: the real AID bash client, the real Rails issuer (test env, own database),
// the gateway, and an old system that only knows API keys. Nothing of the issuer is simulated.
import { execFile, spawnSync } from 'node:child_process'
import { promisify } from 'node:util'
const execFileAsync = promisify(execFile)
import { randomBytes } from 'node:crypto'
import { mkdtempSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
const HERE = dirname(fileURLToPath(import.meta.url))
const AID = resolve(HERE, '../..')                                   // this repository
const RAILS = process.env.AUTH_API_DIR                               // the auth server checkout, on the branch with the federation changes
const E2E = process.env.E2E_DIR                                      // a throwaway directory: the agent's home, fixtures.json
const SCRIPTS = HERE                                                 // fixtures.rb, admin.rb, deliver.rb
if (!RAILS || !E2E) { console.error('Set AUTH_API_DIR and E2E_DIR (see README.md)'); process.exit(2) }
const { createGateway } = await import(`${AID}/gateway/src/gateway.js`)
const { validateTenantConfig } = await import(`${AID}/gateway/src/tenants.js`)
const { EncryptedFileVault } = await import(`${AID}/gateway/src/vault.js`)
const { startOldSystem } = await import(`${AID}/examples/gateway-demo/old-system.js`)

const fx = JSON.parse(readFileSync(`${E2E}/fixtures.json`, 'utf8').trim().split('\n').pop())
const results = []
const check = (name, pass, detail = '') => { results.push({ name, pass: !!pass, detail }); console.log(pass ? '  ok  ' : '  FAIL', name, detail ? `(${detail})` : '') }
const say = t => console.log(`\n${t}`)

// The issuer runs in its own TEST environment on its own database (never the spec database: a spec run empties it)
const railsEnv = { ...process.env, RAILS_ENV: 'test', WEB_CONCURRENCY: '0' }
// Asynchronous on purpose: the gateway lives in THIS process, and the issuer's runner delivers events to it. A blocking
// call here would freeze the gateway and the delivery would time out (it did, in the first version of this script).
const rails = async (args, extra = {}) => {
  try { const r = await execFileAsync('bundle', ['exec', ...args], { cwd: RAILS, env: { ...railsEnv, ...extra }, encoding: 'utf8', maxBuffer: 1 << 24 }); return { status: 0, stdout: r.stdout, stderr: r.stderr } }
  catch (e) { return { status: e.code ?? 1, stdout: e.stdout ?? '', stderr: e.stderr ?? String(e) } }
}
const deliver = async () => (await rails(['rails', 'runner', `${SCRIPTS}/deliver.rb`])).stdout.trim().split('\n').pop()
const operator = async action => (await rails(['rails', 'runner', `${SCRIPTS}/admin.rb`], { E2E_ACTION: action, E2E_ADDRESS: fx.agent_address })).stdout.trim().split('\n').pop()
/** the REAL client: aid-token.sh, with Lola's own key, in a throwaway home */
const clientToken = (...extra) => {
  const r = spawnSync(`${AID}/scripts/aid-token.sh`, ['--auth', fx.issuer, '--no-cache', '-q', ...extra], { env: { ...process.env, HOME: `${E2E}/home`, CLAUDE_AGENT_NAME: 'lola' }, encoding: 'utf8' })
  return { token: r.stdout.trim(), error: r.stderr.trim(), ok: r.status === 0 && r.stdout.trim().split('.').length === 3 }
}
const claims = t => JSON.parse(Buffer.from(t.split('.')[1], 'base64url').toString('utf8'))

const LOLA_KEY = `lola-${randomBytes(12).toString('hex')}`
const dataDir = mkdtempSync(join(tmpdir(), 'aid-e2e-'))
const old = await startOldSystem({ users: [
  { name: 'ana', kind: 'human', apiKey: `ana-${randomBytes(8).toString('hex')}`, permissions: ['contacts:read', 'contacts:create', 'orders:delete', 'reports:read'] },
  { name: 'lola', kind: 'agent', apiKey: LOLA_KEY, permissions: ['contacts:read', 'contacts:create', 'reports:read'] },
] })
const vault = new EncryptedFileVault(join(dataDir, 'vault.json'), randomBytes(32))
await vault.set(`acme/${fx.agent_address}`, { type: 'header', name: 'X-API-Key', value: LOLA_KEY })
const ADMIN = randomBytes(24).toString('base64url')
const gateway = createGateway({ dataDir, vault, adminToken: ADMIN, allowInsecureHttp: true, allowInsecureUpstream: true, allowPrivateUpstream: true })
const tenant = introspect => validateTenantConfig({
  displayName: 'Acme',
  issuers: [{
    issuer: fx.issuer, kind: 'own', jwksUri: `${fx.issuer}/.well-known/jwks.json`, audience: [fx.resource], allowAllActiveAgents: true,
    introspect, ...(introspect !== 'never' ? { introspection: { endpoint: `${fx.issuer}/oauth/introspect`, clientId: fx.client_id, clientSecret: fx.client_secret } } : {}),
    scopeMap: { 'contacts:read': ['contacts.read'], 'contacts:create': ['contacts.create'], 'orders:delete': ['orders.delete'], 'reports:read': ['reports.read'] },
  }],
  events: { audience: fx.resource, maxAgeSec: 300 },
  upstream: { baseUrl: old.url },
  catalog: [
    { permission: 'contacts.read', method: 'GET', pathTemplate: '/contacts' },
    { permission: 'contacts.create', method: 'POST', pathTemplate: '/contacts' },
    { permission: 'orders.delete', method: 'DELETE', pathTemplate: '/orders/{id}' },
  ],
  agents: { [fx.agent_address]: { upstreamUser: 'lola' } },
}, { allowInsecureUpstream: true, allowInsecureHttp: true, allowPrivateUpstream: true }).config
gateway.store.put('acme', tenant('always'))
const addr = await gateway.listen(4101)
const gw = `http://127.0.0.1:${addr.port}/acme`
const call = async (token, path, init = {}) => {
  const res = await fetch(`${gw}${path}`, { ...init, headers: { authorization: `Bearer ${token}`, ...(init.headers ?? {}) } })
  const text = await res.text(); let body = null; try { body = JSON.parse(text) } catch { /* none */ }
  return { status: res.status, body, text }
}

try {
  say('1. The REAL client gets a token from the REAL issuer for the old system, and the REAL gateway checks it')
  const t1 = clientToken('--audience', fx.resource)
  check('the real client gets a token for the registered service', t1.ok, t1.error.slice(0, 120))
  const c1 = t1.ok ? claims(t1.token) : {}
  check('its audience is exactly the old system', JSON.stringify(c1.aud) === JSON.stringify([fx.resource]), JSON.stringify(c1.aud))
  check('it carries the scope string', typeof c1.scope === 'string' && c1.scope.includes('contacts:read'))
  const made = await call(t1.token, '/contacts', { method: 'POST', body: JSON.stringify({ name: 'Lead from the real flow' }) })
  check('Lola creates a contact through the gateway (201)', made.status === 201 && made.body?.createdBy === 'lola', `status ${made.status} ${made.text.slice(0, 100)}`)
  check('the old system\'s own log says lola', old.audit.some(a => a.who === 'lola' && a.ok))
  const rep = await call(t1.token, '/reports/revenue')
  check('a path outside the catalog is refused by the gateway (403)', rep.status === 403, `status ${rep.status}`)
  check('the old system never saw that request', !old.audit.some(a => /reports/.test(a.action)))
  check('the old system\'s key is in nothing Lola received', !(made.text + rep.text).includes(LOLA_KEY))

  say('2. Tokens that should not work, against the real issuer')
  const generic = clientToken()
  check('a generic-audience token (no --audience) is refused by the gateway', generic.ok && (await call(generic.token, '/contacts')).status === 401)
  const bad = clientToken('--audience', 'https://not-registered.example')
  check('the real issuer refuses a service nobody registered (invalid_target)', !bad.ok && /invalid_target/.test(bad.error), bad.error.slice(0, 80))

  say('3. The issuer suspends Lola: the gateway asks the real issuer (introspection with the connected app\'s own credentials)')
  console.log('   operator:', await operator('suspend'))
  check('the token she holds stops working at once (401)', (await call(t1.token, '/contacts')).status === 401)
  const denied = clientToken('--audience', fx.resource)
  check('and the real issuer will not give her a new token', !denied.ok)
  console.log('   operator:', await operator('reactivate'))

  say('4. Freshness by the issuer\'s own status events (no introspection): the REAL issuer publishes a signed event, the gateway verifies it')
  gateway.store.put('acme', tenant('never'))
  const t2 = clientToken('--audience', fx.resource)
  check('after reactivation she gets a token again', t2.ok, t2.error.slice(0, 100))
  check('and works (200)', (await call(t2.token, '/contacts')).status === 200)
  // the reactivation event may be pending: deliver everything due, then suspend and deliver again
  console.log('   delivery:', await deliver())
  console.log('   operator:', await operator('suspend'))
  console.log('   delivery:', await deliver())
  await new Promise(r => setTimeout(r, 500))
  const after = await call(t2.token, '/contacts')
  check('the signed suspension event from the real issuer stops her (401)', after.status === 401, `status ${after.status}`)
  console.log('   operator:', await operator('reactivate'))
  console.log('   delivery:', await deliver())

  say('5. The issuer rotates its signing key')
  const before = clientToken('--audience', fx.resource)
  const rot = await rails(['rake', `aid:rotate_signing_key[${fx.url_id}]`], { CONFIRM: 'yes', FORCE: 'yes' })
  check('rotation ran', rot.status === 0, (rot.stdout + rot.stderr).slice(-120))
  const jwks = await (await fetch(`${fx.issuer}/.well-known/jwks.json`)).json()
  check('the issuer now publishes two keys (new first, old during the overlap)', jwks.keys.length === 2, `${jwks.keys.length} keys`)
  gateway.store.put('acme', tenant('never'))
  // A gateway that refreshed its key list in the last 30 s will not look again at once (it cannot be made to hammer the issuer),
  // so a token signed by the brand-new key can be refused for up to that long. Wait it out, as a real client would retry.
  const early = clientToken('--audience', fx.resource)
  const earlyStatus = early.ok ? (await call(early.token, '/contacts')).status : 'no token'
  console.log('   first call with the new key, right after rotation:', earlyStatus)
  await new Promise(r => setTimeout(r, 31_000))
  const t3 = clientToken('--audience', fx.resource)
  check('a token signed with the NEW key is accepted by the gateway (after the key list refreshes)', t3.ok && (await call(t3.token, '/contacts')).status === 200)
  check('a token signed with the OLD key is still accepted during the overlap', before.ok && (await call(before.token, '/contacts')).status === 200)
} finally {
  await gateway.close?.()
  await old.stop?.()
}
const failed = results.filter(r => !r.pass)
console.log(`\n${results.length - failed.length} of ${results.length} checks passed`)
process.exit(failed.length ? 1 : 0)
