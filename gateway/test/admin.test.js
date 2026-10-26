import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createGateway } from '../src/gateway.js'
import { MemoryVault } from '../src/vault.js'
import { safeEqual } from '../src/admin.js'
import { ADMIN_TOKEN, setup, KEYS } from './helpers.js'

const INTRO_SECRET = 'introspection-secret-ABCDEF123456'
const NEW_KEY = 'brand-new-agent-key-zyxwvu-987'

function client(base) {
  return async (path, { method = 'GET', body, token = ADMIN_TOKEN } = {}) => {
    const res = await fetch(`${base}/_admin/${path}`, { method, headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), 'content-type': 'application/json' }, body: body === undefined ? undefined : (typeof body === 'string' ? body : JSON.stringify(body)) })
    const text = await res.text()
    let json
    try { json = JSON.parse(text) } catch { /* html */ }
    return { status: res.status, text, json, headers: res.headers }
  }
}

test('admin API: no token, a wrong token and a near-miss token are all 401; the right one works', async () => {
  const t = await setup()
  const api = client(t.base)
  try {
    assert.equal((await api('tenants', { token: null })).status, 401)
    assert.equal((await api('tenants', { token: 'wrong' })).status, 401)
    assert.equal((await api('tenants', { token: `${ADMIN_TOKEN}x` })).status, 401)
    assert.equal((await api('tenants', { token: ADMIN_TOKEN.slice(0, -1) })).status, 401)
    assert.equal((await api('tenants')).status, 200)
    for (const [m, p] of [['GET', 'tenants/acme'], ['GET', 'audit'], ['POST', 'tenants/acme/disable'], ['PUT', 'tenants/acme/agents/x/credential'], ['GET', 'tenants/acme/agents']]) assert.equal((await api(p, { method: m, token: null })).status, 401, p)
    assert.equal((await api('health', { token: null })).status, 200)
    assert.equal((await fetch(`${t.base}/_admin/tenants`, { headers: { authorization: `Bearer ${await t.tokenFor(t.lola)}` } })).status, 401, 'an agent token is not an admin token')
    assert.equal(safeEqual('a', 'a'), true)
    assert.equal(safeEqual('a', 'b'), false)
    assert.equal(safeEqual('a', 'aa'), false)
  } finally { await t.stop() }
})

test('admin API: repeated failures from one address are slowed down', async () => {
  const t = await setup()
  const api = client(t.base)
  try {
    for (let i = 0; i < 30; i++) assert.equal((await api('tenants', { token: `guess-${i}` })).status, 401)
    assert.equal((await api('tenants', { token: 'guess-final' })).status, 429)
  } finally { await t.stop() }
})

test('admin API: create, read, update a tenant; validation refuses a bad one; secrets never come back', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'aid-adm-'))
  const gw = createGateway({ dataDir: dir, vault: new MemoryVault(), adminToken: ADMIN_TOKEN })   // strict: https only, no internal addresses
  const addr = await gw.listen(0)
  const api = client(`http://127.0.0.1:${addr.port}`)
  const config = {
    issuers: [{ issuer: 'https://auth.example.com/acme', kind: 'own', jwksUri: 'https://auth.example.com/acme/jwks.json', audience: ['https://gw.example.com/acme'], allowAllActiveAgents: true,
      introspection: { endpoint: 'https://auth.example.com/acme/introspect', clientId: 'gw', clientSecret: INTRO_SECRET }, scopeMap: { read: ['contacts.read'] } }],
    upstream: { baseUrl: 'https://crm.example.com/api' },
    catalog: [{ permission: 'contacts.read', method: 'GET', pathTemplate: '/contacts' }],
    agents: { 'lola@acme.example': { upstreamUser: 'lola' } },
  }
  const everything = []
  const rec = r => { everything.push(r.text); return r }
  try {
    const created = rec(await api('tenants/acme', { method: 'PUT', body: config }))
    assert.equal(created.status, 201, created.text)
    assert.ok(Array.isArray(created.json.warnings))
    assert.equal(created.json.config.issuers[0].introspection.clientSecret, '[redacted]')
    const got = rec(await api('tenants/acme'))
    assert.equal(got.json.config.issuers[0].introspection.clientSecret, '[redacted]')
    assert.equal(got.json.config.issuers[0].introspection.clientId, 'gw')
    rec(await api('tenants'))
    // sending the placeholder back keeps the stored secret
    const again = structuredClone(got.json.config)
    again.catalog.push({ permission: 'contacts.create', method: 'POST', pathTemplate: '/contacts' })
    const upd = rec(await api('tenants/acme', { method: 'PUT', body: again }))
    assert.equal(upd.status, 200, upd.text)
    assert.equal(JSON.parse(readFileSync(join(dir, 'tenants', 'acme.json'), 'utf8')).issuers[0].introspection.clientSecret, INTRO_SECRET)
    assert.equal(statSync(join(dir, 'tenants', 'acme.json')).mode & 0o777, 0o600)
    // a placeholder with nothing to restore is refused
    const orphan = structuredClone(config); orphan.issuers[0].issuer = 'https://auth.example.com/other'; orphan.issuers[0].introspection.clientSecret = '[redacted]'
    assert.equal(rec(await api('tenants/new', { method: 'PUT', body: orphan })).status, 400)

    const invalid = {
      'unknown field': { ...config, evil: 1 },
      'no issuers': { ...config, issuers: [] },
      'generic audience': { ...config, issuers: [{ ...config.issuers[0], audience: ['client_app', 'api_service'] }] },
      'http upstream': { ...config, upstream: { baseUrl: 'http://crm.example.com/api' } },
      'internal upstream': { ...config, upstream: { baseUrl: 'https://169.254.169.254/latest' } },
      'loopback upstream': { ...config, upstream: { baseUrl: 'https://127.0.0.1/' } },
      'upstream with credentials': { ...config, upstream: { baseUrl: 'https://u:p@crm.example.com/' } },
      'http jwks': { ...config, issuers: [{ ...config.issuers[0], jwksUri: 'http://auth.example.com/jwks' }] },
      'bad catalog': { ...config, catalog: [{ permission: 'x', method: 'GET', pathTemplate: '/a/../b' }] },
      'forward a cookie': { ...config, upstream: { baseUrl: 'https://crm.example.com', forwardHeaders: ['cookie'] } },
      'forward an auth-ish header': { ...config, upstream: { baseUrl: 'https://crm.example.com', forwardHeaders: ['x-session-token'] } },
      'absurd limit': { ...config, limits: { maxBodyBytes: 1e12 } },
      'two issuers, agent without one': { ...config, issuers: [config.issuers[0], { ...config.issuers[0], issuer: 'https://auth.example.com/b' }] },
    }
    for (const [name, body] of Object.entries(invalid)) assert.equal(rec(await api('tenants/bad', { method: 'PUT', body })).status, 400, name)
    assert.equal(rec(await api('tenants/Bad_Name', { method: 'PUT', body: config })).status, 400)
    assert.equal(rec(await api('tenants/_admin', { method: 'PUT', body: config })).status, 400)
    assert.equal(rec(await api('tenants/nosuch')).status, 404)
    assert.equal((await api('tenants/bad')).status, 404, 'a refused config was not saved')
    assert.equal(rec(await api('tenants/acme', { method: 'PUT', body: '{not json' })).status, 400)

    for (const text of everything) assert.ok(!text.includes(INTRO_SECRET), 'an admin response carried the introspection secret')
  } finally { await gw.close() }
})

test('admin API: set a credential, list agents, disable, delete; no response or audit record ever shows the secret', async () => {
  const t = await setup({ credentials: false })
  const api = client(t.base)
  const seen = []
  const rec = r => { seen.push(r.text); return r }
  try {
    const put = rec(await api('tenants/acme/agents/lola%40acme.example/credential', { method: 'PUT', body: { credential: { type: 'header', name: 'X-API-Key', value: NEW_KEY } } }))
    assert.equal(put.status, 200, put.text)
    assert.deepEqual(put.json, { ok: true, agent: 'lola@acme.example', credentialType: 'header' })
    const list = rec(await api('tenants/acme/agents'))
    const lola = list.json.agents.find(a => a.key === 'lola@acme.example')
    assert.equal(lola.hasCredential, true)
    assert.equal(lola.credentialType, 'header')
    assert.equal(list.json.agents.find(a => a.key === 'rex@acme.example').hasCredential, false)
    // it works through the proxy with the stored value; the agent does not see it
    const call = await t.call('/acme/contacts', { token: await t.tokenFor(t.lola) })
    assert.equal(t.upstream.requests[0].headers['x-api-key'], NEW_KEY)
    seen.push(call.text, JSON.stringify([...call.headers]))
    // a new agent through the API
    const newAgent = rec(await api('tenants/acme/agents/nina%40acme.example/credential', { method: 'PUT', body: { credential: { type: 'bearer', token: `${NEW_KEY}-nina` } } }))
    assert.equal(newAgent.status, 200)
    assert.ok((await api('tenants/acme')).json.config.agents['nina@acme.example'])
    // bad credentials are refused without echoing them
    for (const credential of [{ type: 'header', name: 'Cookie', value: NEW_KEY }, { type: 'header', name: 'X-API-Key', value: `${NEW_KEY}\r\nX: y` }, { type: 'oauth2_client_credentials', clientId: 'a', clientSecret: NEW_KEY }, { type: 'pwn', value: NEW_KEY }, 'a-string']) {
      const r = rec(await api('tenants/acme/agents/lola%40acme.example/credential', { method: 'PUT', body: { credential } }))
      assert.equal(r.status, 400)
    }
    assert.equal(rec(await api('tenants/acme/agents/lola%40acme.example/disable', { method: 'POST' })).status, 200)
    assert.equal(rec(await api('tenants/acme/agents/nobody%40acme.example/disable', { method: 'POST' })).status, 404)
    assert.equal(rec(await api('tenants/acme/agents/lola%40acme.example/credential', { method: 'DELETE' })).status, 200)
    rec(await api('audit?limit=500'))
    rec(await api('audit?agent=lola%40acme.example&decision=deny'))
    rec(await api('tenants/acme'))
    for (const text of seen) for (const s of [NEW_KEY, ...Object.values(KEYS)]) assert.ok(!text.includes(s), 'a response carried a secret')
    await t.gw.audit.flush()
    const auditFile = readFileSync(join(t.dir, 'audit.jsonl'), 'utf8')
    assert.ok(!auditFile.includes(NEW_KEY))
    assert.ok(auditFile.includes('agent.credential.set'), 'admin actions are in the audit trail')
  } finally { await t.stop() }
})

test('admin API: the audit list filters by agent and decision', async () => {
  const t = await setup()
  const api = client(t.base)
  try {
    const lola = await t.tokenFor(t.lola)
    const rex = await t.tokenFor(t.rex)
    await t.call('/acme/contacts', { token: lola })
    await t.call('/acme/secrets', { token: lola })
    await t.call('/acme/contacts', { token: rex })
    await t.call('/acme/contacts')
    const denies = (await api('audit?decision=deny')).json.records
    assert.ok(denies.length >= 2 && denies.every(r => r.decision === 'deny'))
    const lolaOnly = (await api('audit?agent=lola%40acme.example')).json.records
    assert.ok(lolaOnly.length === 2 && lolaOnly.every(r => r.agentAddress === 'lola@acme.example'))
    assert.ok((await api('audit?decision=deny&reason=not_in_catalog')).json.records.every(r => r.reason === 'not_in_catalog'))
  } finally { await t.stop() }
})

test('admin page: static, no external requests, a CSP without unsafe-inline, no token storage', async () => {
  const t = await setup()
  try {
    const res = await fetch(`${t.base}/_admin/ui`)
    assert.equal(res.status, 200)
    const html = await res.text()
    assert.match(res.headers.get('content-type'), /text\/html/)
    const csp = res.headers.get('content-security-policy')
    assert.ok(csp.includes("default-src 'none'") && csp.includes("connect-src 'self'") && !csp.includes('unsafe-inline') && !csp.includes('unsafe-eval'))
    assert.match(csp, /script-src 'sha256-[A-Za-z0-9+/=]+'/)
    assert.match(csp, /style-src 'sha256-[A-Za-z0-9+/=]+'/)
    assert.ok(!/https?:\/\//.test(html), 'no URL at all')
    assert.ok(!/localStorage|sessionStorage|document\.cookie|indexedDB/.test(html), 'the token is kept in memory only')
    assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(/.test(html), 'data from the audit log is only ever set as text')
    assert.ok(html.includes('<label for="token">') && html.includes('aria-live="polite"') && html.includes('lang="en"'))
  } finally { await t.stop() }
})

test('startup: the gateway refuses to be built without an admin token or a vault', () => {
  const dataDir = mkdtempSync(join(tmpdir(), 'aid-start-'))
  const vault = new MemoryVault()
  assert.throws(() => createGateway({ dataDir, vault }), /AID_GATEWAY_ADMIN_TOKEN/)
  assert.throws(() => createGateway({ dataDir, vault, adminToken: '' }), /AID_GATEWAY_ADMIN_TOKEN/)
  assert.throws(() => createGateway({ dataDir, vault, adminToken: 'short' }), /AID_GATEWAY_ADMIN_TOKEN/)
  assert.throws(() => createGateway({ dataDir, adminToken: ADMIN_TOKEN }), /vault/)
  assert.throws(() => createGateway({ vault, adminToken: ADMIN_TOKEN }), /dataDir/)
  assert.doesNotThrow(() => createGateway({ dataDir, vault, adminToken: ADMIN_TOKEN }))
})
