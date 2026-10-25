import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createSign, generateKeyPairSync } from 'node:crypto'
import http from 'node:http'
import { setup, KEYS, AUDIENCE, rawRequest } from './helpers.js'

const everything = r => `${JSON.stringify([...r.headers])}\n${r.text}`
const assertNoSecrets = (r, secrets = Object.values(KEYS)) => { const all = everything(r); for (const s of secrets) assert.ok(!all.includes(s), `a secret leaked: ${s.slice(0, 8)}...`) }

function forgedToken(issuer, kid = 'demo-1', over = {}) {
  const stranger = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const b = x => Buffer.from(JSON.stringify(x)).toString('base64url')
  const now = Math.floor(Date.now() / 1000)
  const input = `${b({ alg: 'RS256', typ: 'JWT', kid })}.${b({ iss: issuer, sub: 'agent:x', aud: [AUDIENCE], exp: now + 60, iat: now, nbf: now, jti: 'f', token_type: 'agent', agent_id: 'x', agent_address: 'lola@acme.example', scope: 'contacts:read', ...over })}`
  return `${input}.${createSign('RSA-SHA256').update(input).sign(stranger.privateKey).toString('base64url')}`
}

test('a good token reads through the gateway, with the agent\'s own key at the old system', async () => {
  const t = await setup()
  try {
    const r = await t.call('/acme/contacts', { token: await t.tokenFor(t.lola) })
    assert.equal(r.status, 200)
    assert.equal(r.json.user, 'lola')
    assert.equal(t.upstream.requests.length, 1)
    assert.equal(t.upstream.requests[0].headers['x-api-key'], KEYS.lola)
  } finally { await t.stop() }
})

test('token errors: 401 for a token that is not good, 403 for an agent that is known but not let in', async () => {
  const t = await setup()
  try {
    const cases = {
      'no token': await t.call('/acme/contacts'),
      'not a token': await t.call('/acme/contacts', { token: 'garbage' }),
      'wrong scheme': await t.call('/acme/contacts', { headers: { authorization: 'Basic abc' } }),
      'forged signature': await t.call('/acme/contacts', { token: forgedToken(t.issuer.issuer) }),
      'unknown issuer': await t.call('/acme/contacts', { token: forgedToken('https://evil.example/x') }),
      'expired': await t.call('/acme/contacts', { token: t.issuer.signRaw({ iss: t.issuer.issuer, sub: 'agent:x', aud: [AUDIENCE], exp: 1000, iat: 900, nbf: 900, token_type: 'agent', agent_id: 'x', scope: 'contacts:read' }) }),
      'another service': await t.call('/acme/contacts', { token: await t.tokenFor(t.lola, { resource: 'https://other.example' }) }),
      'generic audience (no resource)': await t.call('/acme/contacts', { token: await t.lola.requestToken(t.issuer.issuer) }),
    }
    for (const [name, r] of Object.entries(cases)) {
      assert.equal(r.status, 401, name)
      assert.match(r.headers.get('www-authenticate'), /Bearer/, name)
      assert.deepEqual(Object.keys(r.json).sort(), ['error', 'request_id'], name)
    }
    assert.equal(t.upstream.requests.length, 0)
    const reasons = t.gw.audit.query({ decision: 'deny' }).map(r => r.reason)
    for (const code of ['no_token', 'malformed_token', 'bad_signature', 'untrusted_issuer', 'token_expired', 'bad_audience']) assert.ok(reasons.includes(code), code)
  } finally { await t.stop() }
})

test('an agent the issuer vouches for but this tenant never set up is 403', async () => {
  const t = await setup({ tenant: { agents: { 'rex@acme.example': {} } } })
  try {
    const r = await t.call('/acme/contacts', { token: await t.tokenFor(t.lola) })
    assert.equal(r.status, 403)
    assert.equal(r.json.code, 'agent_not_configured')
    assert.equal(t.upstream.requests.length, 0)
  } finally { await t.stop() }
})

test('a suspended agent is refused (introspection on) and its audit record says why', async () => {
  const t = await setup()
  try {
    const token = await t.tokenFor(t.lola)
    assert.equal((await t.call('/acme/contacts', { token })).status, 200)
    t.issuer.suspend(t.lola.address)
    const r = await t.call('/acme/contacts', { token })
    assert.equal(r.status, 401)
    assert.equal(t.gw.audit.query({ decision: 'deny' })[0].reason, 'agent_inactive')
  } finally { await t.stop() }
})

test('deny by default: a request not in the catalog is 403 and never forwarded', async () => {
  const t = await setup()
  try {
    const token = await t.tokenFor(t.lola)
    for (const [method, path] of [['GET', '/secrets'], ['GET', '/contacts/1/notes'], ['PUT', '/contacts'], ['PATCH', '/contacts/1'], ['DELETE', '/contacts/1'], ['POST', '/orders/100'], ['GET', '/'], ['PROPFIND', '/contacts']]) {
      const r = await t.call(`/acme${path}`, { token, method })
      assert.equal(r.status, 403, `${method} ${path}`)
      assert.equal(r.json.code, 'not_in_catalog')
    }
    assert.equal(t.upstream.requests.length, 0)
  } finally { await t.stop() }
})

test('the more specific template wins and a parameter matches exactly one segment', async () => {
  const t = await setup({ tenant: { catalog: [
    { permission: 'contacts.read', method: 'GET', pathTemplate: '/contacts/{id}' },
    { permission: 'contacts.search', method: 'GET', pathTemplate: '/contacts/search' },
  ] } })
  try {
    const token = await t.tokenFor(t.lola)
    assert.equal((await t.call('/acme/contacts/search', { token })).status, 403, 'lola holds no contacts.search: the literal template won over {id}')
    assert.equal((await t.call('/acme/contacts/7', { token })).status, 200)
    assert.equal((await t.call('/acme/contacts/7/extra', { token })).status, 403)
  } finally { await t.stop() }
})

test('permission narrowing: the token\'s scopes, the scope map and a grant ceiling can only narrow', async () => {
  const t = await setup()
  try {
    const readOnly = await t.tokenFor(t.lola, { scope: 'contacts:read' })
    assert.equal((await t.call('/acme/contacts', { token: readOnly })).status, 200)
    const denied = await t.call('/acme/contacts', { token: readOnly, method: 'POST', body: '{}' })
    assert.equal(denied.status, 403)
    assert.equal(denied.json.code, 'insufficient_permissions')
    assert.equal(t.upstream.requests.length, 1)
  } finally { await t.stop() }

  // a scope the tenant never mapped grants nothing, even if the issuer put it in the token
  const t2 = await setup()
  try {
    const cfg = structuredClone(t2.config)
    delete cfg.issuers[0].scopeMap['orders:delete']
    t2.gw.store.put('acme', cfg)
    const token = await t2.tokenFor(t2.lola)
    assert.equal((await t2.call('/acme/orders/100', { token, method: 'DELETE' })).status, 403)
    assert.equal(t2.upstream.requests.length, 0)
  } finally { await t2.stop() }

  const t3 = await setup()
  try {
    const cfg = structuredClone(t3.config)
    cfg.grants = [{ issuer: t3.issuer.issuer, address: 'lola@acme.example', permissions: ['contacts.read'], sponsor: 'ana@acme.example' }]
    t3.gw.store.put('acme', cfg)
    const token = await t3.tokenFor(t3.lola)
    assert.equal((await t3.call('/acme/contacts', { token })).status, 200)
    assert.equal((await t3.call('/acme/contacts', { token, method: 'POST', body: '{}' })).status, 403, 'the ceiling is lower than the token')
  } finally { await t3.stop() }
})

test('the old system\'s own permissions stay the ceiling: its refusal passes through', async () => {
  const t = await setup()
  try {
    const r = await t.call('/acme/orders/100', { token: await t.tokenFor(t.lola), method: 'DELETE' })
    assert.equal(r.status, 403)
    assert.match(r.text, /lola may not delete orders/)
    assert.equal(t.gw.audit.query()[0].upstreamStatus, 403)
    assert.equal(t.gw.audit.query()[0].decision, 'allow', 'the gateway let it through; the old system said no')
    assert.equal((await t.call('/acme/orders/100', { token: await t.tokenFor(t.rex), method: 'DELETE' })).status, 204)
  } finally { await t.stop() }
})

test('the agent never receives the upstream credential: success, errors, redirects, cookies and echoing systems', async () => {
  const t = await setup()
  try {
    const token = await t.tokenFor(t.lola)
    const paths = [['GET', '/acme/contacts'], ['GET', '/acme/set-cookie'], ['GET', '/acme/redirect-other'], ['GET', '/acme/redirect-same'], ['GET', '/acme/nope'], ['GET', '/acme/echo-key'], ['GET', '/acme/echo-key-header'], ['POST', '/acme/contacts'], ['DELETE', '/acme/orders/1'], ['GET', '/acme/../x'], ['GET', '/nosuch/x']]
    for (const [method, path] of paths) {
      const r = await t.call(path, { token, method, body: method === 'POST' ? '{}' : undefined })
      assertNoSecrets(r)
      assert.equal(r.headers.get('set-cookie'), null, path)
      assert.equal(r.headers.get('www-authenticate'), null, path)
    }
    // an upstream that rejects the key sends a challenge naming it: it must not reach the agent
    await t.vault.set('acme/lola@acme.example', { type: 'header', name: 'X-API-Key', value: 'wrong-key-value-123' })
    const bad = await t.call('/acme/contacts', { token })
    assert.equal(bad.status, 401)
    assert.equal(bad.headers.get('www-authenticate'), null)
    assert.equal(bad.headers.get('set-cookie'), null)
    assertNoSecrets(bad, ['wrong-key-value-123', ...Object.values(KEYS)])
    // and the two echo routes were refused rather than relayed
    const echo = await t.call('/acme/echo-key', { token: await t.tokenFor(t.rex) })
    assert.equal(echo.status, 502)
    assert.equal(echo.json.error, 'upstream_response_blocked')
    const hdr = await t.call('/acme/echo-key-header', { token: await t.tokenFor(t.rex) })   // echoed in a header the allow-list drops
    assert.equal(hdr.status, 200)
    assert.equal(hdr.headers.get('x-debug'), null)
    assertNoSecrets(hdr)
  } finally { await t.stop() }
})

test('inbound credential-like headers are stripped; the outbound credential is the agent\'s own', async () => {
  const t = await setup()
  try {
    const token = await t.tokenFor(t.lola)
    const r = await t.call('/acme/contacts', { token, headers: {
      cookie: 'session=attacker', 'x-api-key': 'attacker-key', 'proxy-authorization': 'Basic YXR0YWNrZXI6eA==', 'x-custom': 'nope', 'x-forwarded-for': '6.6.6.6',
      accept: 'application/json', 'accept-encoding': 'gzip',
    } })
    assert.equal(r.status, 200)
    // hop-by-hop headers fetch will not send: use a raw socket
    const raw = await rawRequest(new URL(t.base).port, '/acme/contacts', { headers: { authorization: `Bearer ${token}`, upgrade: 'websocket', te: 'trailers', 'proxy-connection': 'keep-alive', 'keep-alive': 'timeout=5', connection: 'close, x-hop', 'x-hop': 'secret-hop' } })
    assert.equal(raw.status, 200)
    assert.equal(t.upstream.requests[1].headers.upgrade, undefined)
    assert.equal(t.upstream.requests[1].headers['x-hop'], undefined)
    assert.equal(t.upstream.requests[1].headers.te, undefined)
    const h = t.upstream.requests[0].headers
    assert.equal(h['x-api-key'], KEYS.lola)
    for (const name of ['cookie', 'proxy-authorization', 'authorization', 'x-custom', 'x-forwarded-for', 'upgrade', 'te', 'keep-alive']) assert.equal(h[name], undefined, name)
    assert.equal(h['accept-encoding'], 'identity')
    assert.equal(h.accept, 'application/json')
    assert.ok(!JSON.stringify(h).includes(token), 'the AID token never goes to the old system')
  } finally { await t.stop() }
})

test('attribution headers are set from the verified token and cannot be spoofed', async () => {
  const t = await setup()
  try {
    const r = await t.call('/acme/contacts', { token: await t.tokenFor(t.lola), headers: {
      'x-aid-agent': 'rex', 'x-aid-agent-address': 'rex@acme.example', 'x-aid-issuer': 'https://evil.example', 'x-request-id': 'spoofed-id', 'x-aid-extra': 'x',
    } })
    const h = t.upstream.requests[0].headers
    assert.equal(h['x-aid-agent'], t.lolaRec.id)
    assert.equal(h['x-aid-agent-address'], 'lola@acme.example')
    assert.equal(h['x-aid-issuer'], t.issuer.issuer)
    assert.notEqual(h['x-request-id'], 'spoofed-id')
    assert.match(h['x-request-id'], /^[0-9a-f-]{36}$/)
    assert.equal(r.headers.get('x-request-id'), h['x-request-id'])
    assert.equal(h['x-aid-extra'], undefined)
    assert.equal(t.gw.audit.query()[0].requestId, h['x-request-id'])
  } finally { await t.stop() }
})

test('per-agent credentials give per-agent attribution at the old system', async () => {
  const t = await setup()
  try {
    const a = await t.call('/acme/contacts', { token: await t.tokenFor(t.lola) })
    const b = await t.call('/acme/contacts', { token: await t.tokenFor(t.rex) })
    assert.equal(a.json.user, 'lola')
    assert.equal(b.json.user, 'rex')
    assert.deepEqual(t.upstream.requests.map(r => r.headers['x-api-key']), [KEYS.lola, KEYS.rex])
    assert.deepEqual(t.upstream.requests.map(r => r.headers['x-aid-agent-address']), ['lola@acme.example', 'rex@acme.example'])
  } finally { await t.stop() }
})

test('an agent with no credential stored gets 502 and nothing is forwarded', async () => {
  const t = await setup({ credentials: false })
  try {
    const r = await t.call('/acme/contacts', { token: await t.tokenFor(t.lola) })
    assert.equal(r.status, 502)
    assert.equal(t.upstream.requests.length, 0)
    assert.equal(t.gw.audit.query()[0].reason, 'no_credential')
  } finally { await t.stop() }
})

test('redirects are never followed; a Location to another host is dropped, one into the same upstream goes back through the gateway', async () => {
  const t = await setup()
  try {
    const token = await t.tokenFor(t.lola)
    const other = await t.call('/acme/redirect-other', { token })
    assert.equal(other.status, 302)
    assert.equal(other.headers.get('location'), null)
    assert.equal(other.headers.get('set-cookie'), null)
    assert.equal(t.upstream.requests.length, 1, 'not followed')
    const same = await t.call('/acme/redirect-same', { token })
    assert.equal(same.status, 302)
    assert.equal(same.headers.get('location'), '/acme/contacts')
    assert.equal(t.upstream.requests.length, 2, 'not followed')
  } finally { await t.stop() }
})

test('set-cookie and auth challenges from the old system are not passed on; unknown response headers are dropped', async () => {
  const t = await setup()
  try {
    const r = await t.call('/acme/set-cookie', { token: await t.tokenFor(t.lola) })
    assert.equal(r.status, 200)
    for (const h of ['set-cookie', 'www-authenticate', 'x-powered-by']) assert.equal(r.headers.get(h), null, h)
  } finally { await t.stop() }
})

test('body limit: 413 over the default 1 MiB, over a configured limit, and for chunked bodies with no length', async () => {
  const t = await setup()
  try {
    const token = await t.tokenFor(t.lola)
    const big = await t.call('/acme/contacts', { token, method: 'POST', body: 'x'.repeat(1024 * 1024 + 1) })
    assert.equal(big.status, 413)
    assert.equal(t.upstream.requests.length, 0)
    const ok = await t.call('/acme/contacts', { token, method: 'POST', body: JSON.stringify({ n: 'y'.repeat(1000) }) })
    assert.equal(ok.status, 201)
  } finally { await t.stop() }

  const t2 = await setup({ tenant: { limits: { maxBodyBytes: 50 } } })
  try {
    const token = await t2.tokenFor(t2.lola)
    assert.equal((await t2.call('/acme/contacts', { token, method: 'POST', body: JSON.stringify({ a: 'z'.repeat(100) }) })).status, 413)
    // chunked, no content-length
    const port = new URL(t2.base).port
    const status = await new Promise(resolve => {
      const req = http.request({ host: '127.0.0.1', port, method: 'POST', path: '/acme/contacts', headers: { authorization: `Bearer ${token}`, 'transfer-encoding': 'chunked' } }, res => { res.resume(); resolve(res.statusCode) })
      req.on('error', () => resolve(0))
      req.write('a'.repeat(40)); req.write('b'.repeat(40)); req.end()
    })
    assert.equal(status, 413)
    assert.equal(t2.upstream.requests.length, 0)
  } finally { await t2.stop() }
})

test('a GET with a body is refused', async () => {
  const t = await setup()
  try {
    const r = await rawRequest(new URL(t.base).port, '/acme/contacts', { headers: { authorization: `Bearer ${await t.tokenFor(t.lola)}` }, body: 'abc' })
    assert.equal(r.status, 400)
    assert.equal(t.upstream.requests.length, 0)
  } finally { await t.stop() }
})

test('upstream timeout is 504 and a response over the cap is 502', async () => {
  const t = await setup({ tenant: { limits: { timeoutMs: 200, maxResponseBytes: 1024 } } })
  try {
    const token = await t.tokenFor(t.lola)
    const slow = await t.call('/acme/slow', { token })
    assert.equal(slow.status, 504)
    assert.equal(t.gw.audit.query()[0].reason, 'upstream_timeout')
    const big = await t.call('/acme/big', { token })
    assert.equal(big.status, 502)
    assert.ok(big.text.length < 300)
  } finally { await t.stop() }
})

test('the upstream host is fixed: nothing in the request or token can choose it', async () => {
  const t = await setup()
  try {
    const token = await t.tokenFor(t.lola)
    await t.call('/acme/contacts', { token, headers: { host: 'evil.example', 'x-forwarded-host': 'evil.example', 'x-upstream': 'http://evil.example', forwarded: 'host=evil.example' } })
    const h = t.upstream.requests[0].headers
    assert.equal(h.host, new URL(t.upstream.url).host)
    assert.equal(h['x-forwarded-host'], undefined)
    // a query that looks like a URL stays a query
    const q = await t.call('/acme/contacts?url=http://evil.example/x', { token })
    assert.equal(q.status, 200)
    assert.equal(t.upstream.requests[1].url, '/contacts?url=http://evil.example/x')
  } finally { await t.stop() }
})

test('internal addresses are refused unless the operator allows them', async () => {
  const t = await setup({ gateway: { allowPrivateUpstream: false } })
  try {
    const token = await t.tokenFor(t.lola)
    // the upstream is 127.0.0.1 here: the stored config does not validate under this policy, so the tenant is not served
    const r = await t.call('/acme/contacts', { token })
    assert.equal(r.status, 500)
    assert.equal(t.gw.audit.query()[0].reason, 'tenant_config_invalid')
    assert.equal(t.upstream.requests.length, 0)
  } finally { await t.stop() }
})

test('a request is audited without the raw path when a template matched, and never with a token, key or body', async () => {
  const t = await setup()
  try {
    const token = await t.tokenFor(t.lola)
    await t.call('/acme/contacts/42?secret=1', { token })
    await t.call('/acme/contacts', { token, method: 'POST', body: JSON.stringify({ ssn: '123-45-6789' }) })
    await t.call('/acme/forbidden/777', { token })
    const [denied, , allowed] = t.gw.audit.query({ limit: 3 })
    const rec = t.gw.audit.query()
    assert.equal(denied.decision, 'deny')
    assert.equal(denied.reason, 'not_in_catalog')
    assert.equal(denied.pathTemplate, null)
    const get42 = rec.find(r => r.method === 'GET' && r.permission === 'contacts.read')
    assert.equal(get42.pathTemplate, '/contacts/{id}')
    assert.equal(get42.agentAddress, 'lola@acme.example')
    assert.equal(get42.agentId, t.lolaRec.id)
    assert.ok(get42.jti)
    assert.equal(get42.upstreamStatus, 200)
    assert.equal(typeof get42.latencyMs, 'number')
    assert.equal(get42.decision, 'allow')
    assert.ok(allowed)
    await t.gw.audit.flush()
    const { readFileSync } = await import('node:fs')
    const file = readFileSync(`${t.dir}/audit.jsonl`, 'utf8')
    assert.equal(file.trim().split('\n').length, rec.length)
    for (const line of file.trim().split('\n')) JSON.parse(line)
    for (const bad of [token, KEYS.lola, '123-45-6789', '/contacts/42', 'secret=1']) assert.ok(!file.includes(bad) && !JSON.stringify(rec).includes(bad), bad)
  } finally { await t.stop() }
})

test('per-agent rate limit: 429 with Retry-After, other agents unaffected, refills with time', async () => {
  let offset = 0
  const t = await setup({ tenant: { limits: { ratePerMinute: 6, burst: 2 } }, now: () => Date.now() + offset })
  try {
    const lola = await t.tokenFor(t.lola)
    const rex = await t.tokenFor(t.rex)
    assert.equal((await t.call('/acme/contacts', { token: lola })).status, 200)
    assert.equal((await t.call('/acme/contacts', { token: lola })).status, 200)
    const limited = await t.call('/acme/contacts', { token: lola })
    assert.equal(limited.status, 429)
    assert.ok(Number(limited.headers.get('retry-after')) >= 1)
    assert.equal(t.upstream.requests.length, 2)
    assert.equal((await t.call('/acme/contacts', { token: rex })).status, 200)
    offset += 11_000
    assert.equal((await t.call('/acme/contacts', { token: lola })).status, 200)
  } finally { await t.stop() }
})

test('kill switches take effect on the very next request: one agent, then the whole tenant', async () => {
  const t = await setup()
  const admin = (path, method = 'POST') => fetch(`${t.base}/_admin/${path}`, { method, headers: { authorization: 'Bearer admin-token-for-tests-0123456789abcdef-xyz' } })
  try {
    const lola = await t.tokenFor(t.lola)
    const rex = await t.tokenFor(t.rex)
    assert.equal((await t.call('/acme/contacts', { token: lola })).status, 200)
    assert.equal((await admin('tenants/acme/agents/lola%40acme.example/disable')).status, 200)
    const off = await t.call('/acme/contacts', { token: lola })
    assert.equal(off.status, 403)
    assert.equal(off.json.code, 'agent_disabled')
    assert.equal((await t.call('/acme/contacts', { token: rex })).status, 200, 'only lola')
    assert.equal((await admin('tenants/acme/agents/lola%40acme.example/enable')).status, 200)
    assert.equal((await t.call('/acme/contacts', { token: lola })).status, 200)
    const before = t.upstream.requests.length
    assert.equal((await admin('tenants/acme/disable')).status, 200)
    for (const tok of [lola, rex]) {
      assert.equal((await t.call('/acme/contacts', { token: tok })).status, 403)
      assert.equal(t.gw.audit.query()[0].reason, 'tenant_disabled')
    }
    assert.equal(t.upstream.requests.length, before)
    assert.equal((await admin('tenants/acme/enable')).status, 200)
    assert.equal((await t.call('/acme/contacts', { token: lola })).status, 200)
  } finally { await t.stop() }
})

test('an update that does not mention a disabled agent or tenant does not switch it back on', async () => {
  const t = await setup()
  const adm = (path, method, body) => fetch(`${t.base}/_admin/${path}`, { method, headers: { authorization: 'Bearer admin-token-for-tests-0123456789abcdef-xyz', 'content-type': 'application/json' }, body: body && JSON.stringify(body) })
  try {
    await adm('tenants/acme/agents/lola%40acme.example/disable', 'POST')
    const put = await adm('tenants/acme', 'PUT', t.config)
    assert.equal(put.status, 200)
    const token = await t.tokenFor(t.lola)
    assert.equal((await t.call('/acme/contacts', { token })).json.code, 'agent_disabled')
    await adm('tenants/acme/disable', 'POST')
    await adm('tenants/acme', 'PUT', t.config)
    const r = await t.call('/acme/contacts', { token })
    assert.equal(r.status, 403)
    assert.equal(t.gw.audit.query()[0].reason, 'tenant_disabled')
  } finally { await t.stop() }
})

test('unknown tenants are 404 and reveal nothing', async () => {
  const t = await setup()
  try {
    const r = await t.call('/nosuch/contacts', { token: await t.tokenFor(t.lola) })
    assert.equal(r.status, 404)
    assert.deepEqual(Object.keys(r.json).sort(), ['error', 'request_id'])
  } finally { await t.stop() }
})
