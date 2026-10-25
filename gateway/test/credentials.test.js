import { test } from 'node:test'
import assert from 'node:assert/strict'
import { setup, KEYS } from './helpers.js'

const CLIENT = { id: 'lola-client', secret: 'client-secret-xyz-98765' }

/** An old system with its own OAuth token endpoint; every token request is recorded */
function oauthUpstream(tokens, { expiresIn = 120, fail = false } = {}) {
  return async (req, res, rec, send) => {
    if (req.method === 'POST' && req.url === '/oauth/token') {
      tokens.push(rec)
      if (fail) return send(500, { error: 'boom', detail: CLIENT.secret }) || true
      return send(200, { access_token: `oauth-token-lola`, token_type: 'Bearer', expires_in: expiresIn }) || true
    }
    return false
  }
}

const withOauth = async (opts = {}, tokens = []) => {
  let offset = 0
  const t = await setup({ upstreamExtra: oauthUpstream(tokens, opts), now: () => Date.now() + offset, credentials: false })
  const cfg = structuredClone(t.config)
  cfg.upstream.tokenUrl = `${t.upstream.url}/oauth/token`
  t.gw.store.put('acme', cfg)
  await t.vault.set('acme/lola@acme.example', { type: 'oauth2_client_credentials', clientId: CLIENT.id, clientSecret: CLIENT.secret })
  return Object.assign(t, { tokens, advance: ms => { offset += ms } })
}

test('oauth2 client credentials: fetched once, cached, refetched shortly before expiry', async () => {
  const t = await withOauth({ expiresIn: 120 })
  try {
    const token = await t.tokenFor(t.lola)
    for (let i = 0; i < 3; i++) assert.equal((await t.call('/acme/contacts', { token })).status, 200)
    assert.equal(t.tokens.length, 1, 'one token request for three calls')
    const up = t.upstream.requests.filter(r => r.url === '/contacts')
    assert.ok(up.every(r => r.headers.authorization === 'Bearer oauth-token-lola'))
    assert.ok(up.every(r => r.headers['x-api-key'] === undefined))
    // the token request itself: Basic auth with the agent's own client, form body
    const tr = t.tokens[0]
    assert.equal(tr.headers.authorization, `Basic ${Buffer.from(`${CLIENT.id}:${CLIENT.secret}`).toString('base64')}`)
    assert.match(tr.body, /grant_type=client_credentials/)
    t.advance(100_000)   // 120 s lifetime, refetched 30 s early
    assert.equal((await t.call('/acme/contacts', { token })).status, 200)
    assert.equal(t.tokens.length, 2, 'refetched before it expired')
    assert.equal(t.gw.audit.query({ limit: 1 })[0].decision, 'allow')
  } finally { await t.stop() }
})

test('oauth2: concurrent first requests share one token fetch', async () => {
  const t = await withOauth({ expiresIn: 600 })
  try {
    const token = await t.tokenFor(t.lola)
    const rs = await Promise.all([1, 2, 3, 4].map(() => t.call('/acme/contacts', { token })))
    assert.ok(rs.every(r => r.status === 200))
    assert.equal(t.tokens.length, 1)
  } finally { await t.stop() }
})

test('oauth2: a very short lifetime is not cached; a failing token endpoint is 502 and leaks nothing', async () => {
  const t = await withOauth({ expiresIn: 10 })
  try {
    const token = await t.tokenFor(t.lola)
    await t.call('/acme/contacts', { token })
    await t.call('/acme/contacts', { token })
    assert.equal(t.tokens.length, 2)
  } finally { await t.stop() }

  const t2 = await withOauth({ fail: true })
  try {
    const r = await t2.call('/acme/contacts', { token: await t2.tokenFor(t2.lola) })
    assert.equal(r.status, 502)
    assert.equal(t2.gw.audit.query()[0].reason, 'credential_unavailable')
    assert.ok(!`${JSON.stringify([...r.headers])}${r.text}`.includes(CLIENT.secret))
    assert.equal(t2.upstream.requests.filter(x => x.url === '/contacts').length, 0)
  } finally { await t2.stop() }
})

test('oauth2: the client secret and the access token never reach the agent', async () => {
  const t = await withOauth({ expiresIn: 600 })
  try {
    const token = await t.tokenFor(t.lola)
    for (const p of ['/acme/contacts', '/acme/nope', '/acme/set-cookie', '/acme/echo-key']) {
      const r = await t.call(p, { token })
      const all = `${JSON.stringify([...r.headers])}${r.text}`
      for (const s of [CLIENT.secret, 'oauth-token-lola']) assert.ok(!all.includes(s), `${p} leaked ${s}`)
    }
  } finally { await t.stop() }
})

test('bearer and basic credentials are sent as such, per agent', async () => {
  const t = await setup({ credentials: false })
  try {
    await t.vault.set('acme/lola@acme.example', { type: 'bearer', token: 'bearer-token-lola-123' })
    await t.vault.set('acme/rex@acme.example', { type: 'basic', username: 'rex', password: 'rex-password-456' })
    await t.call('/acme/contacts', { token: await t.tokenFor(t.lola) })
    await t.call('/acme/contacts', { token: await t.tokenFor(t.rex) })
    assert.equal(t.upstream.requests[0].headers.authorization, 'Bearer bearer-token-lola-123')
    assert.equal(t.upstream.requests[1].headers.authorization, `Basic ${Buffer.from('rex:rex-password-456').toString('base64')}`)
    assert.notEqual(t.upstream.requests[0].headers.authorization, `Bearer ${await t.tokenFor(t.lola)}`)
  } finally { await t.stop() }
})

test('the credential reference lets two agents map to named credentials; an issuer-qualified entry cannot be reached by another issuer', async () => {
  const t = await setup({ credentials: false })
  try {
    await t.vault.set('acme/shared-ref', { type: 'header', name: 'X-API-Key', value: KEYS.rex })
    const cfg = structuredClone(t.config)
    cfg.agents['lola@acme.example'] = { credentialRef: 'shared-ref', issuer: t.issuer.issuer }
    t.gw.store.put('acme', cfg)
    assert.equal((await t.call('/acme/contacts', { token: await t.tokenFor(t.lola) })).json.user, 'rex')
    const edited = structuredClone(cfg)
    edited.agents['lola@acme.example'].issuer = 'https://some-other-issuer.example'
    const seenBefore = t.upstream.requests.length
    t.gw.store.put('acme', edited)   // written past validation on purpose (a hand-edited file): it is validated again on load and not served
    const r = await t.call('/acme/contacts', { token: await t.tokenFor(t.lola) })
    assert.equal(r.status, 500)
    assert.equal(t.gw.audit.query()[0].reason, 'tenant_config_invalid')
    assert.equal(t.upstream.requests.length, seenBefore)
  } finally { await t.stop() }
})
