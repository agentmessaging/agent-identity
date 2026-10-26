import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createSign, generateKeyPairSync } from 'node:crypto'
import { createGateway } from '../src/gateway.js'
import { setup, ADMIN_TOKEN, AUDIENCE } from './helpers.js'

const EVENT_AUD = `${AUDIENCE}/_events`
const b64 = x => Buffer.from(JSON.stringify(x)).toString('base64url')
const nowSec = () => Math.floor(Date.now() / 1000)
const claims = (t, over = {}) => ({ iss: t.issuer.issuer, aud: EVENT_AUD, iat: nowSec(), jti: `evt-${Math.random()}`, events: { 'urn:aid:event:agent-suspended': { agent_id: t.lolaRec.id } }, ...over })
const signWithStranger = (payload, header = {}) => {
  const key = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey
  const input = `${b64({ alg: 'RS256', typ: 'secevent+jwt', kid: 'demo-1', ...header })}.${b64(payload)}`
  return `${input}.${createSign('RSA-SHA256').update(input).sign(key).toString('base64url')}`
}
const post = (t, set, path = '/acme/_events') => fetch(`${t.base}${path}`, { method: 'POST', headers: { 'content-type': 'application/secevent+jwt' }, body: set }).then(async r => ({ status: r.status, json: await r.json().catch(() => null) }))

test('a signed suspension from the issuer stops the agent at once, with introspection off', async () => {
  const t = await setup({ introspect: 'never' })
  try {
    const token = await t.tokenFor(t.lola)
    assert.equal((await t.call('/acme/contacts', { token })).status, 200)
    const r = await post(t, t.issuer.signRaw(claims(t)))
    assert.equal(r.status, 202)
    const after = await t.call('/acme/contacts', { token })
    assert.equal(after.status, 401)
    assert.equal(t.gw.audit.query()[0].reason, 'agent_revoked')
    assert.equal((await t.call('/acme/contacts', { token: await t.tokenFor(t.rex) })).status, 200, 'only lola')
    // reactivated
    const back = await post(t, t.issuer.signRaw(claims(t, { events: { 'urn:aid:event:agent-reactivated': { agent_id: t.lolaRec.id } } })))
    assert.equal(back.status, 202)
    assert.equal((await t.call('/acme/contacts', { token })).status, 200)
    // deleted
    await post(t, t.issuer.signRaw(claims(t, { events: { 'urn:aid:event:agent-deleted': { agent_id: t.lolaRec.id } } })))
    assert.equal((await t.call('/acme/contacts', { token })).status, 401)
  } finally { await t.stop() }
})

test('token-revoked stops one token, not the agent', async () => {
  const t = await setup({ introspect: 'never' })
  try {
    const token = await t.tokenFor(t.lola)
    const other = await t.tokenFor(t.lola)
    const jti = JSON.parse(Buffer.from(token.split('.')[1], 'base64url')).jti
    assert.equal((await post(t, t.issuer.signRaw(claims(t, { events: { 'urn:aid:event:token-revoked': { jti } } })))).status, 202)
    assert.equal((await t.call('/acme/contacts', { token })).status, 401)
    assert.equal((await t.call('/acme/contacts', { token: other })).status, 200)
  } finally { await t.stop() }
})

test('a bad event is refused and changes nothing: signature, audience, issuer, age, replay, shape', async () => {
  const t = await setup({ introspect: 'never' })
  try {
    const token = await t.tokenFor(t.lola)
    const bad = {
      'bad signature': signWithStranger(claims(t)),
      'wrong audience': t.issuer.signRaw(claims(t, { aud: 'https://other.example/_events' })),
      'no audience': t.issuer.signRaw(claims(t, { aud: undefined })),
      'unknown issuer': t.issuer.signRaw(claims(t, { iss: 'https://evil.example/x' })),
      'old iat (replayed later)': t.issuer.signRaw(claims(t, { iat: nowSec() - 3600 })),
      'future iat': t.issuer.signRaw(claims(t, { iat: nowSec() + 3600 })),
      'no iat': t.issuer.signRaw(claims(t, { iat: undefined })),
      'expired': t.issuer.signRaw(claims(t, { exp: nowSec() - 1000 })),
      'no jti': t.issuer.signRaw(claims(t, { jti: undefined })),
      'no events': t.issuer.signRaw(claims(t, { events: undefined })),
      'empty events': t.issuer.signRaw(claims(t, { events: {} })),
      'no subject': t.issuer.signRaw(claims(t, { events: { 'urn:aid:event:agent-suspended': {} } })),
      'alg none': `${b64({ alg: 'none' })}.${b64(claims(t))}.`,
      'alg HS256': `${b64({ alg: 'HS256', kid: 'demo-1' })}.${b64(claims(t))}.${Buffer.from('x').toString('base64url')}`,
      'not a token': 'hello',
      'empty': '',
    }
    for (const [name, set] of Object.entries(bad)) {
      const r = await post(t, set)
      assert.equal(r.status, 400, name)
      assert.ok(r.json?.err, name)
    }
    assert.equal((await t.call('/acme/contacts', { token })).status, 200, 'none of them suspended lola')

    const good = t.issuer.signRaw(claims(t))
    assert.equal((await post(t, good)).status, 202)
    const replay = await post(t, good)
    assert.equal(replay.status, 400)
    assert.match(replay.json.description, /already received/)
  } finally { await t.stop() }
})

test('what the real issuer sends: the subject is nested, an event the gateway does not act on is ignored, not an error', async () => {
  const t = await setup({ introspect: 'never' })
  try {
    const token = await t.tokenFor(t.lola)
    assert.equal((await t.call('/acme/contacts', { token })).status, 200)

    // an event type this receiver does not act on, even a made-up one, is skipped: accepted, applied to nothing
    const ignored = await post(t, t.issuer.signRaw(claims(t, { events: { 'urn:aid:event:agent-role-changed': { subject: { agent_id: t.lolaRec.id }, agent_role: 'viewer' }, 'urn:aid:event:make-admin': { subject: { agent_id: t.lolaRec.id } } } })))
    assert.equal(ignored.status, 202)
    assert.equal(ignored.json.accepted, 0)
    assert.equal((await t.call('/acme/contacts', { token })).status, 200, 'ignored events changed nothing')

    // known and unknown together: the known one is applied, the unknown one skipped
    const mixed = await post(t, t.issuer.signRaw(claims(t, { events: { 'urn:evil': {}, 'urn:aid:event:agent-suspended': { subject: { agent_id: t.lolaRec.id, agent_address: 'lola@acme.example' }, agent_status: 'suspended' } } })))
    assert.equal(mixed.status, 202)
    assert.equal(mixed.json.accepted, 1)
    assert.equal((await t.call('/acme/contacts', { token })).status, 401, 'the suspension in the nested subject took effect')
  } finally { await t.stop() }
})

test('a known event with no subject is still refused', async () => {
  const t = await setup({ introspect: 'never' })
  try {
    for (const events of [{ 'urn:aid:event:agent-suspended': {} }, { 'urn:aid:event:agent-suspended': { subject: {} } }, { 'urn:aid:event:token-revoked': { subject: {} } }]) {
      const r = await post(t, t.issuer.signRaw(claims(t, { events })))
      assert.equal(r.status, 400, JSON.stringify(events))
    }
  } finally { await t.stop() }
})

test('the receiver is POST only, per tenant, and off unless configured', async () => {
  const t = await setup({ introspect: 'never' })
  try {
    assert.equal((await fetch(`${t.base}/acme/_events`)).status, 405)
    assert.equal((await post(t, t.issuer.signRaw(claims(t)), '/nosuch/_events')).status, 404)
    assert.equal((await post(t, 'x'.repeat(20_000))).status, 400)
    const cfg = structuredClone(t.config); delete cfg.events
    t.gw.store.put('acme', cfg)
    assert.equal((await post(t, t.issuer.signRaw(claims(t)))).status, 403)
  } finally { await t.stop() }
})

test('a disabled tenant still takes events; an event only touches the issuer that signed it', async () => {
  const t = await setup({ introspect: 'never' })
  try {
    await fetch(`${t.base}/_admin/tenants/acme/disable`, { method: 'POST', headers: { authorization: `Bearer ${ADMIN_TOKEN}` } })
    assert.equal((await post(t, t.issuer.signRaw(claims(t)))).status, 202)
  } finally { await t.stop() }
})

test('suspensions survive a restart of the gateway', async () => {
  const t = await setup({ introspect: 'never' })
  try {
    const token = await t.tokenFor(t.lola)
    assert.equal((await post(t, t.issuer.signRaw(claims(t)))).status, 202)
    const second = createGateway({ dataDir: t.dir, vault: t.vault, adminToken: ADMIN_TOKEN, allowInsecureHttp: true, allowInsecureUpstream: true, allowPrivateUpstream: true })
    const addr = await second.listen(0)
    try {
      const r = await fetch(`http://127.0.0.1:${addr.port}/acme/contacts`, { headers: { authorization: `Bearer ${token}` } })
      assert.equal(r.status, 401)
    } finally { await second.close() }
  } finally { await t.stop() }
})
