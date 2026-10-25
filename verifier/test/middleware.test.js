import { test } from 'node:test'
import assert from 'node:assert/strict'
import { aidMiddleware, bearerToken, createVerifier } from '../src/index.js'
import { agentPayload, makeFetch, makeIssuer } from './helpers.js'

const ACME = 'https://auth.example/acme'

function res() {
  const r = { headers: {}, code: 200, body: null, setHeader(k, v) { r.headers[k] = v }, status(c) { r.code = c; return r }, json(b) { r.body = b; return r } }
  return r
}

async function run({ authorization, permissions = [], scopes } = {}) {
  const acme = makeIssuer(ACME)
  const v = createVerifier({ issuers: [{ issuer: ACME, jwksUri: acme.jwksUri, kind: 'own', audience: ['acme-key'], allowAllActiveAgents: true }] }, { fetch: makeFetch([acme]) })
  const req = { headers: { authorization: authorization ? authorization(acme) : undefined } }
  const out = res()
  let called = false
  await aidMiddleware(v, { permissions })(req, out, () => { called = true })
  return { req, out, called }
}

test('bearerToken reads a well-formed header only', () => {
  assert.equal(bearerToken('Bearer abc.def.ghi'), 'abc.def.ghi')
  for (const h of ['', 'Basic abc', 'Bearer', 'Bearer a b', undefined, null, 5]) assert.equal(bearerToken(h), null)
})

test('no token is a 401 with a challenge', async () => {
  const { out, called } = await run()
  assert.equal(out.code, 401)
  assert.equal(out.headers['WWW-Authenticate'], 'Bearer')
  assert.equal(called, false)
})

test('a bad token is a 401 that does not say why', async () => {
  const { out, called } = await run({ authorization: () => 'Bearer not.a.token' })
  assert.equal(out.code, 401)
  assert.deepEqual(out.body, { error: 'invalid_token' })
  assert.equal(called, false)
})

test('a good token reaches the handler with the principal', async () => {
  const { req, called } = await run({ authorization: a => `Bearer ${a.sign(agentPayload(ACME))}` })
  assert.equal(called, true)
  assert.equal(req.aid.agentId, 'ag-1')
})

test('a known agent without the permission is a 403', async () => {
  const { out, called } = await run({ permissions: ['billing.write'], authorization: a => `Bearer ${a.sign(agentPayload(ACME))}` })
  assert.equal(out.code, 403)
  assert.deepEqual(out.body, { error: 'insufficient_scope' })
  assert.equal(called, false)
})
