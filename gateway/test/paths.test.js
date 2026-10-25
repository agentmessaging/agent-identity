import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parseTarget, TargetError } from '../src/paths.js'
import { setup, rawRequest } from './helpers.js'

/** Targets an attacker might send. Every one must be refused before anything is forwarded. */
const ATTACKS = [
  '/acme/contacts/../orders/1',
  '/acme/contacts/%2e%2e/orders/1',
  '/acme/contacts/%2E%2E/orders/1',
  '/acme/contacts/..%2forders/1',
  '/acme/contacts/%2e%2e%2forders/1',
  '/acme/contacts%2f..%2f..%2fetc/passwd',
  '/acme/contacts/%252e%252e/orders',
  '/acme//contacts',
  '//acme/contacts',
  '/acme/contacts\\..\\orders',
  '/acme/contacts/%5c..%5corders',
  '/acme/contacts/%5C',
  'http://evil.example/acme/contacts',
  'https://evil.example/',
  '/acme/contacts/.',
  '/acme/./contacts',
  '/acme/contacts/....',
  '/acme/contacts;/../orders/1',
  '/acme/contacts/1;jsessionid=x',
  '/acme/contacts/%00',
  '/acme/contacts/1%00.json',
  '/acme/contacts/%2f%2fevil.example',
  '/acme/contacts/',
  '/acme/contacts/%zz',
  '/acme/contacts/%',
  '/acme/contacts/%c0%ae%c0%ae/orders',
  '/acme/contacts/%0d%0aX-Injected:%20y',
  '/acme/contacts/%0a',
  '/acme/contacts/%7f',
  '/acme/%2e%2e%2f%2e%2e/etc/passwd',
  '/acme/contacts#frag',
  '/ACME/contacts',
  '/%61cme/contacts',
  '/acme%2fcontacts',
  '*',
  'acme/contacts',
]

test('parseTarget refuses every attack string', () => {
  assert.ok(ATTACKS.length >= 12)
  for (const a of ATTACKS) assert.throws(() => parseTarget(a), TargetError, a)
})

test('parseTarget accepts normal targets and canonicalizes the path', () => {
  assert.deepEqual(parseTarget('/acme/contacts/42?x=1&y=2'), { tenant: 'acme', segments: ['contacts', '42'], path: '/contacts/42', query: '?x=1&y=2' })
  assert.equal(parseTarget('/acme/contacts/%34%32').path, '/contacts/42', 'encoded unreserved characters are normalized')
  assert.equal(parseTarget('/acme/files/a%20b').path, '/files/a%20b')
  assert.equal(parseTarget('/acme/files/caf%C3%A9').path, '/files/caf%C3%A9')
  assert.equal(parseTarget('/acme').path, '/')
  assert.equal(parseTarget('/acme/').path, '/')
  assert.equal(parseTarget('/acme/x?').query, '?')
})

test('over the wire, every attack string is a 400 and nothing reaches the old system', async () => {
  const t = await setup()
  try {
    const token = await t.tokenFor(t.lola)
    const port = new URL(t.base).port
    for (const a of ATTACKS) {
      const r = await rawRequest(port, a, { headers: { authorization: `Bearer ${token}` } })
      assert.ok(r.status === 400 || r.status === 404 || r.status === 0, `${a} -> ${r.status}`)
      assert.notEqual(r.status, 200, a)
    }
    assert.equal(t.upstream.requests.length, 0, 'nothing was forwarded')
    const reasons = new Set(t.gw.audit.query({ limit: 200 }).map(r => r.reason))
    for (const code of ['dot_segment', 'double_encoding', 'forbidden_character', 'absolute_form', 'empty_segment', 'bad_encoding']) assert.ok(reasons.has(code), `audit has ${code}`)
  } finally { await t.stop() }
})

test('a legitimate path with an encoded space reaches the old system exactly as authorized', async () => {
  const t = await setup({ tenant: { catalog: [{ permission: 'contacts.read', method: 'GET', pathTemplate: '/contacts/{id}' }] } })
  try {
    const r = await t.call('/acme/contacts/a%20b?x=%2e%2e', { token: await t.tokenFor(t.lola) })
    assert.equal(r.status, 404)   // the fake old system has no such contact; what matters is what it was asked for
    assert.equal(t.upstream.requests[0].url, '/contacts/a%20b?x=%2e%2e')
  } finally { await t.stop() }
})
