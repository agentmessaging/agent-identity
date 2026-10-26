import { test } from 'node:test'
import assert from 'node:assert/strict'
import { compileCatalog, validateCatalog } from '../src/catalog.js'
import { importOpenApi } from '../src/openapi.js'

test('catalog: deny by default, method and template both matter', () => {
  const c = compileCatalog([
    { permission: 'contacts.read', method: 'GET', pathTemplate: '/contacts' },
    { permission: 'contacts.read', method: 'GET', pathTemplate: '/contacts/{id}' },
    { permission: 'contacts.create', method: 'POST', pathTemplate: '/contacts' },
  ])
  assert.deepEqual(c.match('GET', ['contacts']), { permission: 'contacts.read', pathTemplate: '/contacts' })
  assert.deepEqual(c.match('GET', ['contacts', '7']), { permission: 'contacts.read', pathTemplate: '/contacts/{id}' })
  assert.equal(c.match('DELETE', ['contacts', '7']), null)
  assert.equal(c.match('POST', ['contacts', '7']), null)
  assert.equal(c.match('GET', ['contacts', '7', 'x']), null)
  assert.equal(c.match('GET', []), null)
  assert.equal(c.match('get', ['contacts']), null, 'methods are exact')
  assert.equal(c.match('GET', ['Contacts']), null, 'literals are case sensitive')
})

test('catalog: an empty catalog refuses everything', () => {
  assert.equal(compileCatalog([]).match('GET', ['x']), null)
})

test('catalog: validation refuses what it cannot be sure about', () => {
  const bad = [
    [{ permission: 'a.b', method: 'GET', pathTemplate: 'contacts' }],
    [{ permission: 'a.b', method: 'TRACE', pathTemplate: '/x' }],
    [{ permission: 'a.b', method: 'OPTIONS', pathTemplate: '/x' }],
    [{ permission: 'a b', method: 'GET', pathTemplate: '/x' }],
    [{ permission: 'a.b', method: 'GET', pathTemplate: '/x/../y' }],
    [{ permission: 'a.b', method: 'GET', pathTemplate: '/x/{id}.json' }],
    [{ permission: 'a.b', method: 'GET', pathTemplate: '/x//y' }],
    [{ permission: 'a.b', method: 'GET', pathTemplate: '/x/*' }],
    [{ permission: 'a.b', method: 'GET', pathTemplate: '/_events' }],
    [{ permission: 'a.b', method: 'GET', pathTemplate: '/x', extra: 1 }],
    [{ permission: 'a.b', method: 'GET', pathTemplate: '/x/{a}' }, { permission: 'c.d', method: 'GET', pathTemplate: '/x/{b}' }],
    'nope',
  ]
  for (const b of bad) assert.throws(() => validateCatalog(b), TypeError, JSON.stringify(b))
})

test('openapi import: permissions come from tags or path plus the method, never from operationId', () => {
  const doc = {
    openapi: '3.0.3', info: { title: 'Legacy CRM', version: '1' },
    paths: {
      '/contacts': {
        get: { tags: ['Contacts'], operationId: 'listContacts' },
        post: { tags: ['Contacts'], operationId: 'getOrCreateContact', summary: 'looks like a read, is a write' },
        parameters: [],
      },
      '/contacts/{id}': { get: { tags: ['Contacts'] }, put: { tags: ['Contacts'] }, patch: {}, delete: { tags: ['Contacts'] } },
      '/api/v1/orders/{orderId}/items': { get: {}, post: {} },
      '/v1/users/{id}': { delete: {}, options: {}, head: {} },
      '/files/{id}.json': { get: {} },
      '/export': { get: { 'x-aid-permission': 'reports.export' } },
      '/ref': { $ref: '#/components/pathItems/x' },
    },
  }
  const out = importOpenApi(doc)
  assert.equal(out.draft, true)
  const by = (m, p) => out.catalog.find(e => e.method === m && e.pathTemplate === p)
  assert.equal(by('GET', '/contacts').permission, 'contacts.read')
  assert.equal(by('POST', '/contacts').permission, 'contacts.create', 'a POST named getOrCreate is still a create')
  assert.equal(by('GET', '/contacts/{id}').permission, 'contacts.read')
  assert.equal(by('PUT', '/contacts/{id}').permission, 'contacts.update')
  assert.equal(by('PATCH', '/contacts/{id}').permission, 'contacts.update'.replace('contacts', 'contacts'), 'patch with no tag derives from the path')
  assert.equal(by('DELETE', '/contacts/{id}').permission, 'contacts.delete')
  assert.equal(by('GET', '/api/v1/orders/{orderId}/items').permission, 'orders.items.read')
  assert.equal(by('POST', '/api/v1/orders/{orderId}/items').permission, 'orders.items.create')
  assert.equal(by('DELETE', '/v1/users/{id}').permission, 'users.delete')
  assert.equal(by('HEAD', '/v1/users/{id}').permission, 'users.read')
  assert.equal(by('GET', '/export').permission, 'reports.export')
  assert.equal(by('OPTIONS', '/v1/users/{id}'), undefined)
  assert.equal(by('GET', '/files/{id}.json'), undefined)
  assert.equal(by('GET', '/contacts').operationId, 'listContacts', 'operationId is kept as a hint')
  assert.ok(out.notes.some(n => /files\/\{id\}\.json/.test(n)))
  assert.ok(out.notes.some(n => /destructive/.test(n) && /contacts\.delete/.test(n)))
  assert.ok(out.notes.some(n => /OPTIONS/.test(n)))
  assert.ok(out.notes.some(n => /draft/.test(n)))
  // the draft is a valid catalog as it stands
  assert.doesNotThrow(() => compileCatalog(out.catalog))
})

test('openapi import: JSON OpenAPI 3 only', () => {
  assert.throws(() => importOpenApi({ swagger: '2.0', paths: {} }), /OpenAPI 3/)
  assert.throws(() => importOpenApi('openapi: 3.0.0'), /OpenAPI 3/)
  assert.throws(() => importOpenApi({ openapi: '3.0.0' }), /paths/)
})
