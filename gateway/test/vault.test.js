import { test } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { inspect } from 'node:util'
import { Credential, validateCredential } from '../src/credentials.js'
import { EncryptedFileVault, loadMasterKey, MemoryVault } from '../src/vault.js'

const dir = () => mkdtempSync(join(tmpdir(), 'aid-vault-'))
const SECRET = 'super-secret-api-key-0123456789'

test('vault: encryption round trip; the file holds no plaintext, no names, and has mode 600', async () => {
  const path = join(dir(), 'vault.json')
  const v = new EncryptedFileVault(path, randomBytes(32))
  await v.set('acme/lola@acme.example', { type: 'header', name: 'X-API-Key', value: SECRET })
  const got = await v.get('acme/lola@acme.example')
  assert.equal(got.reveal().value, SECRET)
  assert.equal(got.type, 'header')
  assert.deepEqual(await v.describe('acme/lola@acme.example'), { type: 'header' })
  const file = readFileSync(path, 'utf8')
  for (const plain of [SECRET, 'X-API-Key', 'lola', 'acme', 'header']) assert.ok(!file.includes(plain), `plaintext "${plain}" in the file`)
  assert.equal(statSync(path).mode & 0o777, 0o600)
  assert.equal(await v.get('acme/nobody'), null)
  assert.equal(await v.delete('acme/lola@acme.example'), true)
  assert.equal(await v.has('acme/lola@acme.example'), false)
})

test('vault: a random IV for every write, so the same secret never encrypts the same way twice', async () => {
  const path = join(dir(), 'vault.json')
  const v = new EncryptedFileVault(path, randomBytes(32))
  const cred = { type: 'bearer', token: SECRET }
  await v.set('a/x', cred)
  const first = Object.values(JSON.parse(readFileSync(path, 'utf8')).entries)[0]
  await v.set('a/x', cred)
  const second = Object.values(JSON.parse(readFileSync(path, 'utf8')).entries)[0]
  assert.notEqual(first.iv, second.iv)
  assert.notEqual(first.ct, second.ct)
  assert.equal(Buffer.from(second.iv, 'base64').length, 12)
})

test('vault: the wrong master key is refused at start-up', async () => {
  const path = join(dir(), 'vault.json')
  const key = randomBytes(32)
  await new EncryptedFileVault(path, key).set('a/x', { type: 'bearer', token: SECRET })
  assert.throws(() => new EncryptedFileVault(path, randomBytes(32)), /wrong master key/)
  assert.doesNotThrow(() => new EncryptedFileVault(path, key))
})

test('vault: tampering is detected (a flipped bit, a swapped entry, a forged canary)', async () => {
  const path = join(dir(), 'vault.json')
  const key = randomBytes(32)
  const v = new EncryptedFileVault(path, key)
  await v.set('a/one', { type: 'bearer', token: 'token-one-aaaaaaaa' })
  await v.set('a/two', { type: 'bearer', token: 'token-two-bbbbbbbb' })
  const original = readFileSync(path, 'utf8')

  const flip = JSON.parse(original)
  const [id1] = Object.keys(flip.entries)
  const ct = Buffer.from(flip.entries[id1].ct, 'base64'); ct[0] ^= 1; flip.entries[id1].ct = ct.toString('base64')
  writeFileSync(path, JSON.stringify(flip))
  await assert.rejects(Promise.all([v.get('a/one'), v.get('a/two')]), /integrity/)

  const swap = JSON.parse(original)
  const [a, b] = Object.keys(swap.entries)
  ;[swap.entries[a], swap.entries[b]] = [swap.entries[b], swap.entries[a]]
  writeFileSync(path, JSON.stringify(swap))
  await assert.rejects(v.get('a/one'), /integrity/)
  await assert.rejects(v.get('a/two'), /integrity/)

  const badCheck = JSON.parse(original)
  badCheck.check.tag = Buffer.alloc(16).toString('base64')
  writeFileSync(path, JSON.stringify(badCheck))
  assert.throws(() => new EncryptedFileVault(path, key), /wrong master key|modified/)
  writeFileSync(path, original)
  assert.equal((await v.get('a/one')).reveal().token, 'token-one-aaaaaaaa')
})

test('vault: master key from the environment, 32 bytes of base64, or refuse', () => {
  const good = randomBytes(32).toString('base64')
  assert.equal(loadMasterKey({ AID_GATEWAY_MASTER_KEY: good }).length, 32)
  assert.throws(() => loadMasterKey({}), /not set/)
  assert.throws(() => loadMasterKey({ AID_GATEWAY_MASTER_KEY: '' }), /not set/)
  assert.throws(() => loadMasterKey({ AID_GATEWAY_MASTER_KEY: randomBytes(16).toString('base64') }), /32/)
  assert.throws(() => loadMasterKey({ AID_GATEWAY_MASTER_KEY: randomBytes(33).toString('base64') }), /32/)
  assert.throws(() => loadMasterKey({ AID_GATEWAY_MASTER_KEY: 'not base64 at all!!' }), /32/)
  assert.throws(() => loadMasterKey({ AID_GATEWAY_MASTER_KEY: Buffer.alloc(32, 7).toString('base64') }), /random/)
  assert.throws(() => new EncryptedFileVault(join(dir(), 'v.json'), Buffer.alloc(16, 1)), /32-byte/)
})

test('secrets are never shown by logging, JSON or inspect of a vault or a credential', async () => {
  for (const v of [new MemoryVault(), new EncryptedFileVault(join(dir(), 'v.json'), randomBytes(32))]) {
    await v.set('a/x', { type: 'basic', username: 'lola', password: SECRET })
    const c = await v.get('a/x')
    for (const shown of [JSON.stringify(v), inspect(v), String(v), JSON.stringify(c), inspect(c, { depth: 5, showHidden: true }), String(c), `${JSON.stringify({ c })}`]) assert.ok(!shown.includes(SECRET))
    assert.ok(c instanceof Credential)
  }
})

test('credentials: every type validates, anything odd is refused, and errors never echo the value', () => {
  assert.equal(validateCredential({ type: 'header', name: 'X-API-Key', value: 'abc' }).type, 'header')
  assert.equal(validateCredential({ type: 'bearer', token: 'abc.def' }).type, 'bearer')
  assert.equal(validateCredential({ type: 'basic', username: 'u', password: 'p w' }).type, 'basic')
  assert.equal(validateCredential({ type: 'oauth2_client_credentials', clientId: 'id', clientSecret: 's', scope: 'a b' }).type, 'oauth2_client_credentials')
  const bad = [
    { type: 'header', name: 'Authorization-Evil\r\n', value: 'x' },
    { type: 'header', name: 'Cookie', value: 'x' },
    { type: 'header', name: 'Host', value: 'x' },
    { type: 'header', name: 'X-AID-Agent', value: 'x' },
    { type: 'header', name: 'X-API-Key', value: `${SECRET}\r\nInjected: 1` },
    { type: 'header', name: 'X-API-Key', value: ` ${SECRET}` },
    { type: 'bearer', token: `${SECRET} two` },
    { type: 'basic', username: 'a:b', password: SECRET },
    { type: 'basic', username: 'u', password: `${SECRET}\n` },
    { type: 'bearer', token: SECRET, extra: 1 },
    { type: 'magic', token: SECRET },
    { type: 'oauth2_client_credentials', clientId: 'id', clientSecret: SECRET },
    null,
  ]
  for (const b of bad) {
    try {
      validateCredential(b, { tokenUrlConfigured: b?.type !== 'oauth2_client_credentials' })
      assert.fail(`accepted ${JSON.stringify(b)}`)
    } catch (e) {
      assert.ok(e instanceof TypeError, e.message)
      assert.ok(!e.message.includes(SECRET))
    }
  }
})
