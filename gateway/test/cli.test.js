import { test } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, writeFileSync, statSync, readdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Readable } from 'node:stream'
import { fileURLToPath } from 'node:url'
import { main } from '../src/cli.js'
import { isBlockedAddress } from '../src/outbound.js'
import { EncryptedFileVault } from '../src/vault.js'
import { startUpstream } from './helpers.js'

const BIN = fileURLToPath(new URL('../bin/aid-gateway.js', import.meta.url))
const sink = () => { const lines = []; return { write: s => { lines.push(s) }, text: () => lines.join('') } }
const io = (env = {}, stdin = Readable.from([])) => ({ env, stdin, stdout: sink(), stderr: sink() })

test('run refuses to start without a master key, or with a bad one, or without an admin token (real process)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'aid-cli-'))
  const run = env => spawnSync(process.execPath, [BIN, 'run', '--dir', dir, '--port', '0'], { env: { PATH: process.env.PATH, ...env }, encoding: 'utf8', timeout: 10_000 })
  const key = randomBytes(32).toString('base64')
  const token = randomBytes(32).toString('base64url')
  for (const [name, env, message] of [
    ['nothing', {}, /AID_GATEWAY_MASTER_KEY/],
    ['short key', { AID_GATEWAY_MASTER_KEY: randomBytes(16).toString('base64'), AID_GATEWAY_ADMIN_TOKEN: token }, /32/],
    ['no admin token', { AID_GATEWAY_MASTER_KEY: key }, /AID_GATEWAY_ADMIN_TOKEN/],
    ['short admin token', { AID_GATEWAY_MASTER_KEY: key, AID_GATEWAY_ADMIN_TOKEN: 'short' }, /AID_GATEWAY_ADMIN_TOKEN/],
  ]) {
    const r = run(env)
    assert.equal(r.status, 1, name)
    assert.match(r.stderr, message, name)
  }
})

test('init creates a data directory and a sample tenant that validates; run serves it', async () => {
  const dir = join(mkdtempSync(join(tmpdir(), 'aid-cli-')), 'data')
  const a = io()
  assert.equal(await main(['init', '--dir', dir], a), 0)
  assert.match(a.stdout.text(), /AID_GATEWAY_MASTER_KEY=/)
  assert.ok(readdirSync(join(dir, 'tenants')).includes('sample.json'))
  assert.equal(statSync(join(dir, 'tenants', 'sample.json')).mode & 0o777, 0o600)
  assert.equal(statSync(dir).mode & 0o777, 0o700)
  assert.equal(await main(['init', '--dir', dir], io()), 0, 'init twice is harmless')

  const key = randomBytes(32).toString('base64')
  const adminToken = randomBytes(32).toString('base64url')
  const started = await main(['run', '--dir', dir, '--port', '0'], io({ AID_GATEWAY_MASTER_KEY: key, AID_GATEWAY_ADMIN_TOKEN: adminToken }))
  try {
    const base = `http://127.0.0.1:${started.address.port}`
    assert.equal((await fetch(`${base}/_admin/health`)).status, 200)
    const tenants = await (await fetch(`${base}/_admin/tenants`, { headers: { authorization: `Bearer ${adminToken}` } })).json()
    assert.deepEqual(tenants.tenants.map(t => t.name), ['sample'])
    assert.equal((await fetch(`${base}/sample/contacts`)).status, 401)
  } finally { await started.gateway.close() }
})

test('add-agent-credential reads the secret from stdin, never argv, and stores it encrypted', async () => {
  const dir = join(mkdtempSync(join(tmpdir(), 'aid-cli-')), 'data')
  await main(['init', '--dir', dir], io())
  const key = randomBytes(32)
  const env = { AID_GATEWAY_MASTER_KEY: key.toString('base64') }
  const SECRET = 'cli-secret-value-abcdef-123456'
  const a = io(env, Readable.from([`${SECRET}\n`]))
  assert.equal(await main(['add-agent-credential', '--dir', dir, '--tenant', 'sample', '--agent', 'Lola@sample.example', '--type', 'header', '--header-name', 'X-API-Key'], a), 0, a.stderr.text())
  assert.ok(!a.stdout.text().includes(SECRET) && !a.stderr.text().includes(SECRET))
  const vaultFile = readFileSync(join(dir, 'vault.json'), 'utf8')
  assert.ok(!vaultFile.includes(SECRET))
  assert.equal(statSync(join(dir, 'vault.json')).mode & 0o777, 0o600)
  const cred = await new EncryptedFileVault(join(dir, 'vault.json'), key).get('sample/lola@sample.example')
  assert.equal(cred.reveal().value, SECRET)
  assert.ok(!readFileSync(join(dir, 'tenants', 'sample.json'), 'utf8').includes(SECRET))

  // a secret on the command line is refused
  const b = io(env, Readable.from(['x\n']))
  assert.equal(await main(['add-agent-credential', '--dir', dir, '--tenant', 'sample', '--agent', 'a@b', '--type', 'bearer', '--secret', SECRET], b), 1)
  assert.match(b.stderr.text(), /never accepted as arguments/)
  assert.ok(!b.stderr.text().includes(SECRET))
  // no key, no write
  assert.equal(await main(['add-agent-credential', '--dir', dir, '--tenant', 'sample', '--agent', 'a@b', '--type', 'bearer'], io({}, Readable.from(['x\n']))), 1)
  // empty secret
  assert.equal(await main(['add-agent-credential', '--dir', dir, '--tenant', 'sample', '--agent', 'a@b', '--type', 'bearer'], io(env, Readable.from(['\n']))), 1)
  // oauth2 without a token URL on the tenant
  assert.equal(await main(['add-agent-credential', '--dir', dir, '--tenant', 'sample', '--agent', 'a@b', '--type', 'oauth2', '--client-id', 'c'], io(env, Readable.from(['s\n']))), 1)
})

test('import-openapi prints a draft, reads JSON only, and warns on stderr', async () => {
  const d = mkdtempSync(join(tmpdir(), 'aid-cli-'))
  writeFileSync(join(d, 'api.json'), JSON.stringify({ openapi: '3.0.0', info: { title: 'T', version: '1' }, paths: { '/things': { get: {}, delete: {} }, '/things/{id}': { get: {} } } }))
  const a = io()
  assert.equal(await main(['import-openapi', join(d, 'api.json')], a), 0)
  const out = JSON.parse(a.stdout.text())
  assert.equal(out.draft, true)
  assert.deepEqual(out.catalog.map(e => e.permission), ['things.read', 'things.delete', 'things.read'])
  assert.match(a.stderr.text(), /draft/)
  writeFileSync(join(d, 'api.yaml'), 'openapi: 3.0.0\npaths: {}\n')
  const y = io()
  assert.equal(await main(['import-openapi', join(d, 'api.yaml')], y), 1)
  assert.match(y.stderr.text(), /JSON/)
  const o = io()
  assert.equal(await main(['import-openapi', join(d, 'api.json'), '--out', join(d, 'catalog.json')], o), 0)
  assert.equal(JSON.parse(readFileSync(join(d, 'catalog.json'), 'utf8')).catalog.length, 3)
})

test('address policy: private, loopback, link-local and mapped addresses are blocked, public ones are not', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '::1', '::', 'fe80::1', 'fc00::1', '::ffff:127.0.0.1', '::ffff:10.0.0.1', 'not-an-ip']) assert.equal(isBlockedAddress(ip), true, ip)
  for (const ip of ['8.8.8.8', '1.1.1.1', '93.184.216.34', '2606:4700:4700::1111']) assert.equal(isBlockedAddress(ip), false, ip)
})

test('a hostname that resolves to loopback is refused at connection time when internal addresses are not allowed', async () => {
  const { setup } = await import('./helpers.js')
  const t = await setup({ gateway: { allowPrivateUpstream: false } })
  try {
    const cfg = structuredClone(t.config)
    cfg.upstream.baseUrl = t.upstream.url.replace('127.0.0.1', 'localhost')
    t.gw.store.put('acme', cfg)
    // the issuer is on loopback too, so the token check itself is refused first: the gateway is closed by default
    const r = await t.call('/acme/contacts', { token: await t.tokenFor(t.lola) })
    assert.ok([401, 500, 502].includes(r.status))
    assert.equal(t.upstream.requests.length, 0)
  } finally { await t.stop() }
  const up = await startUpstream()
  try {
    const { outboundRequest } = await import('../src/outbound.js')
    await assert.rejects(outboundRequest(new URL(up.url.replace('127.0.0.1', 'localhost'))), { code: 'blocked_address' })
    await assert.rejects(outboundRequest(new URL(up.url)), { code: 'blocked_address' })
    assert.equal(up.requests.length, 0)
    const ok = await outboundRequest(new URL(up.url.replace('127.0.0.1', 'localhost')), { allowPrivate: true })
    assert.equal(ok.status, 401)
  } finally { await up.stop() }
})
