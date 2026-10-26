import { createCipheriv, createDecipheriv, createHmac, hkdfSync, randomBytes } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { inspect } from 'node:util'
import { atomicWriteFile } from './fsutil.js'
import { Credential, validateCredential } from './credentials.js'

/**
 * The credential vault. Interface (every method may be async):
 *   set(name, credentialObject)   write a secret; it is validated and never returned to anyone but the proxy
 *   get(name)                     a Credential (or null). Only the proxy calls this.
 *   has(name), describe(name)     existence, and { type } only
 *   delete(name)
 * No method returns a secret to an API, a log or an error message. Implementations: MemoryVault (tests) and
 * EncryptedFileVault (AES-256-GCM, a fresh random IV for every write, master key from AID_GATEWAY_MASTER_KEY).
 */

export function loadMasterKey(env = process.env) {
  const raw = env.AID_GATEWAY_MASTER_KEY
  if (typeof raw !== 'string' || raw.trim() === '') throw new Error('AID_GATEWAY_MASTER_KEY is not set. Generate one with: openssl rand -base64 32')
  if (!/^[A-Za-z0-9+/]{43}=$/.test(raw.trim())) throw new Error('AID_GATEWAY_MASTER_KEY must be 32 random bytes, base64 encoded (44 characters)')
  const key = Buffer.from(raw.trim(), 'base64')
  if (key.length !== 32 || new Set(key).size < 8) throw new Error('AID_GATEWAY_MASTER_KEY is not 32 random bytes')
  return key
}

class VaultBase {
  toJSON() { return `[${this.constructor.name}]` }
  [inspect.custom]() { return `[${this.constructor.name}]` }
}

export class MemoryVault extends VaultBase {
  #items = new Map()
  async set(name, cred) { this.#items.set(name, JSON.stringify(validateCredential(cred))) }
  async get(name) { const s = this.#items.get(name); return s ? new Credential(JSON.parse(s)) : null }
  async has(name) { return this.#items.has(name) }
  async describe(name) { const s = this.#items.get(name); return s ? { type: JSON.parse(s).type } : null }
  async delete(name) { return this.#items.delete(name) }
}

const FORMAT = 1
const CANARY = 'aid-gateway-vault-ok'

export class EncryptedFileVault extends VaultBase {
  #path
  #encKey
  #idKey

  /** @param {string} path @param {Buffer} masterKey 32 bytes */
  constructor(path, masterKey) {
    super()
    if (!Buffer.isBuffer(masterKey) || masterKey.length !== 32) throw new Error('the vault needs a 32-byte master key')
    this.#path = path
    this.#encKey = Buffer.from(hkdfSync('sha256', masterKey, Buffer.alloc(0), 'aid-gateway vault encryption v1', 32))
    this.#idKey = Buffer.from(hkdfSync('sha256', masterKey, Buffer.alloc(0), 'aid-gateway vault entry ids v1', 32))
    this.#load()   // refuses a wrong key at start-up
  }

  #id(name) { return createHmac('sha256', this.#idKey).update(name).digest('hex') }
  #aad(id) { return Buffer.from(`aid-gateway-vault:v${FORMAT}:${id}`) }

  #seal(id, plaintext) {
    const iv = randomBytes(12)
    const c = createCipheriv('aes-256-gcm', this.#encKey, iv)
    c.setAAD(this.#aad(id))
    const ct = Buffer.concat([c.update(plaintext, 'utf8'), c.final()])
    return { iv: iv.toString('base64'), tag: c.getAuthTag().toString('base64'), ct: ct.toString('base64') }
  }

  #open(id, box) {
    const d = createDecipheriv('aes-256-gcm', this.#encKey, Buffer.from(box.iv, 'base64'))
    d.setAAD(this.#aad(id))
    d.setAuthTag(Buffer.from(box.tag, 'base64'))
    return Buffer.concat([d.update(Buffer.from(box.ct, 'base64')), d.final()]).toString('utf8')
  }

  #load() {
    if (!existsSync(this.#path)) return { entries: {} }
    let file
    try { file = JSON.parse(readFileSync(this.#path, 'utf8')) } catch { throw new Error('the vault file is not readable') }
    if (file?.v !== FORMAT || typeof file.entries !== 'object' || !file.check) throw new Error('the vault file has an unknown format')
    let ok = false
    try { ok = this.#open('check', file.check) === CANARY } catch { /* fall through */ }
    if (!ok) throw new Error('the vault cannot be opened: wrong master key, or the file was modified')
    return file
  }

  #save(entries) {
    atomicWriteFile(this.#path, `${JSON.stringify({ v: FORMAT, check: this.#seal('check', CANARY), entries })}\n`)
  }

  async set(name, cred) {
    const value = validateCredential(cred)
    const file = this.#load()
    const id = this.#id(name)
    this.#save({ ...file.entries, [id]: this.#seal(id, JSON.stringify(value)) })
  }

  async get(name) {
    const id = this.#id(name)
    const box = this.#load().entries[id]
    if (!box) return null
    try { return new Credential(JSON.parse(this.#open(id, box))) } catch { throw new Error('a vault entry failed its integrity check') }
  }

  async has(name) { return Object.hasOwn(this.#load().entries, this.#id(name)) }
  async describe(name) { const c = await this.get(name); return c ? { type: c.type } : null }

  async delete(name) {
    const file = this.#load()
    const id = this.#id(name)
    if (!Object.hasOwn(file.entries, id)) return false
    const { [id]: _gone, ...rest } = file.entries
    this.#save(rest)
    return true
  }
}
