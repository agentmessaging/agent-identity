import { randomBytes } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { createGateway } from './gateway.js'
import { importOpenApi } from './openapi.js'
import { atomicWriteFile } from './fsutil.js'
import { assertTenantName, TenantStore, validateTenantConfig, credentialName } from './tenants.js'
import { validateCredential } from './credentials.js'
import { EncryptedFileVault, loadMasterKey } from './vault.js'

const USAGE = `aid-gateway: an AID hosted gateway for systems that have their own credentials (kind B)

  aid-gateway init [--dir DIR]
      create the data directory and a sample tenant, and print a master key and an admin token to keep
  aid-gateway import-openapi FILE.json [--out catalog.json]
      draft a permission catalog from an OpenAPI 3 document (JSON only) for you to review and edit
  aid-gateway add-agent-credential --tenant T --agent ADDRESS --type header|bearer|basic|oauth2
        [--header-name NAME] [--username U] [--client-id ID] [--scope S] [--issuer ISSUER] [--dir DIR]
      store an agent's credential for the old system. The secret is read from standard input (hidden when
      typed), never from an argument. Needs AID_GATEWAY_MASTER_KEY.
  aid-gateway run [--dir DIR] [--host 127.0.0.1] [--port 8787]
      start the gateway. Needs AID_GATEWAY_MASTER_KEY and AID_GATEWAY_ADMIN_TOKEN (32+ characters).

Environment: AID_GATEWAY_ALLOW_PRIVATE_UPSTREAM=1 lets a tenant's upstream (and its issuers) be an internal address, which
a gateway inside the customer's own network needs; leave it unset on a shared host.`

const KNOWN_FLAGS = new Set(['dir', 'out', 'tenant', 'agent', 'type', 'header-name', 'username', 'client-id', 'scope', 'issuer', 'host', 'port'])

function parseArgs(argv) {
  const positional = []
  const flags = {}
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith('--')) {
      const key = argv[i].slice(2)
      if (!KNOWN_FLAGS.has(key)) throw new Error(`unknown option --${key} (secrets are never accepted as arguments; pipe them on standard input)`)
      const value = argv[i + 1]
      if (value === undefined || value.startsWith('--')) throw new Error(`--${key} needs a value`)
      flags[key] = value
      i++
    } else positional.push(argv[i])
  }
  return { positional, flags }
}

/** Read a secret from stdin: the whole stream, minus one trailing newline; hidden if it is a terminal */
export async function readSecret(stdin, stderr) {
  if (stdin.isTTY) {
    stderr.write('Secret (input is hidden): ')
    return new Promise((resolveSecret, reject) => {
      let text = ''
      stdin.setRawMode(true)
      stdin.resume()
      stdin.setEncoding('utf8')
      const onData = ch => {
        for (const c of ch) {
          if (c === '\u0003') { stdin.setRawMode(false); stdin.pause(); stdin.off('data', onData); return reject(new Error('cancelled')) }
          if (c === '\r' || c === '\n') { stdin.setRawMode(false); stdin.pause(); stdin.off('data', onData); stderr.write('\n'); return resolveSecret(text) }
          if (c === '\u007f') text = text.slice(0, -1); else text += c
        }
      }
      stdin.on('data', onData)
    })
  }
  const chunks = []
  for await (const c of stdin) chunks.push(Buffer.from(c))
  return Buffer.concat(chunks).toString('utf8').replace(/\r?\n$/, '')
}

const SAMPLE_TENANT = {
  displayName: 'Sample tenant (edit me)',
  issuers: [{
    issuer: 'https://auth.example.com/sample', kind: 'own', jwksUri: 'https://auth.example.com/sample/.well-known/jwks.json',
    audience: ['https://gateway.example.com/sample'], allowAllActiveAgents: true,
    introspection: { endpoint: 'https://auth.example.com/sample/oauth/introspect', clientId: 'gateway', clientSecret: 'replace-me' },
    scopeMap: { 'contacts:read': ['contacts.read'], 'contacts:create': ['contacts.create'] },
  }],
  grants: [],
  events: { audience: 'https://gateway.example.com/sample/_events', maxAgeSec: 300 },
  upstream: { baseUrl: 'https://crm.example.com/api' },
  catalog: [
    { permission: 'contacts.read', method: 'GET', pathTemplate: '/contacts' },
    { permission: 'contacts.read', method: 'GET', pathTemplate: '/contacts/{id}' },
    { permission: 'contacts.create', method: 'POST', pathTemplate: '/contacts' },
  ],
  agents: { 'lola@sample.example': { upstreamUser: 'lola' } },
  limits: { ratePerMinute: 120, burst: 30 },
}

/**
 * @param {string[]} argv
 * @param {{ env?: NodeJS.ProcessEnv, stdin?: any, stdout?: {write(s: string): any}, stderr?: {write(s: string): any} }} [io]
 * @returns {Promise<number | { gateway: object, address: object }>} an exit code, or the running gateway for `run`
 */
export async function main(argv, { env = process.env, stdin = process.stdin, stdout = process.stdout, stderr = process.stderr } = {}) {
  const out = s => stdout.write(`${s}\n`)
  const err = s => stderr.write(`${s}\n`)
  try {
    const [cmd, ...rest] = argv
    if (!cmd || cmd === '--help' || cmd === 'help') { out(USAGE); return cmd ? 0 : 1 }
    const { positional, flags } = parseArgs(rest)
    const dir = resolve(flags.dir ?? env.AID_GATEWAY_DIR ?? './gateway-data')

    if (cmd === 'init') {
      mkdirSync(dir, { recursive: true, mode: 0o700 })
      const store = new TenantStore(dir)
      if (store.list().includes('sample')) out(`${dir}/tenants/sample.json already exists; left alone`)
      else {
        const { config } = validateTenantConfig(SAMPLE_TENANT)
        store.put('sample', config)
        out(`created ${dir}/tenants/sample.json`)
      }
      out('')
      out('Keep these two values somewhere safe (they are not stored anywhere by the gateway). Losing the master key means')
      out('losing every stored credential; anyone holding the admin token controls the gateway.')
      out(`  export AID_GATEWAY_MASTER_KEY=${randomBytes(32).toString('base64')}`)
      out(`  export AID_GATEWAY_ADMIN_TOKEN=${randomBytes(32).toString('base64url')}`)
      out('')
      out(`Then: aid-gateway add-agent-credential --dir ${dir} --tenant sample --agent lola@sample.example --type header --header-name X-API-Key`)
      out(`      aid-gateway run --dir ${dir}`)
      return 0
    }

    if (cmd === 'import-openapi') {
      if (!positional[0]) throw new Error('import-openapi needs a file')
      let doc
      try { doc = JSON.parse(readFileSync(positional[0], 'utf8')) } catch { throw new Error('the file is not JSON (YAML is not supported; convert it to JSON first)') }
      const draft = importOpenApi(doc)
      const text = `${JSON.stringify(draft, null, 2)}\n`
      if (flags.out) { atomicWriteFile(resolve(flags.out), text); out(`wrote a DRAFT catalog with ${draft.catalog.length} entries to ${flags.out}; review it before use`) } else out(text.trimEnd())
      for (const n of draft.notes) err(`note: ${n}`)
      return 0
    }

    if (cmd === 'add-agent-credential') {
      const { tenant, agent, type } = flags
      if (!tenant || !agent || !type) throw new Error('add-agent-credential needs --tenant, --agent and --type')
      assertTenantName(tenant)
      const key = loadMasterKey(env)
      const store = new TenantStore(dir)
      const cfg = store.get(tenant)
      if (!cfg) throw new Error(`no tenant "${tenant}" in ${dir}`)
      const secret = await readSecret(stdin, stderr)
      if (!secret) throw new Error('the secret on standard input is empty')
      let raw
      switch (type) {
        case 'header': raw = { type: 'header', name: flags['header-name'], value: secret }; break
        case 'bearer': raw = { type: 'bearer', token: secret }; break
        case 'basic': raw = { type: 'basic', username: flags.username, password: secret }; break
        case 'oauth2': raw = { type: 'oauth2_client_credentials', clientId: flags['client-id'], clientSecret: secret, ...(flags.scope ? { scope: flags.scope } : {}) }; break
        default: throw new Error('--type must be header, bearer, basic or oauth2')
      }
      const cred = validateCredential(raw, { tokenUrlConfigured: !!cfg.upstream.tokenUrl })
      const existing = Object.keys(cfg.agents).find(k => k.toLowerCase() === agent.toLowerCase())
      const next = structuredClone(cfg)
      const k = existing ?? agent
      next.agents[k] = { ...(next.agents[k] ?? {}), ...(flags.issuer ? { issuer: flags.issuer } : {}) }
      if (!next.agents[k].issuer && cfg.issuers.length === 1) next.agents[k].issuer = cfg.issuers[0].issuer
      const { config } = validateTenantConfig(next, { allowInsecureHttp: true, allowInsecureUpstream: true, allowPrivateUpstream: true })
      await new EncryptedFileVault(join(dir, 'vault.json'), key).set(credentialName(tenant, k, config.agents[k]), cred)
      store.put(tenant, config)
      out(`stored a ${cred.type} credential for ${k} in tenant ${tenant}`)
      return 0
    }

    if (cmd === 'run') {
      const key = loadMasterKey(env)
      const adminToken = env.AID_GATEWAY_ADMIN_TOKEN
      if (!adminToken || adminToken.length < 32) throw new Error('AID_GATEWAY_ADMIN_TOKEN is not set or shorter than 32 characters')
      if (!existsSync(dir)) throw new Error(`${dir} does not exist; run "aid-gateway init" first`)
      const gateway = createGateway({
        dataDir: dir, vault: new EncryptedFileVault(join(dir, 'vault.json'), key), adminToken,
        allowPrivateUpstream: env.AID_GATEWAY_ALLOW_PRIVATE_UPSTREAM === '1',
      })
      const address = await gateway.listen(Number(flags.port ?? 8787), flags.host ?? '127.0.0.1')
      out(`aid-gateway listening on http://${address.address}:${address.port} (data ${dir}); put TLS in front of it`)
      out(`admin page: http://${address.address}:${address.port}/_admin/ui`)
      return { gateway, address }
    }

    err(`unknown command "${cmd}"`)
    err(USAGE)
    return 1
  } catch (e) {
    err(`aid-gateway: ${e.message}`)
    return 1
  }
}
