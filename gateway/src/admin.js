import { createHash, timingSafeEqual } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { bearerToken } from './verifier.js'
import { validateCredential } from './credentials.js'
import { credentialName, redactTenant, restoreSecrets, validateTenantConfig } from './tenants.js'
import { TENANT_NAME } from './paths.js'

const MAX_ADMIN_BODY = 256 * 1024
const uiHtml = readFileSync(fileURLToPath(new URL('./ui.html', import.meta.url)), 'utf8')
const sha = s => createHash('sha256').update(s).digest('base64')
const inline = tag => [...uiHtml.matchAll(new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`, 'g'))].map(m => `'sha256-${sha(m[1])}'`).join(' ')
const UI_CSP = `default-src 'none'; script-src ${inline('script')}; style-src ${inline('style')}; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`

class AdminError extends Error {
  constructor(status, code, detail) { super(code); this.status = status; this.code = code; this.detail = detail }
}

/** Constant-time comparison of two strings of any length (both are hashed first, so length does not leak) */
export function safeEqual(a, b) {
  return timingSafeEqual(createHash('sha256').update(String(a)).digest(), createHash('sha256').update(String(b)).digest())
}

/**
 * The admin API under /_admin. Everything but /_admin/health and /_admin/ui needs `Authorization: Bearer <admin token>`.
 * No response ever contains a credential or an introspection secret.
 */
export function createAdmin({ store, vault, audit, adminToken, now, validation }) {
  const failures = new Map()   // remote address -> [timestamps]

  function limited(addr) {
    const recent = (failures.get(addr) ?? []).filter(t => now() - t < 60_000)
    failures.set(addr, recent)
    return recent.length >= 30
  }

  const json = (res, status, body, headers = {}) => {
    const text = JSON.stringify(body)
    res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(text), 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', ...headers })
    res.end(text)
  }

  async function body(req) {
    const chunks = []
    let size = 0
    for await (const c of req) {
      size += c.length
      if (size > MAX_ADMIN_BODY) throw new AdminError(413, 'body_too_large')
      chunks.push(c)
    }
    try {
      const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'))
      if (!parsed || typeof parsed !== 'object') throw new Error('x')
      return parsed
    } catch { throw new AdminError(400, 'invalid_json') }
  }

  const note = (tenant, action) => audit.record({ tenant, method: 'ADMIN', permission: action, decision: 'allow', reason: 'admin_action', status: 200 })

  function tenantOr404(name) {
    if (!TENANT_NAME.test(name)) throw new AdminError(404, 'not_found')
    const cfg = store.get(name)
    if (!cfg) throw new AdminError(404, 'not_found')
    return cfg
  }

  const agentKey = raw => {
    let key
    try { key = decodeURIComponent(raw) } catch { throw new AdminError(400, 'bad_agent') }
    if (!/^[\x21-\x7e]{1,254}$/.test(key)) throw new AdminError(400, 'bad_agent')
    return key
  }

  async function agentView(tenant, cfg) {
    const out = []
    for (const [key, a] of Object.entries(cfg.agents)) {
      const d = await vault.describe(credentialName(tenant, key, a))
      out.push({ key, issuer: a.issuer ?? cfg.issuers[0].issuer, disabled: !!a.disabled, upstreamUser: a.upstreamUser ?? null, note: a.note ?? null, hasCredential: !!d, credentialType: d?.type ?? null })
    }
    return out
  }

  function save(name, cfg, extra = {}) {
    const { config, warnings } = validateTenantConfig(cfg, validation)
    store.put(name, config)
    return { config, warnings, ...extra }
  }

  async function route(req, res, url, parts) {
    const method = req.method
    // parts: ['tenants', name?, 'agents'?, key?, action?]
    if (parts[0] === 'audit' && method === 'GET') {
      const q = url.searchParams
      const limit = Math.min(Number(q.get('limit')) || 100, 1000)
      return json(res, 200, { records: audit.query({ tenant: q.get('tenant') || undefined, agent: q.get('agent') || undefined, decision: q.get('decision') || undefined, reason: q.get('reason') || undefined, limit }) })
    }
    if (parts[0] !== 'tenants') throw new AdminError(404, 'not_found')
    if (parts.length === 1 && method === 'GET') {
      return json(res, 200, { tenants: store.list().map(n => { const c = store.get(n); return { name: n, displayName: c.displayName ?? null, disabled: !!c.disabled, upstream: c.upstream.baseUrl, agents: Object.keys(c.agents).length, catalogEntries: c.catalog.length } }) })
    }
    const name = parts[1]
    if (!TENANT_NAME.test(name ?? '')) throw new AdminError(400, 'bad_tenant')
    if (parts.length === 2) {
      if (method === 'GET') return json(res, 200, { name, config: redactTenant(tenantOr404(name)) })
      if (method === 'PUT') {
        const existing = store.get(name)
        const incoming = restoreSecrets(await body(req), existing)
        // A kill switch is not silently released by an update that does not mention it: say `"disabled": false` to turn something back on
        if (existing?.disabled && incoming.disabled === undefined) incoming.disabled = true
        for (const [k, a] of Object.entries(incoming.agents ?? {})) if (existing?.agents?.[k]?.disabled && a && typeof a === 'object' && a.disabled === undefined) a.disabled = true
        const r = save(name, incoming)
        note(name, existing ? 'tenant.update' : 'tenant.create')
        return json(res, existing ? 200 : 201, { ok: true, warnings: r.warnings, config: redactTenant(r.config) })
      }
      throw new AdminError(405, 'method_not_allowed')
    }
    const cfg = tenantOr404(name)
    if (parts.length === 3 && (parts[2] === 'disable' || parts[2] === 'enable') && method === 'POST') {
      const next = structuredClone(cfg)
      if (parts[2] === 'disable') next.disabled = true; else delete next.disabled
      save(name, next)
      note(name, `tenant.${parts[2]}`)
      return json(res, 200, { ok: true, disabled: parts[2] === 'disable' })
    }
    if (parts[2] !== 'agents') throw new AdminError(404, 'not_found')
    if (parts.length === 3 && method === 'GET') return json(res, 200, { agents: await agentView(name, cfg) })
    const key = agentKey(parts[3] ?? '')
    const action = parts[4]
    if (parts.length === 5 && (action === 'disable' || action === 'enable') && method === 'POST') {
      const found = Object.keys(cfg.agents).filter(k => k.toLowerCase() === key.toLowerCase())
      if (found.length === 0) throw new AdminError(404, 'not_found')
      const next = structuredClone(cfg)
      for (const k of found) { if (action === 'disable') next.agents[k].disabled = true; else delete next.agents[k].disabled }
      save(name, next)
      note(name, `agent.${action}`)
      return json(res, 200, { ok: true, agent: key, disabled: action === 'disable' })
    }
    if (parts.length === 5 && action === 'credential') {
      const existingKey = Object.keys(cfg.agents).find(k => k.toLowerCase() === key.toLowerCase())
      if (method === 'PUT') {
        const input = await body(req)
        let cred
        try { cred = validateCredential(input.credential, { tokenUrlConfigured: !!cfg.upstream.tokenUrl }) } catch (e) { throw new AdminError(400, 'invalid_credential', e.message) }
        const next = structuredClone(cfg)
        const k = existingKey ?? key
        next.agents[k] = { ...(next.agents[k] ?? {}), ...(input.issuer ? { issuer: input.issuer } : {}), ...(input.upstreamUser ? { upstreamUser: input.upstreamUser } : {}) }
        if (!next.agents[k].issuer && cfg.issuers.length === 1) next.agents[k].issuer = cfg.issuers[0].issuer
        const saved = validateTenantConfig(next, validation).config
        await vault.set(credentialName(name, k, saved.agents[k]), cred)
        store.put(name, saved)
        note(name, 'agent.credential.set')
        return json(res, 200, { ok: true, agent: k, credentialType: cred.type })
      }
      if (method === 'DELETE') {
        if (!existingKey) throw new AdminError(404, 'not_found')
        await vault.delete(credentialName(name, existingKey, cfg.agents[existingKey]))
        note(name, 'agent.credential.delete')
        return json(res, 200, { ok: true })
      }
    }
    throw new AdminError(404, 'not_found')
  }

  return {
    async handle(req, res) {
      const url = new URL(req.url, 'http://x')
      const sub = url.pathname.slice('/_admin'.length).replace(/^\//, '')
      try {
        if (req.method === 'GET' && sub === 'health') return json(res, 200, { status: 'ok' })
        if (req.method === 'GET' && sub === 'ui') {
          res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'content-security-policy': UI_CSP, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', 'content-length': Buffer.byteLength(uiHtml) })
          return res.end(uiHtml)
        }
        const addr = req.socket.remoteAddress ?? '?'
        if (limited(addr)) throw new AdminError(429, 'too_many_failures')
        const token = bearerToken(req.headers.authorization)
        if (!token || !safeEqual(token, adminToken)) {
          failures.get(addr).push(now())
          return json(res, 401, { error: 'unauthorized' }, { 'www-authenticate': 'Bearer' })
        }
        await route(req, res, url, sub.split('/').filter(Boolean))
      } catch (e) {
        if (e instanceof AdminError) return json(res, e.status, { error: e.code, ...(e.detail ? { detail: e.detail } : {}) })
        if (e instanceof TypeError) return json(res, 400, { error: 'invalid_config', detail: e.message })
        return json(res, 500, { error: 'internal_error' })
      }
    },
  }
}
