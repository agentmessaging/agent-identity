import { randomUUID } from 'node:crypto'
import { appendFileSync, existsSync, readFileSync, chmodSync } from 'node:fs'
import { createServer } from 'node:http'
import { join } from 'node:path'
import { performance } from 'node:perf_hooks'
import { AUTHENTICATION_CODES, bearerToken, createVerifier, JwksCache, normalizeConfig, RevocationList } from './verifier.js'
import { createAdmin } from './admin.js'
import { AuditLog } from './audit.js'
import { compileCatalog } from './catalog.js'
import { authHeader, secretStrings } from './credentials.js'
import { OAuthTokenCache } from './oauth.js'
import { makeSafeFetch, OutboundError, outboundRequest } from './outbound.js'
import { parseTarget, TargetError } from './paths.js'
import { RateLimiter } from './ratelimit.js'
import { SetError, verifySecurityEvent } from './set.js'
import { credentialName, TenantStore, validateTenantConfig } from './tenants.js'

/** Inbound headers that are forwarded. Everything else is dropped: cookies, API keys, Authorization, proxy credentials, hop-by-hop. */
const FORWARD_ALLOW = ['accept', 'accept-language', 'content-type', 'content-language', 'if-match', 'if-none-match', 'if-modified-since', 'if-unmodified-since', 'idempotency-key']
/** Response headers that are passed back. Set-Cookie, WWW-Authenticate and the like never are. */
const RESPONSE_ALLOW = ['content-type', 'content-language', 'content-disposition', 'etag', 'last-modified', 'cache-control', 'expires', 'retry-after', 'vary']
const BODY_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])
const SET_MAX_BYTES = 16 * 1024

const clean = (v, n = 256) => String(v ?? '').replace(/[^\x20-\x7e]/g, '').slice(0, n)

/** `code` is what the caller may be told; `reason` (default: the code) is what the audit log records */
class Refusal extends Error {
  constructor(status, code, { headers = {}, decision = 'deny', reason } = {}) { super(code); this.status = status; this.code = code; this.reason = reason ?? code; this.headers = headers; this.decision = decision }
}

/**
 * @param {object} opts
 * @param {string} opts.dataDir tenants/, audit.jsonl, revocations.jsonl live here
 * @param {{ get(name: string): Promise<object|null> }} opts.vault a credential vault (see vault.js)
 * @param {string} opts.adminToken bearer token for /_admin (at least 32 characters)
 * @param {boolean} [opts.allowInsecureHttp] let issuer keys and introspection use http (tests and demos only)
 * @param {boolean} [opts.allowInsecureUpstream] let a tenant's upstream use http (tests and demos only)
 * @param {boolean} [opts.allowPrivateUpstream] let upstream and issuers be internal addresses (self-hosted, or tests)
 */
export function createGateway({ dataDir, vault, adminToken, tenantStore, now = () => Date.now(), allowInsecureHttp = false, allowInsecureUpstream = false, allowPrivateUpstream = false, auditSize = 2000 } = {}) {
  if (typeof dataDir !== 'string' || !dataDir) throw new Error('createGateway needs a dataDir')
  if (!vault || typeof vault.get !== 'function') throw new Error('createGateway needs a credential vault')
  if (typeof adminToken !== 'string' || adminToken.length < 32) throw new Error('AID_GATEWAY_ADMIN_TOKEN is not set or too short (at least 32 characters). Generate one with: openssl rand -base64 32')

  const store = tenantStore ?? new TenantStore(dataDir)
  const audit = new AuditLog({ file: join(dataDir, 'audit.jsonl'), size: auditSize })
  const limiter = new RateLimiter({ now })
  const oauth = new OAuthTokenCache({ now, allowPrivate: allowPrivateUpstream })
  const safeFetch = makeSafeFetch({ allowPrivate: allowPrivateUpstream })
  const jwks = new JwksCache({ fetch: safeFetch, now, allowInsecureHttp })
  const revocations = new Map()      // tenant -> RevocationList, kept across config changes
  const seenEvents = new Map()       // tenant -> Map(event key -> until)
  const runtimes = new Map()         // tenant -> { cfg, ... } rebuilt whenever the stored config object changes
  const revocationFile = join(dataDir, 'revocations.jsonl')

  const listFor = tenant => {
    let l = revocations.get(tenant)
    if (!l) { l = new RevocationList({ now }); revocations.set(tenant, l) }
    return l
  }

  if (existsSync(revocationFile)) {
    for (const line of readFileSync(revocationFile, 'utf8').split('\n')) {
      if (!line.trim()) continue
      try { const { tenant, event } = JSON.parse(line); listFor(tenant).apply(event) } catch { /* a damaged line is skipped; introspection stays the source of truth */ }
    }
  }

  /**
   * The live form of a tenant's stored config. It is validated again here, whatever wrote the file (the admin API, the CLI or
   * a person with an editor), so a hand-edited file cannot switch a control off; one that does not validate is not served.
   */
  function runtimeFor(name, source) {
    const hit = runtimes.get(name)
    if (hit && hit.source === source) return hit
    let cfg
    try { cfg = validateTenantConfig(source, { allowInsecureHttp, allowInsecureUpstream, allowPrivateUpstream }).config } catch {
      const bad = { source, invalid: true }
      runtimes.set(name, bad)
      return bad
    }
    const verifierConfig = { issuers: cfg.issuers, grants: cfg.grants, clockSkewSec: cfg.clockSkewSec }
    const rt = {
      source, cfg,
      catalog: compileCatalog(cfg.catalog),
      issuers: normalizeConfig(verifierConfig).issuers,
      revocations: listFor(name),
      verifier: createVerifier(verifierConfig, { fetch: safeFetch, now, jwks, revocations: listFor(name), allowInsecureHttp }),
      base: new URL(cfg.upstream.baseUrl),
    }
    runtimes.set(name, rt)
    return rt
  }

  function findAgent(cfg, principal) {
    const address = principal.address?.toLowerCase()
    const hits = []
    for (const [key, entry] of Object.entries(cfg.agents)) {
      if (entry.issuer && entry.issuer !== principal.issuer) continue
      const k = key.toLowerCase()
      if ((address && k === address) || key === principal.agentId) hits.push([key, entry])
    }
    if (hits.length === 0) return null
    return { key: hits[0][0], entry: hits[0][1], disabled: hits.some(([, e]) => e.disabled) }
  }

  const sendJson = (res, status, body, headers = {}) => {
    const text = JSON.stringify(body)
    res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(text), 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', connection: 'close', ...headers })
    res.end(text)
  }

  async function readBody(req, max) {
    const declared = Number(req.headers['content-length'])
    if (Number.isFinite(declared) && declared > max) throw new Refusal(413, 'body_too_large')
    const chunks = []
    let size = 0
    for await (const chunk of req) {
      size += chunk.length
      if (size > max) throw new Refusal(413, 'body_too_large')
      chunks.push(chunk)
    }
    return Buffer.concat(chunks)
  }

  /** The Location of a redirect, kept only if it points back into the same upstream; then rewritten to go through the gateway */
  function rewriteLocation(value, tenant, base) {
    try {
      const u = new URL(String(value), base.href)
      if (u.origin !== base.origin) return null
      const prefix = base.pathname.replace(/\/$/, '')
      if (prefix && u.pathname !== prefix && !u.pathname.startsWith(`${prefix}/`)) return null
      return `/${tenant}${u.pathname.slice(prefix.length) || '/'}${u.search}`
    } catch { return null }
  }

  async function handleEvents(req, res, ctx, tenant, cfg, rt) {
    if (req.method !== 'POST') throw new Refusal(405, 'method_not_allowed', { headers: { allow: 'POST' } })
    if (!cfg.events) throw new Refusal(403, 'events_disabled')
    const body = (await readBody(req, SET_MAX_BYTES).catch(() => { throw new SetError('invalid_request', 'too large') })).toString('utf8').trim()
    let seen = seenEvents.get(tenant)
    if (!seen) { seen = new Map(); seenEvents.set(tenant, seen) }
    const events = await verifySecurityEvent(body, { issuers: rt.issuers, jwks, audience: cfg.events.audience, maxAgeSec: cfg.events.maxAgeSec, now, seen, clockSkewSec: cfg.clockSkewSec ?? 60 })
    for (const event of events) {
      rt.revocations.apply(event)
      appendFileSync(revocationFile, `${JSON.stringify({ tenant, at: new Date(now()).toISOString(), event })}\n`, { mode: 0o600 })
    }
    try { chmodSync(revocationFile, 0o600) } catch { /* best effort */ }
    ctx.reason = `event:${events.map(e => e.type).join('+') || 'ignored'}`
    ctx.decision = 'allow'
    ctx.issuer = events[0]?.issuer ?? null
    sendJson(res, 202, { accepted: events.length })
  }

  async function handleProxy(req, res, ctx, tenant, target, cfg, rt) {
    // 1. who is this
    const token = bearerToken(req.headers.authorization)
    if (!token) throw new Refusal(401, 'no_token', { headers: { 'www-authenticate': 'Bearer' } })
    const verdict = await rt.verifier.verify(token)
    if (!verdict.ok) {
      if (AUTHENTICATION_CODES.has(verdict.code)) throw new Refusal(401, 'invalid_token', { reason: verdict.code, headers: { 'www-authenticate': 'Bearer error="invalid_token"' } })
      if (verdict.code === 'internal_error') throw new Refusal(500, 'internal_error', { decision: 'error' })
      throw new Refusal(403, verdict.code, { headers: { 'www-authenticate': 'Bearer error="insufficient_scope"' } })
    }
    const principal = verdict.principal
    Object.assign(ctx, { agentId: principal.agentId, agentAddress: principal.address ?? null, issuer: principal.issuer, jti: principal.jti || null })

    // 2. is this agent set up here, and switched on
    const agent = findAgent(cfg, principal)
    if (!agent) throw new Refusal(403, 'agent_not_configured')
    if (agent.disabled) throw new Refusal(403, 'agent_disabled')

    // 3. not too fast
    const rate = limiter.take(`${tenant}\u0000${principal.issuer}\u0000${principal.agentId}`, cfg.limits)
    if (!rate.ok) throw new Refusal(429, 'rate_limited', { headers: { 'retry-after': String(rate.retryAfterSec) } })

    // 4. is this request in the catalog, and does the token carry its permission
    if (!rt.catalog.methods.has(req.method)) throw new Refusal(403, 'not_in_catalog')
    const hit = rt.catalog.match(req.method, target.segments)
    if (!hit) { ctx.pathSample = clean(target.path, 120); throw new Refusal(403, 'not_in_catalog') }
    ctx.pathTemplate = hit.pathTemplate
    ctx.permission = hit.permission
    if (!principal.permissions.includes(hit.permission)) throw new Refusal(403, 'insufficient_permissions', { headers: { 'www-authenticate': 'Bearer error="insufficient_scope"' } })

    // 5. the body, then the agent's own credential
    let body
    if (BODY_METHODS.has(req.method)) body = await readBody(req, cfg.limits.maxBodyBytes)
    else if ((Number(req.headers['content-length']) || 0) > 0 || req.headers['transfer-encoding']) throw new Refusal(400, 'unexpected_body')
    const credName = credentialName(tenant, agent.key, agent.entry)
    let cred
    try { cred = await vault.get(credName) } catch { throw new Refusal(502, 'credential_unavailable', { decision: 'error' }) }
    if (!cred) throw new Refusal(502, 'no_credential', { decision: 'error' })
    const secret = cred.reveal()
    let accessToken
    if (secret.type === 'oauth2_client_credentials') {
      if (!cfg.upstream.tokenUrl) throw new Refusal(502, 'credential_unavailable', { decision: 'error' })
      try { accessToken = await oauth.get(credName, secret, cfg.upstream) } catch { throw new Refusal(502, 'credential_unavailable', { decision: 'error' }) }
    }

    // 6. forward, to the one host this tenant has
    const headers = {}
    for (const name of [...FORWARD_ALLOW, ...(cfg.upstream.forwardHeaders ?? [])]) if (typeof req.headers[name] === 'string') headers[name] = req.headers[name]
    Object.assign(headers, authHeader(secret, accessToken), {
      'accept-encoding': 'identity', 'user-agent': 'aid-gateway/0.1', 'x-request-id': ctx.requestId,
      'x-aid-agent': clean(principal.agentId), 'x-aid-agent-address': clean(principal.address), 'x-aid-issuer': clean(principal.issuer, 512),
    })
    const prefix = rt.base.pathname.replace(/\/$/, '')
    const url = new URL(`${rt.base.origin}${prefix}${target.path}${target.query}`)
    if (url.origin !== rt.base.origin) throw new Refusal(500, 'internal_error', { decision: 'error' })   // cannot happen; the host is never taken from the request
    let up
    try {
      up = await outboundRequest(url, { method: req.method, headers, body: body?.length ? body : undefined, timeoutMs: cfg.limits.timeoutMs, maxBytes: cfg.limits.maxResponseBytes, allowPrivate: allowPrivateUpstream })
    } catch (e) {
      if (!(e instanceof OutboundError)) throw e
      if (e.code === 'timeout') throw new Refusal(504, 'upstream_timeout', { decision: 'error' })
      if (e.code === 'too_large') throw new Refusal(502, 'upstream_response_too_large', { decision: 'error' })
      throw new Refusal(502, 'upstream_unavailable', { decision: 'error' })
    }
    ctx.upstreamStatus = up.status
    if (up.status === 401 && secret.type === 'oauth2_client_credentials') oauth.invalidate(credName)

    // 7. back to the agent: an allow-list of headers, and a refusal if the old system echoed the credential
    const out = {}
    for (const name of RESPONSE_ALLOW) if (up.headers[name] !== undefined) out[name] = Array.isArray(up.headers[name]) ? up.headers[name].join(', ') : up.headers[name]
    if (up.status >= 300 && up.status < 400 && up.headers.location) {
      const loc = rewriteLocation(up.headers.location, tenant, rt.base)
      if (loc) out.location = loc
    }
    const leaks = secretStrings(secret, accessToken)
    const haystack = Buffer.concat([up.body, Buffer.from(Object.values(out).join('\n'))])
    if (leaks.some(s => haystack.includes(s))) throw new Refusal(502, 'upstream_response_blocked', { decision: 'error' })

    ctx.decision = 'allow'
    ctx.reason = 'ok'
    const bodiless = req.method === 'HEAD' || up.status === 204 || up.status === 304 || up.status < 200
    out['x-request-id'] = ctx.requestId
    out['x-content-type-options'] = 'nosniff'
    if (!bodiless) out['content-length'] = String(up.body.length)
    else if (req.method === 'HEAD' && up.headers['content-length'] !== undefined) out['content-length'] = String(up.headers['content-length'])
    res.writeHead(up.status, out)
    res.end(bodiless ? undefined : up.body)
    ctx.status = up.status
  }

  const admin = createAdmin({ store, vault, audit, adminToken, now, validation: { allowInsecureHttp, allowInsecureUpstream, allowPrivateUpstream }, oauth })

  async function handler(req, res) {
    const started = performance.now()
    const ctx = { requestId: randomUUID(), tenant: null, agentId: null, agentAddress: null, issuer: null, jti: null, pathTemplate: null, permission: null, decision: 'deny', reason: 'unknown', status: 0, upstreamStatus: null }
    const pathOnly = (req.url ?? '').split('?')[0]
    if (pathOnly === '/_admin' || pathOnly.startsWith('/_admin/')) return admin.handle(req, res)
    try {
      let target
      try { target = parseTarget(req.url) } catch (e) {
        if (e instanceof TargetError) throw new Refusal(400, 'bad_request', { reason: e.code })
        throw e
      }
      ctx.tenant = target.tenant
      const source = store.get(target.tenant)
      if (!source) throw new Refusal(404, 'not_found', { reason: 'unknown_tenant' })
      const rt = runtimeFor(target.tenant, source)
      if (rt.invalid) throw new Refusal(500, 'internal_error', { decision: 'error', reason: 'tenant_config_invalid' })
      const cfg = rt.cfg
      if (target.segments[0] === '_events') {
        if (target.segments.length !== 1) throw new Refusal(404, 'not_found')
        await handleEvents(req, res, ctx, target.tenant, cfg, rt)
        ctx.status = 202
      } else {
        if (cfg.disabled) throw new Refusal(403, 'tenant_disabled')
        await handleProxy(req, res, ctx, target.tenant, target, cfg, rt)
      }
    } catch (e) {
      let status
      let body
      let headers = {}
      if (e instanceof Refusal) {
        status = e.status
        ctx.decision = e.decision
        ctx.reason = e.reason
        body = status === 403 ? { error: 'forbidden', ...(ctx.agentId ? { code: e.code } : {}) } : { error: e.code }
        headers = e.headers
      } else if (e instanceof SetError) {
        status = 400; ctx.decision = 'deny'; ctx.reason = `event_${e.err}`
        body = { err: e.err, description: e.description }
      } else {
        status = 500; ctx.decision = 'error'; ctx.reason = 'internal_error'; body = { error: 'internal_error' }
      }
      ctx.status = status
      if (!res.headersSent) sendJson(res, status, { ...body, request_id: ctx.requestId }, { ...headers, 'x-request-id': ctx.requestId })
    } finally {
      audit.record({
        tenant: ctx.tenant, agentAddress: ctx.agentAddress, agentId: ctx.agentId, issuer: ctx.issuer, jti: ctx.jti,
        method: clean(req.method, 16), pathTemplate: ctx.pathTemplate, ...(ctx.pathTemplate ? {} : ctx.pathSample ? { pathSample: ctx.pathSample } : {}),
        permission: ctx.permission, decision: ctx.decision, reason: ctx.reason, status: ctx.status, upstreamStatus: ctx.upstreamStatus,
        latencyMs: Math.round(performance.now() - started), requestId: ctx.requestId,
      })
    }
  }

  const server = createServer({ requestTimeout: 60_000, headersTimeout: 15_000, maxHeaderSize: 16 * 1024 }, (req, res) => {
    handler(req, res).catch(() => { try { if (!res.headersSent) res.writeHead(500).end() ; else res.destroy() } catch { /* nothing more to do */ } })
  })
  server.keepAliveTimeout = 5000

  return {
    server, audit, store, handler,
    warnings: [],
    listen: (port = 0, host = '127.0.0.1') => new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, host, () => resolve(server.address())) }),
    close: async () => { await new Promise(r => { server.close(r); server.closeAllConnections?.() }); await audit.flush() },
  }
}
