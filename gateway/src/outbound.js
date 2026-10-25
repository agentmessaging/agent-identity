import dns from 'node:dns'
import http from 'node:http'
import https from 'node:https'
import net from 'node:net'

/**
 * Every call the gateway makes to the outside world (the old system, its token endpoint, an issuer's keys or
 * introspection) goes through here. The destination is always a URL an operator configured, never anything from a request
 * or a token. Redirects are never followed. Unless the operator allows it, a destination that is, or resolves to, a
 * private, loopback, link-local or otherwise internal address is refused, at connection time (so DNS rebinding cannot
 * swap it in afterwards).
 */

const blocked = new net.BlockList()
for (const [a, p] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]]) blocked.addSubnet(a, p, 'ipv4')
for (const [a, p] of [['::', 128], ['::1', 128], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8], ['2001:db8::', 32], ['64:ff9b::', 96], ['2002::', 16]]) blocked.addSubnet(a, p, 'ipv6')

export function isBlockedAddress(ip) {
  const family = net.isIPv6(ip) ? 'ipv6' : net.isIPv4(ip) ? 'ipv4' : null
  return family === null ? true : blocked.check(ip, family)
}

export class OutboundError extends Error {
  /** @param {'timeout'|'too_large'|'blocked_address'|'connect'|'bad_protocol'} code */
  constructor(code) { super(code); this.name = 'OutboundError'; this.code = code }
}

/**
 * @param {URL} url
 * @param {{ method?: string, headers?: Record<string,string>, body?: Buffer|string, timeoutMs?: number, maxBytes?: number, allowPrivate?: boolean }} opts
 * @returns {Promise<{ status: number, headers: Record<string, string|string[]|undefined>, body: Buffer }>}
 */
export function outboundRequest(url, { method = 'GET', headers = {}, body, timeoutMs = 15_000, maxBytes = 5 * 1024 * 1024, allowPrivate = false } = {}) {
  return new Promise((resolve, reject) => {
    const secure = url.protocol === 'https:'
    if (!secure && url.protocol !== 'http:') return reject(new OutboundError('bad_protocol'))
    const host = url.hostname.replace(/^\[|\]$/g, '')
    if (!allowPrivate && net.isIP(host) && isBlockedAddress(host)) return reject(new OutboundError('blocked_address'))

    let settled = false
    let req
    const finish = (fn, value) => { if (settled) return; settled = true; clearTimeout(timer); fn(value) }
    const timer = setTimeout(() => { req?.destroy(); finish(reject, new OutboundError('timeout')) }, timeoutMs)

    const lookup = (hostname, opts, cb) => {
      dns.lookup(hostname, opts, (err, address, family) => {
        if (err) return cb(err)
        const list = Array.isArray(address) ? address : [{ address, family }]
        if (!allowPrivate && list.some(a => isBlockedAddress(a.address))) return cb(Object.assign(new Error('blocked address'), { code: 'ERR_BLOCKED' }))
        return Array.isArray(address) ? cb(null, address) : cb(null, address, family)
      })
    }

    const payload = body === undefined ? undefined : Buffer.from(body)
    const outHeaders = { ...headers }
    if (payload !== undefined) outHeaders['content-length'] = String(payload.length)
    try {
      req = (secure ? https : http).request({
        protocol: url.protocol, hostname: host, port: url.port || undefined, method, path: `${url.pathname}${url.search}`, headers: outHeaders, agent: false, lookup,
      })
    } catch {
      return finish(reject, new OutboundError('connect'))
    }
    req.on('error', e => finish(reject, new OutboundError(e?.code === 'ERR_BLOCKED' ? 'blocked_address' : 'connect')))
    req.on('response', res => {
      const declared = Number(res.headers['content-length'])
      if (Number.isFinite(declared) && declared > maxBytes) { res.destroy(); req.destroy(); return finish(reject, new OutboundError('too_large')) }
      const chunks = []
      let size = 0
      res.on('data', chunk => {
        size += chunk.length
        if (size > maxBytes) { res.destroy(); req.destroy(); return finish(reject, new OutboundError('too_large')) }
        chunks.push(chunk)
      })
      res.on('end', () => finish(resolve, { status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }))
      res.on('error', () => finish(reject, new OutboundError('connect')))
      res.on('close', () => { if (!res.complete) finish(reject, new OutboundError('connect')) })
    })
    req.end(payload)
  })
}

/**
 * A fetch-shaped function for the verifier (issuer keys, introspection) that obeys the same rules: configured address
 * only, no redirects, no internal addresses, small answers, short time. Only what the verifier uses is implemented.
 */
export function makeSafeFetch({ allowPrivate = false, timeoutMs = 5000 } = {}) {
  return async function safeFetch(input, init = {}) {
    const url = new URL(String(input))
    const headers = {}
    for (const [k, v] of Object.entries(init.headers ?? {})) headers[k.toLowerCase()] = String(v)
    const body = init.body === undefined ? undefined : String(init.body)
    const r = await outboundRequest(url, { method: init.method ?? 'GET', headers, body, timeoutMs, maxBytes: 1024 * 1024, allowPrivate })
    return { ok: r.status >= 200 && r.status < 300, status: r.status, async json() { return JSON.parse(r.body.toString('utf8')) } }
  }
}
