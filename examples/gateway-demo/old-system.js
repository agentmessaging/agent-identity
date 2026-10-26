/**
 * A PRETEND OLD SYSTEM that can only check its own per-user API keys (kind B in docs/federation.md). It cannot read an
 * outside token and there is no way to teach it: anything not an `X-API-Key` of one of its own users is refused. Each
 * user has permissions held HERE, and they are the limit of what that user can do, whoever is calling for them.
 */
import { createServer } from 'node:http'

/**
 * @param {Array<{ name: string, kind: 'human'|'agent', apiKey: string, permissions: string[] }>} users
 */
export async function startOldSystem({ users }) {
  const contacts = [{ id: 1, name: 'Existing customer' }]
  const orders = [{ id: 100, total: 250 }, { id: 101, total: 90 }]
  /** this system's own log: who did what, as the system itself sees it */
  const audit = []
  let requests = 0

  const server = createServer(async (req, res) => {
    requests++
    const send = (code, body) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)) }
    const user = users.find(u => u.apiKey && u.apiKey === req.headers['x-api-key'])
    const url = new URL(req.url, 'http://x')
    if (!user) {
      audit.push({ who: '(nobody)', action: `${req.method} ${url.pathname}`, ok: false, why: 'no valid API key' })
      return send(401, { error: 'unauthorized', message: 'send your X-API-Key' })
    }
    const need = (perm, run) => {
      if (!user.permissions.includes(perm)) {
        audit.push({ who: user.name, kind: user.kind, action: `${req.method} ${url.pathname}`, ok: false, why: `lacks ${perm}` })
        return send(403, { error: 'forbidden', message: `${user.name} may not ${perm}` })
      }
      const out = run()
      audit.push({ who: user.name, kind: user.kind, action: `${req.method} ${url.pathname}`, ok: true })
      return send(out.status ?? 200, out.body)
    }
    let body = ''
    for await (const c of req) body += c
    if (req.method === 'GET' && url.pathname === '/contacts') return need('contacts:read', () => ({ body: contacts }))
    if (req.method === 'POST' && url.pathname === '/contacts') {
      return need('contacts:create', () => { const c = { id: contacts.length + 1, name: JSON.parse(body || '{}').name ?? 'unnamed', createdBy: user.name }; contacts.push(c); return { status: 201, body: c } })
    }
    if (req.method === 'GET' && url.pathname === '/reports/revenue') return need('reports:read', () => ({ body: { revenue: 1_250_000 } }))
    const del = /^\/orders\/(\d+)$/.exec(url.pathname)
    if (req.method === 'DELETE' && del) return need('orders:delete', () => { const i = orders.findIndex(o => o.id === Number(del[1])); if (i >= 0) orders.splice(i, 1); return { status: 204, body: {} } })
    return send(404, { error: 'not_found' })
  })
  await new Promise(r => server.listen(0, '127.0.0.1', r))
  return {
    url: `http://127.0.0.1:${server.address().port}`, audit, orders, contacts, users,
    get requests() { return requests },
    stop: () => new Promise(r => { server.close(r); server.closeAllConnections() }),
  }
}
