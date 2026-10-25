import { validateCatalog, METHODS } from './catalog.js'

/**
 * Draft a permission catalog from an OpenAPI 3 document (JSON only; convert YAML first). It is a DRAFT for the company to
 * review and edit, never a policy: nothing it produces authorizes anything until an issuer scope is mapped to its
 * permissions in the tenant's scopeMap.
 *
 * Permission = <resource>.<verb>. The verb comes from the HTTP method ONLY (GET and HEAD read, POST create, PUT and PATCH
 * update, DELETE delete): an operationId such as "getOrCreateContact" on a POST must not make a write look like a read. The
 * resource is the operation's first tag when it has one, else the literal path segments (version prefixes dropped),
 * joined with dots. `x-aid-permission` on an operation overrides both. operationId and summary are carried along as
 * hints for the reviewer.
 */

const VERB = { GET: 'read', HEAD: 'read', POST: 'create', PUT: 'update', PATCH: 'update', DELETE: 'delete' }
const VERSION_SEGMENT = /^(api|v\d+(\.\d+)*|rest)$/i

const slug = s => String(s).toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '')

export function importOpenApi(doc) {
  const notes = []
  if (!doc || typeof doc !== 'object' || typeof doc.openapi !== 'string' || !doc.openapi.startsWith('3.')) {
    throw new TypeError('not an OpenAPI 3 document (JSON only; if you have YAML, convert it to JSON first)')
  }
  if (!doc.paths || typeof doc.paths !== 'object') throw new TypeError('the document has no "paths"')
  const draft = []
  for (const [path, item] of Object.entries(doc.paths)) {
    if (!item || typeof item !== 'object') continue
    if (item.$ref) { notes.push(`${path}: skipped, a path item that is a $ref (resolve it first)`); continue }
    for (const [m, op] of Object.entries(item)) {
      const method = m.toUpperCase()
      if (!METHODS.has(method)) {
        if (['OPTIONS', 'TRACE'].includes(method)) notes.push(`${method} ${path}: skipped, the gateway never forwards ${method}`)
        continue
      }
      const operation = op && typeof op === 'object' ? op : {}
      const segs = path === '/' ? [] : path.slice(1).split('/')
      if (segs.some(s => /[{}]/.test(s) && !/^\{[A-Za-z_][A-Za-z0-9_]*\}$/.test(s))) { notes.push(`${method} ${path}: skipped, a parameter that is only part of a segment`); continue }
      const literal = segs.filter(s => !s.startsWith('{') && !VERSION_SEGMENT.test(s)).map(slug).filter(Boolean)
      const tag = Array.isArray(operation.tags) && operation.tags.length ? slug(operation.tags[0]) : ''
      const resource = tag || literal.join('.') || 'root'
      const permission = typeof operation['x-aid-permission'] === 'string' ? operation['x-aid-permission'] : `${resource}.${VERB[method]}`
      draft.push({ permission, method, pathTemplate: path, ...(operation.operationId ? { operationId: String(operation.operationId) } : {}), ...(operation.summary ? { summary: String(operation.summary).slice(0, 120) } : {}) })
    }
  }
  const catalog = []
  for (const e of draft) {
    try { catalog.push(...validateCatalog([e])) } catch (err) { notes.push(`${e.method} ${e.pathTemplate}: skipped, ${err.message}`) }
  }
  // validateCatalog drops hints; put them back for the reviewer
  const hints = new Map(draft.map(e => [`${e.method} ${e.pathTemplate}`, e]))
  const out = catalog.map(c => {
    const h = hints.get(`${c.method} ${c.pathTemplate}`)
    return { ...c, ...(h?.operationId ? { operationId: h.operationId } : {}), ...(h?.summary ? { summary: h.summary } : {}) }
  })
  const seen = new Set()
  const deduped = []
  for (const e of out) {
    const shape = `${e.method} ${e.pathTemplate.replace(/\{[^}]+\}/g, '{}')}`
    if (seen.has(shape)) { notes.push(`${e.method} ${e.pathTemplate}: skipped, same shape as an earlier path`); continue }
    seen.add(shape)
    deduped.push(e)
  }
  const perms = new Map()
  for (const e of deduped) perms.set(e.permission, (perms.get(e.permission) ?? 0) + 1)
  for (const [p, n] of perms) if (n > 1) notes.push(`permission ${p} covers ${n} operations; split it if they should be granted separately`)
  const destructive = deduped.filter(e => e.method === 'DELETE').map(e => e.permission)
  if (destructive.length) notes.push(`review these destructive permissions before mapping any scope to them: ${[...new Set(destructive)].join(', ')}`)
  notes.push('this is a draft: remove what the agents should never do, rename what is unclear, then map issuer scopes to these permissions in the tenant "scopeMap"')
  return { draft: true, source: { title: doc.info?.title ?? null, version: doc.info?.version ?? null }, catalog: deduped, notes }
}
