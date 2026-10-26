/**
 * The permission catalog: a list of { permission, method, pathTemplate }. A request is allowed only when its method and
 * path match an entry; the agent must then hold that entry's permission. No match, no forwarding: deny by default.
 * Templates are literal segments and whole-segment parameters like `/contacts/{id}`.
 */

export const METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'])
const PERMISSION = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/
const LITERAL = /^[A-Za-z0-9._~-]+$/
const PARAM = /^\{([A-Za-z_][A-Za-z0-9_]*)\}$/
const MAX_ENTRIES = 1000

/** @returns {Array<string|{param: string}>} */
export function parseTemplate(template) {
  if (typeof template !== 'string' || !template.startsWith('/') || template.length > 512) throw new TypeError(`bad pathTemplate ${JSON.stringify(String(template).slice(0, 80))}`)
  if (template === '/') return []
  return template.slice(1).split('/').map(seg => {
    const p = PARAM.exec(seg)
    if (p) return { param: p[1] }
    if (!LITERAL.test(seg) || /^\.+$/.test(seg)) throw new TypeError(`bad segment "${seg}" in pathTemplate ${template}: literal segments use letters, digits . _ ~ - and parameters are whole segments like {id}`)
    return seg
  })
}

export function validateCatalog(raw) {
  if (!Array.isArray(raw)) throw new TypeError('catalog must be an array')
  if (raw.length > MAX_ENTRIES) throw new TypeError(`catalog has more than ${MAX_ENTRIES} entries`)
  const seen = new Map()
  return raw.map((e, i) => {
    if (!e || typeof e !== 'object') throw new TypeError(`catalog[${i}] must be an object`)
    for (const k of Object.keys(e)) if (!['permission', 'method', 'pathTemplate', 'description', 'summary', 'operationId'].includes(k)) throw new TypeError(`catalog[${i}]: unknown field "${k}"`)
    if (typeof e.permission !== 'string' || !PERMISSION.test(e.permission)) throw new TypeError(`catalog[${i}]: bad permission name`)
    const method = typeof e.method === 'string' ? e.method.toUpperCase() : ''
    if (!METHODS.has(method)) throw new TypeError(`catalog[${i}]: method must be one of ${[...METHODS].join(', ')}`)
    const segs = parseTemplate(e.pathTemplate)
    if (segs[0] === '_events') throw new TypeError(`catalog[${i}]: "/_events" is reserved for the gateway`)
    const shape = `${method} /${segs.map(s => (typeof s === 'string' ? s : '{}')).join('/')}`
    if (seen.has(shape)) throw new TypeError(`catalog[${i}] repeats the shape of catalog[${seen.get(shape)}] (${shape}); the second could never be told apart`)
    seen.set(shape, i)
    return { permission: e.permission, method, pathTemplate: e.pathTemplate, ...(e.description ? { description: String(e.description).slice(0, 300) } : {}) }
  })
}

/** Compare two templates' specificity: at the first segment where one is literal and the other a parameter, the literal wins */
function moreSpecific(a, b) {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    const la = typeof a[i] === 'string'
    const lb = typeof b[i] === 'string'
    if (la !== lb) return la ? -1 : 1
  }
  return 0
}

export function compileCatalog(raw) {
  const entries = validateCatalog(raw).map(e => ({ ...e, segs: parseTemplate(e.pathTemplate) }))
  const methods = new Set(entries.map(e => e.method))
  return {
    entries: entries.map(({ segs, ...e }) => e),
    methods,
    /** @param {string} method @param {string[]} segments decoded path segments @returns {{permission: string, pathTemplate: string}|null} */
    match(method, segments) {
      const hits = entries.filter(e => e.method === method && e.segs.length === segments.length
        && e.segs.every((s, i) => (typeof s === 'string' ? s === segments[i] : segments[i].length > 0)))
      if (hits.length === 0) return null
      hits.sort((a, b) => moreSpecific(a.segs, b.segs))
      return { permission: hits[0].permission, pathTemplate: hits[0].pathTemplate }
    },
  }
}
