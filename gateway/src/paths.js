/**
 * Request targets. The gateway accepts only origin-form paths `/<tenant>/<path>?<query>` and refuses anything that could
 * make the route mean something other than what it says: absolute-form targets, `..`, `.`, encoded slashes and dots,
 * double encoding, backslashes, `;` path parameters, empty segments, control characters. Refusing is cheaper than
 * deciding what an old system's web server would have made of it.
 */

export class TargetError extends Error {
  constructor(code) { super(code); this.name = 'TargetError'; this.code = code }
}

export const TENANT_NAME = /^[a-z0-9][a-z0-9_-]{0,62}$/
const MAX_TARGET = 8192
const MAX_QUERY = 4096
const strictUtf8 = new TextDecoder('utf-8', { fatal: true })

function decodeSegment(raw) {
  if (/%(?![0-9A-Fa-f]{2})/.test(raw)) throw new TargetError('bad_encoding')
  const bytes = []
  for (let i = 0; i < raw.length; i++) {
    if (raw[i] === '%') { bytes.push(parseInt(raw.slice(i + 1, i + 3), 16)); i += 2 } else bytes.push(raw.charCodeAt(i))
  }
  let text
  try { text = strictUtf8.decode(Uint8Array.from(bytes)) } catch { throw new TargetError('bad_encoding') }
  if (text.includes('%')) throw new TargetError('double_encoding')
  if (/[\u0000-\u001f\u007f\\/;]/.test(text)) throw new TargetError('forbidden_character')
  if (/^\.+$/.test(text)) throw new TargetError('dot_segment')
  return text
}

/** Re-encode a decoded segment conservatively: what is authorized is exactly what the old system will see */
export function encodeSegment(text) {
  let out = ''
  for (const b of Buffer.from(text, 'utf8')) {
    const c = String.fromCharCode(b)
    out += /[A-Za-z0-9\-._~]/.test(c) ? c : `%${b.toString(16).toUpperCase().padStart(2, '0')}`
  }
  return out
}

/**
 * @param {string} target the raw request target from the request line
 * @returns {{ tenant: string, segments: string[], path: string, query: string }} `segments` are decoded; `path` is the
 *   canonical re-encoded path (starting with "/") to send upstream; `query` includes the leading "?" or is empty
 */
export function parseTarget(target) {
  if (typeof target !== 'string' || target.length === 0 || target.length > MAX_TARGET) throw new TargetError('bad_target')
  if (target[0] !== '/') throw new TargetError('absolute_form')
  if (!/^[\x21-\x7e]+$/.test(target)) throw new TargetError('forbidden_character')
  if (target.includes('\\') || target.includes('#')) throw new TargetError('forbidden_character')
  if (target[1] === '/') throw new TargetError('double_slash')
  const q = target.indexOf('?')
  const rawPath = q === -1 ? target : target.slice(0, q)
  const query = q === -1 ? '' : target.slice(q)
  if (query.length > MAX_QUERY) throw new TargetError('bad_target')
  const parts = rawPath.slice(1).split('/')
  const tenant = parts[0]
  if (!TENANT_NAME.test(tenant)) throw new TargetError('bad_tenant')
  let rest = parts.slice(1)
  if (rest.length === 1 && rest[0] === '') rest = []   // "/tenant/" is the upstream root
  const segments = rest.map(seg => {
    if (seg === '') throw new TargetError('empty_segment')
    return decodeSegment(seg)
  })
  return { tenant, segments, path: `/${segments.map(encodeSegment).join('/')}`, query }
}
