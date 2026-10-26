import { AidError } from './errors.js'

/**
 * RFC 7662: ask the issuer whether a token is still good. The verifier authenticates to the endpoint (Basic with a
 * client id and secret, or a bearer token) because AID leaves that open and an open endpoint is an oracle for anyone
 * holding a stolen token. Any failure is a refusal: if Acme cannot find out, it does not guess.
 */
export async function introspect({ endpoint, clientId, clientSecret, bearer }, token, { fetch: fetchImpl = globalThis.fetch } = {}) {
  const headers = { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }
  if (bearer) headers.Authorization = `Bearer ${bearer}`
  else if (clientId && clientSecret) headers.Authorization = `Basic ${Buffer.from(`${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`).toString('base64')}`
  let res
  try {
    res = await fetchImpl(endpoint, { method: 'POST', headers, body: new URLSearchParams({ token, token_type_hint: 'access_token' }), signal: AbortSignal.timeout(5000) })
  } catch {
    throw new AidError('introspection_failed', 'The issuer could not be asked whether the agent is active')
  }
  if (!res.ok) throw new AidError('introspection_failed', `The issuer's introspection returned ${res.status}`)
  try {
    const body = await res.json()
    if (!body || typeof body.active !== 'boolean') throw new Error('no active')
    return body
  } catch {
    throw new AidError('introspection_failed', 'The issuer\'s introspection answer is not valid')
  }
}
