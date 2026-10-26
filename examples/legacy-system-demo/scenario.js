import { generateKeyPairSync, createSign } from 'node:crypto'
import { createAgent } from './agent.js'
import { startIssuer } from './issuer.js'
import { startLegacySystem } from './legacy-system.js'

const SERVICE = 'https://crm.acme.example'   // what Acme's old system is called in a token's `aud`
const ALL_SCOPES = ['contacts:read', 'contacts:create', 'orders:delete']

/**
 * Acme runs an old system. Acme made a user "lola" in it (permissions: read and create contacts), registered the agent
 * Lola at the issuer, and told the old system to trust that issuer. Then Lola works. Returns one entry per thing checked.
 */
export async function runScenario({ log = () => {} } = {}) {
  const results = []
  const check = (name, pass, detail = '') => { results.push({ name, pass: !!pass, detail }); log(pass ? '  ok  ' : '  FAIL', name, detail ? `(${detail})` : '') }
  const say = text => log(`\n${text}`)

  const issuer = await startIssuer({ tokenLifetimeSec: 60 })
  const idp = { issuer: issuer.issuer, jwksUri: issuer.jwksUri, audience: SERVICE, userClaim: 'agent_address' }
  const users = [
    { id: 'u1', name: 'ana', kind: 'human', permissions: ['contacts:read', 'contacts:create', 'orders:delete'] },
    // The user Acme created for the agent. Its permissions are THIS system's, and they are the limit.
    { id: 'u2', name: 'lola', kind: 'agent', externalId: 'lola@acme.example', permissions: ['contacts:read', 'contacts:create'] },
  ]
  const legacy = await startLegacySystem({ idp, users })
  const lola = createAgent({ name: 'lola', address: 'lola@acme.example' })
  const rex = createAgent({ name: 'rex', address: 'rex@acme.example' })
  // The issuer lets both agents ask for all three scopes: what an agent MAY CLAIM is the issuer's ceiling, not what it may do here
  issuer.register({ name: lola.name, address: lola.address, publicKeyPem: lola.publicKeyPem, scopes: ALL_SCOPES })
  issuer.register({ name: rex.name, address: rex.address, publicKeyPem: rex.publicKeyPem, scopes: ALL_SCOPES })

  try {
    say('1. Lola proves she is Lola to the issuer, gets a token meant for the CRM, and presents it')
    const token = await lola.requestToken(issuer.issuer, { resource: SERVICE })
    const me = await lola.call(legacy.url, '/whoami', token)
    check('the old system knows her as its own user "lola", an agent', me.status === 200 && me.body.user === 'lola' && me.body.kind === 'agent', JSON.stringify(me.body))

    say('2. She does what her user is allowed to do')
    const made = await lola.call(legacy.url, '/contacts', token, { method: 'POST', body: JSON.stringify({ name: 'New lead' }) })
    check('creates a contact', made.status === 201 && made.body.createdBy === 'lola', `status ${made.status}`)
    check('the old system\'s own log says lola did it', legacy.audit.some(a => a.who === 'lola' && a.action === 'POST /contacts' && a.ok))

    say('3. She tries something her user may not do, though her token carries that scope')
    const del = await lola.call(legacy.url, '/orders/100', token, { method: 'DELETE' })
    check('refused by the old system\'s own permissions (403)', del.status === 403, `status ${del.status}`)
    check('the order is still there', legacy.orders.some(o => o.id === 100))
    check('the refusal is in its log too', legacy.audit.some(a => a.who === 'lola' && !a.ok && /lacks orders:delete/.test(a.why)))

    say('4. Tokens that should not work')
    const other = await lola.requestToken(issuer.issuer, { resource: 'https://other.example' })
    check('a token meant for another service is refused (401)', (await lola.call(legacy.url, '/whoami', other)).status === 401)
    check('  and for the right reason: the audience', legacy.audit.some(a => a.why === 'bad_audience'))
    const stranger = generateKeyPairSync('rsa', { modulusLength: 2048 })
    const forged = (() => {
      const b = x => Buffer.from(JSON.stringify(x)).toString('base64url')
      const now = Math.floor(Date.now() / 1000)
      const input = `${b({ alg: 'RS256', typ: 'JWT', kid: 'demo-1' })}.${b({ iss: issuer.issuer, sub: 'agent:x', aud: [SERVICE], exp: now + 60, agent_address: 'lola@acme.example' })}`
      return `${input}.${createSign('RSA-SHA256').update(input).sign(stranger.privateKey).toString('base64url')}`
    })()
    check('a token signed by anyone else is refused (401)', (await lola.call(legacy.url, '/whoami', forged)).status === 401)
    check('  and for the right reason: the signature', legacy.audit.some(a => a.why === 'bad_signature'))
    const now = Math.floor(Date.now() / 1000)
    const expired = issuer.signRaw({ iss: issuer.issuer, sub: 'agent:x', aud: [SERVICE], exp: now - 10, nbf: now - 100, iat: now - 100, agent_address: 'lola@acme.example', token_type: 'agent' })
    check('an expired token is refused (401)', (await lola.call(legacy.url, '/whoami', expired)).status === 401)
    check('  and for the right reason: it has expired', legacy.audit.some(a => a.why === 'token_expired'))
    check('no token is refused (401)', (await fetch(`${legacy.url}/whoami`)).status === 401)

    say('5. An agent the issuer knows but Acme never made a user for')
    const rexToken = await rex.requestToken(issuer.issuer, { resource: SERVICE })
    const rexCall = await rex.call(legacy.url, '/contacts', rexToken)
    check('rex is refused (403): the issuer vouches for him, Acme never let him in', rexCall.status === 403 && /forbidden/.test(JSON.stringify(rexCall.body)), `status ${rexCall.status}`)
    check('  and for the right reason: no user of his in the old system', legacy.audit.some(a => a.why === 'no_local_user'))

    say('6. The issuer suspends Lola. The old system only checks the token\'s signature and expiry')
    issuer.suspend(lola.address)
    let newToken = null
    try { newToken = await lola.requestToken(issuer.issuer, { resource: SERVICE }) } catch { /* expected */ }
    check('she can no longer get a NEW token', newToken === null)
    const still = await lola.call(legacy.url, '/whoami', token)
    check('but the token she already holds keeps working until it expires (the limit of kind A with no introspection)', still.status === 200, `status ${still.status}`)

    say('7. Same, with the old system told to ask the issuer whether the agent is still active')
    issuer.reactivate(lola.address)
    const strict = await startLegacySystem({ idp: { ...idp, introspection: { endpoint: issuer.introspectionEndpoint, clientId: issuer.introspectionClient.id, clientSecret: issuer.introspectionClient.secret } }, users })
    try {
      const t2 = await lola.requestToken(issuer.issuer, { resource: SERVICE })
      check('while active she works', (await lola.call(strict.url, '/whoami', t2)).status === 200)
      issuer.suspend(lola.address)
      check('the moment she is suspended she is refused (401)', (await lola.call(strict.url, '/whoami', t2)).status === 401)
    } finally { await strict.stop() }
  } finally {
    await legacy.stop()
    await issuer.stop()
  }
  return results
}
