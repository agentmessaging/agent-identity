import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { createVerifier } from '../src/index.js'
import { agentPayload, makeFetch, makeIssuer, nowSec } from './helpers.js'

const ACME = 'https://auth.example/acme'
const PARTNER = 'https://auth.example/partner'

function setup({ own = {}, ext = {}, grants, introspect, verifierOpts = {} } = {}) {
  const acme = makeIssuer(ACME)
  const partner = makeIssuer(PARTNER)
  const fetch = makeFetch([acme, partner], { introspect })
  const config = {
    issuers: [
      { issuer: ACME, jwksUri: acme.jwksUri, kind: 'own', audience: ['acme-key'], allowAllActiveAgents: true,
        scopeMap: { 'files:read': ['docs.read'], 'tickets:write': ['tickets.write'] }, ...own },
      { issuer: PARTNER, jwksUri: partner.jwksUri, kind: 'external', audience: ['acme-api'], ...ext },
    ],
    grants: grants ?? [],
  }
  const decisions = []
  const v = createVerifier(config, { fetch, allowInsecureHttp: false, onDecision: d => decisions.push(d), ...verifierOpts })
  return { acme, partner, fetch, v, decisions }
}

describe('Acme\'s own agents', () => {
  test('a valid token from the own tenant is accepted, and permissions come from Acme\'s scope map', async () => {
    const { acme, v } = setup()
    const r = await v.verify(acme.sign(agentPayload(ACME)))
    assert.equal(r.ok, true)
    assert.deepEqual(r.principal.permissions.sort(), ['docs.read', 'tickets.write'])
    assert.equal(r.principal.kind, 'own')
    assert.equal(r.principal.agentId, 'ag-1')
    assert.equal(r.principal.address, 'bot@acme.example')
  })

  test('a scope Acme did not map grants nothing', async () => {
    const { acme, v } = setup()
    const r = await v.verify(acme.sign(agentPayload(ACME, { scopes: ['files:read', 'admin:all'] })), { permissions: ['docs.read'] })
    assert.equal(r.ok, true)
    assert.deepEqual(r.principal.permissions, ['docs.read'])
  })

  test('required permissions the agent lacks are refused', async () => {
    const { acme, v } = setup()
    const r = await v.verify(acme.sign(agentPayload(ACME, { scopes: ['files:read'] })), { permissions: ['tickets.write'] })
    assert.equal(r.ok, false)
    assert.equal(r.code, 'insufficient_permissions')
  })

  test('a grant can narrow one own agent, never widen it', async () => {
    const { acme, v } = setup({ grants: [{ issuer: ACME, agentId: 'ag-1', permissions: ['docs.read', 'billing.write'], sponsor: 'ana@acme.example' }] })
    const r = await v.verify(acme.sign(agentPayload(ACME)))
    assert.deepEqual(r.principal.permissions, ['docs.read'])
  })

  test('also accepts the standard `scope` string', async () => {
    const { acme, v } = setup()
    const p = agentPayload(ACME); delete p.scopes; p.scope = 'files:read tickets:write'
    const r = await v.verify(acme.sign(p))
    assert.equal(r.ok, true)
    assert.equal(r.principal.permissions.length, 2)
  })
})

describe('agents authorized to work in Acme from elsewhere', () => {
  const grant = { issuer: PARTNER, agentId: 'ext-9', permissions: ['docs.read'], sponsor: 'ana@acme.example' }
  const ext = partner => agentPayload(PARTNER, { sub: 'agent:ext-9', agent_id: 'ext-9', agent_address: 'helper@partner.example', aud: ['acme-api'], scopes: ['docs.read', 'tickets.write'] })

  test('without a grant an external agent is refused, however good its token', async () => {
    const { partner, v } = setup()
    const r = await v.verify(partner.sign(ext(partner)))
    assert.equal(r.ok, false)
    assert.equal(r.code, 'agent_not_authorized')
  })

  test('with a grant it is accepted and capped at the grant\'s ceiling', async () => {
    const { partner, v } = setup({ grants: [grant] })
    const r = await v.verify(partner.sign(ext(partner)))
    assert.equal(r.ok, true)
    assert.deepEqual(r.principal.permissions, ['docs.read'])
    assert.equal(r.principal.grant.sponsor, 'ana@acme.example')
    assert.equal(r.principal.kind, 'external')
  })

  test('a grant by address works too, ignoring case', async () => {
    const { partner, v } = setup({ grants: [{ issuer: PARTNER, address: 'HELPER@partner.example', permissions: '*', sponsor: 'ana@acme.example' }] })
    const r = await v.verify(partner.sign(ext(partner)))
    assert.equal(r.ok, true)
  })

  test('an expired grant stops working', async () => {
    const { partner, v } = setup({ grants: [{ ...grant, expiresAt: new Date(Date.now() - 1000).toISOString() }] })
    const r = await v.verify(partner.sign(ext(partner)))
    assert.equal(r.code, 'agent_not_authorized')
  })

  test('a grant for one issuer does not let in the same agent id from another', async () => {
    const { acme, v } = setup({ own: { allowAllActiveAgents: false }, grants: [grant] })
    const r = await v.verify(acme.sign(agentPayload(ACME, { agent_id: 'ext-9', sub: 'agent:ext-9' })))
    assert.equal(r.code, 'agent_not_authorized')
  })

  test('a permission outside the ceiling is refused even though the token carries it', async () => {
    const { partner, v } = setup({ grants: [grant] })
    const r = await v.verify(partner.sign(ext(partner)), { permissions: ['tickets.write'] })
    assert.equal(r.code, 'insufficient_permissions')
  })
})

describe('what a token must be', () => {
  test('an issuer Acme does not trust is refused before any key is fetched', async () => {
    const { fetch, v } = setup()
    const stranger = makeIssuer('https://evil.example/x')
    const r = await v.verify(stranger.sign(agentPayload('https://evil.example/x')))
    assert.equal(r.code, 'untrusted_issuer')
    assert.equal(fetch.calls.jwks, 0)
  })

  test('a signature from the wrong key is refused', async () => {
    const { acme, v } = setup()
    const forger = makeIssuer(ACME)
    const r = await v.verify(forger.sign(agentPayload(ACME)))
    assert.equal(r.code, 'bad_signature')
    assert.equal((await v.verify(acme.sign(agentPayload(ACME)))).ok, true)
  })

  test('a tampered payload is refused', async () => {
    const { acme, v } = setup()
    const t = acme.sign(agentPayload(ACME, { scopes: ['files:read'] }))
    const [h, , s] = t.split('.')
    const forged = Buffer.from(JSON.stringify(agentPayload(ACME, { scopes: ['files:read', 'tickets:write'] }))).toString('base64url')
    assert.equal((await v.verify(`${h}.${forged}.${s}`)).code, 'bad_signature')
  })

  test('alg none, HS256 and other algorithms are refused', async () => {
    const { acme, v } = setup()
    for (const alg of ['none', 'HS256', 'RS384', 'ES256']) {
      const t = acme.sign(agentPayload(ACME), { alg })
      const r = await v.verify(t)
      assert.equal(r.code, 'unsupported_alg', alg)
    }
    const unsigned = `${Buffer.from('{"alg":"none"}').toString('base64url')}.${Buffer.from(JSON.stringify(agentPayload(ACME))).toString('base64url')}.x`
    assert.equal((await v.verify(unsigned)).code, 'unsupported_alg')
  })

  test('headers that point to a key (jku, jwk) are ignored: only the issuer\'s own keys count', async () => {
    const { v } = setup()
    const attacker = makeIssuer(ACME)
    const t = attacker.sign(agentPayload(ACME), { jku: 'https://attacker.example/jwks.json', jwk: { kty: 'RSA' } })
    assert.equal((await v.verify(t)).code, 'bad_signature')
  })

  test('expired, not-yet-valid and too-old tokens are refused', async () => {
    const { acme, v } = setup({ own: { maxTokenAgeSec: 600 } })
    const t = nowSec()
    assert.equal((await v.verify(acme.sign(agentPayload(ACME, { exp: t - 3600 })))).code, 'token_expired')
    assert.equal((await v.verify(acme.sign(agentPayload(ACME, { nbf: t + 3600, iat: t })))).code, 'token_not_yet_valid')
    assert.equal((await v.verify(acme.sign(agentPayload(ACME, { iat: t - 3000 })))).code, 'token_expired')
    assert.equal((await v.verify(acme.sign(agentPayload(ACME, { exp: undefined })))).code, 'malformed_token')
  })

  test('a token meant for another service is refused (audience)', async () => {
    const { acme, v } = setup()
    const r = await v.verify(acme.sign(agentPayload(ACME, { aud: ['client_app', 'api_service', 'someone-elses-key'] })))
    assert.equal(r.code, 'bad_audience')
  })

  test('a user token, or a token with no agent, is refused', async () => {
    const { acme, v } = setup()
    assert.equal((await v.verify(acme.sign(agentPayload(ACME, { token_type: 'user' })))).code, 'not_an_agent_token')
    const p = agentPayload(ACME); delete p.agent_id; p.sub = 'user-5'
    assert.equal((await v.verify(acme.sign(p))).code, 'not_an_agent_token')
  })

  test('garbage and oversized input is refused without throwing', async () => {
    const { v } = setup()
    for (const t of ['', 'abc', 'a.b', 'a.b.c', '...', 'x'.repeat(9000), null, undefined, 42]) {
      const r = await v.verify(t)
      assert.equal(r.ok, false)
      assert.equal(r.code, 'malformed_token')
    }
  })
})

describe('keys', () => {
  test('a rotated key is picked up by one refresh, rate-limited so made-up kids cannot hammer the issuer', async () => {
    let skewMs = 0
    const { acme, fetch, v } = setup({ verifierOpts: { now: () => Date.now() + skewMs } })
    assert.equal((await v.verify(acme.sign(agentPayload(ACME)))).ok, true)
    const first = fetch.calls.jwks
    acme.rotate('k2')
    // Just after the last fetch the refresh is held back (the minimum interval), so the new key is not yet known
    assert.equal((await v.verify(acme.sign(agentPayload(ACME)))).code, 'key_not_found')
    assert.equal(fetch.calls.jwks, first)
    skewMs += 31_000
    assert.equal((await v.verify(acme.sign(agentPayload(ACME)))).ok, true)
    assert.equal(fetch.calls.jwks, first + 1)
    // A stream of made-up kids costs at most one more fetch per interval
    for (let i = 0; i < 6; i++) assert.equal((await v.verify(acme.sign(agentPayload(ACME), { kid: `made-up-${i}` }))).code, 'key_not_found')
    assert.equal(fetch.calls.jwks, first + 1)
    skewMs += 31_000
    assert.equal((await v.verify(acme.sign(agentPayload(ACME), { kid: 'made-up-again' }))).code, 'key_not_found')
    assert.equal(fetch.calls.jwks, first + 2)
  })

  test('an unreachable issuer fails closed', async () => {
    const { acme, fetch, v } = setup()
    fetch.calls.fail = true
    const r = await v.verify(acme.sign(agentPayload(ACME)))
    assert.equal(r.code, 'jwks_unavailable')
  })

  test('a key under 2048 bits is refused', async () => {
    const small = makeIssuer(ACME, { bits: 1024 })
    const fetch = makeFetch([small])
    const v = createVerifier({ issuers: [{ issuer: ACME, jwksUri: small.jwksUri, kind: 'own', audience: ['acme-key'], allowAllActiveAgents: true }] }, { fetch })
    assert.equal((await v.verify(small.sign(agentPayload(ACME)))).code, 'key_not_found')
  })
})

describe('is the agent still active?', () => {
  const answer = (active, extra = {}) => async token => ({ body: { active, ...extra } })

  test('introspection "always" asks the issuer every time, and an inactive agent is refused', async () => {
    const { acme, fetch, v } = setup({ own: { introspection: { endpoint: `${ACME}/introspect`, clientId: 'acme', clientSecret: 's' } }, introspect: answer(false, { reason: 'agent_suspended' }) })
    const r = await v.verify(acme.sign(agentPayload(ACME)))
    assert.equal(r.code, 'agent_inactive')
    assert.match(r.message, /agent_suspended/)
    assert.equal(fetch.calls.introspect, 1)
  })

  test('an active agent passes and the issuer\'s role is reported', async () => {
    const { acme, v } = setup({ own: { introspection: { endpoint: `${ACME}/introspect`, bearer: 't' } }, introspect: async t => ({ body: { active: true, sub: 'agent:ag-1', agent_status: 'active', agent_role: 'support' } }) })
    const r = await v.verify(acme.sign(agentPayload(ACME)))
    assert.equal(r.ok, true)
    assert.equal(r.principal.role, 'support')
  })

  test('an answer about a different subject, or a non-active status, is refused', async () => {
    const a = setup({ own: { introspection: { endpoint: `${ACME}/introspect`, bearer: 't' } }, introspect: async () => ({ body: { active: true, sub: 'agent:someone-else' } }) })
    assert.equal((await a.v.verify(a.acme.sign(agentPayload(ACME)))).code, 'introspection_failed')
    const b = setup({ own: { introspection: { endpoint: `${ACME}/introspect`, bearer: 't' } }, introspect: async () => ({ body: { active: true, agent_status: 'suspended' } }) })
    assert.equal((await b.v.verify(b.acme.sign(agentPayload(ACME)))).code, 'agent_inactive')
  })

  test('if the issuer cannot be asked, the verifier does not guess', async () => {
    const { acme, v } = setup({ own: { introspection: { endpoint: `${ACME}/introspect`, bearer: 't' } }, introspect: async () => ({ status: 500, body: {} }) })
    assert.equal((await v.verify(acme.sign(agentPayload(ACME)))).code, 'introspection_failed')
  })

  test('"for-permissions" asks only when a sensitive permission is involved', async () => {
    const { acme, fetch, v } = setup({ own: { introspect: 'for-permissions', sensitivePermissions: ['tickets.write'], introspection: { endpoint: `${ACME}/introspect`, bearer: 't' } }, introspect: answer(true) })
    await v.verify(acme.sign(agentPayload(ACME, { scopes: ['files:read'] })), { permissions: ['docs.read'] })
    assert.equal(fetch.calls.introspect, 0)
    await v.verify(acme.sign(agentPayload(ACME)), { permissions: ['tickets.write'] })
    assert.equal(fetch.calls.introspect, 1)
  })

  test('a suspension event stops the agent at once, without waiting for the token to expire', async () => {
    const { acme, v } = setup()
    const token = acme.sign(agentPayload(ACME))
    assert.equal((await v.verify(token)).ok, true)
    v.revocations.apply({ issuer: ACME, type: 'agent-suspended', agentId: 'ag-1' })
    assert.equal((await v.verify(token)).code, 'agent_revoked')
    v.revocations.apply({ issuer: ACME, type: 'agent-reactivated', agentId: 'ag-1' })
    assert.equal((await v.verify(token)).ok, true)
  })

  test('one token can be revoked without revoking the agent', async () => {
    const { acme, v } = setup()
    const p = agentPayload(ACME, { jti: 'bad-one' })
    v.revocations.apply({ issuer: ACME, type: 'token-revoked', jti: 'bad-one' })
    assert.equal((await v.verify(acme.sign(p))).code, 'agent_revoked')
    assert.equal((await v.verify(acme.sign(agentPayload(ACME, { jti: 'fine' })))).ok, true)
  })
})

describe('configuration', () => {
  test('refuses an issuer with no audience, a grant with no sponsor, and "allow all" on an external issuer', () => {
    const base = { issuer: ACME, jwksUri: `${ACME}/jwks`, kind: 'own' }
    assert.throws(() => createVerifier({ issuers: [base] }), /audience/)
    assert.throws(() => createVerifier({ issuers: [{ ...base, audience: ['a'] }], grants: [{ issuer: ACME, agentId: 'x' }] }), /sponsor/)
    assert.throws(() => createVerifier({ issuers: [{ ...base, kind: 'external', audience: ['a'], allowAllActiveAgents: true }] }), /own/)
    assert.throws(() => createVerifier({ issuers: [{ ...base, audience: ['a'], introspect: 'always' }] }), /endpoint/)
    assert.throws(() => createVerifier({ issuers: [{ ...base, audience: ['a'] }], grants: [{ issuer: 'https://nobody', agentId: 'x', sponsor: 's' }] }), /not configured/)
  })

  test('warns about a generic audience and about having no introspection', () => {
    const v = createVerifier({ issuers: [{ issuer: ACME, jwksUri: `${ACME}/jwks`, kind: 'own', audience: ['client_app', 'api_service'], allowAllActiveAgents: true }] })
    assert.ok(v.warnings.some(w => /shared by every tenant/.test(w)))
    assert.ok(v.warnings.some(w => /no introspection/.test(w)))
  })

  test('the decision hook hears every outcome and never the token', async () => {
    const { acme, v, decisions } = setup()
    const token = acme.sign(agentPayload(ACME))
    await v.verify(token)
    await v.verify('garbage')
    assert.equal(decisions.length, 2)
    assert.equal(decisions[0].ok, true)
    assert.equal(decisions[1].code, 'malformed_token')
    assert.ok(!JSON.stringify(decisions).includes(token))
  })
})
