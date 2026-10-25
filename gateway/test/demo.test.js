import { test } from 'node:test'
import assert from 'node:assert/strict'
import { runScenario } from '../../examples/gateway-demo/scenario.js'

test('the gateway demo: every check passes', async () => {
  const results = await runScenario()
  assert.ok(results.length >= 25, `only ${results.length} checks ran`)
  const failed = results.filter(r => !r.pass)
  assert.deepEqual(failed, [])
})
