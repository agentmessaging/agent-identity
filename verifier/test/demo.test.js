import { test } from 'node:test'
import assert from 'node:assert/strict'
import { runScenario } from '../../examples/legacy-system-demo/scenario.js'

test('the old-system demo: an agent is a user in the system and only does what that user may', async () => {
  const results = await runScenario()
  assert.ok(results.length >= 12, 'the scenario ran its steps')
  for (const r of results) assert.ok(r.pass, `${r.name} ${r.detail}`)
})
