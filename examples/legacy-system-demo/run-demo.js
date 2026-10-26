#!/usr/bin/env node
import { runScenario } from './scenario.js'

console.log('AID demo: an agent works in an old system that trusts an outside identity provider (kind A)\n')
const results = await runScenario({ log: (...a) => console.log(...a) })
const failed = results.filter(r => !r.pass)
console.log(`\n${results.length - failed.length} of ${results.length} checks passed`)
process.exit(failed.length ? 1 : 0)
