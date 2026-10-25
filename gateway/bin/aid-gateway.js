#!/usr/bin/env node
import { main } from '../src/cli.js'

const result = await main(process.argv.slice(2))
if (typeof result === 'number') process.exit(result)   // `run` returns the server and keeps the process alive
