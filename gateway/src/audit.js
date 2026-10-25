import { appendFile, mkdir } from 'node:fs/promises'
import { dirname } from 'node:path'

/**
 * One JSON line per decision. Never the token, a credential, a header value, or a body. An in-memory ring serves the admin
 * API and the page; the file (mode 600, append only from here) is the durable copy.
 */
export class AuditLog {
  constructor({ file, size = 2000 } = {}) {
    this.file = file
    this.size = size
    this.ring = []
    this.queue = Promise.resolve()
  }

  record(rec) {
    const entry = Object.freeze({ ts: new Date().toISOString(), ...rec })
    this.ring.push(entry)
    if (this.ring.length > this.size) this.ring.shift()
    if (this.file) {
      const line = `${JSON.stringify(entry)}\n`
      this.queue = this.queue.then(async () => {
        await mkdir(dirname(this.file), { recursive: true, mode: 0o700 })
        await appendFile(this.file, line, { mode: 0o600 })
      }).catch(() => { /* an audit write failure must not take the proxy down; the ring still has it */ })
    }
    return entry
  }

  /** newest first */
  query({ tenant, agent, decision, reason, limit = 100 } = {}) {
    const out = []
    for (let i = this.ring.length - 1; i >= 0 && out.length < Math.min(limit, 1000); i--) {
      const r = this.ring[i]
      if (tenant && r.tenant !== tenant) continue
      if (agent && r.agentAddress !== agent && r.agentId !== agent) continue
      if (decision && r.decision !== decision) continue
      if (reason && r.reason !== reason) continue
      out.push(r)
    }
    return out
  }

  flush() { return this.queue }
}
