/** A token bucket per key: `burst` requests at once, refilled at `ratePerMinute`. In memory, per process. */
export class RateLimiter {
  constructor({ now = () => Date.now() } = {}) { this.now = now; this.buckets = new Map() }

  /** @returns {{ ok: true } | { ok: false, retryAfterSec: number }} */
  take(key, { ratePerMinute, burst }) {
    const t = this.now()
    let b = this.buckets.get(key)
    if (!b) {
      if (this.buckets.size > 20_000) this.#sweep(t, ratePerMinute, burst)
      b = { tokens: burst, at: t }
      this.buckets.set(key, b)
    }
    b.tokens = Math.min(burst, b.tokens + ((t - b.at) / 60_000) * ratePerMinute)
    b.at = t
    if (b.tokens >= 1) { b.tokens -= 1; return { ok: true } }
    return { ok: false, retryAfterSec: Math.max(1, Math.ceil(((1 - b.tokens) / ratePerMinute) * 60)) }
  }

  #sweep(t, rate, burst) {
    for (const [k, b] of this.buckets) if (b.tokens + ((t - b.at) / 60_000) * rate >= burst) this.buckets.delete(k)
  }
}
