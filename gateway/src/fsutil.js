import { chmodSync, closeSync, fsyncSync, mkdirSync, openSync, renameSync, writeSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { dirname } from 'node:path'

/** Write a file atomically with mode 600: a temp file in the same directory, flushed, then renamed over the target */
export function atomicWriteFile(path, data) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
  const tmp = `${path}.tmp-${process.pid}-${randomBytes(6).toString('hex')}`
  const fd = openSync(tmp, 'wx', 0o600)
  try {
    writeSync(fd, data)
    fsyncSync(fd)
  } finally {
    closeSync(fd)
  }
  chmodSync(tmp, 0o600)
  renameSync(tmp, path)
}
