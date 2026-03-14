import { readFileSync, writeFileSync, existsSync } from 'fs'
import type { ScanViolation } from '../scanner/cookie.js'
import type { AuditViolation } from '../audit/browser.js'

type BaselineFile = {
  version: 1
  entries: string[]
}

function hash(input: string): string {
  const hasher = new Bun.CryptoHasher('sha256')
  hasher.update(input)
  return hasher.digest('hex')
}

export function fingerprintScanViolation(v: ScanViolation): string {
  return hash(`${v.file}::${v.message}::${v.snippet}`)
}

export function fingerprintAuditViolation(v: AuditViolation): string {
  return hash(`${v.cookieName}::${v.via}`)
}

export function loadBaseline(path: string): BaselineFile | null {
  if (!existsSync(path)) return null
  const data = JSON.parse(readFileSync(path, 'utf-8'))
  return data as BaselineFile
}

export function saveBaseline(path: string, fingerprints: string[]): void {
  const data: BaselineFile = {
    version: 1,
    entries: [...new Set(fingerprints)].sort(),
  }
  writeFileSync(path, JSON.stringify(data, null, 2) + '\n')
}

export function filterNew<T>(
  violations: T[],
  baseline: BaselineFile,
  fingerprinter: (v: T) => string,
): T[] {
  const known = new Set(baseline.entries)
  return violations.filter((v) => !known.has(fingerprinter(v)))
}
