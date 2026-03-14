import { describe, it, expect, afterEach } from 'bun:test'
import { unlinkSync, existsSync } from 'fs'
import { join } from 'path'
import { tmpdir } from 'os'
import {
  fingerprintScanViolation,
  fingerprintAuditViolation,
  loadBaseline,
  saveBaseline,
  filterNew,
} from './baseline.js'
import type { ScanViolation } from '../scanner/cookie.js'
import type { AuditViolation } from '../audit/browser.js'

const tmpFile = join(tmpdir(), 'complykit-baseline-test.json')

afterEach(() => {
  if (existsSync(tmpFile)) unlinkSync(tmpFile)
})

// ---------------------------------------------------------------------------
// Fingerprinting
// ---------------------------------------------------------------------------

describe('fingerprintScanViolation', () => {
  it('produces a stable hash for the same violation', () => {
    const v: ScanViolation = {
      file: 'src/page.tsx',
      line: 5,
      column: 2,
      message: 'Cookie written via document.cookie without consent guard',
      snippet: 'document.cookie = "track=1";',
    }
    expect(fingerprintScanViolation(v)).toBe(fingerprintScanViolation(v))
  })

  it('ignores line/column changes (same file, message, snippet)', () => {
    const base = {
      file: 'src/page.tsx',
      message: 'Cookie written via document.cookie without consent guard',
      snippet: 'document.cookie = "track=1";',
    }
    const v1: ScanViolation = { ...base, line: 5, column: 2 }
    const v2: ScanViolation = { ...base, line: 10, column: 4 }
    expect(fingerprintScanViolation(v1)).toBe(fingerprintScanViolation(v2))
  })

  it('differs when the snippet changes', () => {
    const base = {
      file: 'src/page.tsx',
      line: 5,
      column: 2,
      message: 'Cookie written via document.cookie without consent guard',
    }
    const v1: ScanViolation = { ...base, snippet: 'document.cookie = "a=1";' }
    const v2: ScanViolation = { ...base, snippet: 'document.cookie = "b=2";' }
    expect(fingerprintScanViolation(v1)).not.toBe(fingerprintScanViolation(v2))
  })
})

describe('fingerprintAuditViolation', () => {
  it('produces a stable hash', () => {
    const v: AuditViolation = {
      cookieName: '_ga',
      source: 'https://example.com',
      via: 'set-cookie-header',
    }
    expect(fingerprintAuditViolation(v)).toBe(fingerprintAuditViolation(v))
  })

  it('ignores source URL (may vary between environments)', () => {
    const v1: AuditViolation = {
      cookieName: '_ga',
      source: 'https://staging.example.com',
      via: 'set-cookie-header',
    }
    const v2: AuditViolation = {
      cookieName: '_ga',
      source: 'https://prod.example.com',
      via: 'set-cookie-header',
    }
    expect(fingerprintAuditViolation(v1)).toBe(fingerprintAuditViolation(v2))
  })

  it('differs when cookie name differs', () => {
    const v1: AuditViolation = {
      cookieName: '_ga',
      source: 'https://example.com',
      via: 'set-cookie-header',
    }
    const v2: AuditViolation = {
      cookieName: '_fbp',
      source: 'https://example.com',
      via: 'set-cookie-header',
    }
    expect(fingerprintAuditViolation(v1)).not.toBe(fingerprintAuditViolation(v2))
  })
})

// ---------------------------------------------------------------------------
// Load / Save
// ---------------------------------------------------------------------------

describe('loadBaseline', () => {
  it('returns null when file does not exist', () => {
    expect(loadBaseline('/tmp/nonexistent-baseline.json')).toBeNull()
  })

  it('round-trips through save and load', () => {
    saveBaseline(tmpFile, ['abc', 'def'])
    const loaded = loadBaseline(tmpFile)
    expect(loaded).not.toBeNull()
    expect(loaded!.version).toBe(1)
    expect(loaded!.entries).toEqual(['abc', 'def'])
  })

  it('deduplicates entries on save', () => {
    saveBaseline(tmpFile, ['abc', 'abc', 'def'])
    const loaded = loadBaseline(tmpFile)
    expect(loaded!.entries).toEqual(['abc', 'def'])
  })
})

// ---------------------------------------------------------------------------
// filterNew
// ---------------------------------------------------------------------------

describe('filterNew', () => {
  it('returns all violations when baseline is empty', () => {
    const violations: ScanViolation[] = [
      { file: 'a.ts', line: 1, column: 0, message: 'msg', snippet: 'snip' },
    ]
    const result = filterNew(violations, { version: 1, entries: [] }, fingerprintScanViolation)
    expect(result).toHaveLength(1)
  })

  it('filters out known violations', () => {
    const v: ScanViolation = { file: 'a.ts', line: 1, column: 0, message: 'msg', snippet: 'snip' }
    const fp = fingerprintScanViolation(v)
    const result = filterNew([v], { version: 1, entries: [fp] }, fingerprintScanViolation)
    expect(result).toHaveLength(0)
  })

  it('keeps new violations while filtering known ones', () => {
    const known: ScanViolation = {
      file: 'a.ts',
      line: 1,
      column: 0,
      message: 'msg',
      snippet: 'snip',
    }
    const fresh: ScanViolation = {
      file: 'b.ts',
      line: 1,
      column: 0,
      message: 'msg',
      snippet: 'other',
    }
    const fp = fingerprintScanViolation(known)
    const result = filterNew(
      [known, fresh],
      { version: 1, entries: [fp] },
      fingerprintScanViolation,
    )
    expect(result).toHaveLength(1)
    expect(result[0]?.file).toBe('b.ts')
  })
})
