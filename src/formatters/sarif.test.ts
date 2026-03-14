import { describe, it, expect } from 'bun:test'
import { scanToSarif, auditToSarif } from './sarif.js'
import {
  RULE_DOCUMENT_COOKIE,
  RULE_LOCAL_STORAGE,
  RULE_UNEXPECTED_COOKIE_HEADER,
  RULE_UNEXPECTED_COOKIE_CONTEXT,
} from '../ruleIds.js'
import type { ScanViolation } from '../scanner/cookie.js'
import type { AuditResult } from '../audit/browser.js'

// ---------------------------------------------------------------------------
// scanToSarif
// ---------------------------------------------------------------------------

describe('scanToSarif', () => {
  it('produces valid SARIF 2.1.0 envelope', () => {
    const sarif = JSON.parse(scanToSarif([]))
    expect(sarif.version).toBe('2.1.0')
    expect(sarif.$schema).toContain('sarif-schema-2.1.0')
    expect(sarif.runs).toHaveLength(1)
    expect(sarif.runs[0].tool.driver.name).toBe('complykit')
  })

  it('returns empty results for no violations', () => {
    const sarif = JSON.parse(scanToSarif([]))
    expect(sarif.runs[0].results).toHaveLength(0)
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(0)
  })

  it('maps scan violations to SARIF results with physical locations', () => {
    const violations: ScanViolation[] = [
      {
        file: 'src/page.tsx',
        line: 5,
        column: 2,
        message: 'Cookie written via document.cookie without consent guard',
        snippet: 'document.cookie = "track=1";',
      },
    ]

    const sarif = JSON.parse(scanToSarif(violations))
    const result = sarif.runs[0].results[0]

    expect(result.ruleId).toBe(RULE_DOCUMENT_COOKIE)
    expect(result.ruleIndex).toBe(0)
    expect(result.level).toBe('error')
    expect(result.message.text).toContain('document.cookie')
    expect(result.locations[0].physicalLocation.artifactLocation.uri).toBe('src/page.tsx')
    expect(result.locations[0].physicalLocation.region.startLine).toBe(5)
    expect(result.locations[0].physicalLocation.region.startColumn).toBe(3) // 0-based -> 1-based
  })

  it('deduplicates rules for same ruleId', () => {
    const violations: ScanViolation[] = [
      {
        file: 'a.ts',
        line: 1,
        column: 0,
        message: 'Cookie written via document.cookie without consent guard',
        snippet: 'document.cookie = "a=1";',
      },
      {
        file: 'b.ts',
        line: 3,
        column: 0,
        message: 'Cookie written via document.cookie without consent guard',
        snippet: 'document.cookie = "b=2";',
      },
    ]

    const sarif = JSON.parse(scanToSarif(violations))
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(1)
    expect(sarif.runs[0].results).toHaveLength(2)
    expect(sarif.runs[0].results[0].ruleIndex).toBe(0)
    expect(sarif.runs[0].results[1].ruleIndex).toBe(0)
  })

  it('creates separate rules for different violation types', () => {
    const violations: ScanViolation[] = [
      {
        file: 'a.ts',
        line: 1,
        column: 0,
        message: 'Cookie written via document.cookie without consent guard',
        snippet: 'document.cookie = "a=1";',
      },
      {
        file: 'b.ts',
        line: 1,
        column: 0,
        message: 'Tracking data written to localStorage without consent guard',
        snippet: 'localStorage.setItem("k", "v");',
      },
    ]

    const sarif = JSON.parse(scanToSarif(violations))
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(2)
    expect(sarif.runs[0].tool.driver.rules[0].id).toBe(RULE_DOCUMENT_COOKIE)
    expect(sarif.runs[0].tool.driver.rules[1].id).toBe(RULE_LOCAL_STORAGE)
  })
})

// ---------------------------------------------------------------------------
// auditToSarif
// ---------------------------------------------------------------------------

describe('auditToSarif', () => {
  it('produces valid SARIF envelope for empty audit', () => {
    const result: AuditResult = { pages: [], totalViolations: 0 }
    const sarif = JSON.parse(auditToSarif(result))
    expect(sarif.version).toBe('2.1.0')
    expect(sarif.runs[0].results).toHaveLength(0)
  })

  it('maps audit violations to SARIF results with logical locations', () => {
    const result: AuditResult = {
      pages: [
        {
          url: 'https://example.com/',
          cookiesFound: ['_ga'],
          violations: [
            {
              cookieName: '_ga',
              source: 'https://analytics.example.com/collect',
              via: 'set-cookie-header',
            },
          ],
        },
      ],
      totalViolations: 1,
    }

    const sarif = JSON.parse(auditToSarif(result))
    const res = sarif.runs[0].results[0]

    expect(res.ruleId).toBe(RULE_UNEXPECTED_COOKIE_HEADER)
    expect(res.level).toBe('error')
    expect(res.message.text).toContain('_ga')
    expect(res.locations[0].logicalLocations[0].fullyQualifiedName).toBe('https://example.com/')
  })

  it('uses correct rule IDs for different via types', () => {
    const result: AuditResult = {
      pages: [
        {
          url: 'https://example.com/',
          cookiesFound: ['_ga', '_fbp'],
          violations: [
            { cookieName: '_ga', source: 'https://example.com/', via: 'set-cookie-header' },
            { cookieName: '_fbp', source: 'https://example.com/', via: 'browser-context' },
          ],
        },
      ],
      totalViolations: 2,
    }

    const sarif = JSON.parse(auditToSarif(result))
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(2)
    expect(sarif.runs[0].results[0].ruleId).toBe(RULE_UNEXPECTED_COOKIE_HEADER)
    expect(sarif.runs[0].results[1].ruleId).toBe(RULE_UNEXPECTED_COOKIE_CONTEXT)
  })
})
