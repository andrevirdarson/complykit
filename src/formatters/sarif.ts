import type { ScanViolation } from '../scanner/cookie.js'
import type { AuditResult } from '../audit/browser.js'
import {
  RULE_DOCUMENT_COOKIE,
  RULE_RES_COOKIE,
  RULE_COOKIES_SET,
  RULE_LOCAL_STORAGE,
  RULE_SESSION_STORAGE,
  RULE_TRACKER_SCRIPT,
  RULE_SET_COOKIE_HEADER,
  RULE_UNEXPECTED_COOKIE_HEADER,
  RULE_UNEXPECTED_COOKIE_CONTEXT,
  RULE_GENERIC,
} from '../ruleIds.js'

type SarifResult = {
  ruleId: string
  ruleIndex: number
  level: 'error' | 'warning' | 'note'
  message: { text: string }
  locations: Array<{
    physicalLocation?: {
      artifactLocation: { uri: string }
      region: { startLine: number; startColumn: number }
    }
    logicalLocations?: Array<{ fullyQualifiedName: string }>
  }>
  fingerprints?: Record<string, string>
}

type SarifRule = {
  id: string
  shortDescription: { text: string }
  helpUri?: string
}

function ruleIdFromMessage(message: string): string {
  if (message.includes('document.cookie')) return RULE_DOCUMENT_COOKIE
  if (message.includes('res.cookie')) return RULE_RES_COOKIE
  if (message.includes('cookies().set')) return RULE_COOKIES_SET
  if (message.includes('localStorage')) return RULE_LOCAL_STORAGE
  if (message.includes('sessionStorage')) return RULE_SESSION_STORAGE
  if (message.includes('tracker')) return RULE_TRACKER_SCRIPT
  if (message.includes('Set-Cookie')) return RULE_SET_COOKIE_HEADER
  return RULE_GENERIC
}

function buildSarifEnvelope(rules: SarifRule[], results: SarifResult[]) {
  return {
    $schema:
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0' as const,
    runs: [
      {
        tool: {
          driver: {
            name: 'complykit',
            informationUri: 'https://github.com/andrevirdarson/complykit',
            version: '0.1.0',
            rules,
          },
        },
        results,
      },
    ],
  }
}

export function scanToSarif(violations: ScanViolation[]): string {
  const rulesMap = new Map<string, SarifRule>()
  const results: SarifResult[] = []

  for (const v of violations) {
    const ruleId = ruleIdFromMessage(v.message)
    if (!rulesMap.has(ruleId)) {
      rulesMap.set(ruleId, { id: ruleId, shortDescription: { text: v.message } })
    }

    const ruleIndex = [...rulesMap.keys()].indexOf(ruleId)
    results.push({
      ruleId,
      ruleIndex,
      level: 'error',
      message: { text: `${v.message}\n${v.snippet}` },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: v.file },
            region: { startLine: v.line, startColumn: v.column + 1 },
          },
        },
      ],
    })
  }

  return JSON.stringify(buildSarifEnvelope([...rulesMap.values()], results), null, 2)
}

export function auditToSarif(result: AuditResult): string {
  const rulesMap = new Map<string, SarifRule>()
  const results: SarifResult[] = []

  for (const page of result.pages) {
    for (const v of page.violations) {
      const ruleId =
        v.via === 'set-cookie-header'
          ? RULE_UNEXPECTED_COOKIE_HEADER
          : RULE_UNEXPECTED_COOKIE_CONTEXT

      if (!rulesMap.has(ruleId)) {
        rulesMap.set(ruleId, {
          id: ruleId,
          shortDescription: {
            text:
              v.via === 'set-cookie-header'
                ? 'Unexpected cookie set via HTTP header before consent'
                : 'Unexpected cookie found in browser context before consent',
          },
        })
      }

      const ruleIndex = [...rulesMap.keys()].indexOf(ruleId)
      results.push({
        ruleId,
        ruleIndex,
        level: 'error',
        message: {
          text: `Unexpected cookie "${v.cookieName}" detected before consent (via ${v.via}, source: ${v.source})`,
        },
        locations: [
          {
            logicalLocations: [{ fullyQualifiedName: page.url }],
          },
        ],
      })
    }
  }

  return JSON.stringify(buildSarifEnvelope([...rulesMap.values()], results), null, 2)
}
