import { writeFileSync } from 'fs'
import { runBrowserAudit } from '../audit/browser.js'
import { loadConfig } from '../config/loader.js'
import type { AuditViolation } from '../audit/browser.js'
import { auditToSarif } from '../formatters/sarif.js'
import {
  loadBaseline,
  saveBaseline,
  filterNew,
  fingerprintAuditViolation,
} from '../baseline/baseline.js'
import type { OutputFormat } from './scan.js'
import { EXIT_CLEAN, EXIT_VIOLATIONS } from '../exitCodes.js'

type AuditOpts = {
  config?: string
  format?: OutputFormat
  output?: string
  baseline?: string
  updateBaseline?: boolean
}

function formatPageResult(result: { url: string; violations: AuditViolation[] }): void {
  const status = result.violations.length === 0 ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✖\x1b[0m'
  console.log(`${status} ${result.url}`)

  if (result.violations.length > 0) {
    for (const v of result.violations) {
      console.log(formatViolation(v))
    }
    console.log()
  }
}

function formatViolation(v: AuditViolation): string {
  return [
    `  \x1b[31m[VIOLATION]\x1b[0m Unexpected cookie detected before consent:`,
    `    name:   \x1b[33m${v.cookieName}\x1b[0m`,
    `    source: ${v.source}`,
    `    via:    ${v.via}`,
  ].join('\n')
}

export async function runAudit(baseUrl: string, opts: AuditOpts): Promise<void> {
  const config = loadConfig(opts.config)
  const format = opts.format ?? 'pretty'
  const isPretty = format === 'pretty'

  if (isPretty) {
    console.log(`\nAuditing: ${baseUrl}`)
    console.log(`Pages: ${config.crawlPages.join(', ')}`)
    console.log(`Allowed before consent: ${config.allowedBeforeConsent.join(', ') || '(none)'}\n`)
  }

  const result = await runBrowserAudit({
    baseUrl,
    crawlPages: config.crawlPages,
    allowedBeforeConsent: config.allowedBeforeConsent,
  })

  // Flatten all violations for baseline processing
  let allViolations = result.pages.flatMap((p) => p.violations)
  let violations = allViolations
  let baselinedCount = 0

  if (opts.updateBaseline) {
    const baselinePath = opts.baseline ?? '.complykit-baseline.json'
    const fingerprints = allViolations.map(fingerprintAuditViolation)
    saveBaseline(baselinePath, fingerprints)
    if (isPretty) {
      console.log(
        `\x1b[32m✓ Baseline updated\x1b[0m (${fingerprints.length} violation(s) saved to ${baselinePath})`,
      )
    }
    process.exit(EXIT_CLEAN)
  }

  if (opts.baseline) {
    const baseline = loadBaseline(opts.baseline)
    if (baseline) {
      violations = filterNew(allViolations, baseline, fingerprintAuditViolation)
      baselinedCount = allViolations.length - violations.length

      // Rebuild result with filtered violations for SARIF/JSON output
      for (const page of result.pages) {
        page.violations = page.violations.filter(
          (v) => !baseline.entries.includes(fingerprintAuditViolation(v)),
        )
      }
      result.totalViolations = violations.length
    }
  }

  const write = (content: string) => {
    if (opts.output) {
      writeFileSync(opts.output, content + '\n')
    } else {
      console.log(content)
    }
  }

  if (format === 'json') {
    write(JSON.stringify({ ...result, baselinedCount }, null, 2))
  } else if (format === 'sarif') {
    write(auditToSarif(result))
  } else {
    for (const page of result.pages) {
      formatPageResult(page)
    }

    if (violations.length === 0) {
      const extra = baselinedCount > 0 ? ` (${baselinedCount} baselined)` : ''
      console.log(`\x1b[32m✓ No unexpected cookies found before consent\x1b[0m${extra}`)
      process.exit(EXIT_CLEAN)
    }

    const extra = baselinedCount > 0 ? ` (${baselinedCount} baselined)` : ''
    console.log(`\x1b[31m✖ ${violations.length} cookie violation(s) detected\x1b[0m${extra}`)
  }

  process.exit(violations.length > 0 ? EXIT_VIOLATIONS : EXIT_CLEAN)
}
