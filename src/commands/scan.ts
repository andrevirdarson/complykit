import { writeFileSync } from 'fs'
import { scanDirectory } from '../scanner/cookie.js'
import type { ScanViolation } from '../scanner/cookie.js'
import { loadConfig } from '../config/loader.js'
import { scanToSarif } from '../formatters/sarif.js'
import {
  loadBaseline,
  saveBaseline,
  filterNew,
  fingerprintScanViolation,
} from '../baseline/baseline.js'
import { EXIT_CLEAN, EXIT_VIOLATIONS } from '../exitCodes.js'

export type OutputFormat = 'pretty' | 'json' | 'sarif'

type ScanOpts = {
  config?: string
  format?: OutputFormat
  output?: string
  baseline?: string
  updateBaseline?: boolean
}

function formatViolation(v: ScanViolation): string {
  return [
    `\x1b[31m[ERROR]\x1b[0m ${v.file}:${v.line}:${v.column}`,
    `  ${v.message}`,
    `  \x1b[90m${v.snippet}\x1b[0m`,
  ].join('\n')
}

export async function runScan(targetPath: string, opts: ScanOpts): Promise<void> {
  loadConfig(opts.config)

  const format = opts.format ?? 'pretty'
  const isPretty = format === 'pretty'

  if (isPretty) console.log(`\nScanning: ${targetPath}\n`)

  const { violations: allViolations, filesScanned } = await scanDirectory(targetPath)

  // Baseline filtering
  let violations = allViolations
  let baselinedCount = 0

  if (opts.updateBaseline) {
    const baselinePath = opts.baseline ?? '.complykit-baseline.json'
    const fingerprints = allViolations.map(fingerprintScanViolation)
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
      violations = filterNew(allViolations, baseline, fingerprintScanViolation)
      baselinedCount = allViolations.length - violations.length
    }
  }

  // Output
  const write = (content: string) => {
    if (opts.output) {
      writeFileSync(opts.output, content + '\n')
    } else {
      console.log(content)
    }
  }

  if (format === 'json') {
    write(JSON.stringify({ violations, filesScanned, baselinedCount }, null, 2))
  } else if (format === 'sarif') {
    write(scanToSarif(violations))
  } else {
    if (violations.length === 0) {
      const extra = baselinedCount > 0 ? ` (${baselinedCount} baselined)` : ''
      console.log(
        `\x1b[32m✓ No cookie violations found\x1b[0m (${filesScanned} files scanned)${extra}`,
      )
      process.exit(EXIT_CLEAN)
    }

    for (const v of violations) {
      console.log(formatViolation(v))
      console.log()
    }

    const extra = baselinedCount > 0 ? ` (${baselinedCount} baselined)` : ''
    console.log(
      `\x1b[31m✖ ${violations.length} violation(s) found across ${filesScanned} files\x1b[0m${extra}`,
    )
  }

  process.exit(violations.length > 0 ? EXIT_VIOLATIONS : EXIT_CLEAN)
}
