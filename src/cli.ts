#!/usr/bin/env bun
import { Command } from 'commander'
import { runScan } from './commands/scan.js'
import { runAudit } from './commands/audit.js'
import type { OutputFormat } from './commands/scan.js'
import { EXIT_ERROR } from './exitCodes.js'

const program = new Command()

program
  .name('complykit')
  .description('Cookie compliance checker — static analysis + runtime browser audit')
  .version('0.0.1')

program
  .command('scan <path>')
  .description('Statically scan JS/TS source files for cookie writes without consent guards')
  .option('-c, --config <path>', 'Path to complykit.yml config file')
  .option('-f, --format <format>', 'Output format: pretty, json, sarif', 'pretty')
  .option('--baseline <path>', 'Path to baseline file for incremental adoption')
  .option('-o, --output <path>', 'Write output to file instead of stdout')
  .option('--update-baseline', 'Save current violations as the new baseline')
  .action(
    (
      targetPath: string,
      opts: {
        config?: string
        format?: OutputFormat
        output?: string
        baseline?: string
        updateBaseline?: boolean
      },
    ) => {
      runScan(targetPath, opts).catch((err) => {
        console.error('[fatal]', err instanceof Error ? err.message : err)
        process.exit(EXIT_ERROR)
      })
    },
  )

program
  .command('audit <url>')
  .description('Run a headless browser audit against a live URL')
  .option('-c, --config <path>', 'Path to complykit.yml config file')
  .option('-f, --format <format>', 'Output format: pretty, json, sarif', 'pretty')
  .option('--baseline <path>', 'Path to baseline file for incremental adoption')
  .option('-o, --output <path>', 'Write output to file instead of stdout')
  .option('--update-baseline', 'Save current violations as the new baseline')
  .action(
    (
      url: string,
      opts: {
        config?: string
        format?: OutputFormat
        output?: string
        baseline?: string
        updateBaseline?: boolean
      },
    ) => {
      runAudit(url, opts).catch((err) => {
        console.error('[fatal]', err instanceof Error ? err.message : err)
        process.exit(EXIT_ERROR)
      })
    },
  )

program.parse()
