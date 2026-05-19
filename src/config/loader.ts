import { readFileSync, existsSync } from 'fs'
import { resolve } from 'path'
import yaml from 'js-yaml'

type ComplyKitConfig = {
  allowedBeforeConsent: string[]
  crawlPages: string[]
  consentGuards: string[]
}

const DEFAULT_CONFIG: ComplyKitConfig = {
  allowedBeforeConsent: [],
  crawlPages: ['/'],
  consentGuards: [],
}

// YAML happily parses `consentGuards: hasConsent` as a string, but downstream
// code expects an array. Reject non-array, non-undefined values up front with
// a clear error so the user sees the config mistake instead of a crash later.
function requireStringArray(value: unknown, field: string, fallback: string[]): string[] {
  if (value === undefined || value === null) return fallback
  if (!Array.isArray(value) || !value.every((v) => typeof v === 'string')) {
    throw new Error(
      `[complykit] config field '${field}' must be a list of strings (got ${typeof value === 'object' ? JSON.stringify(value) : typeof value})`,
    )
  }
  return value
}

export function loadConfig(configPath?: string): ComplyKitConfig {
  const candidates = [configPath, 'complykit.yml', 'complykit.yaml'].filter(Boolean) as string[]

  for (const candidate of candidates) {
    const abs = resolve(process.cwd(), candidate)
    if (existsSync(abs)) {
      const raw = readFileSync(abs, 'utf-8')
      const loaded = yaml.load(raw)
      // Treat an entirely empty file as defaults, but reject any non-mapping
      // root (string, number, array) so the user notices a malformed config
      // instead of silently getting defaults.
      if (loaded !== null && loaded !== undefined) {
        if (typeof loaded !== 'object' || Array.isArray(loaded)) {
          throw new Error(
            `[complykit] config file ${candidate} must be a YAML mapping (got ${Array.isArray(loaded) ? 'array' : typeof loaded})`,
          )
        }
      }
      const parsed = (loaded ?? {}) as Record<string, unknown>
      return {
        allowedBeforeConsent: requireStringArray(
          parsed.allowedBeforeConsent,
          'allowedBeforeConsent',
          DEFAULT_CONFIG.allowedBeforeConsent,
        ),
        crawlPages: requireStringArray(parsed.crawlPages, 'crawlPages', DEFAULT_CONFIG.crawlPages),
        consentGuards: requireStringArray(
          parsed.consentGuards,
          'consentGuards',
          DEFAULT_CONFIG.consentGuards,
        ),
      }
    }
  }

  console.warn('[warn] No complykit.yml found — using defaults.')
  return DEFAULT_CONFIG
}
