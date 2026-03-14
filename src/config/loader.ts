import { readFileSync, existsSync } from 'fs'
import { resolve } from 'path'
import yaml from 'js-yaml'

type ComplyKitConfig = {
  allowedBeforeConsent: string[]
  crawlPages: string[]
}

const DEFAULT_CONFIG: ComplyKitConfig = {
  allowedBeforeConsent: [],
  crawlPages: ['/'],
}

export function loadConfig(configPath?: string): ComplyKitConfig {
  const candidates = [configPath, 'complykit.yml', 'complykit.yaml'].filter(Boolean) as string[]

  for (const candidate of candidates) {
    const abs = resolve(process.cwd(), candidate)
    if (existsSync(abs)) {
      const raw = readFileSync(abs, 'utf-8')
      const parsed = yaml.load(raw) as Partial<ComplyKitConfig>
      return {
        allowedBeforeConsent: parsed.allowedBeforeConsent ?? DEFAULT_CONFIG.allowedBeforeConsent,
        crawlPages: parsed.crawlPages ?? DEFAULT_CONFIG.crawlPages,
      }
    }
  }

  console.warn('[warn] No complykit.yml found — using defaults.')
  return DEFAULT_CONFIG
}
