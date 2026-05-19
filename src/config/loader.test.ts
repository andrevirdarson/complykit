import { describe, it, expect, afterEach } from 'bun:test'
import { writeFileSync, unlinkSync, existsSync } from 'fs'
import { join } from 'path'
import { tmpdir } from 'os'
import { loadConfig } from './loader.js'

const tmpFiles: string[] = []
function writeTmpConfig(content: string): string {
  const path = join(tmpdir(), `complykit-${Date.now()}-${Math.random()}.yml`)
  writeFileSync(path, content)
  tmpFiles.push(path)
  return path
}

afterEach(() => {
  for (const f of tmpFiles.splice(0)) if (existsSync(f)) unlinkSync(f)
})

describe('loadConfig validation', () => {
  it('rejects consentGuards as a bare string', () => {
    const path = writeTmpConfig(`consentGuards: hasConsent\n`)
    expect(() => loadConfig(path)).toThrow(/consentGuards/)
  })

  it('rejects consentGuards as a list of non-strings', () => {
    const path = writeTmpConfig(`consentGuards:\n  - 1\n  - 2\n`)
    expect(() => loadConfig(path)).toThrow(/consentGuards/)
  })

  it('rejects allowedBeforeConsent as a non-array', () => {
    const path = writeTmpConfig(`allowedBeforeConsent: session\n`)
    expect(() => loadConfig(path)).toThrow(/allowedBeforeConsent/)
  })

  it('accepts a valid consentGuards list', () => {
    const path = writeTmpConfig(
      `consentGuards:\n  - hasMarketingConsent\n  - user.consent.analytics\n`,
    )
    const config = loadConfig(path)
    expect(config.consentGuards).toEqual(['hasMarketingConsent', 'user.consent.analytics'])
  })

  it('rejects a YAML root that is a bare string', () => {
    const path = writeTmpConfig(`just-a-string\n`)
    expect(() => loadConfig(path)).toThrow(/must be a YAML mapping/)
  })

  it('rejects a YAML root that is an array', () => {
    const path = writeTmpConfig(`- one\n- two\n`)
    expect(() => loadConfig(path)).toThrow(/must be a YAML mapping/)
  })

  it('accepts an entirely empty config file', () => {
    const path = writeTmpConfig(``)
    const config = loadConfig(path)
    expect(config.consentGuards).toEqual([])
    expect(config.crawlPages).toEqual(['/'])
  })

  it('defaults consentGuards to [] when absent', () => {
    const path = writeTmpConfig(`crawlPages:\n  - /\n`)
    const config = loadConfig(path)
    expect(config.consentGuards).toEqual([])
  })
})
