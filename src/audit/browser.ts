import { chromium, type Browser, type BrowserContext, type Page, type Response } from 'playwright'

export type AuditViolation = {
  cookieName: string
  source: string
  via: 'browser-context' | 'set-cookie-header'
}

type PageAuditResult = {
  url: string
  violations: AuditViolation[]
  cookiesFound: string[]
}

export type AuditResult = {
  pages: PageAuditResult[]
  totalViolations: number
}

function extractSetCookieNames(setCookieHeaders: string[]): string[] {
  return setCookieHeaders
    .map((h) => {
      const name = h.split('=')[0]?.trim()
      return name ?? ''
    })
    .filter(Boolean)
}

async function auditPage(
  page: Page,
  context: BrowserContext,
  url: string,
  allowedBeforeConsent: Set<string>,
): Promise<PageAuditResult> {
  const setCookieHeaders: Array<{ name: string; source: string }> = []

  // Capture Set-Cookie headers from all responses.
  // headersArray() preserves duplicate headers (unlike headers() which can collapse them).
  page.on('response', async (response: Response) => {
    const allHeaders = await response.headersArray()
    const cookies = allHeaders
      .filter((h) => h.name.toLowerCase() === 'set-cookie')
      .map((h) => h.value)
    const names = extractSetCookieNames(cookies)
    for (const name of names) {
      setCookieHeaders.push({ name, source: response.url() })
    }
  })

  await page.goto(url, { waitUntil: 'networkidle', timeout: 30_000 })

  // Cookies currently in the browser context
  const contextCookies = await context.cookies()

  const violations: AuditViolation[] = []
  const cookiesFound: string[] = []

  // Check browser context cookies
  for (const cookie of contextCookies) {
    cookiesFound.push(cookie.name)
    if (!allowedBeforeConsent.has(cookie.name)) {
      violations.push({
        cookieName: cookie.name,
        source: url,
        via: 'browser-context',
      })
    }
  }

  // Check Set-Cookie headers captured during navigation
  for (const { name, source } of setCookieHeaders) {
    if (!allowedBeforeConsent.has(name) && !violations.some((v) => v.cookieName === name)) {
      violations.push({
        cookieName: name,
        source,
        via: 'set-cookie-header',
      })
    }
  }

  return { url, violations, cookiesFound }
}

type BrowserAuditOptions = {
  baseUrl: string
  crawlPages: string[]
  allowedBeforeConsent: string[]
}

export async function runBrowserAudit(options: BrowserAuditOptions): Promise<AuditResult> {
  const { baseUrl, crawlPages, allowedBeforeConsent } = options
  const allowedSet = new Set(allowedBeforeConsent)

  let browser: Browser | null = null
  const results: PageAuditResult[] = []

  try {
    browser = await chromium.launch({ headless: true })

    for (const pagePath of crawlPages) {
      // Use the URL constructor so missing/extra slashes don't produce wrong paths.
      const url = new URL(pagePath, baseUrl.endsWith('/') ? baseUrl : baseUrl + '/').href

      // Fresh context per page — no cookies bleed between pages
      const context = await browser.newContext()
      const page = await context.newPage()

      try {
        const result = await auditPage(page, context, url, allowedSet)
        results.push(result)
      } finally {
        await context.close()
      }
    }
  } finally {
    await browser?.close()
  }

  return {
    pages: results,
    totalViolations: results.reduce((sum, r) => sum + r.violations.length, 0),
  }
}
