import { describe, it, expect } from 'bun:test'
import { writeFileSync, unlinkSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import {
  scanFileAST,
  scanFileText,
  buildSuppressedLines,
  TRACKER_HOSTNAMES,
  scanDirectory,
} from './cookie.js'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function violations(source: string) {
  return scanFileAST('test.ts', source)
}

// ---------------------------------------------------------------------------
// document.cookie
// ---------------------------------------------------------------------------

describe('document.cookie assignment', () => {
  it('flags a bare assignment', () => {
    const result = violations(`document.cookie = "analytics=true";`)
    expect(result).toHaveLength(1)
    expect(result[0]?.message).toContain('document.cookie')
    expect(result[0]?.line).toBe(1)
  })

  it('flags assignment on a later line', () => {
    const source = `
const x = 1;
document.cookie = "foo=bar";
`
    const result = violations(source)
    expect(result).toHaveLength(1)
    expect(result[0]?.line).toBe(3)
  })

  it('does not flag a read of document.cookie', () => {
    const result = violations(`const c = document.cookie;`)
    expect(result).toHaveLength(0)
  })

  it('does not flag computed property access', () => {
    // document["cookie"] = ... — unusual but different AST shape; we conservatively ignore
    const result = violations(`document["cookie"] = "x=1";`)
    expect(result).toHaveLength(0)
  })

  it('includes the source snippet', () => {
    const result = violations(`  document.cookie = "a=b";`)
    expect(result[0]?.snippet).toBe(`document.cookie = "a=b";`)
  })
})

// ---------------------------------------------------------------------------
// res.cookie()
// ---------------------------------------------------------------------------

describe('res.cookie() call', () => {
  it('flags res.cookie()', () => {
    const result = violations(`res.cookie("session", "abc");`)
    expect(result).toHaveLength(1)
    expect(result[0]?.message).toContain('res.cookie()')
  })

  it('flags any identifier.cookie() call', () => {
    // response.cookie(), reply.cookie() — same pattern
    const result = violations(`response.cookie("id", "123");`)
    expect(result).toHaveLength(1)
  })

  it('does not flag cookie() called without an object', () => {
    const result = violations(`cookie("name", "val");`)
    expect(result).toHaveLength(0)
  })

  it('does not flag res.clearCookie()', () => {
    const result = violations(`res.clearCookie("session");`)
    expect(result).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// cookies().set() — Next.js / Web API
// ---------------------------------------------------------------------------

describe('cookies().set() call', () => {
  it('flags cookies().set()', () => {
    const result = violations(`cookies().set("consent", "true");`)
    expect(result).toHaveLength(1)
    expect(result[0]?.message).toContain('cookies().set()')
  })

  it('flags cookieStore.set()', () => {
    const result = violations(`cookieStore.set("theme", "dark");`)
    expect(result).toHaveLength(1)
    expect(result[0]?.message).toContain('cookies().set()')
  })

  it('does not flag cookies().get()', () => {
    const result = violations(`const c = cookies().get("consent");`)
    expect(result).toHaveLength(0)
  })

  it('does not flag arbitrary obj.set() calls', () => {
    const result = violations(`map.set("key", "value");`)
    expect(result).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// Multiple violations in one file
// ---------------------------------------------------------------------------

describe('multiple violations', () => {
  it('reports all violations in a single file', () => {
    const source = `
document.cookie = "a=1";
res.cookie("b", "2");
cookies().set("c", "3");
`
    const result = violations(source)
    expect(result).toHaveLength(3)
  })
})

// ---------------------------------------------------------------------------
// TSX support
// ---------------------------------------------------------------------------

describe('TSX files', () => {
  it('parses TSX and still flags document.cookie', () => {
    const source = `
export default function Page() {
  document.cookie = "track=1";
  return <div />;
}
`
    const result = scanFileAST('page.tsx', source)
    expect(result).toHaveLength(1)
    expect(result[0]?.line).toBe(3)
  })
})

// ---------------------------------------------------------------------------
// Graceful parse failure fallback
// ---------------------------------------------------------------------------

describe('parse failure fallback', () => {
  it('falls back to text scan on unparseable input', () => {
    // Valid JS but with a Set-Cookie pattern — the text fallback should catch it
    const source = `THIS IS NOT JAVASCRIPT\nSet-Cookie: foo=bar`
    const result = scanFileAST('broken.ts', source)
    expect(result).toHaveLength(1)
    expect(result[0]?.message).toContain('Set-Cookie')
  })
})

// ---------------------------------------------------------------------------
// Web Storage writes
// ---------------------------------------------------------------------------

describe('localStorage / sessionStorage writes (AST)', () => {
  it('flags localStorage.setItem()', () => {
    const result = violations(`localStorage.setItem('userId', '123');`)
    expect(result).toHaveLength(1)
    expect(result[0]?.message).toContain('localStorage')
    expect(result[0]?.line).toBe(1)
  })

  it('flags sessionStorage.setItem()', () => {
    const result = violations(`sessionStorage.setItem('sessionId', 'abc');`)
    expect(result).toHaveLength(1)
    expect(result[0]?.message).toContain('sessionStorage')
  })

  it('does not flag localStorage.getItem()', () => {
    const result = violations(`const v = localStorage.getItem('consent');`)
    expect(result).toHaveLength(0)
  })

  it('does not flag localStorage.removeItem()', () => {
    const result = violations(`localStorage.removeItem('userId');`)
    expect(result).toHaveLength(0)
  })

  it('does not flag arbitrary obj.setItem()', () => {
    const result = violations(`myCache.setItem('key', 'val');`)
    expect(result).toHaveLength(0)
  })

  it('reports the correct line for a later-line write', () => {
    const source = `\nconst x = 1;\nlocalStorage.setItem('track', '1');\n`
    const result = violations(source)
    expect(result).toHaveLength(1)
    expect(result[0]?.line).toBe(3)
  })
})

// ---------------------------------------------------------------------------
// Third-party script injection — AST
// ---------------------------------------------------------------------------

describe('third-party tracker script injection (AST)', () => {
  it('flags .src assignment to a Google Analytics URL', () => {
    const source = `
const s = document.createElement('script');
s.src = 'https://www.google-analytics.com/analytics.js';
document.head.appendChild(s);
`
    const result = scanFileAST('inject.ts', source)
    expect(result).toHaveLength(1)
    expect(result[0]?.message).toContain('google-analytics.com')
    expect(result[0]?.line).toBe(3)
  })

  it('flags .src assignment to GTM', () => {
    const result = scanFileAST(
      'gtm.ts',
      `el.src = 'https://www.googletagmanager.com/gtm.js?id=GTM-XXXX';`,
    )
    expect(result).toHaveLength(1)
    expect(result[0]?.message).toContain('consent guard')
  })

  it('flags .src assignment to Meta Pixel', () => {
    const result = scanFileAST(
      'fb.ts',
      `script.src = 'https://connect.facebook.net/en_US/fbevents.js';`,
    )
    expect(result).toHaveLength(1)
  })

  it('flags .src assignment to Hotjar', () => {
    const result = scanFileAST('hj.ts', `s.src = 'https://script.hotjar.com/modules.js';`)
    expect(result).toHaveLength(1)
  })

  it('does not flag .src assignment to a non-tracker URL', () => {
    const result = scanFileAST('safe.ts', `img.src = 'https://example.com/logo.png';`)
    expect(result).toHaveLength(0)
  })

  it('does not flag a tracker URL used in a non-src property', () => {
    const result = scanFileAST('safe.ts', `el.href = 'https://www.google-analytics.com/';`)
    expect(result).toHaveLength(0)
  })

  it('exports TRACKER_HOSTNAMES for external use', () => {
    expect(TRACKER_HOSTNAMES.length).toBeGreaterThan(0)
    expect(TRACKER_HOSTNAMES).toContain('google-analytics.com')
  })
})

// ---------------------------------------------------------------------------
// Third-party script injection — HTML text scan
// ---------------------------------------------------------------------------

describe('third-party tracker script injection (HTML)', () => {
  it('flags <script src> pointing to Google Tag Manager', () => {
    const html = `<script src="https://www.googletagmanager.com/gtag/js?id=G-XXX" async></script>`
    const result = scanFileText('index.html', html)
    expect(result).toHaveLength(1)
    expect(result[0]?.message).toContain('googletagmanager.com')
    expect(result[0]?.line).toBe(1)
  })

  it('flags <script src> pointing to Meta Pixel', () => {
    const html = `<script src='https://connect.facebook.net/en_US/fbevents.js'></script>`
    const result = scanFileText('page.html', html)
    expect(result).toHaveLength(1)
  })

  it('reports the correct line in a multi-line HTML file', () => {
    const html = `<!DOCTYPE html>\n<head>\n<script src="https://script.hotjar.com/modules.js"></script>\n</head>`
    const result = scanFileText('page.html', html)
    expect(result).toHaveLength(1)
    expect(result[0]?.line).toBe(3)
  })

  it('does not flag <script src> to a non-tracker domain', () => {
    const html = `<script src="https://cdn.example.com/app.js"></script>`
    const result = scanFileText('page.html', html)
    expect(result).toHaveLength(0)
  })

  it('does not flag inline scripts (no src)', () => {
    const html = `<script>console.log('hello')</script>`
    const result = scanFileText('page.html', html)
    expect(result).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// Suppression comments
// ---------------------------------------------------------------------------

describe('buildSuppressedLines', () => {
  it('marks the inline comment line', () => {
    const suppressed = buildSuppressedLines(`document.cookie = "x=1"; // complykit-allow`)
    expect(suppressed.has(1)).toBe(true)
  })

  it('marks the line after a preceding comment', () => {
    const suppressed = buildSuppressedLines(`// complykit-allow\ndocument.cookie = "x=1";`)
    expect(suppressed.has(2)).toBe(true)
  })

  it('does not mark unrelated lines', () => {
    const suppressed = buildSuppressedLines(`const x = 1;\ndocument.cookie = "x=1";`)
    expect(suppressed.has(2)).toBe(false)
  })

  it('handles extra whitespace between // and complykit-allow', () => {
    const suppressed = buildSuppressedLines(`document.cookie = "x=1"; //   complykit-allow`)
    expect(suppressed.has(1)).toBe(true)
  })
})

describe('suppression comments — AST scanner', () => {
  it('suppresses document.cookie with inline comment', () => {
    const result = scanFileAST('test.ts', `document.cookie = "x=1"; // complykit-allow`)
    expect(result).toHaveLength(0)
  })

  it('suppresses document.cookie with preceding comment', () => {
    const source = `// complykit-allow\ndocument.cookie = "x=1";`
    const result = scanFileAST('test.ts', source)
    expect(result).toHaveLength(0)
  })

  it('suppresses res.cookie() with inline comment', () => {
    const result = scanFileAST('test.ts', `res.cookie("session", "abc"); // complykit-allow`)
    expect(result).toHaveLength(0)
  })

  it('suppresses cookies().set() with preceding comment', () => {
    const source = `// complykit-allow\ncookies().set("csrf", "tok");`
    const result = scanFileAST('test.ts', source)
    expect(result).toHaveLength(0)
  })

  it('suppresses localStorage.setItem() with inline comment', () => {
    const result = scanFileAST(
      'test.ts',
      `localStorage.setItem('theme', 'dark'); // complykit-allow`,
    )
    expect(result).toHaveLength(0)
  })

  it('suppresses tracker .src assignment with preceding comment', () => {
    const source = `// complykit-allow\ns.src = 'https://www.google-analytics.com/analytics.js';`
    const result = scanFileAST('test.ts', source)
    expect(result).toHaveLength(0)
  })

  it('only suppresses the commented line, not others', () => {
    const source = [`document.cookie = "a=1"; // complykit-allow`, `document.cookie = "b=2";`].join(
      '\n',
    )
    const result = scanFileAST('test.ts', source)
    expect(result).toHaveLength(1)
    expect(result[0]?.line).toBe(2)
  })

  it('preceding comment only covers the immediately following line', () => {
    const source = [
      `// complykit-allow`,
      `document.cookie = "a=1";`,
      `document.cookie = "b=2";`,
    ].join('\n')
    const result = scanFileAST('test.ts', source)
    expect(result).toHaveLength(1)
    expect(result[0]?.line).toBe(3)
  })
})

describe('suppression comments — text scanner', () => {
  it('suppresses Set-Cookie header with inline comment', () => {
    const result = scanFileText('a.html', `Set-Cookie: foo=bar // complykit-allow`)
    expect(result).toHaveLength(0)
  })

  it('suppresses Set-Cookie header with preceding comment', () => {
    const source = `// complykit-allow\nSet-Cookie: foo=bar`
    const result = scanFileText('a.html', source)
    expect(result).toHaveLength(0)
  })

  it('suppresses HTML tracker script tag with preceding comment', () => {
    const source = `<!-- complykit-allow -->\n<script src="https://www.googletagmanager.com/gtag/js"></script>`
    // HTML comment form is not supported — only JS // comments; this should still flag
    const result = scanFileText('page.html', source)
    expect(result).toHaveLength(1)
  })

  it('does not suppress an unrelated line', () => {
    const source = `// complykit-allow\n<p>hello</p>\nSet-Cookie: foo=bar`
    const result = scanFileText('a.html', source)
    expect(result).toHaveLength(1)
    expect(result[0]?.line).toBe(3)
  })
})

// ---------------------------------------------------------------------------
// Unicode offset correctness
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// scanDirectory — single-file with unsupported extension
// ---------------------------------------------------------------------------

describe('scanDirectory — unsupported file extension', () => {
  it('skips the file and returns 0 filesScanned', async () => {
    const tmp = join(tmpdir(), 'complykit-test.md')
    writeFileSync(tmp, `document.cookie = "x=1";\nSet-Cookie: foo=bar\n`)
    try {
      const result = await scanDirectory(tmp)
      expect(result.filesScanned).toBe(0)
      expect(result.violations).toHaveLength(0)
    } finally {
      unlinkSync(tmp)
    }
  })
})

// ---------------------------------------------------------------------------
// Unicode offset correctness
// ---------------------------------------------------------------------------

describe('Unicode source — line/column mapping', () => {
  it('reports the correct line when non-ASCII characters precede the violation', () => {
    // The emoji is 4 bytes in UTF-8 but 2 code units in JS — byte-offset vs code-unit offset
    // would produce different results without the Buffer-based fix.
    const source = `const msg = '🎉 party'; // 4-byte emoji\ndocument.cookie = "track=1";`
    const result = scanFileAST('unicode.ts', source)
    expect(result).toHaveLength(1)
    expect(result[0]?.line).toBe(2)
  })

  it('reports the correct line with multi-byte CJK characters on earlier lines', () => {
    // Each CJK character is 3 bytes in UTF-8 but 1 code unit in JS.
    const source = `// 你好世界\ndocument.cookie = "id=1";`
    const result = scanFileAST('cjk.ts', source)
    expect(result).toHaveLength(1)
    expect(result[0]?.line).toBe(2)
  })
})

// ---------------------------------------------------------------------------
// Text scanner (HTML / Set-Cookie headers)
// ---------------------------------------------------------------------------

describe('scanFileText — Set-Cookie header pattern', () => {
  it('flags Set-Cookie: in plain text', () => {
    const result = scanFileText('response.html', `Set-Cookie: _ga=123; Path=/`)
    expect(result).toHaveLength(1)
    expect(result[0]?.line).toBe(1)
  })

  it('is case-insensitive', () => {
    const result = scanFileText('a.html', `set-cookie: foo=bar`)
    expect(result).toHaveLength(1)
  })

  it('does not flag lines without Set-Cookie', () => {
    const result = scanFileText('a.html', `<meta name="description" content="hi">`)
    expect(result).toHaveLength(0)
  })

  it('reports the correct line number for multi-line input', () => {
    const source = `<html>\n<head>\nSet-Cookie: id=abc\n</head>`
    const result = scanFileText('a.html', source)
    expect(result).toHaveLength(1)
    expect(result[0]?.line).toBe(3)
  })
})
