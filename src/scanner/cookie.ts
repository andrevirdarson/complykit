import { readFileSync, readdirSync, statSync } from 'fs'
import { resolve, extname, relative } from 'path'
import { parseSync } from 'oxc-parser'

export type ScanViolation = {
  file: string
  line: number
  column: number
  message: string
  snippet: string
}

// Known third-party tracker hostnames — scripts from these domains set tracking
// cookies and must not be loaded before the user has given consent.
export const TRACKER_HOSTNAMES = [
  'google-analytics.com',
  'googletagmanager.com',
  'connect.facebook.net',
  'analytics.twitter.com',
  'static.ads-twitter.com',
  'snap.licdn.com', // LinkedIn Insight Tag
  'script.hotjar.com',
  'widget.intercom.io',
  'cdn.segment.com',
  'cdn.mxpnl.com', // Mixpanel
  'analytics.tiktok.com',
]

function isTrackerUrl(url: string): boolean {
  try {
    const hostname = new URL(url).hostname
    return TRACKER_HOSTNAMES.some((t) => hostname === t || hostname.endsWith('.' + t))
  } catch {
    // Not a full URL — check if the string contains a known hostname as a substring
    return TRACKER_HOSTNAMES.some((t) => url.includes(t))
  }
}

// Patterns detectable without an AST (plain text scan for non-JS files)
const TEXT_PATTERNS: Array<{ pattern: RegExp; message: string }> = [
  {
    pattern: /Set-Cookie:/i,
    message: 'HTTP Set-Cookie header written without consent guard',
  },
]

// HTML <script src="..."> pattern — captured group 1 is the URL
const SCRIPT_SRC_PATTERN = /<script\b[^>]*\bsrc=["']([^"']+)["'][^>]*>/gi

// Extensions to run through the AST parser
const AST_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'])

// Extensions to scan with plain text patterns only
const TEXT_EXTENSIONS = new Set(['.html', '.htm'])

// Directories to skip
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', '.next', 'out', 'build', '.turbo'])

// ---------------------------------------------------------------------------
// AST traversal — oxc-parser AST format
// Positions are byte offsets (start/end), not loc objects.
// ---------------------------------------------------------------------------

type OxcNode = Record<string, any>

// A walker frame records the parent node and the property key under which we
// descended to reach the current node (e.g. childKey === 'consequent' means we
// entered through the positive branch of an IfStatement). The childKey lets us
// distinguish guarded positions (`if (consent) X`) from unguarded ones
// (`if (consent) {} else { X }`).
type Frame = { node: OxcNode; childKey: string }

function walk(
  node: OxcNode,
  visit: (node: OxcNode, ancestors: Frame[]) => void,
  ancestors: Frame[] = [],
): void {
  if (!node || typeof node !== 'object') return
  visit(node, ancestors)
  for (const [key, value] of Object.entries(node)) {
    const descend = (child: any) => {
      if (child && typeof child === 'object' && 'type' in child) {
        ancestors.push({ node, childKey: key })
        walk(child as OxcNode, visit, ancestors)
        ancestors.pop()
      }
    }
    if (Array.isArray(value)) value.forEach(descend)
    else descend(value)
  }
}

// Convert a code-unit offset (as reported by oxc-parser) to 1-based line + 0-based column.
// oxc-parser uses JavaScript string (UTF-16 code-unit) offsets, so source.slice() is correct here.
function offsetToLineCol(source: string, offset: number): { line: number; column: number } {
  const before = source.slice(0, offset)
  const lines = before.split('\n')
  return { line: lines.length, column: lines.at(-1)?.length ?? 0 }
}

// oxc-parser uses MemberExpression (same as ESTree) with computed: false for a.b access
function isMember(node: OxcNode, objectName: string | null, propertyName: string): boolean {
  if (node.type !== 'MemberExpression') return false
  if (node.computed) return false
  if (node.property?.name !== propertyName) return false
  if (objectName === null) return true
  return node.object?.type === 'Identifier' && node.object.name === objectName
}

function isDocumentCookieAssignment(node: OxcNode): boolean {
  return node.type === 'AssignmentExpression' && isMember(node.left, 'document', 'cookie')
}

function isResCookieCall(node: OxcNode): boolean {
  if (node.type !== 'CallExpression') return false
  const callee = node.callee
  return (
    callee?.type === 'MemberExpression' &&
    !callee.computed &&
    callee.property?.name === 'cookie' &&
    callee.object?.type === 'Identifier'
  )
}

function isCookiesSetCall(node: OxcNode): boolean {
  if (node.type !== 'CallExpression') return false
  const callee = node.callee
  if (callee?.type !== 'MemberExpression' || callee.computed) return false
  if (callee.property?.name !== 'set') return false

  const obj = callee.object
  // cookies().set(...)
  if (
    obj?.type === 'CallExpression' &&
    obj.callee?.type === 'Identifier' &&
    obj.callee.name === 'cookies'
  ) {
    return true
  }
  // cookieStore.set(...)
  if (obj?.type === 'Identifier' && obj.name === 'cookieStore') return true

  return false
}

const WEB_STORAGE_OBJECTS = new Set(['localStorage', 'sessionStorage'])

// localStorage.setItem(...) / sessionStorage.setItem(...)
function isWebStorageWrite(node: OxcNode): boolean {
  if (node.type !== 'CallExpression') return false
  const callee = node.callee
  if (callee?.type !== 'MemberExpression' || callee.computed) return false
  if (callee.property?.name !== 'setItem') return false
  return callee.object?.type === 'Identifier' && WEB_STORAGE_OBJECTS.has(callee.object.name)
}

function getStoreName(node: OxcNode): string {
  return node.callee?.object?.name ?? 'Web Storage'
}

function getSourceSnippet(source: string, line: number): string {
  return (source.split('\n')[line - 1] ?? '').trim()
}

// Extracts a string literal value from a Literal node, or null.
function stringLiteralValue(node: OxcNode): string | null {
  if (node?.type === 'Literal' && typeof node.value === 'string') return node.value as string
  return null
}

// dangerouslySetInnerHTML={{ __html: "...document.cookie..." }} — cookie or
// tracker code hidden inside a raw HTML string bypasses the normal AST checks.
const DANGEROUS_HTML_PATTERNS = [
  /document\.cookie\s*=/,
  /Set-Cookie:/i,
  /localStorage\.setItem/,
  /sessionStorage\.setItem/,
]

function extractDangerousHtmlValue(node: OxcNode): string | null {
  if (node.type !== 'JSXAttribute') return null
  const name = node.name?.name ?? node.name?.value
  if (name !== 'dangerouslySetInnerHTML') return null

  // The value is a JSXExpressionContainer wrapping an ObjectExpression: {{ __html: "..." }}
  const expr = node.value?.expression
  if (expr?.type !== 'ObjectExpression') return null

  for (const prop of expr.properties ?? []) {
    const key = prop.key?.name ?? prop.key?.value
    if (key !== '__html') continue
    // String literal
    if (prop.value?.type === 'StringLiteral' || prop.value?.type === 'Literal') {
      return (prop.value.value as string) ?? null
    }
    // Template literal with no expressions (static)
    if (prop.value?.type === 'TemplateLiteral' && prop.value.quasis?.length === 1) {
      return prop.value.quasis[0]?.value?.raw ?? prop.value.quasis[0]?.value?.cooked ?? null
    }
  }
  return null
}

function isDangerousInnerHTMLCookie(node: OxcNode): boolean {
  const html = extractDangerousHtmlValue(node)
  if (html === null) return false
  return DANGEROUS_HTML_PATTERNS.some((p) => p.test(html))
}

// el.src = "<tracker url>"  — where el might be any identifier or the result
// of createElement. We flag any AssignmentExpression where the left side is
// `<anything>.src` and the right side is a string literal matching a tracker.
function isTrackerSrcAssignment(node: OxcNode): boolean {
  if (node.type !== 'AssignmentExpression') return false
  if (!isMember(node.left, null, 'src')) return false
  const val = stringLiteralValue(node.right)
  return val !== null && isTrackerUrl(val)
}

// ---------------------------------------------------------------------------
// Consent guards
// ---------------------------------------------------------------------------
//
// A violation is suppressed when it sits in the *positive* branch of a control
// flow expression whose test matches a recognized consent check — either the
// built-in OneTrust group-membership pattern, or an identifier/member chain
// listed in the project's `consentGuards` config. The matching is
// intentionally strict — no fuzzy regex on identifier names, no early-return
// inference, no implicit existence checks. If a project's consent flag
// doesn't match, the user adds the name to `consentGuards` or uses
// `// complykit-allow`.

const GLOBAL_PREFIXES = ['window.', 'globalThis.', 'self.']

function stripGlobalPrefix(chain: string): string {
  for (const prefix of GLOBAL_PREFIXES) {
    if (chain.startsWith(prefix)) return chain.slice(prefix.length)
  }
  return chain
}

// Strip syntactic wrappers that don't change the value: `(x)` and `x?.y`
// (oxc-parser wraps optional-chain expressions in a ChainExpression node).
function unwrap(node: OxcNode): OxcNode {
  let current = node
  while (
    current &&
    (current.type === 'ParenthesizedExpression' || current.type === 'ChainExpression')
  ) {
    current = current.expression
  }
  return current
}

// Dotted member chain for non-computed access, else null. Handles optional
// chaining (`a?.b.c`) because the leading ChainExpression is unwrapped here.
// `user.consent.analytics` → 'user.consent.analytics'.
function getMemberChain(node: OxcNode | null | undefined): string | null {
  if (!node) return null
  const n = unwrap(node)
  if (n.type === 'Identifier') return n.name ?? null
  if (n.type === 'MemberExpression' && !n.computed) {
    const base = getMemberChain(n.object)
    const prop = n.property?.name
    return base && prop ? `${base}.${prop}` : null
  }
  return null
}

// Chain of a CallExpression's callee, so `consentGuards: ['User.hasConsent']`
// matches `if (User.hasConsent()) { ... }`. Returns null for anything that
// isn't a call.
function getCalleeChain(node: OxcNode | null | undefined): string | null {
  if (!node) return null
  const n = unwrap(node)
  if (n.type !== 'CallExpression') return null
  return getMemberChain(n.callee)
}

// OneTrust's canonical consent check is array-membership on the active-groups
// string, not a simple chain. The standard idioms are:
//   OnetrustActiveGroups.indexOf('C0002') !== -1   // also !=, > -1, >= 0
//   OnetrustActiveGroups.includes('C0002')         // post-ES7
// We recognize these as positive guards. Existence-only forms like
// `if (OnetrustActiveGroups)` are intentionally NOT matched — they prove the
// variable is set, not that consent was granted for any specific group.
function numericLiteralValue(node: OxcNode | null | undefined): number | null {
  if (!node) return null
  if (
    (node.type === 'Literal' || node.type === 'NumericLiteral') &&
    typeof node.value === 'number'
  ) {
    return node.value
  }
  // oxc-parser may represent `-1` as UnaryExpression('-', Literal(1)).
  if (node.type === 'UnaryExpression' && node.operator === '-') {
    const inner = numericLiteralValue(node.argument)
    return inner === null ? null : -inner
  }
  return null
}

// An empty-string group ID makes both `.indexOf('')` (returns 0) and
// `.includes('')` (returns true) trivially "found", so the guard would always
// pass. We require at least one argument and, when the first arg is a string
// literal, that it's non-empty. Variable or computed arguments pass through
// because we can't determine their value statically.
function hasValidGroupArgument(call: OxcNode): boolean {
  const args = call.arguments
  if (!Array.isArray(args) || args.length < 1) return false
  const first = args[0]
  if (
    (first?.type === 'Literal' || first?.type === 'StringLiteral') &&
    typeof first.value === 'string'
  ) {
    return first.value.length > 0
  }
  if (first?.type === 'TemplateLiteral' && first.quasis?.length === 1) {
    const raw = first.quasis[0]?.value?.raw ?? first.quasis[0]?.value?.cooked ?? ''
    return raw.length > 0
  }
  return true
}

function isOnetrustActiveGroupsMethodCall(node: OxcNode, method: 'indexOf' | 'includes'): boolean {
  const n = unwrap(node)
  if (n.type !== 'CallExpression') return false
  const callee = n.callee
  if (callee?.type !== 'MemberExpression' || callee.computed) return false
  if (callee.property?.name !== method) return false
  const objectChain = getMemberChain(callee.object)
  if (objectChain === null || stripGlobalPrefix(objectChain) !== 'OnetrustActiveGroups') {
    return false
  }
  return hasValidGroupArgument(n)
}

function isOneTrustGroupCheck(expr: OxcNode): boolean {
  // Post-ES7: `OnetrustActiveGroups.includes(...)` is truthy on hit.
  if (isOnetrustActiveGroupsMethodCall(expr, 'includes')) return true
  // Legacy: `OnetrustActiveGroups.indexOf(...) <op> <n>` — accept the four
  // standard "found" comparisons. `=== -1` (the "not found" form) is NOT a
  // positive guard.
  if (expr.type !== 'BinaryExpression') return false
  const { operator, left, right } = expr
  const accept = (call: OxcNode, lit: OxcNode, op: string): boolean => {
    if (!isOnetrustActiveGroupsMethodCall(call, 'indexOf')) return false
    const n = numericLiteralValue(lit)
    if (n === null) return false
    if ((op === '!==' || op === '!=') && n === -1) return true
    if (op === '>' && n === -1) return true
    if (op === '>=' && n === 0) return true
    return false
  }
  // Forms with the call on the left (the idiomatic order).
  if (accept(left, right, operator)) return true
  // Forms with the call on the right (e.g. `-1 !== indexOf(x)`).
  const flipped = operator === '<' ? '>' : operator === '<=' ? '>=' : operator
  return accept(right, left, flipped)
}

// A configured guard pattern matches a chain either exactly, or — when the
// pattern ends in `.*` — as a root wildcard covering the prefix and any
// deeper chain. Wildcards are opt-in so a bare `OneTrust` in `consentGuards`
// does NOT silently suppress unrelated method calls on the same root.
//   'hasConsent'        ↔ exactly `hasConsent`
//   'User.hasConsent'   ↔ exactly `User.hasConsent` (also `User.hasConsent()`)
//   'gtag.*'            ↔ `gtag`, `gtag.x`, `gtag.x.y`, etc.
function chainMatchesPattern(chain: string, pattern: string): boolean {
  if (pattern.endsWith('.*')) {
    const prefix = pattern.slice(0, -2)
    return chain === prefix || chain.startsWith(`${prefix}.`)
  }
  return chain === pattern
}

function expressionIsGuard(expr: OxcNode | undefined, extraNames: string[]): boolean {
  if (!expr) return false
  const e = unwrap(expr)
  // Negation is not a positive guard. `if (!hasConsent) ...` does not protect
  // its consequent — the guard pattern is `if (hasConsent) ...`.
  if (e.type === 'UnaryExpression' && e.operator === '!') return false
  if (isOneTrustGroupCheck(e)) return true
  const chain = getMemberChain(e) ?? getCalleeChain(e)
  if (chain === null) return false
  return extraNames.some((pattern) => chainMatchesPattern(chain, pattern))
}

// Descend into `&&` chains only — `||` does not guarantee the right side runs
// under consent, so we treat it as no guard.
function testIsGuard(test: OxcNode | undefined, extraNames: string[]): boolean {
  if (!test) return false
  const t = unwrap(test)
  if (t.type === 'LogicalExpression' && t.operator === '&&') {
    return testIsGuard(t.left, extraNames) || testIsGuard(t.right, extraNames)
  }
  return expressionIsGuard(t, extraNames)
}

// Crossing a function boundary breaks the guard chain. The cookie write in
// `if (consent) setTimeout(() => document.cookie = "x", 60_000)` runs
// asynchronously — by the time the callback fires, consent may have been
// withdrawn. Strict mode treats only synchronous, same-scope guards as valid.
const FUNCTION_BOUNDARIES = new Set([
  'FunctionDeclaration',
  'FunctionExpression',
  'ArrowFunctionExpression',
])

function isGuardedByConsent(ancestors: Frame[], extraNames: string[]): boolean {
  for (let i = ancestors.length - 1; i >= 0; i--) {
    const { node, childKey } = ancestors[i]!
    if (FUNCTION_BOUNDARIES.has(node.type)) return false
    if (
      (node.type === 'IfStatement' || node.type === 'ConditionalExpression') &&
      childKey === 'consequent'
    ) {
      if (testIsGuard(node.test, extraNames)) return true
    } else if (
      node.type === 'LogicalExpression' &&
      node.operator === '&&' &&
      childKey === 'right'
    ) {
      if (testIsGuard(node.left, extraNames)) return true
    }
  }
  return false
}

// Build a set of 1-based line numbers that are covered by a `// complykit-allow` comment.
// Exported for testing.
// Two forms are supported:
//   1. Inline:   `document.cookie = "x=1"; // complykit-allow`
//   2. Preceding: `// complykit-allow\n   document.cookie = "x=1";`
export function buildSuppressedLines(source: string): Set<number> {
  const suppressed = new Set<number>()
  const lines = source.split('\n')
  lines.forEach((line, idx) => {
    if (!/\/\/\s*complykit-allow\b/.test(line)) return
    // Always suppress the line that carries the comment (inline form).
    suppressed.add(idx + 1)
    // If the comment is the only content on the line, it's a preceding comment —
    // also suppress the next line.
    if (/^\s*\/\/\s*complykit-allow\b/.test(line)) {
      suppressed.add(idx + 2)
    }
  })
  return suppressed
}

function tryGetViolation(node: OxcNode): string | null {
  if (isDocumentCookieAssignment(node)) {
    return 'Cookie written via document.cookie without consent guard'
  } else if (isResCookieCall(node)) {
    return 'Cookie written via res.cookie() without consent guard'
  } else if (isCookiesSetCall(node)) {
    return 'Cookie written via cookies().set() without consent guard'
  } else if (isWebStorageWrite(node)) {
    const store = getStoreName(node)
    return `Tracking data written to ${store} without consent guard`
  } else if (isTrackerSrcAssignment(node)) {
    const url = stringLiteralValue(node.right) ?? ''
    return `Third-party tracker script injected without consent guard (${url})`
  } else if (isDangerousInnerHTMLCookie(node)) {
    return 'Cookie or storage written via dangerouslySetInnerHTML without consent guard'
  }

  return null
}

export function scanFileAST(
  filePath: string,
  source: string,
  consentGuards: string[] = [],
): ScanViolation[] {
  const violations: ScanViolation[] = []
  const suppressed = buildSuppressedLines(source)

  // .cjs is always CommonJS (script mode). .js/.ts/.tsx try module first, then script as fallback
  // because plain .js files are often CommonJS and may use syntax that is only valid in sloppy mode.
  const primarySourceType: 'module' | 'script' = filePath.endsWith('.cjs') ? 'script' : 'module'
  const retryAsScript =
    primarySourceType === 'module' &&
    (filePath.endsWith('.js') || filePath.endsWith('.ts') || filePath.endsWith('.tsx'))

  function tryParseAST(sourceType: 'module' | 'script'): OxcNode | null {
    try {
      const result = parseSync(filePath, source, { sourceType })
      return result.errors?.length ? null : result.program
    } catch {
      return null
    }
  }

  const ast = tryParseAST(primarySourceType) ?? (retryAsScript ? tryParseAST('script') : null)
  if (ast === null) {
    console.warn(
      `[complykit] failed to parse ${filePath} — falling back to text scan (AST violations may be missed)`,
    )
    return scanFileText(filePath, source)
  }

  walk(ast, (node, ancestors) => {
    const { line, column } = offsetToLineCol(source, node.start ?? 0)
    if (suppressed.has(line)) return

    const violation = tryGetViolation(node)
    if (!violation) return
    if (isGuardedByConsent(ancestors, consentGuards)) return

    violations.push({
      file: filePath,
      line,
      column,
      message: violation,
      snippet: getSourceSnippet(source, line),
    })
  })

  return violations
}

export function scanFileText(filePath: string, source: string): ScanViolation[] {
  const violations: ScanViolation[] = []
  const suppressed = buildSuppressedLines(source)
  const lines = source.split('\n')

  for (const { pattern, message } of TEXT_PATTERNS) {
    lines.forEach((line, idx) => {
      if (pattern.test(line) && !suppressed.has(idx + 1)) {
        violations.push({
          file: filePath,
          line: idx + 1,
          column: 0,
          message,
          snippet: line.trim(),
        })
      }
    })
  }

  // Scan HTML for <script src="<tracker>"> tags
  let match: RegExpExecArray | null
  SCRIPT_SRC_PATTERN.lastIndex = 0
  while ((match = SCRIPT_SRC_PATTERN.exec(source)) !== null) {
    const url = match[1] ?? ''
    if (isTrackerUrl(url)) {
      const before = source.slice(0, match.index)
      const lineNumber = before.split('\n').length
      if (!suppressed.has(lineNumber)) {
        violations.push({
          file: filePath,
          line: lineNumber,
          column: 0,
          message: `Third-party tracker script loaded without consent guard (${url})`,
          snippet: match[0].trim(),
        })
      }
    }
  }

  return violations
}

// ---------------------------------------------------------------------------
// Directory walker
// ---------------------------------------------------------------------------

function collectFiles(dir: string): string[] {
  const results: string[] = []

  for (const entry of readdirSync(dir)) {
    if (SKIP_DIRS.has(entry)) continue
    const full = resolve(dir, entry)
    const stat = statSync(full)
    if (stat.isDirectory()) {
      results.push(...collectFiles(full))
    } else if (AST_EXTENSIONS.has(extname(entry)) || TEXT_EXTENSIONS.has(extname(entry))) {
      results.push(full)
    }
  }

  return results
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

type ScanResult = {
  violations: ScanViolation[]
  filesScanned: number
}

export type ScanOptions = {
  consentGuards?: string[]
}

export async function scanDirectory(
  targetPath: string,
  options: ScanOptions = {},
): Promise<ScanResult> {
  const consentGuards = options.consentGuards ?? []
  const stat = statSync(resolve(process.cwd(), targetPath))

  let files: string[]
  if (stat.isDirectory()) {
    files = collectFiles(resolve(process.cwd(), targetPath))
  } else {
    const absPath = resolve(process.cwd(), targetPath)
    const ext = extname(absPath)
    if (!AST_EXTENSIONS.has(ext) && !TEXT_EXTENSIONS.has(ext)) {
      console.warn(`[complykit] skipping ${targetPath}: unsupported file extension '${ext}'`)
      return { violations: [], filesScanned: 0 }
    }
    files = [absPath]
  }

  const violations: ScanViolation[] = []

  for (const file of files) {
    const source = readFileSync(file, 'utf-8')
    const ext = extname(file)
    const rel = relative(process.cwd(), file)

    const fileViolations = AST_EXTENSIONS.has(ext)
      ? scanFileAST(rel, source, consentGuards)
      : scanFileText(rel, source)

    violations.push(...fileViolations)
  }

  return { violations, filesScanned: files.length }
}
