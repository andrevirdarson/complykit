# complykit — agent instructions

## Runtime

This project uses **Bun**. Never use `npm`, `yarn`, or `npx` — always use `bun` and `bunx`.

## Commands

```bash
bun install          # install dependencies
bun test             # run tests
bun run lint         # oxlint
bun run format       # biome format --write (auto-fix)
bun run format:check # biome format (read-only, used in CI)
bun run check        # lint + format:check together
bun run start        # run CLI from source (bun src/cli.ts)
bun run build        # bundle to dist/
```

## Before committing

Always run:

```bash
bun run check && bun test
```

Both must pass with zero errors.

## Code style

Enforced by Biome — do not add semicolons or fix formatting manually, just run `bun run format`.

- No semicolons
- Single quotes
- Trailing commas on multiline arrays/objects

## Project structure

```
src/
  cli.ts                 # entry point
  commands/scan.ts       # scan command
  commands/audit.ts      # audit command
  scanner/cookieScanner.ts  # AST scanning via oxc-parser
  audit/browserAudit.ts  # Playwright browser audit
  config/loadConfig.ts   # YAML config loader
```

## Testing

Tests live next to source files (`*.test.ts`). Scanner tests use inline source strings — no fixtures, no filesystem.

## Static analysis internals

The scanner uses `oxc-parser` (not `@typescript-eslint/typescript-estree`). The oxc AST uses:
- `MemberExpression` with `computed: false` for `a.b` access (same as ESTree)
- `start`/`end` byte offsets for positions (not `loc` objects) — convert with `offsetToLineCol()`
