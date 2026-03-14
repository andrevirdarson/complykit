# complykit

[![Build and Test](https://github.com/andrevirdarson/complykit/actions/workflows/complykit.yml/badge.svg)](https://github.com/andrevirdarson/complykit/actions/workflows/complykit.yml)
[![License](https://img.shields.io/github/license/andrevirdarson/complykit)](LICENSE)

A CI-friendly cookie compliance checker that detects cookies set before user consent — via **static code analysis** and **live browser audits**.

## What it does

| Command | What it checks |
|---|---|
| `complykit scan <path>` | Scans JS/TS/HTML source for cookie writes (`document.cookie =`, `res.cookie()`, `cookies().set()`, `Set-Cookie`), web storage writes (`localStorage.setItem`, `sessionStorage.setItem`), and third-party tracker script injection |
| `complykit audit <url>` | Launches a headless browser, visits configured pages *without* interacting with a consent banner, and flags unexpected cookies |

Both commands exit with **code 1** on violations (CI-compatible) and **code 0** when clean.

## Usage

### GitHub Action

Add complykit to any repo's workflow:

```yaml
name: Cookie Compliance

on: [push, pull_request]

jobs:
  comply:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: andrevirdarson/complykit@main
        with:
          scan_path: src/
          # audit_url: https://your-staging-url.com  # optional
          # config: complykit.yml                     # optional
          # baseline: .complykit-baseline.json        # optional
```

Available inputs:

| Input | Description | Default |
|---|---|---|
| `scan_path` | Path to scan for cookie violations | |
| `audit_url` | URL to audit with headless browser | |
| `config` | Path to complykit.yml config file | |
| `format` | Output format: `pretty`, `json`, `sarif` | `pretty` |
| `baseline` | Path to baseline file for incremental adoption | |

### CLI

```bash
# Static analysis on your source tree
complykit scan src/

# Browser audit against a live URL
complykit audit https://staging.example.com
```

## Configuration

Create a `complykit.yml` in your project root:

```yaml
# Cookies permitted before consent (e.g. session, CSRF tokens)
allowedBeforeConsent:
  - session
  - consent
  - csrf

# Pages the audit command visits (relative paths)
crawlPages:
  - /
```

The config file is auto-discovered. Pass `--config <path>` to override.

## Suppressing violations

The static scanner flags **all** cookie and storage writes. To suppress a legitimate write, add a `// complykit-allow` comment — either inline or on the preceding line:

```ts
// Inline — suppresses this line only
document.cookie = "csrf=" + token; // complykit-allow

// Preceding — suppresses the next line
// complykit-allow
localStorage.setItem("theme", "dark");
```

For the browser audit, use the `allowedBeforeConsent` list in `complykit.yml` to permit known functional cookies.

## Output formats

Both commands support `--format pretty|json|sarif` (default: `pretty`).

```bash
# Human-readable (default)
complykit scan src/

# Machine-readable JSON
complykit scan src/ --format json

# SARIF (write to file with --output)
complykit scan src/ --format sarif --output complykit.sarif
```

SARIF output integrates with GitHub's Code Scanning. To enable, set the repo variable `UPLOAD_SARIF` to `true` — violations will appear in the **Security → Code scanning** tab with inline PR annotations. Requires GitHub Pro/Team/Enterprise for private repos.

## Baseline mode

Baseline mode lets teams adopt complykit incrementally without fixing every existing violation on day one. Only **new** violations fail CI.

```bash
# 1. Snapshot current violations as the baseline
complykit scan src/ --update-baseline

# 2. CI runs — only new violations fail
complykit scan src/ --baseline .complykit-baseline.json

# 3. Re-baseline after fixing known issues
complykit scan src/ --update-baseline --baseline .complykit-baseline.json
```

- `--update-baseline` saves fingerprints of all current violations to `.complykit-baseline.json` (or a custom path via `--baseline <path>`) and exits cleanly.
- `--baseline <path>` loads the baseline and only reports violations not already in it. Baselined violations are counted but don't fail the build.
- Fingerprints are based on file + message + snippet (scan) or cookie name + via (audit), so minor line shifts don't invalidate the baseline.

Both `scan` and `audit` support baseline mode.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No violations found |
| `1` | One or more cookie violations detected |
| `2` | Tool error (config not found, network failure, etc.) |

## Development

```bash
git clone git@github.com:andrevirdarson/complykit.git
cd complykit
bun install
bun run build
bun test
```

To use a local build in another project:

```bash
# In complykit/
bun link

# In your other project/
bun link complykit
bunx complykit scan src/
```

## License

[MIT](LICENSE)
