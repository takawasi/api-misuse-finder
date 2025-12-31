# api-misuse-finder

> **Documentation**: https://takawasi-social.com/tools/api-misuse-finder/

Detect API misuse patterns in your codebase.

Lightweight static analysis for common security and reliability issues.

## Quick Start

```bash
# 1. Install
pip install api-misuse-finder

# 2. Scan
api-finder ./src
```

## What It Detects

### Python
- `requests.get()` without timeout
- `pickle.load()` on untrusted data
- `yaml.load()` without Loader
- `eval()` and `exec()` calls
- `subprocess` with `shell=True`
- SQL injection via f-strings
- Deprecated `distutils` usage

### JavaScript
- `fetch()` without error handling
- `innerHTML` XSS vulnerabilities
- `eval()` and `new Function()`
- `document.write()` deprecation
- `localStorage` for sensitive data

## Usage

```bash
# Scan with default rules
api-finder ./src

# Custom rules
api-finder --rules ./my-rules.yaml ./src

# JSON output
api-finder --format json ./src

# Only show errors
api-finder --min-severity error ./src

# CI: fail on errors
api-finder --fail-on error ./src
```

## Output Example

```
API Misuse Report
==================================================

src/api/client.py
  45: ⚠️ requests-no-timeout
       requests.get(url)
       requests.get() without timeout can hang forever
       → Add timeout=30 parameter

src/utils/data.py
  12: ❌ pickle-insecure
       data = pickle.load(f)
       pickle.load() can execute arbitrary code
       → Use json or msgpack for untrusted data

==================================================
Summary: 1 error(s), 1 warning(s)
```

## Custom Rules

Create a YAML file with your rules:

```yaml
# my-rules.yaml
rules:
  - id: deprecated-api
    language: python
    pattern: "from mylib import old_func"
    message: "old_func is deprecated"
    severity: warning
    suggestion: "Use new_func instead"

  - id: missing-auth
    language: javascript
    pattern: "fetch("
    without: "Authorization"
    message: "fetch without Authorization header"
    severity: error
    suggestion: "Add Authorization header"
```

Then run:

```bash
api-finder --rules my-rules.yaml ./src
```

## Rule Format

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique rule identifier |
| `language` | Yes | `python`, `javascript`, or `any` |
| `pattern` | Yes | String pattern to match |
| `message` | Yes | Error message to display |
| `severity` | No | `warning` (default) or `error` |
| `suggestion` | No | Fix suggestion |
| `without` | No | Pattern that should NOT appear in context |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No issues (or below threshold) |
| 1 | Issues found at/above `--fail-on` threshold |

## Comparison with Semgrep

| Feature | api-misuse-finder | Semgrep |
|---------|-------------------|---------|
| Installation | `pip install` | Requires binary |
| Rules | Simple YAML | Complex YAML |
| AST parsing | No (pattern-based) | Yes |
| Performance | Fast | Varies |
| Custom rules | Easy | Learning curve |

**Use Semgrep if**: You need AST-level precision, complex patterns, or enterprise features.

**Use this if**: You want quick, simple pattern detection with minimal setup.

## License

MIT
