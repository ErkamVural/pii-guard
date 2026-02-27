# 🛡️ PII Guard

A Git pre-commit hook that scans staged files for PII before every commit.

- **Layer 1 — Regex:** Fast, deterministic. Covers TCKN, credit cards, API keys, emails, IBANs.
- **Layer 2 — LLM:** Contextual detection for hidden credentials (optional, off by default).

---

## Installation

### 1. Install pre-commit

**Standard:**
```bash
pip install pre-commit
```

**Kali Linux / Ubuntu 23.04+:**
```bash
sudo apt install pipx && pipx ensurepath
pipx install pre-commit
```

**macOS:**
```bash
brew install pre-commit
```

**Windows:**
```powershell
pip install pre-commit
```
> Requires [Git for Windows](https://git-scm.com/download/win). Hooks do not trigger in PowerShell or CMD without it.

### 2. Create `.pre-commit-config.yaml`

Create this file in your **project root** (next to `.git/`):

```yaml
repos:
  - repo: https://github.com/ErkamVural/pii-guard
    rev: v1.0.0 # check latest tag at github.com/ErkamVural/pii-guard/tags
    hooks:
      - id: pii-guard
```

This is the only file the pre-commit framework needs. It tells it where to find PII Guard and which version to use.

### 3. Activate

```bash
pre-commit install
```

PII Guard now runs automatically on every `git commit`. No files are added to your project.

---

## Configuration

PII Guard is configured via `.pii-guard.yaml`. This file is **optional** — if not present, built-in defaults are used (regex-only mode, no LLM).

Create `.pii-guard.yaml` in your **project root** (safe to commit, contains no secrets):

```yaml
scan:
  # File extensions to scan
  extensions: [.py, .env, .js, .ts, .yaml, .json, .html, .md, .txt]

llm:
  enabled: false          # true → enable LLM layer
  provider: ollama        # ollama | openai | anthropic | openai_compatible

  # Model behavior
  timeout: 30             # seconds to wait for LLM response
  temperature: 0.0        # 0.0 = deterministic output
  seed: 42                # reproducible results

  providers:
    ollama:
      base_url: "http://localhost:11434"
      model: "llama3.2:3b"

    openai:
      base_url: "https://api.openai.com/v1"
      model: "gpt-4o-mini"
      api_key_env: "OPENAI_API_KEY"      # name of the env variable, not the key itself

    anthropic:
      model: "claude-haiku-4-5-20251001"
      api_key_env: "ANTHROPIC_API_KEY"

    openai_compatible:
      base_url: "http://localhost:8080/v1"   # LM Studio, vLLM, Groq, etc.
      model: "your-model-name"
      api_key_env: ""                        # leave empty if no key needed
```

### Bundled patterns

The following patterns are always active out of the box (`pii_guard/data/pii_patterns.json`):

| Name | Detects |
|---|---|
| `TCKN` | Turkish National ID numbers |
| `Credit Card (Compact)` | Visa, Mastercard, Amex, Discover — no spaces |
| `Credit Card (Spaced)` | Card numbers written with spaces |
| `API Key (Keyword-based)` | Values next to keywords like `api_key`, `secret`, `token`, `password` |
| `API Key (sk/pk Prefix)` | Keys starting with `sk-`, `pk-`, `rk-`, `ak-` |
| `Email Address` | Standard email format |
| `IBAN` | International bank account numbers |

### Custom patterns

Create `.pii-guard-patterns.json` in your **project root** to add your own patterns:

```json
{
  "patterns": [
    { "name": "Employee ID", "pattern": "\\bEMP-[0-9]{6}\\b" }
  ]
}
```

Custom patterns are **merged on top of the bundled patterns** — they never replace them. If a custom pattern has the same name as a bundled one, it overrides only that specific pattern. All others remain active.

> To disable a specific bundled pattern, override it with a non-matching regex: `"pattern": "(?!)"`.

### Config resolution order

Settings — first match wins, merged on top of built-in defaults:

| Priority | File | Scope |
|---|---|---|
| 1 | `.pii-guard.yaml` in project root | project |
| 2 | `~/.pii-guard.yaml` | global |
| 3 | `pii_guard/data/defaults.yaml` | built-in |

Patterns — bundled patterns always load first, custom patterns merge on top:

| Priority | File | Scope |
|---|---|---|
| base | `pii_guard/data/pii_patterns.json` | always active |
| +1 | `~/.pii-guard-patterns.json` | merged on top |
| +2 | `.pii-guard-patterns.json` in project root | merged on top (highest priority) |

---

## File Overview

After setup, your project root will contain these PII Guard related files:

```
my-project/
├── .pre-commit-config.yaml     ← required: tells pre-commit to use PII Guard
├── .pii-guard.yaml             ← optional: your LLM and scan settings
├── .pii-guard-patterns.json    ← optional: custom regex patterns
└── ...
```

None of these files contain secrets. All three are safe to commit.

---

## Team & CI/CD

Commit `.pre-commit-config.yaml` and `.pii-guard.yaml` to your repo. When a teammate clones the project, they only need to run:

```bash
pre-commit install
```

For CI/CD (e.g. GitHub Actions):
```yaml
- run: pip install pre-commit && pre-commit run --all-files
```

---

## LLM Providers

| Provider | Requirement |
|---|---|
| `ollama` | Ollama installed locally |
| `openai` | `OPENAI_API_KEY` env variable |
| `anthropic` | `ANTHROPIC_API_KEY` + see below |
| `openai_compatible` | LM Studio, vLLM, Groq, etc. |

> For best results use 7B+ parameter models. Smaller models may produce false positives.

### Using Anthropic via pre-commit

Add `additional_dependencies` to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/ErkamVural/pii-guard
    rev: v1.0.0
    hooks:
      - id: pii-guard
        additional_dependencies: ["anthropic>=0.25.0"]
```

---

## ⚠️ Privacy Warning

When the LLM layer is enabled with an **external provider** (OpenAI or Anthropic), the full content of every staged file is sent to a third-party server for analysis.

This means **your source code leaves your machine.**

For organizations where source code confidentiality matters:

- Use **Ollama** (local model) — no data ever leaves your machine
- Use **openai_compatible** pointing to a self-hosted endpoint (vLLM, LM Studio)
- Disable the LLM layer entirely (`llm.enabled: false`) and rely on regex-only mode

External providers (OpenAI, Anthropic) should only be used when your organization's data policy explicitly permits sending source code to third-party APIs.

---

## Bypassing the Hook

```bash
# Skip only PII Guard
SKIP=pii-guard git commit -m "your message"

# Skip all hooks
git commit -m "your message" --no-verify
```

---

## Known Limitations

- LLM accuracy depends on model size; smaller models may miss findings or produce false positives.
- Full staged file content is scanned, not just changed lines.
- Binary files and extensions outside the configured list are skipped.

---

## License

MIT
