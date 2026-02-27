"""
config_loader.py — Resolves configuration and pattern files.

Settings search order:
  1. .pii-guard.yaml  in current working directory (repo root)
  2. ~/.pii-guard.yaml (global user config)
  3. Bundled pii_guard/data/defaults.yaml

Patterns:
  Bundled patterns (pii_guard/data/pii_patterns.json) are ALWAYS loaded first.
  Custom patterns are then MERGED ON TOP — they extend, never replace.

  Custom pattern search order (first found wins):
  1. .pii-guard-patterns.json in current working directory (repo root)
  2. ~/.pii-guard-patterns.json

  If a custom pattern has the same name as a bundled one, it overrides that
  specific pattern. All other bundled patterns remain active.
"""
import re
import sys
import json
from pathlib import Path

try:
    import yaml
except ImportError:
    print("[ERROR] PyYAML not installed: pip install pyyaml")
    sys.exit(1)

# Bundled data directory — always available after pip install
_DATA_DIR         = Path(__file__).resolve().parent / "data"
_BUNDLED_DEFAULTS = _DATA_DIR / "defaults.yaml"
_BUNDLED_PATTERNS = _DATA_DIR / "pii_patterns.json"


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base, returning a new dict."""
    result = base.copy()
    for key, val in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


def load_settings() -> dict:
    with open(_BUNDLED_DEFAULTS, "r", encoding="utf-8") as f:
        defaults = yaml.safe_load(f)

    search = [
        Path.cwd() / ".pii-guard.yaml",
        Path.home() / ".pii-guard.yaml",
    ]

    for path in search:
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                user_cfg = yaml.safe_load(f) or {}
            return _deep_merge(defaults, user_cfg)

    return defaults


def _parse_patterns(data: dict) -> dict[str, str]:
    """Return a name→pattern mapping from a patterns JSON dict."""
    result = {}
    for entry in data.get("patterns", []):
        if "name" in entry and "pattern" in entry:
            result[entry["name"]] = entry["pattern"]
    return result


def load_patterns() -> list[dict]:
    # Always start with bundled patterns
    with open(_BUNDLED_PATTERNS, "r", encoding="utf-8") as f:
        bundled = _parse_patterns(json.load(f))

    # Look for custom patterns — first found wins
    custom_search = [
        Path.cwd() / ".pii-guard-patterns.json",
        Path.home() / ".pii-guard-patterns.json",
    ]
    custom: dict[str, str] = {}
    for path in custom_search:
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                custom = _parse_patterns(json.load(f))
            break

    # Merge: bundled base + custom on top (same name → custom wins)
    merged = {**bundled, **custom}

    patterns = []
    for name, pattern in merged.items():
        try:
            patterns.append({
                "name": name,
                "regex": re.compile(pattern),
            })
        except re.error as e:
            print(f"[WARN]  Invalid regex skipped ({name}): {e}")

    if not patterns:
        print("[ERROR] No valid patterns found.")
        sys.exit(1)

    return patterns
