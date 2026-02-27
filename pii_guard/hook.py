"""
hook.py — CLI entry point for PII Guard.

Registered as a system-wide command via pyproject.toml:
  [project.scripts]
  pii-guard = "pii_guard.hook:main"

Called by pre-commit framework via .pre-commit-hooks.yaml:
  entry: pii-guard
"""
import os
import sys
import subprocess

from pii_guard.config_loader import load_settings, load_patterns
from pii_guard import regex_scanner, llm_scanner

DEFAULT_FORMAT = [
    "   |",
    "   +-- Line  : {line}",
    "   +-- Type  : {type}",
    "   +-- Value : {value}",
    "   +-- Detail: {detail}",
]


def log(msg: str = "") -> None:
    """Write to stderr so pre-commit framework displays it."""
    print(msg, file=sys.stderr)


def get_staged_files(extensions: list[str]) -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        capture_output=True, text=True,
    )
    return [
        f for f in result.stdout.split("\n")
        if f.strip() and any(f.endswith(ext) for ext in extensions)
    ]


def print_finding(fmt: list[str], line, type_or_label: str, value: str, detail: str) -> None:
    for template in fmt:
        log(template.format(line=line, type=type_or_label, value=value, detail=detail))


def main() -> None:
    settings    = load_settings()
    patterns    = load_patterns()
    llm_cfg     = settings.get("llm", {})
    llm_enabled = llm_cfg.get("enabled", False)
    extensions  = settings.get("scan", {}).get("extensions")

    log(f"[*] {len(patterns)} patterns loaded: {', '.join(p['name'] for p in patterns)}")
    if llm_enabled:
        log(f"[LLM] LLM active - provider: {llm_cfg.get('provider')}")
    else:
        log("[REGEX] Regex-only mode active")

    staged_files = get_staged_files(extensions)
    if not staged_files:
        log("[SKIP] No staged files match the configured extensions. Skipping.")
        sys.exit(0)

    pii_found = False

    for file_path in staged_files:
        if not os.path.exists(file_path):
            continue
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            raw_lines = f.readlines()
        if not "".join(raw_lines).strip():
            continue

        # --- Layer 1: Regex ---
        regex_findings = regex_scanner.scan(raw_lines, patterns)
        if regex_findings:
            pii_found = True
            log(f"\n[!] '{file_path}' - sensitive data detected! [Regex]")
            for finding in regex_findings:
                print_finding(DEFAULT_FORMAT, finding["line"], finding["type"], finding["value"], "Regex match")

        # --- Layer 2: LLM ---
        if llm_enabled:
            llm_findings = llm_scanner.scan(raw_lines, regex_findings, llm_cfg)
            if llm_findings:
                pii_found = True
                label = "LLM - additional findings" if regex_findings else "LLM"
                log(f"\n[!] '{file_path}' - sensitive data detected! [{label}]")
                for lf in llm_findings:
                    print_finding(DEFAULT_FORMAT, lf["line"], "LLM", lf["value"], lf["reason"])
            elif regex_findings:
                log("   [LLM - no additional findings]")

    if pii_found:
        log("\n[BLOCKED] COMMIT BLOCKED: Please remove the sensitive data listed above and try again.")
        sys.exit(1)

    log("[OK] PII scan clean. Proceeding with commit...")
    sys.exit(0)


if __name__ == "__main__":
    main()
