"""
regex_scanner.py — Deterministic PII scanning via pii_patterns.json.
"""


def scan(raw_lines: list[str], patterns: list[dict]) -> list[dict]:
    findings = []
    seen: set[tuple] = set()
    for line_no, content in enumerate(raw_lines, 1):
        for p in patterns:
            for match in p["regex"].finditer(content):
                value = match.group(0)
                key = (line_no, value)
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    "line": line_no,
                    "type": p["name"],
                    "value": value,
                })
    return findings
