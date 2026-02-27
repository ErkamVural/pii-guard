"""
llm_scanner.py — Multi-provider LLM-based PII scanning.

Providers:
  - ollama          : Local Ollama instance
  - openai          : OpenAI API (uses requests, no SDK needed)
  - openai_compatible: Any OpenAI-compatible endpoint (LM Studio, vLLM, Groq, etc.)
  - anthropic       : Anthropic API (requires: pip install anthropic)
"""
import os
import re
import sys

try:
    import requests
except ImportError:
    print("[ERROR] requests not installed: pip install requests")
    sys.exit(1)

# Keys that are safe to forward to LLM providers from the top-level llm config.
# Any other keys (enabled, provider, providers, timeout) are framework-level and must not leak into payloads.
_PAYLOAD_KEYS = {"temperature", "seed", "top_p", "top_k", "num_predict", "repeat_penalty"}


def _get_options(llm_cfg: dict) -> dict:
    """Extract whitelisted LLM options from the top-level llm config."""
    return {k: v for k, v in llm_cfg.items() if k in _PAYLOAD_KEYS}


def _build_prompt(raw_lines: list[str], already_found: list[dict]) -> str:
    numbered = "".join(f"[{i}] {line}" for i, line in enumerate(raw_lines, 1))
    skip_note = ""
    if already_found:
        vals = ", ".join(f["value"] for f in already_found)
        skip_note = f"\nNOTE: These values are already detected, do NOT repeat them: {vals}\n"

    return (
        "You are a strict cybersecurity assistant. Analyze the following lines for sensitive data (PII).\n"
        "Look for: passwords, user:password patterns, base64-encoded credentials, secret tokens, "
        "JWT tokens, database connection strings with credentials, or any contextually sensitive data.\n\n"
        "STRICT RULES — do NOT flag these as sensitive:\n"
        "- Plain URLs without credentials (e.g. https://api.example.com/v1/data)\n"
        "- Random numeric IDs or order numbers with no credential context\n"
        "- Variable names, comments, or import statements\n"
        "- Any value that is clearly fictional, test, or placeholder data\n\n"
        "The [N] at the start of each line is the REAL line number. Use it directly, do NOT count lines yourself.\n"
        + skip_note +
        "\nFor EACH piece of sensitive data found, output exactly this block:\n"
        "---\n"
        "DATA: <copy the exact value from the text>\n"
        "LINE: <just the number from [N]>\n"
        "REASON: <one sentence describing what type of sensitive data it is>\n"
        "---\n"
        "If you find NOTHING sensitive, output only: CLEAN\n\n"
        f"Lines:\n{numbered}"
    )


def _parse_response(result_text: str, raw_lines: list[str], already_found: list[dict]) -> list[dict]:
    if result_text.upper().strip() == "CLEAN":
        return []

    valid_nos = {str(i) for i in range(1, len(raw_lines) + 1)}
    already_values = {f["value"] for f in already_found}
    seen: set[tuple] = set()
    findings = []

    for block in re.split(r"-{2,}", result_text):
        block = block.strip()
        if not block:
            continue
        found_data, line_num, reason = "", "", ""
        for line in block.split("\n"):
            s, u = line.strip(), line.strip().upper()
            if u.startswith("DATA:"):
                found_data = s[len("DATA:"):].strip()
            elif u.startswith("LINE:"):
                line_num = re.sub(r"[\[\]\s]", "", s[len("LINE:"):])
            elif u.startswith("REASON:"):
                reason = s[len("REASON:"):].strip()

        if not found_data or found_data.upper() in ("NONE", "CLEAN", "N/A"):
            continue

        # Filter false positives: model flagged it but reason says it's not sensitive
        _FP_PHRASES = (
            "without credential", "plain url", "random numeric",
            "no credential context", "not sensitive", "not a credential",
            "does not contain", "no sensitive", "transaction id",
            "order number", "public url", "example url",
        )
        if reason and any(fp in reason.lower() for fp in _FP_PHRASES):
            continue

        if any(av in found_data or found_data in av for av in already_values):
            continue
        if line_num not in valid_nos:
            line_num = "?"
        key = (line_num, found_data)
        if key in seen:
            continue
        seen.add(key)
        findings.append({
            "line": line_num,
            "value": found_data,
            "reason": reason or "No description.",
        })

    return findings


def _call_ollama(prompt: str, cfg: dict, llm_cfg: dict) -> str:
    url = cfg.get("base_url", "http://localhost:11434")
    resp = requests.post(
        f"{url}/api/generate",
        json={
            "model": cfg["model"],
            "prompt": prompt,
            "stream": False,
            "options": _get_options(llm_cfg),
        },
        timeout=llm_cfg.get("timeout", 30),
    )
    resp.raise_for_status()
    return resp.json().get("response", "").strip()


def _call_openai_compatible(prompt: str, cfg: dict, llm_cfg: dict) -> str:
    """
    Works for both openai and openai_compatible providers.
    Uses plain requests — no openai SDK needed.
    """
    api_key = os.getenv(cfg.get("api_key_env", ""), "none")
    url = cfg.get("base_url", "https://api.openai.com/v1")
    resp = requests.post(
        f"{url}/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": cfg["model"],
            "messages": [{"role": "user", "content": prompt}],
            **_get_options(llm_cfg),
        },
        timeout=llm_cfg.get("timeout", 30),
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"].strip()


def _call_anthropic(prompt: str, cfg: dict, llm_cfg: dict) -> str:
    """
    Requires: pip install anthropic
    Imported lazily so the package is only needed when this provider is selected.
    """
    try:
        import anthropic as sdk  # type: ignore — avoids IDE warning at top level
    except ImportError:
        print("[ERROR] anthropic package not installed.")
        print("        Run: pip install anthropic")
        sys.exit(1)

    api_key = os.getenv(cfg.get("api_key_env", "ANTHROPIC_API_KEY"), "")
    client = sdk.Anthropic(api_key=api_key)
    msg = client.messages.create(
        model=cfg["model"],
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}],
    )
    return msg.content[0].text.strip()


def scan(raw_lines: list[str], already_found: list[dict], llm_cfg: dict) -> list[dict]:
    provider  = llm_cfg.get("provider")
    providers = llm_cfg.get("providers", {})
    cfg       = providers.get(provider, {})

    prompt = _build_prompt(raw_lines, already_found)

    try:
        if provider == "ollama":
            result_text = _call_ollama(prompt, cfg, llm_cfg)
        elif provider in ("openai", "openai_compatible"):
            result_text = _call_openai_compatible(prompt, cfg, llm_cfg)
        elif provider == "anthropic":
            result_text = _call_anthropic(prompt, cfg, llm_cfg)
        else:
            print(f"[ERROR] Unknown LLM provider: '{provider}'")
            print("   Valid options: ollama | openai | openai_compatible | anthropic")
            sys.exit(1)

    except requests.exceptions.ConnectionError:
        print(f"[ERROR] Connection error ({provider}) - URL: {cfg.get('base_url', 'N/A')}")
        sys.exit(1)
    except requests.exceptions.HTTPError as e:
        print(f"[ERROR] HTTP error ({provider}): {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Unexpected error ({provider}): {e}")
        sys.exit(1)

    return _parse_response(result_text, raw_lines, already_found)