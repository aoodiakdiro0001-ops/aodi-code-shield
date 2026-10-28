"""Secret redaction — the crown compliance rule of a secret scanner.

The moment Code-Shield detects a credential, that value becomes TOXIC: it must
never appear in a report, a GitHub PR comment, a Telegram message, or a log.
Every delivery path routes detected secrets through ``redact()``.

Contracts (pinned by tests):
  * a matched secret is replaced by a stable, non-reversible mask that keeps
    just enough context to identify WHICH secret leaked (first 4 / last 4)
  * redaction is idempotent and never crashes on weird input
  * the mask can never be mistaken for, or reversed into, the original value
"""
import re

MASK = "••••REDACTED••••"


def mask(value):
    """Mask a secret, keeping first-4/last-4 ONLY for long secrets (16+).

    Anything shorter is FULLY masked (no partial leak — an 8-of-13-char
    reveal would leak most of a low-entropy password). The mask is
    decorative and carries no reversible information.
    """
    v = str(value)
    if len(v) >= 16:
        return "%s…%s %s" % (v[:4], v[-4:], MASK)
    return MASK


def redact(text, extra_secrets=None):
    """Redact every known/likely secret from `text`.

    `extra_secrets` is an iterable of exact secret strings found during a scan
    (the scanner passes what it detected). We replace each with its mask, then
    apply a generic sweep for anything that still *looks* like a credential.
    Idempotent and crash-safe.
    """
    if text is None:
        return ""
    s = str(text)
    for sec in (extra_secrets or []):
        sec = str(sec)
        if sec:                             # no length floor: if the scanner
            s = s.replace(sec, mask(sec))   # detected it, it gets masked
    s = _generic_sweep(s)
    return s


# Shared name/value fragments — rules.py imports these so the DETECTION rule
# and the REDACTION sweep can never drift apart (a gap in one is a gap in both).
# Name: any identifier containing a secret keyword (covers DB_PASSWORD,
# db_password, my_api_key, SECRET_KEY, bare `key`, ...). The {0,64} bounds
# keep the engine linear on pathological lines (no O(n^2) backtracking).
SECRET_NAME = (
    r"[A-Za-z0-9_-]{0,64}(?:api[_-]?key|secret[_-]?key|secret|token|password"
    r"|passwd|pwd|access[_-]?key|private[_-]?key|client[_-]?secret"
    r"|auth[_-]?token|key)[A-Za-z0-9_-]{0,64}"
)
# Quoted value: classic Python/YAML/JSON assignment. The (?!\s*=) rejects
# string-annotation-then-default (`password: "Optional[str]" = None`).
SECRET_QUOTED = (
    r"(" + SECRET_NAME + r")(\s*[:=]\s*)(['\"])([^'\"]{8,})\3(?!\s*=)"
)
# Unquoted value: .env style. Value is 12+ chars, contains at least one
# digit/base64-pad char within its first 97 chars (skips `key = LONG_NAME`
# references and type names), stops at parens/dots/quotes, and must end at a
# line/;/# boundary (so `key = get_secret_from_vault()` cannot match).
SECRET_UNQUOTED = (
    r"(" + SECRET_NAME + r")(\s*=\s*)"
    r"(?=[A-Za-z0-9+/=_:-]{0,96}[0-9+/=-])"
    r"([A-Za-z0-9+/=_:-]{12,})(?=\s*(?:[#;]|$))"
)

# Generic post-sweep: catch any credential-shaped token that survived.
_GENERIC = [
    # AWS access key id
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), MASK),
    # GitHub token (classic or fine-grained or PAT)
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), MASK),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), MASK),
    # Slack token
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), MASK),
    # Stripe secret/publishable key
    (re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{10,}\b"), MASK),
    # Google API key
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), MASK),
    # OpenAI-style / Anthropic / OpenRouter / generic sk- keys (hyphenated)
    (re.compile(r"\bsk-(?:ant|or|proj|svc)-[A-Za-z0-9\-_]{10,}\b"), MASK),
    (re.compile(r"\bsk-[A-Za-z0-9][A-Za-z0-9\-_]{15,}\b"), MASK),
    # HuggingFace / npm / PyPI tokens
    (re.compile(r"\bhf_[A-Za-z0-9]{20,}\b"), MASK),
    (re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b"), MASK),
    (re.compile(r"\bpypi-[A-Za-z0-9_\-]{20,}\b"), MASK),
    # Telegram bot token
    (re.compile(r"\b\d{8,10}:[A-Za-z0-9_\-]{30,}\b"), MASK),
    # Bearer/JWT-ish
    (re.compile(r"\bBearer\s+[A-Za-z0-9_\-\.=]{20,}\b"), "Bearer " + MASK),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}\b"), MASK),
    # generic assignment (quoted + unquoted) of a literal to a secret-ish name
    (re.compile(SECRET_QUOTED, re.I),
     lambda m: m.group(1) + m.group(2) + m.group(3) + MASK + m.group(3)),
    (re.compile(SECRET_UNQUOTED, re.I),
     lambda m: m.group(1) + m.group(2) + MASK),
]


def _generic_sweep(s):
    for pat, repl in _GENERIC:
        try:
            s = pat.sub(repl, s)
        except Exception:
            continue
    return s


def looks_like_secret(token):
    """Heuristic: does this bare token look like a credential? (for scanning)."""
    t = str(token).strip()
    if len(t) < 8:
        return False
    for pat, _ in _GENERIC:
        try:
            if pat.search(t):
                return True
        except Exception:
            continue
    return False
