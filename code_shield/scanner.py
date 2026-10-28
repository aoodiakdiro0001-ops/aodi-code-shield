"""The scanner — walks source files, applies regex rules + a Python AST pass.

Bright lines (enforced here, pinned by tests):
  * STATIC only: it reads and parses text; it NEVER imports, execs, or runs the
    scanned code.
  * Findings carry the matched region but secrets are REDACTED before they can
    reach any report (see redact.py).
  * It skips binary/huge/vendored files by default (node_modules, .git, venv).
  * Every finding is a SIGNAL for a human — heuristic, may include false
    positives. No "100% detection" claim.

`scan_path` is the entry point; everything is offline and deterministic (the AI
remediation layer is separate and optional).
"""
import ast
import io
import os
import re

from . import config as config_mod
from . import redact, rules

MAX_FILE_BYTES = 1024 * 1024          # 1 MiB per file cap
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__",
             ".mypy_cache", ".pytest_cache", "dist", "build", ".tox",
             "vendor", ".idea", ".vscode"}
TEXT_EXTS = {".py", ".pyw", ".js", ".jsx", ".mjs", ".ts", ".tsx", ".json",
             ".yml", ".yaml", ".env", ".sh", ".rb", ".php", ".go", ".java",
             ".txt", ".md", ".cfg", ".ini", ".toml"}
SECRET_FILENAMES = {".env", ".env.local", ".env.production", "credentials",
                    "credentials.json", "secrets.json", "id_rsa", "id_ed25519"}


class Finding(object):
    __slots__ = ("rule_id", "title", "severity", "category", "file", "line",
                 "message", "remediation", "snippet")

    def __init__(self, rule_id, title, severity, category, file, line,
                 message, remediation, snippet):
        self.rule_id = rule_id
        self.title = title
        self.severity = severity
        self.category = category
        self.file = file
        self.line = line
        self.message = message
        self.remediation = remediation
        self.snippet = snippet          # already redacted

    def as_dict(self):
        return {"rule_id": self.rule_id, "title": self.title,
                "severity": self.severity, "category": self.category,
                "file": self.file, "line": self.line,
                "message": self.message, "remediation": self.remediation,
                "snippet": self.snippet}


def _lang_for(path):
    _, ext = os.path.splitext(path)
    return rules.EXT_LANG.get(ext, "generic")


def _is_probable_secret_file(path):
    base = os.path.basename(path).lower()
    return base in {f.lower() for f in SECRET_FILENAMES} or base.startswith(".env")


def _read_text(path):
    """Read up to the size cap; return (text, was_truncated) or (None, False)."""
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            with open(path, "rb") as fh:
                raw = fh.read(MAX_FILE_BYTES)
            return raw.decode("utf-8", "replace"), True
        with io.open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(), False
    except (OSError, IOError):
        return None, False


def _redact_line(line):
    """Never let a raw secret leave the scanner via a snippet."""
    return redact.redact(line)


# Rules whose signal IS string content — these must see inside literals
# (`API_KEY = "ghp_..."`, `Access-Control-Allow-Origin: "*"`). Every OTHER
# rule only fires when its match STARTS in real code: a docstring saying
# `use eval(x) carefully` or a rule-pattern string mentioning `TripleDES`
# is not executable code (review fix for false-positive noise).
STRING_CONTENT_RULES = ("CS-SECRET-AWS", "CS-SECRET-GH", "CS-SECRET-GENERIC",
                        "CS-SECRET-FILE", "CS-CONF-WILDCARD-CORS")


def _strip_comment(line, lang):
    """Drop a trailing comment, respecting quoted strings (line-level fallback).

    `#` for python/generic (shell, yaml, env, ruby...), `//` for javascript
    (which also protects `https://` inside strings via quote tracking).
    """
    q = None
    esc = False
    for i, c in enumerate(line):
        if q:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == q:
                q = None
        elif c in "\"'":
            q = c
        elif c == "#" and lang != "javascript":
            return line[:i]
        elif (c == "/" and lang == "javascript"
              and i + 1 < len(line) and line[i + 1] == "/"):
            return line[:i]
    return line


def _in_code_positions(line):
    """Set of char indexes in `line` that are OUTSIDE any string literal."""
    pos = set()
    q = None
    esc = False
    for i, c in enumerate(line):
        if q:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == q:
                q = None
        elif c in "\"'":
            q = c
        else:
            pos.add(i)
    return pos


def _python_string_comment_spans(text):
    """Precise STRING/COMMENT spans via `tokenize` (handles multi-line
    docstrings perfectly; never executes anything). Returns None if the text
    cannot be tokenized (callers fall back to the line-level heuristics)."""
    try:
        import io as _io
        import tokenize
        spans = []
        for t in tokenize.generate_tokens(_io.StringIO(text).readline):
            if t.type in (tokenize.STRING, tokenize.COMMENT):
                spans.append((t.start[0], t.start[1], t.end[0], t.end[1],
                              t.type == tokenize.STRING))
        return spans
    except Exception:
        return None


def _python_row_pieces(line, lineno, spans):
    """For one row: (code_line_with_comments_removed, string_spans_on_row).

    Comments are DROPPED from the code line; strings are KEPT (rules like
    createHash("md5") need their content) but returned as spans so callers
    can tell whether a match sits in code or in a literal.
    """
    cuts = []
    for (r1, c1, r2, c2, is_str) in spans:
        if r2 < lineno or r1 > lineno:
            continue
        if r1 == lineno and r2 == lineno:
            cuts.append((c1, c2, is_str))
        elif r1 == lineno:
            cuts.append((c1, len(line), is_str))
        elif r2 == lineno:
            cuts.append((0, c2, is_str))
        else:
            cuts.append((0, len(line), is_str))     # multi-line string row
    cuts.sort()
    out = []
    str_spans = []
    pos = 0
    for (a, b, is_str) in cuts:
        if a > pos:
            out.append(line[pos:a])
        if is_str:
            out.append(line[a:b])
            str_spans.append((a, b))
        pos = max(pos, b)                           # comment: dropped
    out.append(line[pos:])
    return "".join(out), str_spans


def _match_in_code(code, m, str_spans, code_positions=None):
    """True if match `m` STARTS outside a string literal (code context).

    Start-only (not full-overlap) so rules that legitimately read a string
    ARGUMENT still work: `createHash("md5")` starts at `createHash` (code)
    while a docstring containing `createHash("md5")` starts inside the
    literal and is correctly ignored.
    """
    if str_spans is not None:
        s = m.start()
        for (a, b) in str_spans:
            if a <= s < b:
                return False
        return True
    if code_positions is None:
        code_positions = _in_code_positions(code)
    return m.start() in code_positions


def scan_text(text, path, lang, only_rule=None):
    """Apply regex rules line-by-line; return list of Finding.

    Comment content is excluded (except in credential-like files, where a
    secret in a comment still counts), and — except for STRING_CONTENT_RULES
    (secrets, CORS) — a rule only fires when its match starts in real code,
    never inside a string literal.
    """
    findings = []
    rls = rules.rules_for(lang)
    if only_rule:
        rls = [r for r in rls if r.id == only_rule]
    secret_file = _is_probable_secret_file(path)
    need_ctx = any(r.id not in STRING_CONTENT_RULES for r in rls)
    spans = _python_string_comment_spans(text) if lang == "python" else None
    # SSRF: a variable assigned a literal http(s) URL in this file is a
    # constant (url = "https://..."; requests.get(url)) — not a risk signal.
    const_urls = set(re.findall(
        r"\b(\w+)\s*(?::[^=]+)?=\s*\(?\s*[\"']https?://", text))
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped:
            continue
        code = line
        str_spans = None
        if not secret_file:
            if spans is not None:
                code, str_spans = _python_row_pieces(line, lineno, spans)
            else:
                code = _strip_comment(line, lang)
            if not code.strip():
                continue
        code_positions = None
        snippet = _redact_line(code.strip())[:200]
        for r in rls:
            if r.pattern is None:
                continue
            m = r.pattern.search(code)
            if not m:
                continue
            if (need_ctx and r.id not in STRING_CONTENT_RULES
                    and not _match_in_code(code, m, str_spans,
                                           code_positions)):
                continue
            if r.id == "CS-SSRF-URLVAR" and m.group(1) in const_urls:
                continue
            findings.append(Finding(
                r.id, r.title, r.severity, r.category, path, lineno,
                r.message, r.remediation, snippet))
    return findings


def scan_python_ast(text, path):
    """Python-only AST pass: catches dynamic-code patterns regex can miss.

    Uses the stdlib `ast` module to parse (never executes). Flags calls to
    eval/exec/compile and subprocess with shell=True fed by a formatted string.
    """
    findings = []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return findings               # unparseable: regex pass already ran
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fname = _call_name(node.func)
        if fname in ("eval", "exec", "compile"):
            findings.append(Finding(
                "CS-AST-DYNCODE", "Dynamic code execution (%s)" % fname,
                "high", "injection", path, getattr(node, "lineno", 0),
                "ast: %s() builds/executes code from a runtime value." % fname,
                "Avoid %s on untrusted input; use ast.literal_eval or a "
                "dispatch table." % fname, _redact_line(
                    ast.get_source_segment(text, node) or fname)[:200]))
        if fname in ("os.system", "subprocess.run", "subprocess.call",
                     "subprocess.Popen"):
            for kw in node.keywords:
                if kw.arg == "shell" and _is_true(kw.value):
                    findings.append(Finding(
                        "CS-AST-SHELL", "subprocess with shell=True", "high",
                        "injection", path, getattr(node, "lineno", 0),
                        "ast: shell=True passes the command through the shell; "
                        "combined with dynamic input this is command injection.",
                        "Drop shell=True and pass an argv list; validate any "
                        "dynamic values against an allow-list.",
                        _redact_line(ast.get_source_segment(text, node)
                                     or "shell=True")[:200]))
    return findings


def _call_name(func):
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        base = _call_name(func.value)
        return (base + "." + func.attr) if base else func.attr
    return ""


def _is_true(node):
    return isinstance(node, ast.NameConstant) and node.value is True


def scan_file(path, relpath=None, only_rule=None, allow_secret_file=False):
    """Scan one file (regex + AST for Python); return list of Finding.

    `allow_secret_file=True` suppresses ONLY the "credential file present"
    banner for a documented example file — detected secret VALUES are still
    found and redacted as usual (redaction is never disabled by config).
    """
    rel = relpath or path
    lang = _lang_for(path)
    text, _trunc = _read_text(path)
    if text is None:
        return []
    findings = scan_text(text, rel, lang, only_rule=only_rule)
    if lang == "python":
        findings += scan_python_ast(text, rel)
    # secret files: add a high-signal "committed credential file" finding
    # (unless config explicitly documents this as an example-secret location)
    if _is_probable_secret_file(path) and not allow_secret_file:
        findings.insert(0, Finding(
            "CS-SECRET-FILE", "Credential/env file present in tree", "high",
            "secret", rel, 1,
            "A filename that normally holds credentials is in the scanned tree.",
            "Ensure it is git-ignored and never committed; rotate anything "
            "that was. Load secrets from the environment or a secret manager.",
            _redact_line(os.path.basename(path))))
    return findings


def iter_files(root, include_tests=False):
    """Yield scannable file paths under `root`, skipping vendored/venv dirs."""
    root = os.path.abspath(root)
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS
                       and not d.startswith(".")]
        if not include_tests:
            dirnames[:] = [d for d in dirnames
                           if d.lower() not in ("tests", "test", "__tests__")]
        for fn in filenames:
            _, ext = os.path.splitext(fn)
            if ext.lower() in TEXT_EXTS or _is_probable_secret_file(fn):
                yield os.path.join(dirpath, fn)


def scan_path(root, include_tests=False, only_rule=None, cfg=None):
    """Scan a file or directory; return (findings, files_scanned).

    `cfg` (optional, from config.load_config) can NARROW scope: ignore_rules,
    ignore_paths, allow_secrets_in. It never disables redaction or widens scope.
    """
    cfg = cfg or {}
    ignore_rules = set(cfg.get("ignore_rules") or [])
    ignore_paths = cfg.get("ignore_paths") or []
    allow_secrets = cfg.get("allow_secrets_in") or []
    use_tests = include_tests or bool(cfg.get("include_tests"))
    findings = []
    count = 0
    for path in iter_files(root, include_tests=use_tests):
        rel = os.path.relpath(path, root) if os.path.isdir(root) else os.path.basename(path)
        if config_mod.path_is_ignored(rel, ignore_paths):
            continue
        count += 1
        fnds = scan_file(path, relpath=rel, only_rule=only_rule,
                         allow_secret_file=config_mod.secret_file_allowed(rel, allow_secrets))
        findings.extend([f for f in fnds if f.rule_id not in ignore_rules])
    findings.sort(key=lambda f: (SEV_ORDER.get(f.severity, 9), f.file, f.line))
    return findings, count


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def summarize(findings):
    """Aggregate counts by severity + category for a report header."""
    by_sev = {s: 0 for s in rules.SEVERITIES}
    by_cat = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_cat[f.category] = by_cat.get(f.category, 0) + 1
    return {"total": len(findings), "by_severity": by_sev,
            "by_category": by_cat}
