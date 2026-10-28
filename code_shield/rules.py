"""Vulnerability rule registry — data-driven detection patterns.

Each rule is a declarative record. Two kinds:
  * ``regex`` rules match a single line (fast, language-agnostic-ish)
  * ``ast`` rules are Python-only predicates over the ``ast`` module output

Severity is honest and heuristic: these are SIGNALS for a human, not proof.
A finding may be a false positive (e.g. a test fixture, a non-reachable path).
The report always says so.

Bright line: detection only. A rule NEVER executes, downloads, or exploits
anything — it reads parsed text/AST and returns a finding record.
"""
import re

from .redact import SECRET_QUOTED, SECRET_UNQUOTED

SEVERITIES = ("critical", "high", "medium", "low", "info")


class Rule(object):
    __slots__ = ("id", "title", "severity", "category", "languages",
                 "message", "remediation", "pattern", "flags")

    def __init__(self, id, title, severity, category, message, remediation,
                 pattern=None, languages=None, flags=re.I):
        assert severity in SEVERITIES, "bad severity %r" % severity
        self.id = id
        self.title = title
        self.severity = severity
        self.category = category          # secret|injection|crypto|config|deser|other
        self.message = message
        self.remediation = remediation
        self.pattern = re.compile(pattern, flags) if pattern else None
        self.languages = languages or ("python", "javascript", "generic")

    def __repr__(self):
        return "<Rule %s %s>" % (self.id, self.severity)


# ---------------------------------------------------------------------------
# Regex rules — each matches ONE line. `(?s)` never used; keep them linear.
# ---------------------------------------------------------------------------
REGEX_RULES = [
    # ---- secrets / hardcoded credentials (highest stakes: always redact) ----
    Rule("CS-SECRET-AWS", "Hardcoded AWS access key", "critical", "secret",
         "An AWS access key ID appears hardcoded in source.",
         "Remove the key, revoke/rotate it in IAM, and load it from an "
         "environment variable or a secret manager. Treat it as compromised.",
         pattern=r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", languages=("generic",)),
    Rule("CS-SECRET-GH", "Hardcoded GitHub token", "critical", "secret",
         "A GitHub token appears hardcoded in source.",
         "Revoke the token now, then read it from the environment/secret store.",
         pattern=r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b",
         languages=("generic",)),
    Rule("CS-SECRET-GENERIC", "Hardcoded secret/password assignment", "high",
         "secret", "A secret-like variable is assigned a literal value.",
         "Move the value to an environment variable or secret manager; rotate "
         "it if it was ever committed.",
         # SAME fragments as redact.py's sweep — one source of truth, so a
         # detection gap and a redaction gap can never diverge (review fix).
         pattern=r"(?:%s)|(?:%s)" % (SECRET_QUOTED, SECRET_UNQUOTED),
         languages=("generic",)),

    # ---- injection ----
    Rule("CS-INJ-SQL-FSTR", "Possible SQL injection via f-string", "high",
         "injection", "An f-string is interpolated into a SQL execute() call.",
         "Use a parameterized query: cursor.execute(sql, (param,)) — never "
         "format user input into the SQL string.",
         pattern=r"execute\s*\(\s*f['\"]",
         languages=("python",)),
    Rule("CS-INJ-SQL-CONCAT", "Possible SQL injection via string concatenation",
         "high", "injection",
         "String concatenation (+ or %) is used to build a SQL statement.",
         "Use parameterized queries with placeholders instead of concatenation.",
         pattern=r"execute\s*\(\s*['\"][^'\"]*['\"]\s*(?:\+|%)",
         languages=("python",)),
    Rule("CS-INJ-SQL-FORMAT", "Possible SQL injection via .format()", "high",
         "injection", ".format() is used to build a SQL statement.",
         "Use parameterized queries instead of str.format() for SQL.",
         pattern=r"execute\s*\([^)]*\.format\s*\(",
         languages=("python",)),
    Rule("CS-INJ-CMD-SHELL", "Shell command built from variables", "high",
         "injection", "os.system/subprocess with shell=True and interpolation.",
         "Avoid shell=True; pass an argument list to subprocess.run() and "
         "validate/allow-list any dynamic values.",
         pattern=r"(?:os\.system|os\.popen|subprocess\.(?:run|call|Popen))"
                 r"\s*\([^)]*(?:\+|%|\.format|f['\"])",
         languages=("python",)),
    Rule("CS-INJ-EVAL", "Use of eval()/exec()", "high", "injection",
         "eval()/exec() executes dynamically-built code — a common RCE vector.",
         "Never eval/exec untrusted input. Use ast.literal_eval for literals, "
         "or a parser/dispatch table for real logic.",
         pattern=r"\b(?:eval|exec)\s*\(", languages=("python",)),
    Rule("CS-INJ-NEW-FUNCTION", "Dynamic code via new Function", "high",
         "injection", "new Function() builds code from a string at runtime.",
         "Avoid new Function on untrusted input; use explicit logic instead.",
         pattern=r"new\s+Function\s*\(", languages=("javascript",)),

    # ---- weak crypto ----
    Rule("CS-CRYPTO-MD5", "Weak hash: MD5", "medium", "crypto",
         "MD5 is cryptographically broken (collisions).",
         "Use SHA-256+ for integrity; for passwords use bcrypt/scrypt/argon2.",
         pattern=r"hashlib\.md5\s*\(|createHash\s*\(\s*['\"]md5",
         languages=("python", "javascript")),
    Rule("CS-CRYPTO-SHA1", "Weak hash: SHA-1", "medium", "crypto",
         "SHA-1 is deprecated for security contexts (SHAttered).",
         "Use SHA-256+ for integrity; bcrypt/scrypt/argon2 for passwords.",
         pattern=r"hashlib\.sha1\s*\(|createHash\s*\(\s*['\"]sha1",
         languages=("python", "javascript")),
    Rule("CS-CRYPTO-DES", "Weak cipher: DES/3DES/RC4", "high", "crypto",
         "A broken cipher (DES/3DES/RC4/Blowfish) is referenced.",
         "Use AES-GCM (authenticated encryption) via a vetted library.",
         # Case-SENSITIVE with word lookarounds (review fix): `re.I` made bare
         # `DES` hit variables like `des = load()` (HIGH false positive) while
         # `TripleDES.new(...)` never matched (the old pattern required a
         # literal leading space). Longest alternatives first.
         pattern=r"(?<![A-Za-z0-9_])(?:TripleDES|DES3|3DES|DES|RC4|ARC4"
                 r"|Blowfish)(?![A-Za-z0-9_])",
         flags=0,
         languages=("python",)),
    Rule("CS-CRYPTO-PYRAND", "Insecure randomness for security", "medium",
         "crypto", "random.* used where a CSPRNG is required.",
         "Use the `secrets` module (or os.urandom) for tokens/keys/passwords.",
         pattern=r"\b(?:random\.(?:random|randint|choice|randrange|getrandbits)"
                 r"|Math\.random)\s*\(",
         languages=("python", "javascript")),

    # ---- unsafe deserialization ----
    Rule("CS-SER-PICKLE", "Unsafe deserialization: pickle", "high", "deser",
         "pickle.loads on (possibly untrusted) data can execute arbitrary code.",
         "Never unpickle untrusted data. Use JSON or a schema-validated format.",
         pattern=r"\bpickle\.loads?\s*\(", languages=("python",)),
    Rule("CS-SER-YAML", "Unsafe YAML load", "high", "deser",
         "yaml.load without SafeLoader can instantiate arbitrary objects.",
         "Use yaml.safe_load() (or pass SafeLoader) for untrusted input.",
         pattern=r"\byaml\.load\s*\((?!.*SafeLoader)", languages=("python",)),
    Rule("CS-SER-MARSHAL", "Unsafe deserialization: marshal", "high", "deser",
         "marshal.loads can execute code and is not a data interchange format.",
         "Use json for data; never load untrusted marshal data.",
         pattern=r"\bmarshal\.loads?\s*\(", languages=("python",)),

    # ---- insecure config / transport ----
    Rule("CS-CONF-SSL-OFF", "TLS verification disabled", "high", "config",
         "SSL/TLS certificate verification is turned off (verify=False).",
         "Enable certificate verification. If you must pin a CA, pass the CA "
         "bundle instead of disabling verification.",
         # scoped to real HTTP clients on the same line (review fix): a bare
         # `verify=False` on an unrelated function is not evidence of TLS off.
         pattern=r"(?:requests|httpx|urllib3?|aiohttp|boto3|botocore|axios"
                 r"|fetch|got)\b[^\n]{0,150}?verify\s*=\s*False"
                 r"|curlLOPT_SSL_VERIFYPEER\s*,\s*0"
                 r"|rejectUnauthorized\s*:\s*false",
         languages=("python", "javascript", "generic")),
    Rule("CS-CONF-DEBUG", "Debug mode enabled in code", "low", "config",
         "A debug flag appears set to True in source.",
         "Ensure DEBUG is off in production; drive it from the environment.",
         pattern=r"\bDEBUG\s*=\s*True\b", languages=("python", "generic")),
    Rule("CS-CONF-WILDCARD-CORS", "Wildcard CORS origin", "medium", "config",
         "Access-Control-Allow-Origin is set to a wildcard/any origin.",
         "Restrict CORS to an explicit allow-list of trusted origins.",
         pattern=r"Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]\*",
         languages=("generic",)),
    Rule("CS-CONF-PERM777", "World-writable file permission", "low", "config",
         "chmod 0o777 grants world-writable access.",
         "Use least-privilege permissions (e.g. 0o600 / 0o644).",
         pattern=r"chmod\s*\(\s*[^)]*0o?777", languages=("python",)),

    # ---- path traversal / SSRF-ish ----
    Rule("CS-PATH-JOIN", "Path built from a variable (traversal risk)", "medium",
         "path", "os.path.join/open with a dynamic segment may allow ../ traversal.",
         "Resolve with os.path.realpath and confirm the result stays inside an "
         "intended base directory before opening.",
         pattern=r"open\s*\(\s*os\.path\.join\s*\(", languages=("python",)),
    Rule("CS-SSRF-URLVAR", "URL built from a variable (SSRF risk)", "medium",
         "ssrf", "A request URL is built from a variable — possible SSRF.",
         "Allow-list schemes/hosts; block link-local/metadata ranges (169.254.).",
         # capture group 1 = the variable, so the scanner can skip it when the
         # file assigns that name a literal URL (constant, not attacker input)
         pattern=r"requests\.(?:get|post|put|request)\s*\(\s*([a-zA-Z_]\w*)"
                 r"\s*[,)]",
         languages=("python",)),
]

# Language extension -> rule language tag filter
EXT_LANG = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".ts": "javascript", ".tsx": "javascript",
}


def rules_for(lang):
    """Regex rules whose language list includes `lang` (or 'generic')."""
    out = []
    for r in REGEX_RULES:
        if lang in r.languages or "generic" in r.languages:
            out.append(r)
    return out
