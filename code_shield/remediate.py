"""Remediation layer — propose a fix for each finding.

The AI (Groq free tier / Ollama) is OPTIONAL and only *phrases* a remediation.
The pipeline NEVER depends on it: every rule already carries a deterministic,
human-written ``remediation`` string, and the offline engine below expands it
into concrete guidance. If no AI backend is configured or it errors, the
deterministic text is used — and provider errors are redacted.

Bright lines:
  * no network unless a backend is explicitly configured
  * the AI is never asked to EXPLOIT — only to restate a safer coding pattern
  * provider error text is redacted before it can reach a report
"""
import json
import os
import urllib.request

from . import redact


def _redact(msg):
    for k in ("GROQ_API_KEY", "GEMINI_API_KEY", "HF_TOKEN"):
        v = os.environ.get(k)
        if v:
            msg = msg.replace(v, "***")
    return redact.redact(msg)


class OfflineRemediator(object):
    """Deterministic, offline, zero-network. Default + test fallback."""
    name = "offline"

    # Concrete before/after hints per rule id (kept short, educational).
    SNIPPETS = {
        "CS-INJ-SQL-FSTR":
            "cursor.execute(\"SELECT * FROM t WHERE id = ?\", (user_id,))",
        "CS-INJ-SQL-CONCAT":
            "cursor.execute(\"SELECT * FROM t WHERE name = ?\", (name,))",
        "CS-INJ-SQL-FORMAT":
            "cursor.execute(\"SELECT * FROM t WHERE id = ?\", (the_id,))",
        "CS-INJ-EVAL":
            "value = ast.literal_eval(literal)  # not eval()",
        "CS-INJ-CMD-SHELL":
            "subprocess.run([\"ls\", \"-l\", path], shell=False, check=True)",
        "CS-SER-PICKLE":
            "data = json.loads(payload)  # not pickle.loads on untrusted data",
        "CS-SER-YAML":
            "data = yaml.safe_load(payload)",
        "CS-SER-MARSHAL":
            "data = json.loads(payload)  # not marshal on untrusted data",
        "CS-CRYPTO-MD5":
            "digest = hashlib.sha256(b\"...\").hexdigest()",
        "CS-CRYPTO-SHA1":
            "digest = hashlib.sha256(b\"...\").hexdigest()",
        "CS-CONF-SSL-OFF":
            "requests.get(url, verify=\"/etc/ssl/certs/ca-bundle.crt\")",
        "CS-CRYPTO-PYRAND":
            "token = secrets.token_urlsafe(32)",
        "CS-SECRET-AWS":
            "key = os.environ[\"AWS_ACCESS_KEY_ID\"]  # never hardcode",
        "CS-SECRET-GH":
            "tok = os.environ[\"GITHUB_TOKEN\"]  # never hardcode",
        "CS-SECRET-GENERIC":
            "secret = os.environ[\"MY_SECRET\"]  # load, don't inline",
    }

    def remediate(self, finding):
        base = finding.remediation
        snip = self.SNIPPETS.get(finding.rule_id)
        if snip:
            return "%s\n  safer: `%s`" % (base, snip)
        return base


class GroqRemediator(object):
    """Groq free-tier chat model. Requires GROQ_API_KEY."""
    name = "groq"
    URL = "https://api.groq.com/openai/v1/chat/completions"

    def __init__(self, model=None, timeout=30.0, fallback=None):
        self.model = model or os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant")
        self.timeout = timeout
        self.key = os.environ.get("GROQ_API_KEY", "")
        self.fallback = fallback or OfflineRemediator()

    def remediate(self, finding):
        if not self.key:
            return self.fallback.remediate(finding)
        prompt = ("A code-security scanner flagged this. In ONE short code "
                  "snippet plus one sentence, show the SAFER coding pattern. "
                  "Do not exploit anything. Rule: %s (%s). Context: %s"
                  % (finding.rule_id, finding.title, finding.snippet))
        try:
            body = json.dumps({
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 160, "temperature": 0.1,
            }).encode("utf-8")
            req = urllib.request.Request(
                self.URL, data=body, method="POST",
                headers={"Content-Type": "application/json",
                         "Authorization": "Bearer " + self.key})
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}))
            with opener.open(req, timeout=self.timeout) as r:
                data = json.loads(r.read(1 << 20).decode("utf-8"))
            # AI output is influenced by the scanned text -> sanitize it
            return redact.redact(
                data["choices"][0]["message"]["content"].strip())
        except Exception as e:
            return "(AI offline) " + _redact(str(e))


class GeminiRemediator(object):
    """Google Gemini free tier. Requires GEMINI_API_KEY."""
    name = "gemini"

    def __init__(self, model=None, timeout=30.0, fallback=None):
        self.model = model or os.environ.get("GEMINI_MODEL", "gemini-1.5-flash")
        self.key = os.environ.get("GEMINI_API_KEY", "")
        self.timeout = timeout
        self.fallback = fallback or OfflineRemediator()

    def remediate(self, finding):
        if not self.key:
            return self.fallback.remediate(finding)
        url = ("https://generativelanguage.googleapis.com/v1beta/models/"
               "%s:generateContent?key=%s" % (self.model, self.key))
        prompt = ("Show the safer coding pattern for this security finding in "
                  "one short snippet + one sentence. Do not exploit. %s (%s): %s"
                  % (finding.rule_id, finding.title, finding.snippet))
        try:
            body = json.dumps({"contents": [
                {"parts": [{"text": prompt}]}]}).encode("utf-8")
            req = urllib.request.Request(
                url, data=body, method="POST",
                headers={"Content-Type": "application/json"})
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}))
            with opener.open(req, timeout=self.timeout) as r:
                data = json.loads(r.read(1 << 20).decode("utf-8"))
            # AI output is influenced by the scanned text -> sanitize it
            return redact.redact(
                data["candidates"][0]["content"]["parts"][0]["text"].strip())
        except Exception as e:
            return "(AI offline) " + _redact(str(e))


def get_remediator(kind=None):
    kind = (kind or os.environ.get("CODESHIELD_AI", "offline")).lower()
    if kind == "groq":
        return GroqRemediator()
    if kind in ("gemini", "google"):
        return GeminiRemediator()
    return OfflineRemediator()
