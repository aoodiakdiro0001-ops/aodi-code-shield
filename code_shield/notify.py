"""Telegram notification gateway (stdlib-only, hardened).

Same contracts as the rest of the suite:
  * the opener refuses ambient system proxies (a token never rides an env proxy)
  * outbound reads are capped; redirects are not followed
  * messages are size-clamped and routed through redact() (no secret leaks)
"""
import json
import os
import urllib.error
import urllib.parse
import urllib.request

from . import redact

TOKEN = os.environ.get("TELEGRAM_TOKEN", "")
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
API = "https://api.telegram.org/bot%s"
MAX_READ = 1 << 20


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(newurl, code, "redirect blocked", headers, fp)


_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}), _NoRedirect)


def _int_env(name, default):
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


TIMEOUT = max(1, min(_int_env("CODESHIELD_TG_TIMEOUT", 30), 120))


def send(text, chat_id=None):
    """Send a message; returns {ok:bool} (+redacted err on failure)."""
    if not TOKEN:
        return {"ok": False, "err": "TELEGRAM_TOKEN not set"}
    url = (API % TOKEN) + "/sendMessage"
    payload = urllib.parse.urlencode(
        {"chat_id": chat_id or CHAT_ID,
         "text": redact.redact(str(text))[:4096]}).encode("utf-8")
    req = urllib.request.Request(url, data=payload)
    try:
        with _OPENER.open(req, timeout=TIMEOUT) as r:
            return json.loads(r.read(MAX_READ).decode("utf-8"))
    except Exception as e:
        return {"ok": False, "err": redact.redact(str(e))[:160]}


def build_alert(findings, summary, max_items=8):
    """Compact Telegram alert from findings (already redacted)."""
    lines = ["🛡️ Code-Shield audit — %d finding(s) in %d file(s)"
             % (summary["total_findings"], summary["scanned_files"])]
    sev = summary["by_severity"]
    top = ", ".join("%s:%d" % (k, sev[k]) for k in
                    ("critical", "high", "medium", "low") if sev.get(k))
    if top:
        lines.append("severity — " + top)
    for f in findings[:max_items]:
        lines.append("• [%s] %s:%s — %s"
                     % (f.severity.upper(), f.file, f.line,
                        redact.redact(f.title)[:80]))
    if len(findings) > max_items:
        lines.append("…+%d more (see report)" % (len(findings) - max_items))
    if not findings:
        lines.append("No findings in the current rule set (not a guarantee).")
    return redact.redact("\n".join(lines))
