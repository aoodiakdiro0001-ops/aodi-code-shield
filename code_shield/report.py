"""Report builder — renders findings to dict / Markdown / HTML / PR comment.

Every output path routes through ``redact`` — a detected secret can never reach
a report, a PR comment, or a Telegram message in cleartext. The HTML renderer
escapes all dynamic values (no stored-XSS in a self-hosted report page).

Honesty: the report always states severity is heuristic and findings may
include false positives. There is no "100% clean" or "zero-day-proof" claim.
"""
import datetime
import html as _html

from . import redact

SEV_BADGE = {"critical": "CRIT", "high": "HIGH", "medium": "MED",
             "low": "LOW", "info": "INFO"}
DISCLAIMER = ("Heuristic static analysis. Findings are signals for a human "
              "review and may include false positives. This tool does not "
              "execute code and does not exploit findings.")


def _esc(s):
    return _html.escape(str(s if s is not None else ""))


def build_summary(findings, scanned_files, remediated=None):
    """Structured summary dict (all snippets already redacted by the scanner).

    Remediation text is redacted HERE (choke point): AI-phrased remediations
    are influenced by attacker-controlled scanned text, so they are sanitized
    before they can reach any report artifact.
    """
    by_sev = {}
    by_cat = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_cat[f.category] = by_cat.get(f.category, 0) + 1
    return {
        "generated_utc": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M"),
        "scanned_files": scanned_files,
        "total_findings": len(findings),
        "by_severity": by_sev,
        "by_category": by_cat,
        "remediations": [redact.redact(r) for r in (remediated or [])],
        "disclaimer": DISCLAIMER,
    }


def to_markdown(findings, summary):
    """Human-readable Markdown report. Secrets already redacted."""
    lines = ["# Code-Shield ZeroBaran — Security Audit", ""]
    lines.append("_Generated %s UTC · scanned %d file(s) · %d finding(s)_"
                 % (summary["generated_utc"], summary["scanned_files"],
                    summary["total_findings"]))
    lines.append("")
    sev = summary["by_severity"]
    if sev:
        lines.append("**By severity:** " + " · ".join(
            "%s %d" % (SEV_BADGE.get(k, k.upper()), sev[k])
            for k in ("critical", "high", "medium", "low", "info")
            if sev.get(k)))
        lines.append("")
    if not findings:
        lines.append("No findings matched the current rule set. That is **not** "
                     "a guarantee of absence — see the disclaimer.")
        lines.append("")
    for f in findings:
        lines.append("### [%s] %s" % (SEV_BADGE.get(f.severity, "?"), f.title))
        lines.append("- **Rule:** `%s` · **Category:** %s" % (f.rule_id, f.category))
        lines.append("- **Location:** `%s:%s`" % (f.file, f.line))
        lines.append("- **Why:** %s" % redact.redact(f.message))
        if f.snippet:
            lines.append("- **Code:** `%s`" % redact.redact(f.snippet))
        lines.append("- **Fix:** %s" % redact.redact(f.remediation))
        lines.append("")
    lines.append("---")
    lines.append("> " + DISCLAIMER)
    return "\n".join(lines)


def to_pr_comment(findings, summary, max_items=40):
    """A concise GitHub PR comment (already redacted + size-clamped)."""
    body = ["## 🛡️ Code-Shield ZeroBaran — automated security audit", ""]
    body.append("Scanned **%d file(s)** · **%d finding(s)** (%s)"
                % (summary["scanned_files"], summary["total_findings"],
                   ", ".join("%s:%d" % (k, v) for k, v in
                             sorted(summary["by_severity"].items())
                             if v) or "none"))
    body.append("")
    for f in findings[:max_items]:
        body.append("- **[%s]** `%s:%s` — %s"
                    % (SEV_BADGE.get(f.severity, "?"), f.file, f.line,
                       redact.redact(f.title)))
        body.append("  - fix: %s" % redact.redact(f.remediation)[:300])
    if len(findings) > max_items:
        body.append("\n…and %d more (see the full report artifact)."
                    % (len(findings) - max_items))
    body.append("\n> " + DISCLAIMER)
    return redact.redact("\n".join(body))


def to_html(findings, summary):
    """Self-contained HTML report page (escaped — safe to self-host)."""
    rows = []
    for f in findings:
        rows.append(
            "<tr><td><span class='pill %s'>%s</span></td>"
            "<td class='t'>%s</td><td class='f'>%s:%s</td>"
            "<td class='m'>%s<div class='fix'>%s</div></td></tr>"
            % (_esc(f.severity), _esc(SEV_BADGE.get(f.severity, "?")),
               _esc(f.title), _esc(f.file), _esc(f.line),
               _esc(redact.redact(f.message)),
               _esc(redact.redact(f.remediation))))
    sev = summary["by_severity"]
    cards = "".join(
        "<div class='card'><div class='n'>%d</div><div class='l'>%s</div></div>"
        % (sev.get(k, 0), SEV_BADGE[k])
        for k in ("critical", "high", "medium", "low") if sev.get(k))
    return _TEMPLATE.format(
        now=_esc(summary["generated_utc"]),
        files=_esc(summary["scanned_files"]),
        total=_esc(summary["total_findings"]),
        cards=cards,
        rows="".join(rows) or
        "<tr><td colspan='4' class='muted'>No findings in the current rule "
        "set — not a guarantee of absence.</td></tr>",
        disclaimer=_esc(DISCLAIMER))


_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Code-Shield ZeroBaran — Security Audit</title>
<style>
:root{{--bg:#0b1020;--card:#141b2e;--fg:#e6ebf5;--mut:#8b96ad;--crit:#f87171;--high:#fb923c;--med:#facc15;--low:#60a5fa;--acc:#4ade80}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}}
.wrap{{max-width:1000px;margin:0 auto;padding:32px 20px}}
h1{{font-size:22px;margin:0}} .sub{{color:var(--mut);margin:4px 0 20px}}
.cards{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:22px}}
.card{{background:var(--card);border-radius:12px;padding:14px 20px;min-width:110px}}
.card .n{{font-size:28px;font-weight:700}} .card .l{{color:var(--mut);font-size:12px}}
table{{width:100%;border-collapse:collapse;background:var(--card);border-radius:12px;overflow:hidden}}
th,td{{text-align:left;padding:10px 12px;border-bottom:1px solid #1f2942;font-size:13px;vertical-align:top}}
th{{color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase}}
.t{{font-weight:600}} .f{{color:var(--mut);white-space:nowrap}} .m{{color:#cdd6e6}}
.fix{{color:var(--mut);font-size:12px;margin-top:4px}}
.pill{{padding:2px 8px;border-radius:20px;font-size:11px;font-weight:700;color:#0b1020}}
.pill.critical{{background:var(--crit)}} .pill.high{{background:var(--high)}}
.pill.medium{{background:var(--med)}} .pill.low{{background:var(--low)}} .pill.info{{background:var(--mut)}}
.muted{{color:var(--mut)}}
footer{{color:var(--mut);font-size:12px;margin-top:28px;border-top:1px solid #1f2942;padding-top:14px}}
</style></head><body><div class="wrap">
<h1>Code-Shield ZeroBaran — Security Audit</h1>
<div class="sub">Static analysis · {now} UTC · scanned {files} file(s) · {total} finding(s)</div>
<div class="cards">{cards}</div>
<table><thead><tr><th>Severity</th><th>Finding</th><th>Location</th><th>Detail &amp; fix</th></tr></thead>
<tbody>{rows}</tbody></table>
<footer>{disclaimer}<br>
MIT © 2026 Baran Avisat — Aodı Akdıro Suite · baranavisat@gmail.com ·
WhatsApp +90 531 326 37 22</footer>
</div></body></html>
"""
