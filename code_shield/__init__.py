"""Code-Shield ZeroBaran — an autonomous, defensive code-security auditor.

It statically scans source code YOU own for secrets and common vulnerability
patterns (SQL/command injection, eval/exec, weak crypto, unsafe deserialization,
path traversal, insecure config), then proposes a remediation — optionally
phrased by a free AI (Groq/Ollama), with a deterministic offline fallback.

Bright lines (enforced in code, pinned by tests — see SECURITY.md):
  * STATIC only: it parses and reads files; it NEVER executes the scanned code.
  * It never EXPLOITS a finding — detection + a proposed patch, nothing else.
  * Secrets it finds are REDACTED in every report/comment/notify path.
  * No auto-push to `main`: delivery is a report, a PR comment, or an opened
    PR branch that a human must merge.
  * Honest severity: heuristic detections may include false positives; there is
    no "finds 100% of vulnerabilities" claim anywhere.

MIT (c) 2026 Baran Avisat — Aodı Akdıro Suite
Support: baranavisat@gmail.com · WhatsApp +90 531 326 37 22
"""
__version__ = "1.0.0"
