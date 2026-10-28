# Security & Responsible-Use Policy — Code-Shield ZeroBaran

Code-Shield ZeroBaran is a **defensive, static code-security auditor** for source
code **you own or are authorized to test**. It is built to be safe, honest, and
auditable. This document is the contract — every test in `tests/` pins these
bright lines.

## The bright line (enforced in code, not just prose)

Code-Shield **does** the following, always:

- **Static analysis only.** It reads and parses source files (regex + the Python
  `ast` module). It **never imports, execs, or runs** the code it scans
  (`test_scanner_never_execs_scanned_code` proves a side-effect file stays inert).
- **Detection, never exploitation.** A rule matches a pattern and produces a
  finding record. Code-Shield does not weaponize a finding, does not build a
  proof-of-concept exploit, and does not deliver a payload.
- **Redacts every secret it finds.** The moment a credential is detected it is
  masked (`••••REDACTED••••`) on **every** output path — console, Markdown, HTML,
  PR comment, Telegram (`redact.py`). A secret scanner must never leak a secret.
- **No push to `main`, no auto-merge.** Delivery is a report, a PR comment, or a
  **new** branch + PR that a **human** reviews and merges. The GitHub client
  refuses to target a protected branch as a destination and never force-pushes
  (`github_client.py`).
- **Honest severity.** Findings are **heuristic signals for a human**, not proof
  of a vulnerability. Every report says so. There is **no** "finds 100% of
  vulnerabilities", "zero false negatives", or "guaranteed secure" claim anywhere.

Code-Shield **never** does the following — these are out of scope **by design**:

- **No code execution of scanned input.** No `exec`, no dynamic import of the
  target, no network fetch of a scanned URL.
- **No exploitation / PoC generation.** It suggests a *safer coding pattern*,
  not an attack.
- **No secret exfiltration.** Detected secrets are masked; the tool never sends
  a raw credential to an AI, a report, or a notification.
- **No force-push / auto-merge.** A patch is always a proposal for human review.
- **No ambient proxies on token paths.** GitHub/Telegram/Groq/Gemini calls refuse
  system proxies and redact tokens from error strings.

## What you may scan

Only code you are **authorized** to audit:

- Your own repositories and code.
- Code your organization owns or has a written mandate to test.
- Open-source code, for your own review (do not auto-post findings to someone
  else's repo without permission).

Do **not** point Code-Shield at code you have no right to analyze, and do not use
its findings to attack a system. You are responsible for ensuring your use
complies with your organization's policy and applicable law. This tool is a
**static reviewer** — that is the whole scope.

## What it stores / sends

- Locally: nothing by default. Reports are written only where you ask
  (`report --out`). They contain finding metadata and redacted snippets.
- Remotely (only when YOU configure a credential):
  - `comment`/`patch` post to the repo you name, using `GITHUB_TOKEN`.
  - `notify` sends a redacted alert using `TELEGRAM_TOKEN`.
  - The AI remediation layer (`--ai groq|gemini`) sends the **rule id, title,
    and a redacted snippet** to restate a safer pattern. No raw secret, no file
    contents beyond the redacted snippet.

## Reporting a vulnerability

Email **baranavisat@gmail.com** with the subject `[Code-Shield] security`.
Include reproduction steps. You will get an acknowledgment within 72 hours.
Please do **not** file exploitable issues in the public tracker.

## Scope of this policy

This policy is about the software's behavior. It is **not** legal advice. If you
are unsure whether you are authorized to scan a codebase, do not scan it.

---

MIT © 2026 Baran Avisat — Aodı Akdıro Suite · baranavisat@gmail.com ·
WhatsApp +90 531 326 37 22
