# Deploying Code-Shield ZeroBaran — step-by-step

Everything here runs on **free tiers**: GitHub Actions minutes (unlimited on
public repos), Actions artifacts for reports, optional Groq/Gemini free-tier AI,
and the free Telegram Bot API. Total cost: **$0**.

Reminder of the bright lines (full contract in [../SECURITY.md](../SECURITY.md)):
static-only scanning, detection never exploitation, secrets redacted on every
output path, no push to `main`, no auto-merge — a human reviews every PR.

---

## 1. Add the workflow to your repo

1. Copy `.github/workflows/security-audit.yml` from this project into **your**
   repository at the same path:

   ```
   your-repo/
   └── .github/
       └── workflows/
           └── security-audit.yml
   ```

2. Make sure the `code_shield/` package is present in your repo root (or adjust
   the workflow's checkout so `python -m code_shield.cli` resolves). The engine
   is stdlib-only — no `pip install` step is needed.

3. Commit the workflow file to a branch and open a PR (or push to `main`).
   The workflow triggers on:
   - `pull_request` (opened / synchronize / reopened) — scans and posts the PR comment
   - `push` (any branch) — scans and writes report artifacts
   - `workflow_dispatch` — run it on demand from the Actions tab

4. Check the first run under the **Actions** tab. The first step is `doctor`,
   which prints which optional credentials are set (it never fails the job —
   it runs with `|| true`).

The workflow's permissions are deliberately minimal:

```yaml
permissions:
  contents: read          # scan only; no code push
  pull-requests: write    # only to post the audit comment
```

## 2. How the PR-comment flow works

On every `pull_request` event the workflow runs:

1. `scan . --fail-on critical --include-tests` — fails the job **only** on
   CRITICAL findings (committed credentials).
2. `report . --out codeshield-report.html` and `.json` — written **even if the
   scan step failed** (`if: always()`), then uploaded as the
   `codeshield-report` artifact.
3. A small inline Python step calls the CLI's `comment` command with the PR
   number from `github.event.pull_request.number`:

   ```python
   cli.main(["comment", ".", "--pr", str(pr),
             "--repo", os.environ["GITHUB_REPO"], "--include-tests"])
   ```

   `comment` re-scans locally, renders a concise redacted summary
   (`report.to_pr_comment`, capped at 40 items) and POSTs it via the GitHub API
   using the workflow's built-in `GITHUB_TOKEN` (`secrets.GITHUB_TOKEN`) and the
   repo from `GITHUB_REPO` (`github.repository`).

Notes:

- The comment is **additive only** — the tool never edits code, never pushes,
  and never merges.
- Every secret the scan finds is masked before the comment body is built.
- `GITHUB_TOKEN` and `GITHUB_REPO` are auto-provided by Actions; you normally do
  **not** need to create them as repo secrets. (For local `comment`/`patch` use,
  export them yourself — see `doctor`.)

## 3. Setting the optional secrets

Repo → **Settings → Secrets and variables → Actions → New repository secret**.
All of these are optional; the tool degrades gracefully without them.

| Secret | Used by | If unset |
|---|---|---|
| `TELEGRAM_TOKEN` | `notify` — Telegram bot token from @BotFather | `notify` fails closed with `TELEGRAM_TOKEN not set` |
| `TELEGRAM_CHAT_ID` | `notify` — destination chat id | alert has no target; `notify` won't send |
| `GROQ_API_KEY` | `--ai groq` remediation phrasing | automatic fallback to offline remediation |
| `GEMINI_API_KEY` | `--ai gemini` remediation phrasing | automatic fallback to offline remediation |

The workflow already maps them into the job's `env`. To select an AI backend,
set the `CODESHIELD_AI` environment variable (or pass `--ai groq|gemini`
globally on the command line, before the subcommand). Optional model overrides:
`GROQ_MODEL` (default `llama-3.1-8b-instant`) and `GEMINI_MODEL` (default
`gemini-1.5-flash`).

The AI layer only ever receives the **rule id, title, and a redacted snippet**,
and is only ever asked to restate a safer coding pattern — never to exploit.

## 4. Blocking only leaked credentials: `--fail-on critical`

The workflow's scan step is:

```bash
python -m code_shield.cli scan . --fail-on critical --include-tests
```

`--fail-on <severity>` exits `1` if any finding is **at or above** the given
severity. We deliberately use `critical`, which in the current rule set means
**hardcoded credentials** (AWS access keys, GitHub tokens):

- ✅ A committed AWS key **fails the PR** — a real, unambiguous leak.
- ✅ Heuristic findings (`high`/`medium`/`low` — possible SQL injection, MD5
  use, etc.) are **reported but do not block** — so a false positive can never
  break your CI.

If you want a stricter gate later, switch to `--fail-on high`, but expect that
pattern-based matches can be false positives; review before making it required
in branch protection.

## 5. The artifacts

Every run (including failed scans, thanks to `if: always()`) uploads a
`codeshield-report` artifact containing:

| File | Format | Contents |
|---|---|---|
| `codeshield-report.html` | self-contained HTML | styled, escaped, redacted audit page — safe to self-host (e.g. publish via GitHub Pages if you want a public URL) |
| `codeshield-report.json` | JSON | `summary` + `findings` (+ `remediations` when produced via `report`) — machine-readable for dashboards |

Download: repo → **Actions** → the run → **Artifacts** section at the bottom.

## 6. The optional `.codeshield` config

Place `.codeshield.json` (or `.codeshield.yml` if PyYAML is installed) at the
root of the path you scan. `examples/codeshield.config.json` in this repo is a
working example:

```json
{
  "include_tests": false,
  "fail_on": "critical",
  "ignore_rules": ["CS-CONF-DEBUG"],
  "ignore_paths": ["examples/vuln/", "fixtures/", "third_party/"],
  "allow_secrets_in": [".env.example", "tests/fixtures/"]
}
```

Field meanings:

| Key | Purpose |
|---|---|
| `ignore_rules` | rule ids (e.g. `CS-CONF-DEBUG`) to suppress |
| `ignore_paths` | path substrings to exclude from the scan (vendored code, fixtures, demo dirs) |
| `allow_secrets_in` | files where a "credential file present" banner is expected (documented examples, test fixtures). **Values are still REDACTED** in every report — this only suppresses the presence banner |
| `include_tests` / `fail_on` | same meaning as the CLI flags (`fail_on` is used when `--fail-on` isn't passed) |

The loader is **live** (`code_shield/config.py`), stdlib-only, and crash-safe:
a malformed or unreadable config is ignored with a warning and the scan falls
back to defaults. YAML is read only if PyYAML is already installed — otherwise
use `codeshield.json` (the engine itself never requires a dependency). By
design the config can only ever **narrow** scope: no key can make the scanner
execute code or bypass redaction. The scanner *also* always skips `.git`,
`node_modules`, `venv`, `dist`, `build`, `vendor`, cache dirs and (unless
`--include-tests`) test dirs, and caps files at 1 MiB.

## 7. Troubleshooting

**False positives** (e.g. a test fixture tripping `CS-SECRET-GENERIC`, `eval`
in a benchmark):
- Findings are heuristic signals — this is expected behavior, not a bug.
- Short term: note the rule id and file in the PR; the report/JSON gives you the
  exact `rule_id` + `file:line`.
- Reduce noise for a specific path by not scanning it (point `scan` at a
  subdirectory) or via `ignore_paths` / `ignore_rules` in `.codeshield.json`
  (see section 6).
- Prefer keeping `--fail-on critical` so only leaked credentials can block.

**Too noisy** (large first-run report):
- Run once on `main` to get a baseline artifact; triage from the JSON with
  `jq '.findings | group_by(.rule_id)'`.
- Drop `--include-tests` if fixture noise dominates (the workflow includes
  tests by default for coverage).
- Remember the PR comment is capped (40 items) and Telegram at 8 — the full
  detail is always in the artifacts.

**Comment not posting:**
- Run `python -m code_shield.cli doctor` in the workflow log — check
  `github_token` / `github_repo` are `set`.
- The step only runs `if: github.event_name == 'pull_request'` — pushes never
  comment, by design.
- The workflow needs `pull-requests: write`. In forked-repo PRs the built-in
  token is read-only — the comment step will fail; that is a GitHub permission
  limit, not the tool.
- `comment` re-fails (raises before any network call) if `GITHUB_TOKEN` is
  missing — errors are redacted, so tokens never appear in logs.

**Telegram alert not sending:**
- `TELEGRAM_TOKEN` must be set **and** `TELEGRAM_CHAT_ID` must point at your
  chat (message the bot once so it has a chat id).
- The opener refuses ambient system proxies and does not follow redirects — if
  you are behind a mandatory corporate proxy, the send will fail closed. That
  is intentional token-safety behavior.
- `CODESHIELD_TG_TIMEOUT` (seconds, clamped 1–120) tunes the timeout.

**AI not configured / “(AI offline)” in remediation text:**
- Not an error. Without `GROQ_API_KEY` / `GEMINI_API_KEY` the deterministic
  offline engine is used — same quality fix guidance, zero network.
- If you see `(AI offline) …` after configuring a key, the provider call
  errored (rate limit, bad key, network). The message is redacted and the
  pipeline continues. Check the key and `CODESHIELD_AI` selection, then re-run.

**Scan is failing the job on secrets:**
- That is the gate working: `--fail-on critical` means a committed credential.
  Rotate the credential first (treat it as compromised), remove it from the
  tree, add it to `.gitignore`, then re-run. The report shows the file:line —
  never the raw value.

---

## Local deployment (no CI at all)

```bash
python -m code_shield.cli doctor                    # what's configured?
python -m code_shield.cli scan . --fail-on critical # offline gate
python -m code_shield.cli report . --out audit.html # standalone report
python -m code_shield.cli notify .                  # needs TELEGRAM_* env vars
```

MIT © 2026 Baran Avisat — Aodı Akdıro Suite · baranavisat@gmail.com ·
WhatsApp +90 531 326 37 22
