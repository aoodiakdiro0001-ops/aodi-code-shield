# Code-Shield ZeroBaran — API Reference (v1.0.0)

Concise reference for the public surface of each module, plus the full CLI
table. Everything is **stdlib-only** (Python 3.8+), deterministic, and offline
unless a credential for a specific delivery path is configured.

Bright lines that apply to **every** API below (see [../SECURITY.md](../SECURITY.md)):
static-only (no execution of scanned code), detection never exploitation,
secrets redacted on every output, no push to `main`, no auto-merge.

---

## `code_shield.redact` — secret masking

| Symbol | Signature | Description |
|---|---|---|
| `MASK` | `str = "••••REDACTED••••"` | The non-reversible mask constant used everywhere. |
| `mask(value)` | `mask(value) -> str` | Mask one secret; keeps first-4/last-4 **only** when ≥12 chars, otherwise fully masks. |
| `redact(text, extra_secrets=None)` | `redact(text, extra_secrets=iterable) -> str` | Replace known secrets with their masks, then run a generic credential-shape sweep (AWS, GitHub, Slack, Stripe, Google, OpenAI-style, Telegram, Bearer/JWT, secret-ish assignments). Idempotent and crash-safe; `None` → `""`. |
| `looks_like_secret(token)` | `looks_like_secret(token) -> bool` | Heuristic check: does a bare token look like a credential? (≥8 chars + pattern match) |

`_generic_sweep(s)` is internal; the pattern table `_GENERIC` drives both
`redact()` and `looks_like_secret()`.

## `code_shield.rules` — rule registry

| Symbol | Signature | Description |
|---|---|---|
| `SEVERITIES` | `("critical","high","medium","low","info")` | Valid severity ladder (validated in `Rule.__init__`). |
| `Rule` | `Rule(id, title, severity, category, message, remediation, pattern=None, languages=None, flags=re.I)` | Declarative detection rule; `pattern` is compiled to a regex. `category` ∈ secret/injection/crypto/config/deser/path/ssrf/other. |
| `Rule` attrs | `.id .title .severity .category .message .remediation .pattern .languages` | Read-only slots. |
| `REGEX_RULES` | `list[Rule]` | The built-in rule set (secrets, SQL/command injection, eval/exec, `new Function`, MD5/SHA-1/DES/RC4, pickle/yaml/marshal, TLS-off, debug, CORS, 0o777, path join, SSRF-ish). |
| `EXT_LANG` | `dict` | File extension → language tag (`.py`→python, `.js/.ts/...`→javascript). |
| `rules_for(lang)` | `rules_for(lang) -> list[Rule]` | Regex rules whose language list includes `lang` or `"generic"`. |

Rules are detection-only: they never execute, download, or exploit anything.

## `code_shield.scanner` — the scanner

| Symbol | Signature | Description |
|---|---|---|
| `Finding` | `Finding(rule_id, title, severity, category, file, line, message, remediation, snippet)` | One finding record; `snippet` is already redacted by the scanner. |
| `Finding.as_dict()` | `-> dict` | JSON-ready representation of the finding. |
| `scan_text(text, path, lang, only_rule=None)` | `-> list[Finding]` | Line-by-line regex pass over in-memory text (comments skipped except in credential-like files). |
| `scan_python_ast(text, path)` | `-> list[Finding]` | Python-only `ast` pass (never executes): flags `eval`/`exec`/`compile` calls and `os.system`/`subprocess.*` with `shell=True`. |
| `scan_file(path, relpath=None, only_rule=None, allow_secret_file=False)` | `-> list[Finding]` | Scan one file (regex + AST for Python); adds a `CS-SECRET-FILE` finding for credential-like filenames (`.env`, `credentials`, `id_rsa`, …) unless `allow_secret_file=True` (which suppresses only the banner — secret values are still found + redacted). |
| `iter_files(root, include_tests=False)` | `-> iterator[path]` | Yield scannable text files; skips `.git`, `node_modules`, venvs, `dist`/`build`/`vendor`, dot-dirs, and (by default) test dirs. |
| `scan_path(root, include_tests=False, only_rule=None, cfg=None)` | `-> (list[Finding], int)` | Scan a file or directory; returns findings sorted by severity + the number of files scanned. `cfg` (from `config.load_config`) can narrow scope via `ignore_rules` / `ignore_paths` / `allow_secrets_in` / `include_tests`. |
| `summarize(findings)` | `-> dict` | `{total, by_severity, by_category}` counts. |

Constants: `MAX_FILE_BYTES = 1 MiB` (per-file cap), `SKIP_DIRS`, `TEXT_EXTS`,
`SECRET_FILENAMES`, `SEV_ORDER`.

## `code_shield.config` — optional scan config (scope-narrowing only)

| Symbol | Signature | Description |
|---|---|---|
| `load_config(root)` | `-> (dict, path_or_None, warning_or_None)` | Find + parse `.codeshield.json`/`.yml` at `root`. Never raises: a malformed/unreadable config returns defaults + a warning. YAML is read only if PyYAML is already installed. |
| `path_is_ignored(relpath, ignore_paths)` | `-> bool` | Case-insensitive substring match against `ignore_paths`. |
| `secret_file_allowed(relpath, allow_secrets_in)` | `-> bool` | True for documented example-secret locations (suppresses the presence banner only). |

Default keys: `include_tests`, `fail_on`, `ignore_rules`, `ignore_paths`,
`allow_secrets_in`. By design the config can only **narrow** scope — it can
never disable redaction or make the scanner execute code.

## `code_shield.remediate` — remediation layer (AI optional)

| Symbol | Signature | Description |
|---|---|---|
| `OfflineRemediator()` | `.name = "offline"` | Deterministic, zero-network default; expands the rule's fix text with a concrete `safer:` snippet (`SNIPPETS` table). |
| `OfflineRemediator.remediate(finding)` | `-> str` | Fix text for a finding (never networks — the class has no URL at all). |
| `GroqRemediator(model=None, timeout=30.0, fallback=None)` | `.name = "groq"` | Groq free-tier chat model (default `llama-3.1-8b-instant`, override via `GROQ_MODEL`); requires `GROQ_API_KEY`, else uses `fallback`. |
| `GeminiRemediator(model=None, timeout=30.0, fallback=None)` | `.name = "gemini"` | Gemini free tier (default `gemini-1.5-flash`, override via `GEMINI_MODEL`); requires `GEMINI_API_KEY`, else uses `fallback`. |
| `*.remediate(finding)` | `-> str` | One short safer-pattern phrasing; on any provider error returns a **redacted** `"(AI offline) …"` string — the pipeline never depends on the AI. |
| `get_remediator(kind=None)` | `-> remediator` | Factory: `"groq"` → Groq, `"gemini"`/`"google"` → Gemini, anything else (default env `CODESHIELD_AI`) → `OfflineRemediator`. |

The AI is only ever asked to restate a safer coding pattern (never to exploit),
and only receives the rule id, title, and a redacted snippet.

## `code_shield.report` — renderers

| Symbol | Signature | Description |
|---|---|---|
| `DISCLAIMER` | `str` | The honest-severity disclaimer embedded in every report. |
| `build_summary(findings, scanned_files, remediated=None)` | `-> dict` | `{generated_utc, scanned_files, total_findings, by_severity, by_category, remediations, disclaimer}`. |
| `to_markdown(findings, summary)` | `-> str` | Human-readable Markdown audit (redacted; states that zero findings ≠ guaranteed absence). |
| `to_pr_comment(findings, summary, max_items=40)` | `-> str` | Concise GitHub PR comment; redacted and size-clamped, with an "…and N more" tail. |
| `to_html(findings, summary)` | `-> str` | Self-contained HTML page; all dynamic values HTML-escaped (no stored XSS) and redacted — safe to self-host. |

JSON output is assembled in the CLI (`summary` + `findings` + `remediations`),
not here.

## `code_shield.notify` — Telegram gateway

| Symbol | Signature | Description |
|---|---|---|
| `send(text, chat_id=None)` | `-> dict` | POST `sendMessage`; returns the Telegram JSON (`{ok: …}`) or `{ok: False, err}` — fails closed if `TELEGRAM_TOKEN` unset. Message is redacted and capped at 4096 chars. |
| `build_alert(findings, summary, max_items=8)` | `-> str` | Compact redacted alert text: totals, severity counts, top findings, "+N more". |

Hardening: opener refuses ambient system proxies, redirects are blocked,
reads capped at 1 MiB, timeout via `CODESHIELD_TG_TIMEOUT` (clamped 1–120 s,
default 30). Reads `TELEGRAM_TOKEN` and `TELEGRAM_CHAT_ID` from the
environment.

## `code_shield.github_client` — GitHub delivery (stdlib-only)

| Symbol | Signature | Description |
|---|---|---|
| `GitHubError` | `Exception` | Raised on any API/auth failure; message is token-redacted (≤200 chars). |
| `GitHub(token=None, repo=None, timeout=30.0)` | client | Token/repo default from `GITHUB_TOKEN` / `GITHUB_REPO` (`owner/name`). Refuses ambient proxies; never follows redirects. |
| `GitHub.comment_on_pr(number, body)` | `-> True` | POST an audit comment on a PR (additive only; body redacted, ≤65535 chars). Raises `GitHubError` before any network call if no token. |
| `GitHub.create_patch_branch(base_branch, new_branch, message, files)` | `-> str` (PR URL) | Create `new_branch` off `base_branch`, commit `files` (`{rel_path: content}`), and open a PR. **Refuses `main`/`master` as destination** (`PROTECTED_BRANCHES`), fast-forward only — never force-pushes, never merges; the PR body asks a human to review. |

All outbound requests send `Authorization: Bearer <token>` with the
`2022-11-28` API version header; token values are stripped from every error
path.

## `code_shield.cli` — command-line interface

Global flag (before the subcommand): `--ai offline|groq|gemini` (default env
`CODESHIELD_AI`, else `offline`).

| Command | Purpose | Network | Exit code |
|---|---|---|---|
| `scan <path>` | Static-scan a file/dir; print findings + summary (+ optional JSON) | never | `1` if `--fail-on` threshold met, else `0` |
| `report <path>` | Scan and write a Markdown / HTML / JSON report | never | `0` |
| `comment <path>` | Scan + post a redacted PR comment | GitHub API | `0` (raises on auth error) |
| `patch <path>` | Scan + open a new branch + PR containing `CODESHIELD_AUDIT.md` | GitHub API | `0`; prints the PR URL |
| `notify <path>` | Scan + send a redacted Telegram alert | Telegram API | `0` if sent, else `1` |
| `doctor` | Print which optional credentials/backends are configured | never | `0` |

Flags per command:

| Command | Flag | Meaning |
|---|---|---|
| all scan-based | `--include-tests` | Also scan `tests/`/`test/`/`__tests__/` dirs (skipped by default) |
| all scan-based | `--json` | Print the full summary+findings JSON to stdout (after the console report) |
| `scan` | `--fail-on <severity>` | Exit `1` if any finding is at/above `critical`/`high`/`medium`/`low`/`info` |
| `report` | `--out <file>` **(required)** | Output path; format chosen by extension: `.html`, `.json`, anything else → Markdown |
| `comment` | `--pr <int>` **(required)** | PR number to comment on |
| `comment` / `patch` | `--repo owner/name` | Target repo (default env `GITHUB_REPO`) |
| `patch` | `--base <branch>` | Base branch for the PR (default `main`) |
| `patch` | `--branch <name>` | Name for the new branch (default `codeshield/audit-<epoch>`) |

Environment variables read across the package:

| Variable | Module | Purpose |
|---|---|---|
| `CODESHIELD_AI` | remediate | Default AI backend (`offline`/`groq`/`gemini`) |
| `GROQ_API_KEY`, `GROQ_MODEL` | remediate | Groq key + model override |
| `GEMINI_API_KEY`, `GEMINI_MODEL` | remediate | Gemini key + model override |
| `TELEGRAM_TOKEN`, `TELEGRAM_CHAT_ID` | notify | Telegram bot token + destination chat |
| `CODESHIELD_TG_TIMEOUT` | notify | Send timeout in seconds (1–120, default 30) |
| `GITHUB_TOKEN`, `GITHUB_REPO` | github_client, cli | API token and `owner/name` for `comment`/`patch` |

Note: in v1.0.0 the CLI does not yet load a `.codeshield` config file; see
[DEPLOY.md §6](DEPLOY.md) for the documented schema and current workarounds.

---

MIT © 2026 Baran Avisat — Aodı Akdıro Suite · baranavisat@gmail.com ·
WhatsApp +90 531 326 37 22 · github.com/aoodiakdiro0001-ops
