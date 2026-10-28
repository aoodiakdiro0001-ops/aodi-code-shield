# 🛡️ Code-Shield ZeroBaran

**An autonomous, defensive code-security auditor that runs 100% on free tiers — it statically scans YOUR repos for secrets and common vulnerability patterns, then proposes a fix.**

> **Compliance first:** static analysis only (it **never executes** the code it scans), **detection — never exploitation**, secrets **REDACTED on every output path**, **no push to `main` / no auto-merge** (a human reviews every PR), and **honest heuristic severity** (findings may include false positives). See [SECURITY.md](SECURITY.md) for the full contract.

---

## What it does

Code-Shield walks your source tree and applies two detection passes:

1. **Regex rules** — fast, language-agnostic-ish, one rule per line of code (`rules.py`)
2. **Python `ast` pass** — structural checks regex can miss, e.g. `shell=True` fed by a formatted string (`scanner.py`). The AST is **parsed**, never executed.

What it looks for:

| Category | Examples |
|---|---|
| 🔑 **Hardcoded secrets** | AWS access keys (`AKIA…`), GitHub tokens (`ghp_…`, `github_pat_…`), generic `password = "…"` assignments — **always REDACTED** in reports/comments/alerts |
| 💉 **SQL / command injection** | `execute(f"…")`, `execute("…" + x)`, `.format()` into SQL, `os.system`/`subprocess` with interpolation, `shell=True` |
| ⚡ **Dynamic code** | `eval()` / `exec()` / `compile()`, JavaScript `new Function()` |
| 🔓 **Weak crypto** | MD5, SHA-1, DES/3DES/RC4/Blowfish, `random.*` / `Math.random()` where a CSPRNG belongs |
| 📦 **Unsafe deserialization** | `pickle.loads`, `yaml.load` without `SafeLoader`, `marshal.loads` |
| 🌐 **Insecure config / transport** | `verify=False` (TLS off), wildcard CORS, `DEBUG = True`, `chmod 777` |
| 🗂️ **Path traversal / SSRF risk** | `open(os.path.join(…))` with a dynamic segment, `requests.get(<variable>)` |

Then, for each finding, it **proposes a remediation**:

- **Deterministic offline engine** (default, zero network, stdlib-only): expands the human-written fix text from the rule with a concrete "safer:" code snippet.
- **Optional free-AI phrasing** — `--ai groq` (Groq free tier) or `--ai gemini` (Gemini free tier) merely *rephrases* the safer pattern. The AI is never asked to exploit anything; if it errors or is unconfigured, the offline text is used automatically.

Delivery paths (all redacted):

- 📄 **Reports** — Markdown / self-contained HTML / JSON
- 💬 **GitHub PR comment** — a concise audit comment on the PR
- 🌿 **Patch PR branch** — opens a NEW branch + PR containing the audit report; a human must review and merge. It never pushes to `main`/`master` and never force-pushes.
- 📲 **Telegram alert** — a compact redacted summary

## Architecture

```
 push / PR (GitHub Actions, free minutes on public repos)
        │
        ▼
 ┌──────────────────────┐   reads files, NEVER executes them
 │  static scanner      │──►  regex rules (rules.py)
 │  (scanner.py)        │──►  python ast pass (eval/exec, shell=True)
 └──────────┬───────────┘
            │ findings
            ▼
 ┌──────────────────────┐
 │  redaction           │  every snippet/secret masked (redact.py)
 │  (mandatory)         │  ••••REDACTED••••
 └──────────┬───────────┘
            ▼
 ┌──────────────────────┐
 │  remediation         │  offline deterministic (default)
 │  (remediate.py)      │  OR optional Groq / Gemini free tier
 └──────────┬───────────┘
            ▼
   report artifact (HTML/JSON) ──► GitHub Actions artifact
   PR comment        (comment) ──► github_client.py  (additive only)
   patch PR branch   (patch)   ──► NEW branch + PR, human merges
   Telegram alert    (notify)  ──► redacted, size-clamped
```

## Quickstart (offline, stdlib-only, no pip install)

Requirements: Python 3.8+ — **zero dependencies**, no `pip install`.

```bash
# scan a directory (or a single file)
python -m code_shield.cli scan .

# scan the deliberately-vulnerable example
python -m code_shield.cli scan examples/vuln

# write reports: .md / .html / .json by extension
python -m code_shield.cli report examples/vuln --out r.html
python -m code_shield.cli report examples/vuln --out r.json

# environment self-check (keys, token, repo)
python -m code_shield.cli doctor
```

Run the offline test suite (no network):

```bash
python -m unittest discover -s tests -v
```

`scan` and `report` **never touch the network**. `comment` / `patch` / `notify` only reach out when you have configured their credentials.

## The free stack — $0 to run

| Piece | Tool | Cost |
|---|---|---|
| CI runner | GitHub Actions (public repos: unlimited minutes) | $0 |
| Report hosting | Actions artifacts — HTML report downloadable per run (or GitHub Pages if you prefer) | $0 |
| AI remediation phrasing | Groq free tier / Gemini free tier — **optional**; offline fallback otherwise | $0 |
| Alerts | Telegram Bot API | $0 |
| Engine | Python stdlib only — no pip, no services | $0 |

See [docs/DEPLOY.md](docs/DEPLOY.md) for the step-by-step GitHub Actions setup and [docs/API.md](docs/API.md) for the full API/CLI reference.

## ⚠️ Responsible use & compliance

This section is the point of the project. Please read it before using Code-Shield.

- **STATIC only.** The scanner reads and parses files (regex + Python `ast`). It **never imports, execs, or runs** the code it scans. A test (`test_scanner_never_execs_scanned_code`) proves a file with side effects stays inert when scanned.
- **Detection, never exploitation.** A rule matches a pattern and produces a finding record. Code-Shield does **not** weaponize findings, does **not** generate proof-of-concept exploits, and does **not** deliver payloads.
- **Secrets are REDACTED on every path.** The moment a credential is detected it is masked in the console, Markdown, HTML, JSON, PR comment, Telegram alert, and AI prompt. A secret scanner must never leak a secret.
- **No push to `main`, no auto-merge.** The GitHub client refuses to target `main`/`master` as a branch destination and never force-opens a merge. Delivery is a report, a comment, or a **new** branch + PR — **a human reviews and merges**.
- **Honest severity.** Findings are **heuristic signals for a human reviewer**, not proof of a vulnerability. Detection is regular-expression and AST-pattern based, so **false positives are possible** (and so are misses). There is **no** "finds 100% of vulnerabilities", "zero false negatives", or "guaranteed secure" claim — anywhere, in code or docs. Every report carries this disclaimer.
- **Scan only what you own or are authorized to audit.** Do not point this at repositories you have no right to analyze, and never use findings to attack a system.

The full bright-line contract, what it sends where, and how to report a vulnerability in Code-Shield itself: **[SECURITY.md](SECURITY.md)**.

## Honest limits

- It is a **heuristic** tool: regex + a small AST pass. It will not catch logic bugs, business-logic flaws, or novel vulnerability classes, and it can flag safe code (e.g. `eval` on a trusted constant).
- **False positives are possible** by design; treat findings as signals to investigate, not verdicts.
- It is **not a substitute** for a human security review or a full SAST suite (Semgrep, CodeQL, Bandit, etc.). It complements them, cheaply.
- The **AI remediation layer is optional** and only rephrases safer patterns; the offline engine works with zero configuration and zero network.
- A clean scan means "no rule in the current set matched" — **not** proof that the code is secure.

## Project layout

```
aodi-code-shield/
├── code_shield/
│   ├── __init__.py        # package docstring + bright lines
│   ├── redact.py          # secret masking (crown rule)
│   ├── rules.py           # declarative regex rule registry
│   ├── scanner.py         # file walker + regex pass + python ast pass
│   ├── remediate.py       # offline / Groq / Gemini remediation
│   ├── report.py          # Markdown / HTML / JSON / PR-comment renderers
│   ├── notify.py          # Telegram gateway (hardened)
│   ├── github_client.py   # PR comment + patch-branch PR (no main, no merge)
│   └── cli.py             # scan / report / comment / patch / notify / doctor
├── .github/workflows/
│   ├── security-audit.yml # the reusable audit workflow
│   └── ci.yml             # offline unit tests on every push/PR
├── examples/
│   ├── vuln/app.py        # deliberately vulnerable sample to scan
│   └── codeshield.config.json
├── tests/test_shield.py   # detection + compliance contracts
├── SECURITY.md            # responsible-use policy
└── LICENSE                # MIT
```

---

# 🇸🇦 القسم العربي

## ما هو Code-Shield ZeroBaran؟

**مُدقِّق أمني دفاعي مستقل للكود، يعمل بالكامل على أدوات مجانية — يفحص مستودعاتك ثابتياً بحثاً عن الأسرار المدمجة وأنماط الثغرات الشائعة، ثم يقترح الحل.**

> **التزامام أولاً:** تحليل **ثابت فقط** (لا يُنفّذ الكود المفحوص أبداً)، **اكتشاف وليس استغلالاً**، **إخفاء الأسرار في كل مسار إخراج**، **لا دفع مباشر إلى `main` ولا دمج تلقائي** (إنسان يراجع كل Pull Request)، و**تصنيف صادق قائم على الاستدلال** (قد تشمل النتائج إيجابيات خاطئة). راجع [SECURITY.md](SECURITY.md).

## ماذا يفعل؟

يتجول الأداة في شجرة الكود ويطبّق مرحلتين:

1. **قواعد Regex** — سريعة، سطر واحد لكل قاعدة.
2. **مرحلة `ast` بلغة بايثون** — يلتقط أنماطاً بنيوية يفوتها الـ regex مثل `shell=True` مع نص مُنسّق. الـ AST يُ **تُحلَّل فقط، لا يُنفَّذ**.

**ما الذي يبحث عنه؟**

- **أسرار مدمجة** (مفاتيح AWS، رموز GitHub، كلمات مرور) — تُخفى دائماً (`••••REDACTED••••`) في كل التقارير والتعليقات والتنبيهات.
- **حقن SQL / أوامر** — `execute(f"…")`، بناء الأوامر بمتغيرات، `shell=True`.
- **كود ديناميكي** — `eval()` / `exec()` / `compile()` و `new Function`.
- **تشفير ضعيف** — MD5، SHA-1، DES/3DES/RC4، و`random.*` في المواضع التي تتطلب مولّداً عشوائياً آمناً.
- **فكوّات غير آمنة** — `pickle.loads`، `yaml.load` بدون `SafeLoader`، `marshal.loads`.
- **إعدادات غير آمنة** — تعطيل التحقق من TLS (`verify=False`)، CORS عام، وضع DEBUG، صلاحيات `777`.
- **مخاطر اجتياز المسارات / SSRF** — فتح ملفات بمسار يتضمن متغيراً، وطلبات HTTP لعنوان مبني على متغير.

بعد ذلك يقترح **الإصلاح** لكل نتيجة: محرك محلي حتمي (بدون إنترنت) افتراضياً، أو صياغة اختيارية عبر الذكاء الاصطناعي المجاني (Groq / Gemini) — **لا يُطلب من الذكاء الاصطناعي استغلال أي شيء**، وإن فشل أو لم يُعدَّ يرجع تلقائياً للنص المحلي.

**قنوات الإخراج** (كلها مُخفّاة): تقارير Markdown/HTML/JSON، تعليق على Pull Request، فرع إصلاح جديد مع PR **يجب أن يراجعه ويدمجه إنسان**، وتنبيه Telegram.

## المتطلبات والتشغيل السريع

- بايثون 3.8+ فقط — **بدون أي مكتبات خارجية** (`stdlib` فقط)، لا حاجة لـ `pip install`.

```bash
python -m code_shield.cli scan .
python -m code_shield.cli scan examples/vuln
python -m code_shield.cli report examples/vuln --out r.html
python -m code_shield.cli doctor
```

أوامر `scan` و`report` **لا تلمس الشبكة إطلاقاً**.

## المكدس المجاني ($0)

| الجزء | الأداة | التكلفة |
|---|---|---|
| بيئة التشغيل | GitHub Actions (مستودعات عامة: دقائق غير محدودة) | $0 |
| استضافة التقارير | ملفات مرفقة بالبناء (Artifacts) | $0 |
| صياغة الإصلاح بالذكاء الاصطناعي | Groq / Gemini — اختياري، مع بديل محلي | $0 |
| التنبيهات | Telegram Bot API | $0 |
| المحرك | بايثون المعياري فقط | $0 |

إرشادات النشر خطوة بخطوة: [docs/DEPLOY.md](docs/DEPLOY.md) · مرجع الواجهة: [docs/API.md](docs/API.md)

## ⚠️ الاستخدام المسؤول والامتثال

- **تحليل ثابت فقط** — لا يستورد ولا يُنفّذ الكود المفحوص أبداً (مثبت اختبارياً).
- **اكتشاف وليس استغلالاً** — لا يُنشئ إثباتات استغلال (PoC) ولا يرسل أي حمولة.
- **إخفاء الأسرار إلزامي** في كل مسار إخراج: وحدة التحكم، التقارير، تعليق PR، تنبيه Telegram، وحتى موجّه الذكاء الاصطناعي.
- **لا دفع إلى `main` ولا دمج تلقائي** — الأداة ترفض استهداف الفروع المحمية، والإنسان هو من يراجع ويدمج.
- **صدق في التصنيف** — النتائج إشارات استدلالية قد تتضمن **إيجابيات خاطئة**؛ لا توجد أي ادعاءات بـ«اكتشاف 100%» أو «صفر نتائج خاطئة» أو «كود مضمون آمن». كل تقرير يحمل هذا التنويه.
- **افحص ما تملكه فقط أو ما تملك تصريحاً قانونياً لفحصه.**

## حدود صادقة

الأداة استدلالية (regex + AST محدود)، وقد تفوّت ثغرات منطقية أو جديدة، وقد تُعلّم كوداً آمناً. إنها ** ليست بديلاً** عن مراجعة أمنية بشرية أو حزمة تحليل أمني كاملة (Semgrep، CodeQL، Bandit…) بل تكمّلها بتكلفة صفر. الطبقة الاصطناعية اختيارية. الفحص النظيف يعني «لا قاعدة مطابقة» — وليس ضماناً للأمان.

---

MIT © 2026 Baran Avisat — Aodı Akdıro Suite · [baranavisat@gmail.com](mailto:baranavisat@gmail.com) · WhatsApp +90 531 326 37 22 · [github.com/aoodiakdiro0001-ops](https://github.com/aoodiakdiro0001-ops)
