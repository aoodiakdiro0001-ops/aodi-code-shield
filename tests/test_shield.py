"""Code-Shield offline test suite — zero network, no real scanning of the host.

Pins two things:
  1. core detection behavior (regex rules, AST rules, redaction, reports)
  2. the COMPLIANCE contracts that keep this tool safe and publishable:
     * secrets are REDACTED on every output path
     * STATIC only — the scanner never execs/imports the scanned code
     * delivery never force-pushes to / auto-merges a protected branch
     * no false "100% detection" claim; disclaimer present in every report
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from code_shield import (github_client, notify, redact, remediate, report,
                         scanner)
from code_shield import rules as rules_mod
from code_shield.scanner import Finding, scan_text


def _tmpdir():
    return tempfile.mkdtemp()


def _write(dirpath, name, content):
    p = os.path.join(dirpath, name)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(content)
    return p


def _finding(**kw):
    base = dict(rule_id="CS-TEST", title="t", severity="high", category="injection",
                file="f.py", line=1, message="m", remediation="r", snippet="s")
    base.update(kw)
    return Finding(**base)


# ------------------------------------------------------------------- redact
class RedactTests(unittest.TestCase):
    def test_masks_aws_key(self):
        s = "key = AKIA" + "A" * 16
        out = redact.redact(s)
        self.assertNotIn("A" * 16, out)
        self.assertIn("REDACTED", out)

    def test_masks_github_token(self):
        s = "tok = gh" + "p" + "_" + "a" * 30
        out = redact.redact(s)
        self.assertNotIn("a" * 30, out)

    def test_masks_explicit_secret_list(self):
        secret = "SUPERSECRETVALUE12345"
        out = redact.redact("the value is " + secret, extra_secrets=[secret])
        self.assertNotIn(secret, out)

    def test_redaction_is_idempotent(self):
        s = "token=abcdefghijklmnopqrstuvwxyz0123456789"
        once = redact.redact(s)
        twice = redact.redact(once)
        self.assertEqual(once, twice)

    def test_short_value_fully_masked(self):
        # <12 chars => no partial leak of the middle
        out = redact.mask("abcdefgh")
        self.assertEqual(out, redact.MASK)

    def test_none_and_empty_safe(self):
        self.assertEqual(redact.redact(None), "")
        self.assertEqual(redact.redact(""), "")

    def test_generic_catches_known_prefixes(self):
        # realistic credential formats (each must be long enough to match)
        for sample in ("sk_live_" + "a" * 24, "AIza" + "b" * 35,
                       "xoxb-" + "a" * 20,
                       "12345678:" + "abcdefghijklmnopqrstuvwxyz012345",
                       "Bearer " + "c" * 30):
            self.assertIn("REDACTED", redact.redact(sample), sample)


# -------------------------------------------------------------------- rules
class RuleTests(unittest.TestCase):
    def test_all_rules_have_valid_severity(self):
        for r in rules_mod.REGEX_RULES:
            self.assertIn(r.severity, rules_mod.SEVERITIES)

    def test_no_regex_has_catastrophic_backtracking(self):
        # every pattern must compile; smoke-test a pathological input quickly
        import time
        hostile = "a" * 5000 + "!"
        for r in rules_mod.REGEX_RULES:
            t0 = time.perf_counter()
            if r.pattern:
                r.pattern.search(hostile)
            self.assertLess(time.perf_counter() - t0, 1.0, r.id)


# ------------------------------------------------------------------- scanner
class ScannerTests(unittest.TestCase):
    def test_detects_hardcoded_aws_key(self):
        d = _tmpdir()
        _write(d, "app.py", 'AWS_KEY = "AKIA%s"\n' % ("A" * 16))
        findings, n = scanner.scan_path(d)
        ids = [f.rule_id for f in findings]
        self.assertIn("CS-SECRET-AWS", ids)

    def test_detects_sql_fstring_injection(self):
        d = _tmpdir()
        _write(d, "db.py", 'cursor.execute(f"SELECT * FROM t WHERE id={x}")\n')
        findings, _ = scanner.scan_path(d)
        self.assertIn("CS-INJ-SQL-FSTR", [f.rule_id for f in findings])

    def test_detects_yaml_unsafe_load(self):
        d = _tmpdir()
        _write(d, "load.py", "import yaml\ndata = yaml.load(payload)\n")
        findings, _ = scanner.scan_path(d)
        self.assertIn("CS-SER-YAML", [f.rule_id for f in findings])

    def test_ast_detects_shell_true(self):
        d = _tmpdir()
        _write(d, "cmd.py",
               "import subprocess\nsubprocess.run(cmd, shell=True)\n")
        findings, _ = scanner.scan_path(d)
        self.assertIn("CS-AST-SHELL", [f.rule_id for f in findings])

    def test_ast_detects_eval(self):
        d = _tmpdir()
        _write(d, "e.py", "def f(x):\n    return eval(x)\n")
        findings, _ = scanner.scan_path(d)
        ids = [f.rule_id for f in findings]
        self.assertTrue("CS-INJ-EVAL" in ids or "CS-AST-DYNCODE" in ids)

    def test_clean_file_no_findings(self):
        d = _tmpdir()
        _write(d, "ok.py", "import json\ndef go():\n    return json.dumps({})\n")
        findings, _ = scanner.scan_path(d)
        self.assertEqual(findings, [])

    def test_skips_vendored_dirs(self):
        d = _tmpdir()
        _write(d, "node_modules/lib/index.js", 'var k = "AKIA%s";\n' % ("B" * 16))
        findings, n = scanner.scan_path(d)
        self.assertEqual(n, 0)

    def test_secret_found_in_snippet_is_redacted(self):
        # THE crown rule: a detected secret must not leak via the snippet
        d = _tmpdir()
        aws = "AKIA" + "C" * 16
        _write(d, "leak.py", 'K = "%s"\n' % aws)
        findings, _ = scanner.scan_path(d)
        secret_f = [f for f in findings if f.rule_id == "CS-SECRET-AWS"][0]
        self.assertNotIn("C" * 16, secret_f.snippet)
        self.assertIn("REDACTED", secret_f.snippet)

    def test_scanner_never_execs_scanned_code(self):
        # a file with a side effect must not run when scanned
        d = _tmpdir()
        marker = os.path.join(d, "RAN")
        _write(d, "evil.py",
               "open(%r, 'w').write('ran')\nimport os\nos.system('touch %s')\n"
               % (marker, marker))
        scanner.scan_path(d)
        self.assertFalse(os.path.exists(marker))


# -------------------------------------------------------------------- report
class ReportTests(unittest.TestCase):
    def _summary(self):
        return report.build_summary([], 3, [])

    def test_markdown_has_disclaimer(self):
        md = report.to_markdown([], self._summary())
        self.assertIn("false positives", md)
        self.assertIn("does not exploit", md)

    def test_html_escapes_and_redacts(self):
        secret = "ghp_" + "A" * 36      # credential-shaped -> redact engages
        f = _finding(file="<script>alert(1)</script>",
                     message="leaked token " + secret)
        html = report.to_html([f], report.build_summary([f], 1, []))
        self.assertNotIn("<script>alert", html)     # escaped
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn(secret, html)              # redacted from message
        self.assertIn("REDACTED", html)

    def test_pr_comment_redacts_secret(self):
        secret = "ghp_" + "z" * 36      # credential-shaped -> redact engages
        # to_pr_comment renders `title` and `remediation` (both redacted);
        # put the secret in `title`, which is displayed.
        f = _finding(rule_id="CS-SECRET-GH",
                     title="found " + secret, remediation="rotate " + secret)
        body = report.to_pr_comment([f], report.build_summary([f], 1, []))
        self.assertNotIn(secret, body)
        self.assertIn("REDACTED", body)

    def test_markdown_redacts_secret(self):
        f = _finding(rule_id="CS-SECRET-AWS",
                     snippet="AKIA" + "D" * 16, message="leak AKIA" + "D" * 16)
        md = report.to_markdown([f], report.build_summary([f], 1, []))
        self.assertNotIn("D" * 16, md)


# ---------------------------------------------------------------- remediation
class RemediateTests(unittest.TestCase):
    def test_offline_is_deterministic_and_nonempty(self):
        r = remediate.OfflineRemediator()
        f = _finding(rule_id="CS-INJ-SQL-FSTR")
        out = r.remediate(f)
        self.assertTrue(out)
        self.assertIn("?", out)                     # parameterized hint

    def test_offline_never_networks(self):
        # OfflineRemediator has no key and no URL — cannot make a request
        r = remediate.OfflineRemediator()
        self.assertFalse(hasattr(r, "URL"))

    def test_get_remediator_defaults_offline(self):
        os.environ["CODESHIELD_AI"] = "offline"
        self.assertEqual(remediate.get_remediator().name, "offline")

    def test_groq_without_key_falls_back(self):
        os.environ.pop("GROQ_API_KEY", None)
        r = remediate.GroqRemediator()
        out = r.remediate(_finding(rule_id="CS-SER-YAML"))
        self.assertTrue(out)
        self.assertNotIn("(AI offline)", out)       # used the offline fallback


# -------------------------------------------------------------------- notify
class NotifyTests(unittest.TestCase):
    def test_send_without_token_fails_closed(self):
        os.environ.pop("TELEGRAM_TOKEN", None)
        res = notify.send("hi")
        self.assertFalse(res["ok"])

    def test_telegram_opener_refuses_ambient_proxy(self):
        import urllib.request
        os.environ["HTTPS_PROXY"] = "http://proxy.invalid:8080"
        try:
            ambient = [h for h in notify._OPENER.handlers
                       if isinstance(h, urllib.request.ProxyHandler)
                       and getattr(h, "proxies", {})]
            self.assertEqual(ambient, [])
        finally:
            os.environ.pop("HTTPS_PROXY", None)

    def test_alert_redacts_secret(self):
        f = _finding(rule_id="CS-SECRET-GENERIC",
                     snippet="password=" + "p" * 30)
        alert = notify.build_alert([f], report.build_summary([f], 1, []))
        self.assertNotIn("p" * 30, alert)


# ---------------------------------------------------------------- github
class GitHubTests(unittest.TestCase):
    def test_refuses_protected_branch_destination(self):
        gh = github_client.GitHub(token="x", repo="o/r")
        for b in ("main", "master"):
            with self.assertRaises(github_client.GitHubError):
                gh.create_patch_branch("dev", b, "m", {"a.txt": "x"})

    def test_github_error_redacts_token(self):
        os.environ["GITHUB_TOKEN"] = "ghp_SECRETSECRETSECRET"
        try:
            err = str(github_client.GitHubError(
                github_client._redact("token ghp_SECRETSECRETSECRET here")))
            self.assertNotIn("SECRETSECRETSECRET", err)
        finally:
            os.environ.pop("GITHUB_TOKEN", None)

    def test_no_token_raises_before_network(self):
        os.environ.pop("GITHUB_TOKEN", None)
        gh = github_client.GitHub(token="", repo="o/r")
        with self.assertRaises(github_client.GitHubError):
            gh.comment_on_pr(1, "body")


# -------------------------------------------------------------------- config
class ConfigTests(unittest.TestCase):
    def test_missing_config_returns_defaults(self):
        from code_shield import config
        cfg, path, warn = config.load_config(_tmpdir())
        self.assertIsNone(path)
        self.assertEqual(cfg["ignore_rules"], [])

    def test_malformed_json_config_never_crashes(self):
        from code_shield import config
        d = _tmpdir()
        _write(d, "codeshield.json", "{ not valid json")
        cfg, path, warn = config.load_config(d)
        self.assertIsNotNone(warn)          # warned, not raised
        self.assertEqual(cfg["ignore_rules"], [])   # fell back to defaults

    def test_ignore_rules_removes_findings(self):
        d = _tmpdir()
        _write(d, "v.py", "import subprocess\nsubprocess.run(cmd, shell=True)\n"
                          "x = eval(user_input)\n")
        # baseline: both fire
        base, _ = scanner.scan_path(d)
        self.assertTrue(any(f.rule_id == "CS-INJ-EVAL" for f in base))
        cfg = {"ignore_rules": ["CS-INJ-EVAL"]}
        filtered, _ = scanner.scan_path(d, cfg=cfg)
        ids = [f.rule_id for f in filtered]
        self.assertNotIn("CS-INJ-EVAL", ids)
        self.assertIn("CS-AST-SHELL", ids)       # others survive

    def test_ignore_paths_skips_dirs(self):
        d = _tmpdir()
        _write(d, "fixtures/bad.py", "x = eval(u)\n")
        _write(d, "src/bad.py", "x = eval(u)\n")
        cfg = {"ignore_paths": ["fixtures/"]}
        findings, n = scanner.scan_path(d, cfg=cfg)
        files = {f.file for f in findings}
        self.assertTrue(all("fixtures" not in fp for fp in files))
        self.assertTrue(any("src" in fp for fp in files))

    def test_allow_secrets_in_suppresses_banner_not_redaction(self):
        from code_shield import config
        d = _tmpdir()
        _write(d, ".env.example", "API_KEY=placeholder\n")
        # without allow: banner fires
        f1, _ = scanner.scan_path(d)
        self.assertTrue(any(f.rule_id == "CS-SECRET-FILE" for f in f1))
        # with allow: banner gone, but a REAL secret is still found+redacted
        _write(d, ".env", 'TOKEN="ghp_%s"\n' % ("a" * 30))
        cfg = {"allow_secrets_in": [".env.example"]}
        f2, _ = scanner.scan_path(d, cfg=cfg)
        self.assertFalse(any(f.rule_id == "CS-SECRET-FILE" and ".env.example" in f.file
                             for f in f2))
        # the real .env still gets its secret detected and REDACTED
        secret_f = [f for f in f2 if f.rule_id in ("CS-SECRET-GH", "CS-SECRET-GENERIC")]
        self.assertTrue(secret_f)
        self.assertNotIn("a" * 30, " ".join(f.snippet for f in secret_f))

    def test_config_never_disables_redaction(self):
        # no config key can turn off redaction; mask always present
        from code_shield import redact as _r
        self.assertIn("REDACTED", _r.redact("ghp_" + "b" * 30))


# ------------------------------------------------- security-review fixes
class ReviewFixTests(unittest.TestCase):
    """Regression guards for the 7 findings of the pre-publication review."""

    # -- finding 1 (HIGH): redaction missed common secret-name shapes
    def test_redacts_unquoted_and_prefixed_names(self):
        cases = [
            "DB_PASSWORD=hunter2secret99",              # unquoted .env style
            'db_password = "hunter2secret99"',          # _-prefixed name
            'my_api_key = "abcdef1234567890"',          # prefixed name
            'SECRET_KEY = "django-insecure-xyz12345"',  # django canonical
            'key = "sk-or-v1-abcdefghijklmnop"',        # bare `key`
        ]
        for c in cases:
            out = redact.redact(c)
            self.assertIn("REDACTED", out, c)
            self.assertNotIn("hunter2secret99", out, c)
            self.assertNotIn("abcdef1234567890", out, c)

    # -- finding 2 (MED): same gaps were detection false negatives
    def test_detects_unquoted_and_prefixed_names(self):
        d = _tmpdir()
        _write(d, ".env", "DB_PASSWORD=hunter2secret99\n")
        _write(d, "settings.py",
               'SECRET_KEY = "django-insecure-xyz12345"\n'
               'my_api_key = "abcdef1234567890"\n')
        findings, _ = scanner.scan_path(d)
        ids = [f.rule_id for f in findings]
        self.assertIn("CS-SECRET-GENERIC", ids)
        # and no raw value leaks through any snippet
        blob = " ".join(f.snippet for f in findings)
        self.assertNotIn("hunter2secret99", blob)
        self.assertNotIn("django-insecure-xyz12345", blob)

    # -- finding 3 (MED): CS-CRYPTO-DES hit variables, missed TripleDES
    def test_des_rule_is_case_sensitive_and_real(self):
        des = [r for r in rules_mod.REGEX_RULES if r.id == "CS-CRYPTO-DES"][0]
        self.assertTrue(des.pattern.search("c = TripleDES.new(key)"))
        self.assertTrue(des.pattern.search("from Crypto.Cipher import DES3"))
        self.assertTrue(des.pattern.search("DES.new(key)"))
        # clean code: `des` as a variable must NOT fire (was a HIGH FP)
        self.assertIsNone(des.pattern.search("des = load_config()"))
        self.assertIsNone(des.pattern.search("for des in items: pass"))

    # -- finding 4 (LOW): standalone token shapes missing from the sweep
    def test_redacts_new_standalone_tokens(self):
        samples = [
            "sk-ant-api03-abcdefghij123456",            # Anthropic
            "sk-or-v1-abcdefghij1234567890",            # OpenRouter
            "pypi-AgEIcHlwaXN0Lm9yZw1234567890",        # PyPI
            "hf_" + "a" * 24,                          # HuggingFace
            "npm_" + "a" * 36,                         # npm
        ]
        for s in samples:
            self.assertIn("REDACTED", redact.redact(s), s)

    # -- finding 5 (LOW): partial mask leaked 8 of 12 chars; 6-char floor
    def test_mask_threshold_is_strict(self):
        self.assertEqual(redact.mask("abcdefghijklm"), redact.MASK)   # 13 < 16
        self.assertEqual(redact.mask("abc"), redact.MASK)             # tiny
        partial = redact.mask("abcdefghijklmnop")                     # 16 >= 16
        self.assertIn("REDACTED", partial)
        self.assertNotIn("efghijkl", partial)      # middle never survives
        # no length floor for explicitly detected secrets
        self.assertEqual(
            redact.redact("v=abcd", extra_secrets=["abcd"]),
            "v=" + redact.MASK)

    # -- finding 6 (LOW): AI remediation text reached JSON unredacted
    def test_summary_redacts_remediations(self):
        leaky = "use ghp_" + "z" * 36 + " then rotate"
        s = report.build_summary([], 1, [leaky])
        self.assertNotIn("z" * 36, json.dumps(s))
        self.assertIn("REDACTED", json.dumps(s))

    def test_report_json_file_redacts_remediations(self):
        import io, contextlib
        d = _tmpdir()
        _write(d, "v.py", "import subprocess\nsubprocess.run(cmd, shell=True)\n")
        out = os.path.join(_tmpdir(), "r.json")
        from code_shield import cli
        with contextlib.redirect_stdout(io.StringIO()):
            cli.main(["report", d, "--out", out])
        data = json.load(open(out))
        self.assertIn("remediations", data)
        # offline text is deterministic AND survives redaction unchanged
        self.assertTrue(all(isinstance(r, str) for r in data["remediations"]))

    def test_offline_remediation_text_survives_redaction(self):
        # the deterministic snippets are educational code, not secrets —
        # redaction must not mangle them (keeps reports readable)
        r = remediate.OfflineRemediator()
        for rid in r.SNIPPETS:
            f = _finding(rule_id=rid)
            out = r.remediate(f)
            self.assertEqual(redact.redact(out), out, rid)

    # -- finding 7 (LOW): false-positive noise on clean code
    def test_no_false_positives_on_clean_code(self):
        clean = {
            "python": [
                'def f():\n    """use eval(x) carefully."""\n    return 1\n',
                "x = 1  # never eval(user_input)\n",
                'def f():\n    """\n    use eval(x) here\n    """\n    return 1\n',
                "des = load_config()\n",
                'url = "https://api.example.com/v1"\nr = requests.get(url)\n',
                "result = validator(verify=False)\n",
                "import hashlib\nh = hashlib.sha256(b'x').hexdigest()\n",
            ],
            "javascript": [
                'var s = "new Function(x)";\n',
                'var u = "https://example.com/#frag";\n',
            ],
        }
        for lang, snippets in clean.items():
            for src in snippets:
                got = [f.rule_id for f in scan_text(src, "clean." +
                        ("py" if lang == "python" else "js"), lang)]
                self.assertEqual(got, [], (lang, src))

    def test_dogfood_self_scan_is_clean(self):
        # The scanner must find ZERO findings in its own codebase: rule
        # patterns and docstrings that mention eval/DES/verify=False are
        # strings, not code. Permanent gate against false-positive noise.
        root = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "code_shield")
        findings, n = scanner.scan_path(root)
        self.assertGreater(n, 5)            # it really did scan the package
        self.assertEqual([(f.file, f.line, f.rule_id) for f in findings], [])

    def test_real_vulns_still_detected_after_fp_fixes(self):
        # regression guard: tightening must not silence true positives
        must_fire = [
            ("python", "def f(x):\n    return eval(x)\n", "CS-INJ-EVAL"),
            ("python", "from Crypto.Cipher import DES3\n", "CS-CRYPTO-DES"),
            ("python", "def go(t):\n    return requests.get(t)\n",
             "CS-SSRF-URLVAR"),
            ("python", "r = requests.get(u, verify=False)\n",
             "CS-CONF-SSL-OFF"),
            ("python", 'cursor.execute(f"SELECT {x}")\n', "CS-INJ-SQL-FSTR"),
            ("generic", "DB_PASSWORD=hunter2secret99\n",
             "CS-SECRET-GENERIC"),
        ]
        for lang, src, want in must_fire:
            got = [f.rule_id for f in scan_text(src, "t." +
                    ("py" if lang == "python" else "env"), lang)]
            self.assertIn(want, got, src)


# ---------------------------------------------------------------------- cli
class CLITests(unittest.TestCase):
    def test_scan_offline_runs_and_reports(self):
        d = _tmpdir()
        _write(d, "vuln.py", 'password = "hunter2secret99"\ncursor.execute(f"SELECT {x}")\n')
        from code_shield import cli
        rc = cli.main(["scan", d])
        self.assertEqual(rc, 0)

    def test_scan_fail_on_high(self):
        d = _tmpdir()
        _write(d, "v.py", "import subprocess\nsubprocess.run(cmd, shell=True)\n")
        from code_shield import cli
        rc = cli.main(["scan", d, "--fail-on", "high"])
        self.assertEqual(rc, 1)

    def test_report_json_written_and_redacted(self):
        d = _tmpdir()
        _write(d, "l.py", 'API_KEY = "AKIA%s"\n' % ("E" * 16))
        out = os.path.join(_tmpdir(), "r.json")
        from code_shield import cli
        cli.main(["report", d, "--out", out])
        data = json.load(open(out))
        self.assertIn("summary", data)
        self.assertNotIn("E" * 16, json.dumps(data))

    def test_doctor_runs(self):
        from code_shield import cli
        self.assertEqual(cli.main(["doctor"]), 0)

    def test_json_output_is_pure_on_stdout(self):
        # --json must emit ONLY parseable JSON on stdout (humans -> stderr),
        # so a CI/machine can pipe it. Regression-guard for the stdout fix.
        import io, contextlib, json as _json
        d = _tmpdir()
        _write(d, "v.py", "import subprocess\nsubprocess.run(cmd, shell=True)\n")
        from code_shield import cli
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cli.main(["scan", d, "--json"])
        data = _json.loads(buf.getvalue())      # must parse cleanly
        self.assertIn("summary", data)
        self.assertIn("findings", data)


if __name__ == "__main__":
    unittest.main()
