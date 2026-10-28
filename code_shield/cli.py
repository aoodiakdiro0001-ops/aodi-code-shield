"""Code-Shield CLI — the single entry GitHub Actions calls.

Commands:
  scan <path>        static-scan a file/dir; print findings + summary
  report <path>      scan and write markdown/html/json report(s)
  comment <path>     scan + post a PR comment (needs GITHUB_TOKEN/REPO)
  patch <path>       scan + open a patch PR branch (needs GITHUB_TOKEN/REPO)
  notify <path>      scan + send a Telegram alert (needs TELEGRAM_TOKEN)
  doctor             environment self-check

Offline-safe: `scan`/`report` never touch the network. `comment`/`patch`/
`notify` only reach out when their credentials are configured. Secrets are
redacted on every output path.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from code_shield import (config, github_client, notify, redact, remediate,  # noqa: E402
                         report, scanner)


def _load_remediator(args):
    r = remediate.get_remediator(getattr(args, "ai", None))
    # always keep an offline fallback so nothing depends on the network
    if not isinstance(r, remediate.OfflineRemediator):
        r.fallback = remediate.OfflineRemediator()
    return r


def _scan(args):
    cfg, cfg_path, warn = config.load_config(args.path)
    if warn:
        print("config: %s" % warn, file=sys.stderr)
    findings, nfiles = scanner.scan_path(args.path,
                                         include_tests=args.include_tests,
                                         cfg=cfg)
    rem = _load_remediator(args)
    remediated = [rem.remediate(f) for f in findings]
    summary = report.build_summary(findings, nfiles, remediated)
    return findings, remediated, summary


def _print_console(findings, summary, remediated, out=None):
    """Human-readable summary. `out` is a stream (default stdout).

    When --json is used, the caller passes sys.stderr so stdout stays PURE,
    parseable JSON (a CI/machine can pipe it).
    """
    p = out.write if out is not None else print
    p("Code-Shield ZeroBaran — %d finding(s) in %d file(s)\n"
      % (summary["total_findings"], summary["scanned_files"]))
    sev = summary["by_severity"]
    top = ", ".join("%s:%d" % (k, sev[k]) for k in
                    ("critical", "high", "medium", "low", "info") if sev.get(k))
    if top:
        p("  severity — " + top + "\n")
    for f, fix in zip(findings, remediated):
        p("  [%s] %s:%s  %s\n" % (f.severity.upper(), f.file, f.line, f.title))
        p("     rule=%s  %s\n" % (f.rule_id, redact.redact(f.message)[:120]))
        p("     fix: %s\n" % redact.redact(fix).replace("\n", " ")[:160])
    if not findings:
        p("  No findings in the current rule set (not a guarantee of "
          "absence — see disclaimer).\n")
    p("  " + report.DISCLAIMER + "\n")


def cmd_scan(args):
    findings, _rem, summary = _scan(args)
    if args.json:
        # keep stdout PURE JSON for machine/CI parsing; humans go to stderr
        _print_console(findings, summary, _rem, out=sys.stderr)
        print(json.dumps({"summary": summary,
                          "findings": [f.as_dict() for f in findings]},
                         indent=2, ensure_ascii=False))
    else:
        _print_console(findings, summary, _rem)
    level = args.fail_on
    if not level:
        # fall back to config.fail_on when the flag isn't given
        cfg, _p, _w = config.load_config(args.path)
        level = cfg.get("fail_on")
    if level and _exceeds(findings, level):
        return 1
    return 0


def _exceeds(findings, level):
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    threshold = order.get(level, 9)
    return any(order.get(f.severity, 9) <= threshold for f in findings)


def cmd_report(args):
    findings, remediated, summary = _scan(args)
    _print_console(findings, summary, remediated)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    if args.out.endswith(".html"):
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(report.to_html(findings, summary))
    elif args.out.endswith(".json"):
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump({"summary": summary,
                       "findings": [f.as_dict() for f in findings],
                       # AI-influenced text is sanitized before it hits disk
                       "remediations": [redact.redact(r) for r in remediated]},
                      fh, indent=2, ensure_ascii=False)
    else:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(report.to_markdown(findings, summary))
    print("report written to %s (%d bytes)" % (args.out,
                                               os.path.getsize(args.out)))
    return 0


def cmd_comment(args):
    findings, _rem, summary = _scan(args)
    gh = github_client.GitHub(repo=args.repo)
    body = report.to_pr_comment(findings, summary)
    gh.comment_on_pr(args.pr, body)
    print("comment posted on PR #%s (%d finding(s))" % (args.pr, len(findings)))
    return 0


def cmd_patch(args):
    findings, _rem, summary = _scan(args)
    if not findings:
        print("no findings; nothing to patch")
        return 0
    gh = github_client.GitHub(repo=args.repo)
    # We deliver the audit as a report file on a new branch (never touch main).
    md = report.to_markdown(findings, summary)
    branch = args.branch or "codeshield/audit-%d" % int(__import__("time").time())
    url = gh.create_patch_branch(
        args.base, branch,
        "Code-Shield: security audit report (%d finding(s))" % len(findings),
        {"CODESHIELD_AUDIT.md": md})
    print("patch branch + PR opened: %s" % url)
    print("(a human must review and merge — this tool never merges or "
          "force-pushes to %r)" % args.base)
    return 0


def cmd_notify(args):
    findings, _rem, summary = _scan(args)
    res = notify.send(notify.build_alert(findings, summary))
    print("[tg] ok=%s %s" % (res.get("ok"), res.get("err", "")))
    return 0 if res.get("ok") else 1


def cmd_doctor(args):
    checks = [
        ("ai", remediate.get_remediator(None).name),
        ("groq_key", "set" if os.environ.get("GROQ_API_KEY") else "unset (offline remediation)"),
        ("gemini_key", "set" if os.environ.get("GEMINI_API_KEY") else "unset (offline remediation)"),
        ("telegram_token", "set" if os.environ.get("TELEGRAM_TOKEN") else "unset (notify won't send)"),
        ("telegram_chat", os.environ.get("TELEGRAM_CHAT_ID") or "unset"),
        ("github_token", "set" if os.environ.get("GITHUB_TOKEN") else "unset (comment/patch disabled)"),
        ("github_repo", os.environ.get("GITHUB_REPO") or "unset"),
    ]
    out = ["Code-Shield doctor", "=" * 44]
    for k, v in checks:
        out.append("  %-16s %s" % (k, v))
    out.append("=" * 44)
    out.append("static, non-exploiting auditor. Secrets redacted on output.")
    out.append("findings are heuristic signals, not proof of a vulnerability.")
    print("\n".join(out))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="code-shield", description=__doc__)
    ap.add_argument("--ai", default=None, help="offline | groq | gemini")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def _add_scan_flags(p):
        p.add_argument("path", help="file or directory to scan")
        p.add_argument("--include-tests", action="store_true")
        p.add_argument("--json", action="store_true")

    p = sub.add_parser("scan", help="static-scan a file/dir")
    _add_scan_flags(p)
    p.add_argument("--fail-on", default=None,
                   help="exit 1 if any finding >= this severity")
    p.set_defaults(fn=cmd_scan)

    p = sub.add_parser("report", help="scan + write a report file")
    _add_scan_flags(p)
    p.add_argument("--out", required=True, help=".md | .html | .json")
    p.set_defaults(fn=cmd_report)

    p = sub.add_parser("comment", help="scan + post a PR comment")
    _add_scan_flags(p)
    p.add_argument("--pr", required=True, type=int)
    p.add_argument("--repo", default=None, help="owner/name (or GITHUB_REPO)")
    p.set_defaults(fn=cmd_comment)

    p = sub.add_parser("patch", help="scan + open a patch PR branch")
    _add_scan_flags(p)
    p.add_argument("--repo", default=None)
    p.add_argument("--base", default="main")
    p.add_argument("--branch", default=None)
    p.set_defaults(fn=cmd_patch)

    p = sub.add_parser("notify", help="scan + send a Telegram alert")
    _add_scan_flags(p)
    p.set_defaults(fn=cmd_notify)

    p = sub.add_parser("doctor", help="environment self-check")
    p.set_defaults(fn=cmd_doctor)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
