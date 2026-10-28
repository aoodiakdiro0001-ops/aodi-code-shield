"""GitHub delivery client (stdlib-only) — post a PR comment / open a patch PR.

Bright lines (enforced here, pinned by tests):
  * it NEVER pushes to `main`/`master` directly, and NEVER force-pushes
  * it NEVER auto-merges a PR — a human reviews and merges
  * delivery is additive: a PR comment, or a NEW branch + PR from a diff the
    tool generated locally
  * the token is redacted from every error path
"""
import json
import os
import urllib.error
import urllib.request

from . import redact

API = "https://api.github.com"
MAX_READ = 1 << 20
PROTECTED_BRANCHES = ("main", "master")


def _redact(msg):
    tok = os.environ.get("GITHUB_TOKEN")
    if tok:
        msg = msg.replace(tok, "***")
    return redact.redact(msg)[:200]


class GitHubError(Exception):
    pass


class GitHub(object):
    def __init__(self, token=None, repo=None, timeout=30.0):
        self.token = token or os.environ.get("GITHUB_TOKEN", "")
        self.repo = repo or os.environ.get("GITHUB_REPO", "")   # owner/name
        self.timeout = timeout
        # refuse ambient proxies; do not follow redirects (token safety)
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect())

    def _req(self, method, path, body=None):
        if not self.token:
            raise GitHubError("GITHUB_TOKEN not set")
        url = path if path.startswith("http") else (API + path)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", "Bearer " + self.token)
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        if data:
            req.add_header("Content-Type", "application/json")
        try:
            with self._opener.open(req, timeout=self.timeout) as r:
                raw = r.read(MAX_READ).decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            raise GitHubError("HTTP %s: %s" % (e.code, _redact(e.read(400).decode("utf-8", "replace"))))
        except urllib.error.URLError as e:
            raise GitHubError(_redact(str(getattr(e, "reason", e))))
        except Exception as e:
            raise GitHubError(_redact(str(e)))

    # ------------------------------------------------------------ PR comment
    def comment_on_pr(self, number, body):
        """Post an audit comment on a pull request. Additive only."""
        self._req("POST", "/repos/%s/issues/%s/comments" % (self.repo, number),
                  {"body": redact.redact(str(body))[:65535]})
        return True

    # ------------------------------------------------------------ patch PR
    def _ref_sha(self, ref):
        data = self._req("GET", "/repos/%s/git/ref/%s" % (self.repo, ref))
        return data["object"]["sha"]

    def create_patch_branch(self, base_branch, new_branch, message, files):
        """Create a branch off `base_branch` and commit `files` (dict path->text).

        Refuses to use a protected branch as the DESTINATION and never
        force-pushes. `files` is {relative_path: content}. Returns the PR URL.
        """
        if new_branch in PROTECTED_BRANCHES:
            raise GitHubError("refusing to target protected branch %r" % new_branch)
        base_sha = self._ref_sha("heads/" + base_branch)
        # 1. branch
        self._req("POST", "/repos/%s/git/refs" % self.repo,
                  {"ref": "refs/heads/" + new_branch, "sha": base_sha})
        # 2. blobs -> base tree -> commit
        tree = []
        for rel, content in files.items():
            blob = self._req("POST", "/repos/%s/git/blobs" % self.repo,
                             {"content": content, "encoding": "utf-8"})
            tree.append({"path": rel, "mode": "100644", "type": "blob",
                         "sha": blob["sha"]})
        base_commit = self._req("GET", "/repos/%s/git/commits/%s" % (self.repo, base_sha))
        base_tree = base_commit["tree"]["sha"]
        new_tree = self._req("POST", "/repos/%s/git/trees" % self.repo,
                             {"base_tree": base_tree, "tree": tree})
        commit = self._req("POST", "/repos/%s/git/commits" % self.repo,
                           {"message": redact.redact(message),
                            "tree": new_tree["sha"], "parents": [base_sha]})
        self._req("PATCH", "/repos/%s/git/refs/heads/%s" % (self.repo, new_branch),
                  {"sha": commit["sha"]})      # fast-forward only, no force
        # 3. open the PR (a human must merge)
        pr = self._req("POST", "/repos/%s/pulls" % self.repo,
                       {"title": redact.redact(message),
                        "head": new_branch, "base": base_branch,
                        "body": "Automated security patch from Code-Shield "
                                "ZeroBaran. **Please review before merging** — "
                                "this is a proposed fix, not an auto-merge."})
        return pr.get("html_url", "")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(newurl, code, "redirect blocked", headers, fp)
