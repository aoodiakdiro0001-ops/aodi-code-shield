"""Optional scan config loader (`.codeshield.yml` / `codeshield.json`).

Config can only NARROW scope (ignore rules/paths, allow example-secret files).
It can NEVER widen it: it cannot disable redaction, cannot make the scanner
execute code, and cannot force a finding to be hidden from a report's summary.

Loading is stdlib-only: JSON always; YAML only if PyYAML happens to be
installed (otherwise a `.yml` config is skipped with a clear note — the engine
stays dependency-free).

Contracts (pinned by tests):
  * a malformed config never crashes the scan — it's ignored with a warning
  * `ignore_rules` / `ignore_paths` / `allow_secrets_in` only reduce findings
  * redaction is unaffected by any config key
"""
import json
import os

CONFIG_NAMES = (".codeshield.yml", ".codeshield.yaml", "codeshield.json",
                ".codeshield.json")

DEFAULTS = {
    "include_tests": False,
    "fail_on": None,
    "ignore_rules": [],
    "ignore_paths": [],
    "allow_secrets_in": [],
}


def _load_yaml(text):
    try:
        import yaml  # optional; only if the host already has PyYAML
        return yaml.safe_load(text) or {}
    except Exception:
        return None                    # PyYAML absent -> caller warns


def load_config(root):
    """Find + parse a config at `root` (file's dir, or the dir itself).

    Returns (config_dict, path_or_None, warning_or_None). Never raises.
    """
    base = root if os.path.isdir(root) else os.path.dirname(os.path.abspath(root))
    for name in CONFIG_NAMES:
        p = os.path.join(base, name)
        if not os.path.isfile(p):
            continue
        try:
            with open(p, "r", encoding="utf-8") as fh:
                text = fh.read()
        except (OSError, IOError) as e:
            return dict(DEFAULTS), p, "cannot read config: %s" % e
        if name.endswith((".yml", ".yaml")):
            data = _load_yaml(text)
            if data is None:
                return (dict(DEFAULTS), p,
                        "PyYAML not installed; ignoring %s (use "
                        "codeshield.json instead)" % name)
        else:
            try:
                data = json.loads(text)
            except ValueError as e:
                return dict(DEFAULTS), p, "malformed JSON config: %s" % e
        if not isinstance(data, dict):
            return dict(DEFAULTS), p, "config root must be a mapping"
        cfg = dict(DEFAULTS)
        for k in DEFAULTS:
            if k in data:
                cfg[k] = data[k]
        return cfg, p, None
    return dict(DEFAULTS), None, None


def path_is_ignored(relpath, ignore_paths):
    """True if relpath matches any ignore prefix/substring (case-insensitive)."""
    if not ignore_paths:
        return False
    rp = (relpath or "").replace("\\", "/").lower()
    for pat in ignore_paths:
        pat = str(pat).replace("\\", "/").lower().strip("/")
        if not pat:
            continue
        if pat in rp:
            return True
    return False


def secret_file_allowed(relpath, allow_secrets_in):
    """True if this path is a documented example-secret location.

    NOTE: this only suppresses the 'credential file present' BANNER — any
    detected secret value is still redacted everywhere. Redaction is not
    affected by config.
    """
    return path_is_ignored(relpath, allow_secrets_in)
