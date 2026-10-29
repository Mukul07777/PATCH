"""Deterministic remediation for scan-only projects: rewrite vulnerable pins to the least-change safe version.

The fix agent repairs code; this does the part that needs no model. Each vulnerable exact pin in a requirements
file is moved to the smallest release that clears every advisory, comments and unrelated lines are kept as they
are, and every changed line says why.
"""
import re

from patchpilot.intel import manifests

PIN_LINE = re.compile(r"^(\s*)([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?(\s*)===?(\s*)([A-Za-z0-9][A-Za-z0-9._+!-]*)(.*)$")


def fixed_requirements(text, safe):
    """(new text, changes) for a requirements file. safe maps (normalized name, version) -> safe version."""
    out, changes = [], []
    lines = text.splitlines()
    for line in lines:
        m = PIN_LINE.match(line)
        key = (manifests.normalize(m.group(2)), m.group(6)) if m else None
        to = safe.get(key) if key else None
        if not to or to == m.group(6):
            out.append(line)
            continue
        rest = m.group(7)
        note = f"  # PatchPilot: {m.group(6)} -> {to} clears every known advisory (least-change upgrade)"
        comment = "" if "#" not in rest else rest[rest.index("#"):]
        markers = rest.split("#")[0].rstrip()  # environment markers / hashes stay
        out.append(f"{m.group(1)}{m.group(2)}{m.group(3) or ''}=={to}{markers}{note}"
                   + (f" {comment.lstrip('# ').strip()}" if comment else ""))
        changes.append({"package": m.group(2), "from": m.group(6), "to": to})
    return "\n".join(out) + ("\n" if text.endswith("\n") or not text else ""), changes


def safe_map(summary):
    """(normalized name, version) -> least-change safe version, from a scan summary's vulnerable_packages."""
    return {(manifests.normalize(p["package"]), p["version"]): p["safe"]
            for p in (summary or {}).get("vulnerable_packages") or [] if p.get("safe")}
