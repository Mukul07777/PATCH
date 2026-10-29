"""A security grade (A-F) and a to-do list in plain words, for people who do not read CVE ids.

The grade is arithmetic on facts the scan already has, so the same scan always gets the same grade:
severity of open findings, whether any is being exploited right now (CISA KEV), how much of the dependency set
could be checked at all, and the supply-chain signals (malicious, typosquat, yanked, abandoned, copyleft).
"""

LABELS = {"A": "Safe", "B": "Minor issues", "C": "Needs attention", "D": "At risk", "F": "Critical risk",
          "?": "Not enough information"}
PENALTY = {"critical": 35, "high": 15, "moderate": 5, "low": 1, "unknown": 2}


def _letter(score):
    return "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 55 else "D" if score >= 35 else "F"


def grade(counts, kev=0, coverage=None, supply=None):
    """{letter, label, score, reasons} from severity counts, the number of exploited-now findings, the scan's
    coverage state and an optional supply-chain summary."""
    c = {k.lower().replace("medium", "moderate"): v or 0 for k, v in (counts or {}).items()}
    c["unknown"] = c.get("unknown", 0) + c.pop("unrated", 0)
    reasons = []
    if (coverage or {}).get("state") == "unverified":
        return {"letter": "?", "label": LABELS["?"], "score": None,
                "reasons": ["No dependency had an exact version, so nothing could be checked"]}
    score = 100
    for sev, pts in PENALTY.items():
        n = c.get(sev, 0)
        if n:
            score -= min(pts * n, 60 if sev in ("critical", "high") else 30)
            reasons.append(f"{n} {sev} security hole{'s' if n > 1 else ''}")
    s = (supply or {}).get("summary") or {}
    if s.get("typosquat"):
        score -= 35
        reasons.append(f"{s['typosquat']} package name(s) that look like a fake copy of a popular package")
    if s.get("yanked"):
        score -= 10
        reasons.append(f"{s['yanked']} version(s) withdrawn by their own maintainers")
    if s.get("stale"):
        score -= 3 * s["stale"]
        reasons.append(f"{s['stale']} package(s) nobody has updated in years")
    if (coverage or {}).get("state") == "partial":
        score -= 5
        reasons.append("some dependencies have no exact version, so they could not be checked")
    letter = _letter(max(score, 0))
    if kev:
        letter = "F"
        reasons.insert(0, f"{kev} hole(s) are being used by attackers right now")
    if s.get("malicious"):
        letter = "F"
        reasons.insert(0, f"{s['malicious']} known malicious package(s)")
    if not reasons:
        reasons = ["No known security holes in any checked dependency"]
    return {"letter": letter, "label": LABELS[letter], "score": max(score, 0), "reasons": reasons}


def todo(summary, supply=None, findings=()):
    """Ordered, plain-language actions: the most important first."""
    steps = []
    kev = {f["package"].lower() for f in findings if f.get("kev") and not f.get("suppressed")}
    for row in (supply or {}).get("packages") or []:
        kinds = {f["kind"] for f in row["flags"]}
        if "malicious" in kinds:
            steps.append({"priority": "now", "text": f"Remove {row['package']} immediately: it is a known malicious package."})
        elif "typosquat" in kinds:
            target = next((f["text"].split("'")[1] for f in row["flags"] if f["kind"] == "typosquat" and "'" in f["text"]), "")
            steps.append({"priority": "now", "text": f"Check {row['package']}: the name looks like a fake copy of "
                          f"'{target}'. If you meant '{target}', replace it."})
    vp = sorted((summary or {}).get("vulnerable_packages") or [],
                key=lambda p: (p["package"].lower() not in kev, -p.get("advisories", 0)))
    for p in vp:
        n = p.get("advisories", 0)
        if p.get("safe"):
            steps.append({"priority": "now" if p["package"].lower() in kev else "soon",
                          "text": f"Upgrade {p['package']} from {p['version']} to {p['safe']}: this fixes {n} security "
                                  f"hole{'s' if n != 1 else ''}" + (" (one is being attacked right now)" if p["package"].lower() in kev else "") + "."})
        else:
            steps.append({"priority": "soon", "text": f"{p['package']} {p['version']} has {n} security hole(s) with no "
                          "fixed release yet: limit how it is used, or switch to an alternative."})
    for row in (supply or {}).get("packages") or []:
        kinds = {f["kind"]: f for f in row["flags"]}
        if "yanked" in kinds:
            steps.append({"priority": "soon", "text": f"Move off {row['package']} {row['version']}: its own "
                          "maintainers withdrew this version."})
        if "stale" in kinds or "inactive" in kinds:
            steps.append({"priority": "later", "text": f"Plan to replace {row['package']}: it has not been updated "
                          f"since {row['health'].get('last_release') or 'a long time'}."})
        if row["license_class"] == "strong-copyleft":
            steps.append({"priority": "later", "text": f"Ask legal about {row['package']} ({row['license']}): if you "
                          "ship your software to others, this license can require you to publish your source code."})
    unpinned = (summary or {}).get("unpinned") or []
    if unpinned:
        steps.append({"priority": "later", "text": f"Pin exact versions for {len(unpinned)} package(s) "
                      f"({', '.join(unpinned[:4])}{'…' if len(unpinned) > 4 else ''}) so they can be checked."})
    return steps
