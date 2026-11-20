"""Supply-chain view of the cpp-aibom scan (served at /api/supply-chain).

build(aibom) turns the scanner's aibom-json output into one row per
package: its version, how it reaches users, its highest-scored open
advisory and every open advisory, most severe first. The dashboard reads
aibom-latest.json per request, so a new nightly scan shows up at once.
"""

SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4, "UNKNOWN": 5}
VULN_FIELDS = ("id", "cve", "aliases", "summary", "severity", "score", "cvss_version", "cvss_vector",
               "score_source", "published", "modified", "fixed", "cwe_ids", "url", "references")


def _vuln_key(v):
    score = v.get("score")
    return (0 if score is not None else 1, -(score or 0), SEV_RANK.get(v.get("severity"), 5), v.get("id", ""))


def _package(c):
    vulns = sorted(({k: v.get(k) for k in VULN_FIELDS} for v in c.get("vulnerabilities") or []), key=_vuln_key)
    top = vulns[0] if vulns else {}
    status = c.get("osv_status") or ("checked" if vulns else "not checked")
    return {
        "name": c.get("name", ""),
        "version": c.get("version", ""),
        "commit": c.get("commit", ""),
        "purl": c.get("purl", ""),
        "license": c.get("license", ""),
        "repo_url": c.get("repo_url", ""),
        "category": c.get("category", ""),
        "scope": c.get("scope") or "required",
        "delivery": c.get("delivery", ""),
        "osv_status": status,
        "max_score": top.get("score"),
        "max_severity": top.get("severity") or ("UNKNOWN" if vulns else ""),
        "top_id": top.get("id", ""),
        "top_cve": top.get("cve", ""),
        "vulns": vulns,
    }


def _pkg_key(p):
    has = 0 if p["vulns"] else 1
    score = p["max_score"]
    unchecked = 0 if p["osv_status"] == "checked" else 1
    return (has, 0 if score is not None else 1, -(score or 0), SEV_RANK.get(p["max_severity"], 5),
            -len(p["vulns"]), unchecked, p["name"].lower())


def build(aibom):
    comps = (aibom.get("aibom_analysis") or {}).get("components") or []
    packages = sorted((_package(c) for c in comps), key=_pkg_key)
    by_sev = {}
    for p in packages:
        for v in p["vulns"]:
            by_sev[v["severity"]] = by_sev.get(v["severity"], 0) + 1
    checked = sum(1 for p in packages if p["osv_status"] == "checked")
    return {
        "scan_time": aibom.get("scan_time", ""),
        "scanner_version": aibom.get("version", ""),
        "commit": aibom.get("target_commit", ""),
        "summary": {
            "total": len(packages),
            "checked": checked,
            "not_checked": len(packages) - checked,
            "affected": sum(1 for p in packages if p["vulns"]),
            "open_advisories": sum(len(p["vulns"]) for p in packages),
            "by_severity": by_sev,
        },
        "packages": packages,
    }
