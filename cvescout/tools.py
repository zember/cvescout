"""Tools exposed to the agent. Each returns JSON and records the CVE IDs it returned,
so the agent's final answer can be checked against data actually fetched."""

from __future__ import annotations

import json
from typing import Literal

from anthropic import beta_tool

from . import sources

# CVE IDs returned by any tool during the current run (see agent.find_unsourced_cves)
seen_cve_ids: set[str] = set()


def _result(payload: dict, ids: list[str]) -> str:
    seen_cve_ids.update(ids)
    return json.dumps(payload, ensure_ascii=False)


def _error(e: Exception) -> str:
    return json.dumps(
        {"error": f"Source unavailable: {e}. Do not substitute CVEs from memory."}
    )


@beta_tool
def get_current_datetime() -> str:
    """Return the current date and time in UTC. Call this first: "latest" and "recent" are relative to this date, not to your training data."""
    now = sources.now_utc()
    return json.dumps({"utc_now": now.isoformat(), "date": now.date().isoformat()})


@beta_tool
def search_recent_cves(
    days: int = 7,
    keywords: list[str] | None = None,
    min_severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None,
    limit: int = 25,
    min_score: float | None = None,
    rce_only: bool = False,
    match_any: bool = False,
    poc_only: bool = False,
    since: str | None = None,
    cpes: list[str] | None = None,
    source: Literal["nvd", "cvelist"] = "nvd",
    sort_by: Literal["published", "risk"] = "published",
    reference_urls: list[str] | None = None,
) -> str:
    """Search for CVEs published in the last N days (or since a date), enriched with EPSS exploit probability, CISA KEV membership and a risk score (patch priority).

    Args:
        sort_by: "published" (newest first) or "risk" (highest patch priority first, ranked over all matches). Use "risk" for "what should I patch first", "most dangerous", "top N".
        reference_urls: Only with source="cvelist": match parts of reference links, OR-ed with keywords/cpes. A product's security advisory page finds CVEs filed under libraries it bundles, e.g. ["nodejs.org/en/blog/vulnerability"] finds a Brotli or OpenSSL CVE that Node.js lists. Use it together with keywords for a product.
        source: "nvd" (default; NVD API, any date range, CPE filters cover NVD-analyzed CVEs) or "cvelist" (CVEProject CVE List: last 30 days only, no rate limit, CVEs appear about an hour before NVD, includes vendor-supplied affected versions; keywords also match vendor and product names; CPE filters only match where the vendor supplied CPEs). Use "cvelist" for the last hours or days, or when NVD is unavailable or slow.
        days: Look-back window in days. Use small windows (1-7) for "latest". Ignored when `since` is set.
        keywords: Optional free-text filters, OR-ed (one search each), e.g. ["openssl"] or ["node.js", "curl"]. Matches anywhere in the description, so it is broad.
        since: Optional start date YYYY-MM-DD for historical questions ("since 2020"). Ranges over 120 days require keywords or cpes.
        cpes: Optional exact products as CPE names, OR-ed: "vendor:product" for applications, "o:vendor:product" for operating systems, e.g. ["nodejs:node.js", "haxx:curl", "o:linux:linux_kernel"]. Use find_cpe_name if unsure. More precise than keywords but only covers CVEs NVD has already analyzed.
        min_severity: Optional minimum CVSS severity.
        limit: Maximum number of CVEs to return (1-100).
        min_score: Optional minimum CVSS base score (0-10), e.g. 8.
        rce_only: Only remote code execution (code/command injection reachable over the network; heuristic on CWE, description and CVSS vector).
        match_any: If true, keep items meeting ANY of min_severity/min_score/rce_only/poc_only instead of ALL of them.
        poc_only: Only items with a public exploit: a PoC repository on GitHub (listed in github_pocs, from nomi-sec/PoC-in-GitHub), a CISA SSVC or CVSS v4 rating of a public PoC (ignored when the CVE links a bug bounty report such as HackerOne), or exploitation in the wild (CISA KEV). A reference NVD tagged "Exploit" alone does not count.
    """
    fetch = sources.fetch_cvelist_recent if source == "cvelist" else sources.fetch_nvd_recent
    try:
        data = fetch(
            days=days,
            keyword=keywords,
            min_severity=min_severity,
            min_score=min_score,
            rce=rce_only,
            match_any=match_any,
            poc=poc_only,
            since=since,
            cpe=cpes,
            limit=100_000 if sort_by == "risk" else max(1, min(limit, 100)),
            **({"url": reference_urls} if source == "cvelist" else {}),
        )
    except sources.SourceError as e:
        return _error(e)
    sources.add_risk(data["cves"], sort=sort_by == "risk")
    data["cves"] = data["cves"][: max(1, min(limit, 100))]
    data["sorted_by"] = sort_by
    for c in data["cves"]:
        c["description"] = c["description"][:600]
    return _result(data, [c["id"] for c in data["cves"]])


@beta_tool
def find_cpe_name(product: str) -> str:
    """Look up the exact NVD CPE name ("vendor:product", or "o:vendor:product" for operating systems) for a product, to pass in search_recent_cves(cpes=...). Products whose name matches best come first; deprecated names show their replacement.

    Args:
        product: Product name, e.g. "curl", "node.js", "apache http server", "linux kernel".
    """
    try:
        return json.dumps(sources.find_cpe(product, limit=10), ensure_ascii=False)
    except sources.SourceError as e:
        return _error(e)


@beta_tool
def get_cve_details(cve_id: str) -> str:
    """Fetch full, current details of one CVE from the NVD, with the vendor's affected versions from the CVE List, EPSS, CISA KEV status and any GitHub advisories (affected packages and patched versions). Falls back to the CVE List when NVD is unavailable or does not have the CVE yet.

    Args:
        cve_id: CVE identifier, e.g. "CVE-2026-12345".
    """
    try:
        cvelist = sources.fetch_cvelist_cve(cve_id)
    except sources.SourceError as e:
        cvelist, cvelist_error = None, e
    else:
        cvelist_error = None
    try:
        cve = sources.fetch_nvd_cve(cve_id)
    except sources.SourceError as e:
        if cvelist is None:
            return _error(e)
        cve, cvelist["note"] = cvelist, f"NVD unavailable ({e}); data from the CVE List."
    if cve is None:
        if cvelist is None:
            return json.dumps({"error": f"{cve_id} not found in NVD or the CVE List."})
        cve, cvelist["note"] = cvelist, "Not in NVD yet; data from the CVE List."
    elif cvelist:
        cve["affected"] = cvelist["affected"]
    elif cvelist_error:
        cve["affected"] = f"unavailable: {cvelist_error}"
    if isinstance(cve.get("affected"), list):
        cve["affected_note"] = sources.AFFECTED_NOTE
    sources.add_risk([cve])
    try:
        cve["github_advisories"] = sources.fetch_ghsa_for_cve(cve["id"])
    except sources.SourceError as e:
        cve["github_advisories"] = f"unavailable: {e}"
    return _result(cve, [cve["id"]])


@beta_tool
def search_github_advisories(
    days: int = 7,
    ecosystem: Literal[
        "actions", "composer", "erlang", "go", "maven", "npm", "nuget",
        "other", "pip", "pub", "rubygems", "rust", "swift",
    ] | None = None,
    package: str | None = None,
    min_severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None,
    include_unreviewed: bool = False,
    limit: int = 25,
    min_score: float | None = None,
    rce_only: bool = False,
    match_any: bool = False,
    poc_only: bool = False,
    sort_by: Literal["published", "risk"] = "published",
) -> str:
    """Search the GitHub Advisory Database for security advisories published in the last N days, newest first. Best source for open-source dependencies: each reviewed advisory names the package, vulnerable version range and first patched version. Some advisories have no CVE ID (only a GHSA ID).

    Args:
        days: Look-back window in days.
        ecosystem: Optional package ecosystem filter (pip = Python, npm = JavaScript, maven = Java, rust = crates.io, ...).
        package: Optional package name, e.g. "lodash" or "django".
        min_severity: Optional minimum severity.
        include_unreviewed: Also include advisories not yet reviewed by GitHub (usually NVD mirrors without package data).
        limit: Maximum number of advisories to return (1-100).
        min_score: Optional minimum CVSS base score (0-10), e.g. 8.
        rce_only: Only remote code execution (code/command injection reachable over the network; heuristic on CWE, description and CVSS vector).
        match_any: If true, keep items meeting ANY of min_severity/min_score/rce_only/poc_only instead of ALL of them.
        poc_only: Only items with a public exploit: a PoC repository on GitHub (listed in github_pocs, from nomi-sec/PoC-in-GitHub), a CISA SSVC or CVSS v4 rating of a public PoC (ignored when the CVE links a bug bounty report such as HackerOne), or exploitation in the wild (CISA KEV). A reference NVD tagged "Exploit" alone does not count.
        sort_by: "published" (newest first) or "risk" (highest patch priority first, over the newest 100 advisories).
    """
    try:
        data = sources.fetch_ghsa_recent(
            days=days,
            ecosystem=ecosystem,
            package=package,
            min_severity=min_severity,
            include_unreviewed=include_unreviewed,
            limit=100 if sort_by == "risk" else max(1, min(limit, 100)),
            min_score=min_score,
            rce=rce_only,
            match_any=match_any,
            poc=poc_only,
        )
    except sources.SourceError as e:
        return _error(e)
    sources.add_risk(data["advisories"], key="cve_id", sort=sort_by == "risk")
    data["advisories"] = data["advisories"][: max(1, min(limit, 100))]
    data["sorted_by"] = sort_by
    return _result(data, [a["cve_id"] for a in data["advisories"] if a["cve_id"]])


@beta_tool
def get_recent_exploited(days: int = 30, limit: int = 50) -> str:
    """List vulnerabilities CISA added to its Known Exploited Vulnerabilities (KEV) catalog in the last N days - CVEs confirmed exploited in the wild. Note: an old CVE can be newly added here; report its date_added.

    Args:
        days: Look-back window in days.
        limit: Maximum number of entries to return.
    """
    try:
        data = sources.fetch_kev_recent(days=days, limit=max(1, min(limit, 200)))
    except sources.SourceError as e:
        return _error(e)
    return _result(data, [v["id"] for v in data["vulnerabilities"]])


ALL_TOOLS = [
    get_current_datetime,
    search_recent_cves,
    search_github_advisories,
    find_cpe_name,
    get_cve_details,
    get_recent_exploited,
]
