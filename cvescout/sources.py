"""Live CVE data sources: NVD API 2.0, CVE List V5, GitHub Advisory Database, CISA KEV and FIRST EPSS.

Everything here is fetched at call time, relative to the current UTC date,
so results never depend on what a language model remembers.
"""

from __future__ import annotations

import io
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta, timezone

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
GHSA_URL = "https://api.github.com/advisories"
CVELIST_REPO = "CVEProject/cvelistV5"
CVELIST_RAW_URL = f"https://raw.githubusercontent.com/{CVELIST_REPO}/main/cves"
CVELIST_RELEASES_URL = f"https://github.com/{CVELIST_REPO}/releases/download"
CVELIST_LATEST_URL = f"https://api.github.com/repos/{CVELIST_REPO}/releases/latest"
CVELIST_DELTALOG_URL = f"{CVELIST_RAW_URL}/deltaLog.json"

NVD_MAX_WINDOW_DAYS = 120  # NVD rejects pubStartDate/pubEndDate ranges longer than this
NVD_PAGE_SIZE = 2000
NVD_MAX_PAGES = 15
SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

CACHE_TTL = 600
# url -> (monotonic expiry time, parsed response)
_cache: dict[str, tuple[float, object]] = {}
_last_nvd_request = 0.0


class SourceError(RuntimeError):
    """A data source could not be reached or returned an unusable response."""


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _nvd_timestamp(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _is_cached(url: str) -> bool:
    cached = _cache.get(url)
    return cached is not None and time.monotonic() < cached[0]


def _get(
    url: str,
    parse,
    headers: dict[str, str] | None = None,
    retries: int = 3,
    retry_on: tuple[int, ...] = (403, 429, 500, 502, 503, 504),
    ttl: float = CACHE_TTL,
):
    """Download `url`, return parse(body) and cache it for `ttl` seconds."""
    if _is_cached(url):
        return _cache[url][1]

    req = urllib.request.Request(url, headers={"User-Agent": "cvescout/0.1", **(headers or {})})
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = parse(resp.read())
            _cache[url] = (time.monotonic() + ttl, data)
            return data
        except urllib.error.HTTPError as e:
            # NVD answers 403/429 when rate limited and 503 when overloaded
            if e.code in retry_on and attempt < retries:
                time.sleep(6 * (attempt + 1))
                continue
            raise SourceError(f"{urllib.parse.urlsplit(url).netloc}: HTTP {e.code}") from e
        except (urllib.error.URLError, TimeoutError, ValueError, zipfile.BadZipFile) as e:
            if attempt < retries:
                time.sleep(2 * (attempt + 1))
                continue
            raise SourceError(f"{urllib.parse.urlsplit(url).netloc}: {e}") from e
    raise AssertionError("unreachable")


def _get_json(
    url: str,
    headers: dict[str, str] | None = None,
    retries: int = 3,
    retry_on: tuple[int, ...] = (403, 429, 500, 502, 503, 504),
) -> dict:
    return _get(url, json.loads, headers, retries, retry_on)


def _nvd_get(params: dict[str, str | int], base: str = NVD_URL) -> dict:
    """Call the NVD API, respecting its rate limit (5 req/30s, 50 with an API key)."""
    global _last_nvd_request
    api_key = os.environ.get("NVD_API_KEY")
    min_interval = 0.6 if api_key else 6.0
    url = f"{base}?{urllib.parse.urlencode(params)}"
    if not _is_cached(url):
        wait = _last_nvd_request + min_interval - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        _last_nvd_request = time.monotonic()
    return _get_json(url, headers={"apiKey": api_key} if api_key else None)


def _pick_cvss(metrics: dict) -> tuple[float | None, str | None, str | None, str | None]:
    """Return (score, severity, vector, version), preferring NVD's own (Primary) and newest CVSS."""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = next((m for m in entries if m.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData", {})
        severity = data.get("baseSeverity") or entry.get("baseSeverity")
        return data.get("baseScore"), severity, data.get("vectorString"), data.get("version")
    return None, None, None, None


# Weaknesses whose exploitation means running attacker-supplied code or commands
RCE_CWES = {"CWE-77", "CWE-78", "CWE-94", "CWE-95", "CWE-96", "CWE-917", "CWE-1336"}
# XSS runs attacker code in the victim's browser, not on the target - not RCE
XSS_CWES = {"CWE-79", "CWE-80"}
XSS_TEXT = re.compile(r"cross[- ]site scripting|\bXSS\b|in the (victim's|user's|victim’s|user’s) browser", re.IGNORECASE)
RCE_TEXT = re.compile(
    r"remote code execution|\bRCE\b|arbitrary (code|command) execution"
    r"|execut\w*\s+(of\s+)?arbitrary\s+(\w+\s+)?(code|commands?)"
    r"|(code|command) injection",
    re.IGNORECASE,
)


def is_rce(text: str, cwes: list[str], vector: str | None) -> bool:
    """Heuristic: code/command execution by CWE or wording, reachable over the network.

    If a CVSS vector is known it must say AV:N (network); a local-only code
    execution bug is not RCE.
    """
    if vector and "AV:N" not in vector:
        return False
    if XSS_CWES.intersection(cwes) or XSS_TEXT.search(text or ""):
        return False
    return bool(RCE_CWES.intersection(cwes)) or bool(RCE_TEXT.search(text or ""))


EXPLOIT_RANK = {"poc": 1, "active": 2}


def exploit_status(cve: dict) -> tuple[str | None, list[str]]:
    """('active' | 'poc' | None, exploit reference URLs) from NVD data.

    Signals: CISA SSVC "exploitation" (none/poc/active), CVSS v4 exploit
    maturity (E:P / E:A) and references NVD tagged "Exploit". KEV membership
    is added later by mark_kev_exploited/enrich.
    """
    refs = [r["url"] for r in cve.get("references", []) if "Exploit" in (r.get("tags") or [])]
    status = "poc" if refs else None

    def bump(new: str) -> None:
        nonlocal status
        if EXPLOIT_RANK[new] > EXPLOIT_RANK.get(status or "", 0):
            status = new

    metrics = cve.get("metrics", {})
    for m in metrics.get("ssvcV203", []):
        for option in m.get("ssvcData", {}).get("options", []):
            if option.get("exploitation") in EXPLOIT_RANK:
                bump(option["exploitation"])
    for m in metrics.get("cvssMetricV40", []):
        vector = m.get("cvssData", {}).get("vectorString") or ""
        if "/E:A" in vector:
            bump("active")
        elif "/E:P" in vector:
            bump("poc")
    return status, refs[:5]


def mark_kev_exploited(items: list[dict], key: str = "id") -> None:
    """Set exploit='active' on items listed in CISA KEV. Failures leave items as they are."""
    try:
        kev = kev_ids()
    except SourceError:
        return
    for i in items:
        if i.get(key) in kev:
            i["exploit"] = "active"


def apply_filters(
    items: list[dict],
    min_severity: str | None = None,
    min_score: float | None = None,
    rce: bool = False,
    match_any: bool = False,
    poc: bool = False,
) -> list[dict]:
    """Keep items meeting all given criteria (or any of them with `match_any`)."""
    checks = []
    if min_severity:
        threshold = SEVERITY_ORDER[min_severity.upper()]
        checks.append(lambda i: SEVERITY_ORDER.get(i["severity"] or "", 0) >= threshold)
    if min_score is not None:
        checks.append(lambda i: i["cvss_score"] is not None and i["cvss_score"] >= min_score)
    if rce:
        checks.append(lambda i: i["rce"])
    if poc:
        checks.append(lambda i: i.get("exploit") in EXPLOIT_RANK)
    if not checks:
        return items
    combine = any if match_any else all
    return [i for i in items if combine(check(i) for check in checks)]


def affected_products(cve: dict) -> list[str]:
    """CPE shorthands ('haxx:curl', 'o:linux:linux_kernel') NVD marks as vulnerable.

    Platforms a product merely runs on (vulnerable: false) are left out.
    """
    found = set()
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                fields = match.get("criteria", "").split(":")
                if match.get("vulnerable") and len(fields) > 4:
                    found.add(_cpe_shorthand(fields[2], fields[3], fields[4]))
    return sorted(found)


def normalize_nvd(cve: dict) -> dict:
    score, severity, vector, version = _pick_cvss(cve.get("metrics", {}))
    description = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
    )
    cwes = sorted(
        {
            d["value"]
            for w in cve.get("weaknesses", [])
            for d in w.get("description", [])
            if d.get("value", "").startswith("CWE-")
        }
    )
    exploit, exploit_refs = exploit_status(cve)
    return {
        "id": cve["id"],
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "status": cve.get("vulnStatus"),
        "description": description,
        "cvss_score": score,
        "severity": severity,
        "cvss_version": version,
        "vector": vector,
        "cwe": cwes,
        "rce": is_rce(description, cwes, vector),
        "exploit": exploit,
        "exploit_refs": exploit_refs,
        "affected_products": affected_products(cve),
        "references": [r["url"] for r in cve.get("references", [])[:5]],
        "url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
    }


def _cpe_match_string(cpe: str) -> str:
    """CPE shorthand -> NVD match string. Full 'cpe:...' strings pass through.

    'haxx:curl' -> 'cpe:2.3:a:haxx:curl' (applications are the default);
    'o:linux:linux_kernel' -> 'cpe:2.3:o:linux:linux_kernel' (o = OS, h = hardware).
    """
    if cpe.startswith("cpe:"):
        return cpe
    if cpe.count(":") >= 2 and cpe.split(":", 1)[0] in ("a", "o", "h"):
        return f"cpe:2.3:{cpe}"
    return f"cpe:2.3:a:{cpe}"


def _cpe_shorthand(part: str, vendor: str, product: str) -> str:
    """Inverse of _cpe_match_string: what to pass to --cpe."""
    return f"{vendor}:{product}" if part == "a" else f"{part}:{vendor}:{product}"


def find_cpe(query: str, limit: int = 15) -> dict:
    """Look up CPE vendor:product names in the NVD CPE dictionary.

    The dictionary has one entry per product version, so entries are grouped
    by product. Products whose name matches the query rank first, then those
    still in use, then by number of versions. Searches with very many hits
    (e.g. "node.js" matches every "... for Node.js" package) only look at the
    first 10000 entries.
    """
    data = _nvd_get({"keywordSearch": query, "resultsPerPage": 10000}, base=NVD_CPE_URL)
    products: dict[tuple[str, str, str], dict] = {}
    for entry in data.get("products", []):
        cpe = entry["cpe"]
        fields = cpe["cpeName"].split(":")
        if len(fields) < 6:
            continue
        part, vendor, product, version = fields[2], fields[3], fields[4], fields[5]
        p = products.setdefault(
            (part, vendor, product),
            {"versions": 0, "deprecated": 0, "title": None, "replaced_by": {}},
        )
        p["versions"] += 1
        if p["title"] is None:
            title = next((t["title"] for t in cpe.get("titles", []) if t.get("lang") == "en"), "")
            p["title"] = title.replace(version, "").strip() if version not in ("*", "-") else title
        if cpe.get("deprecated"):
            p["deprecated"] += 1
            for repl in cpe.get("deprecatedBy", []):
                rf = repl.get("cpeName", "").split(":")
                if len(rf) > 4:
                    key = _cpe_shorthand(rf[2], rf[3], rf[4])
                    p["replaced_by"][key] = p["replaced_by"].get(key, 0) + 1

    wanted = re.sub(r"\s+", "_", query.strip().lower())

    def rank(item: tuple[tuple[str, str, str], dict]) -> tuple:
        (_, vendor, product), p = item
        name_match = 2 if product == wanted else 1 if wanted in product else 0
        fully_deprecated = p["deprecated"] == p["versions"]
        return (-name_match, fully_deprecated, -p["versions"], vendor, product)

    results = []
    for (part, vendor, product), p in sorted(products.items(), key=rank)[:limit]:
        fully_deprecated = p["deprecated"] == p["versions"]
        replaced_by = max(p["replaced_by"], key=p["replaced_by"].get) if p["replaced_by"] else None
        results.append(
            {
                "cpe": _cpe_shorthand(part, vendor, product),
                "type": {"a": "application", "o": "os", "h": "hardware"}.get(part, part),
                "title": p["title"],
                "versions": p["versions"],
                "deprecated": fully_deprecated,
                "replaced_by": replaced_by if fully_deprecated else None,
            }
        )
    return {
        "query": query,
        "dictionary_entries": data.get("totalResults", 0),
        "scanned": len(data.get("products", [])),
        "products": results,
    }


def fetch_nvd_recent(
    days: float = 7,
    keyword: str | list[str] | None = None,
    min_severity: str | None = None,
    limit: int = 50,
    min_score: float | None = None,
    rce: bool = False,
    match_any: bool = False,
    since: str | None = None,
    cpe: str | list[str] | None = None,
    poc: bool = False,
) -> dict:
    """CVEs published since `since` (YYYY-MM-DD) or in the last `days` days, newest first.

    Several keywords/CPEs are OR-ed (one query each, merged). NVD only accepts
    date ranges up to 120 days, so a longer range needs a keyword or CPE: it is
    queried without dates and the range is applied locally.
    Filters are applied locally (see apply_filters) so that CVEs scored only
    with CVSS v4 or only by the CNA are not dropped.
    """
    end = now_utc()
    if since:
        start = datetime.fromisoformat(since).replace(tzinfo=timezone.utc)
    else:
        start = end - timedelta(days=max(days, 1 / 24))

    keywords = [keyword] if isinstance(keyword, str) else list(keyword or [])
    cpes = [cpe] if isinstance(cpe, str) else list(cpe or [])
    queries = [{"keywordSearch": k} for k in keywords] + [
        {"virtualMatchString": _cpe_match_string(c)} for c in cpes
    ]

    long_range = end - start > timedelta(days=NVD_MAX_WINDOW_DAYS)
    if long_range and not queries:
        if since:
            raise SourceError(
                f"NVD allows at most {NVD_MAX_WINDOW_DAYS} days without a keyword or CPE filter"
            )
        start, long_range = end - timedelta(days=NVD_MAX_WINDOW_DAYS), False

    found: dict[str, dict] = {}

    def add(vulns: list[dict], query: dict[str, str]) -> None:
        # A CPE also matches CVEs where the product is only the platform
        # (e.g. an app "running on" Linux); keep those where it is vulnerable.
        match = query.get("virtualMatchString")
        wanted = ":".join(match.split(":")[:5]) if match else None  # cpe:2.3:part:vendor:product
        for v in vulns:
            item = normalize_nvd(v["cve"])
            if wanted and not any(
                _cpe_match_string(a) == wanted for a in item["affected_products"]
            ):
                continue
            found[item["id"]] = item

    def fetch_pages(params: dict[str, str | int]) -> None:
        fetched = 0
        for page in range(NVD_MAX_PAGES):
            data = _nvd_get({**params, "resultsPerPage": NVD_PAGE_SIZE, "startIndex": page * NVD_PAGE_SIZE})
            vulns = data.get("vulnerabilities", [])
            fetched += len(vulns)
            add(vulns, params)
            if fetched >= data.get("totalResults", 0) or not vulns:
                break

    def windows() -> list[dict[str, str]]:
        """The range split into NVD-sized date windows."""
        result, w_start = [], start
        while w_start < end:
            w_end = min(w_start + timedelta(days=NVD_MAX_WINDOW_DAYS), end)
            result.append({"pubStartDate": _nvd_timestamp(w_start), "pubEndDate": _nvd_timestamp(w_end)})
            w_start = w_end
        return result

    for query in queries or [{}]:
        # Withdrawn IDs (duplicates, not a vulnerability) have no score or product, only noise
        query = {**query, "noRejected": ""}
        if long_range:
            # Most products have few CVEs: their whole history fits in one page,
            # which is cheaper than one request per 120-day window.
            first = _nvd_get({**query, "resultsPerPage": NVD_PAGE_SIZE, "startIndex": 0})
            vulns = first.get("vulnerabilities", [])
            if len(vulns) >= first.get("totalResults", 0):
                add(vulns, query)
                continue
        for window in windows():
            fetch_pages({**query, **window})

    start_str = start.strftime("%Y-%m-%dT%H:%M:%S")
    items = [i for i in found.values() if (i["published"] or "") >= start_str]
    in_range = len(items)  # after dropping platform-only CPE matches
    if poc:
        mark_kev_exploited(items)
    items = apply_filters(items, min_severity, min_score, rce, match_any, poc)
    items.sort(key=lambda i: i["published"] or "", reverse=True)
    return {
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
        "published_in_window": in_range,
        "matching": len(items),
        "cves": items[:limit],
    }


def fetch_nvd_cve(cve_id: str) -> dict | None:
    data = _nvd_get({"cveId": cve_id.strip().upper()})
    vulns = data.get("vulnerabilities", [])
    return normalize_nvd(vulns[0]["cve"]) if vulns else None


GHSA_ECOSYSTEMS = (
    "actions", "composer", "erlang", "go", "maven", "npm", "nuget",
    "other", "pip", "pub", "rubygems", "rust", "swift",
)


def _ghsa_get(params: dict[str, str | int]) -> list[dict]:
    """Call the GitHub Advisory API (60 req/h anonymously, 5000/h with GITHUB_TOKEN)."""
    url = f"{GHSA_URL}?{urllib.parse.urlencode(params)}"
    try:
        # 403/429 here means the hourly quota is spent; retrying within seconds won't help
        return _get_json(url, headers=_github_headers(), retry_on=(500, 502, 503, 504))  # type: ignore[return-value]
    except SourceError as e:
        if "HTTP 403" in str(e) or "HTTP 429" in str(e):
            raise SourceError(f"{e} (GitHub rate limit; set GITHUB_TOKEN to raise it)") from e
        raise


def normalize_ghsa(adv: dict) -> dict:
    cvss = adv.get("cvss_severities") or {}
    v4, v3 = cvss.get("cvss_v4") or {}, cvss.get("cvss_v3") or {}
    best = v4 if v4.get("score") else v3 if v3.get("score") else adv.get("cvss") or {}
    epss = adv.get("epss") or {}
    cwes = [c["cwe_id"] for c in adv.get("cwes") or []]
    text = f"{adv.get('summary') or ''}\n{adv.get('description') or ''}"
    return {
        "id": adv["ghsa_id"],
        "cve_id": adv.get("cve_id"),
        "published": adv.get("published_at"),
        "updated": adv.get("updated_at"),
        "type": adv.get("type"),
        "severity": (adv.get("severity") or "").upper() or None,
        "cvss_score": best.get("score") or None,
        "vector": best.get("vector_string"),
        "summary": adv.get("summary"),
        "packages": [
            {
                "ecosystem": v["package"]["ecosystem"],
                "name": v["package"]["name"],
                "vulnerable": v.get("vulnerable_version_range"),
                "patched": v.get("first_patched_version"),
            }
            for v in adv.get("vulnerabilities") or []
            if v.get("package")
        ],
        "cwe": cwes,
        "rce": is_rce(text, cwes, best.get("vector_string")),
        "exploit": None,  # GHSA has no exploit data; KEV is applied by mark_kev_exploited
        "exploit_refs": [],
        "epss": {"epss": epss["percentage"], "percentile": epss["percentile"]}
        if epss.get("percentage") is not None
        else None,
        "url": adv.get("html_url"),
    }


def fetch_ghsa_recent(
    days: float = 7,
    ecosystem: str | None = None,
    package: str | None = None,
    min_severity: str | None = None,
    include_unreviewed: bool = False,
    limit: int = 50,
    min_score: float | None = None,
    rce: bool = False,
    match_any: bool = False,
    poc: bool = False,
) -> dict:
    """GitHub security advisories published in the last `days` days, newest first.

    Reviewed advisories are curated by GitHub and name the affected package,
    vulnerable version range and first patched version. Unreviewed ones are
    mostly mirrored from NVD without package data.
    """
    since = now_utc() - timedelta(days=days)
    params: dict[str, str | int] = {
        "published": f">={since.date().isoformat()}",
        "sort": "published",
        "direction": "desc",
        # Score/RCE filters run locally, so fetch a full page to filter from
        "per_page": 100 if (min_score is not None or rce or poc) else max(1, min(limit, 100)),
    }
    if not include_unreviewed:
        params["type"] = "reviewed"
    if ecosystem:
        params["ecosystem"] = ecosystem.lower()
    if package:
        params["affects"] = package

    # The API filters on one exact severity, so ask once per severity at or above the minimum.
    # With match_any a low-severity RCE must still get through, so filter severity locally instead.
    severities = (
        [s.lower() for s, rank in SEVERITY_ORDER.items() if rank >= SEVERITY_ORDER[min_severity.upper()]]
        if min_severity and not match_any
        else [None]
    )
    advisories: dict[str, dict] = {}
    for sev in severities:
        for adv in _ghsa_get({**params, "severity": sev} if sev else params):
            advisories[adv["ghsa_id"]] = normalize_ghsa(adv)

    since_iso = since.strftime("%Y-%m-%dT%H:%M:%SZ")
    recent = [a for a in advisories.values() if (a["published"] or "") >= since_iso]
    if poc:
        mark_kev_exploited(recent, key="cve_id")
    items = sorted(
        apply_filters(recent, min_severity, min_score, rce, match_any, poc),
        key=lambda a: a["published"] or "",
        reverse=True,
    )
    # The API reports no total count, so only say how many were returned
    return {
        "published_since": since_iso,
        "returned": len(items[:limit]),
        "advisories": items[:limit],
    }


def fetch_ghsa_for_cve(cve_id: str) -> list[dict]:
    """GitHub advisories (affected packages, patched versions) for one CVE."""
    return [normalize_ghsa(a) for a in _ghsa_get({"cve_id": cve_id.strip().upper()})]


CVELIST_MAX_DAYS = 30
CVSS_KEYS = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")


def _v2_severity(score: float | None) -> str | None:
    """CVSS v2 records carry no severity label; derive it as NVD does."""
    if score is None:
        return None
    return "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"


def _version_range(v: dict) -> str:
    start = v.get("version") or ""
    if v.get("lessThan"):
        return f"{start} - <{v['lessThan']}" if start not in ("", "0") else f"<{v['lessThan']}"
    if v.get("lessThanOrEqual"):
        return f"{start} - <={v['lessThanOrEqual']}" if start not in ("", "0") else f"<={v['lessThanOrEqual']}"
    return start


def normalize_cvelist(record: dict) -> dict:
    """CVE List V5 record -> the same shape as normalize_nvd, plus `title` and `affected`.

    Data comes from the CNA (the vendor or other assigner) and from ADP
    containers, notably CISA's Vulnrichment (SSVC exploitation, KEV, CVSS
    when the CNA gave none). NVD analysis is not part of these records.
    """
    meta = record["cveMetadata"]
    cna = record.get("containers", {}).get("cna", {})
    containers = [cna, *record.get("containers", {}).get("adp", [])]

    description = next(
        (d["value"] for d in cna.get("descriptions", []) if d.get("lang", "").startswith("en")),
        next((d["value"] for d in cna.get("rejectedReasons", [])), ""),
    )

    score = severity = vector = version = None
    for key in CVSS_KEYS:  # newest CVSS version first, the CNA's before ADP's
        data = next((m[key] for c in containers for m in c.get("metrics", []) if key in m), None)
        if data:
            score, vector, version = data.get("baseScore"), data.get("vectorString"), data.get("version")
            severity = data.get("baseSeverity") or _v2_severity(score)
            break

    cwes = sorted(
        {
            d["cweId"]
            for c in containers
            for p in c.get("problemTypes", [])
            for d in p.get("descriptions", [])
            if d.get("cweId", "").startswith("CWE-")
        }
    )

    refs: dict[str, set[str]] = {}
    for c in containers:
        for r in c.get("references", []):
            refs.setdefault(r["url"], set()).update(r.get("tags") or [])
    exploit_refs = [url for url, tags in refs.items() if "exploit" in tags]

    status = "poc" if exploit_refs else None

    def bump(new: str) -> None:
        nonlocal status
        if EXPLOIT_RANK[new] > EXPLOIT_RANK.get(status or "", 0):
            status = new

    for c in containers:
        for m in c.get("metrics", []):
            other = m.get("other", {})
            if other.get("type") == "kev":
                bump("active")
            elif other.get("type") == "ssvc":
                for option in other.get("content", {}).get("options", []):
                    if option.get("Exploitation") in EXPLOIT_RANK:
                        bump(option["Exploitation"])
    if vector and "/E:A" in vector:
        bump("active")
    elif vector and "/E:P" in vector:
        bump("poc")

    products, affected = set(), []
    for c in containers:
        for applicability in c.get("cpeApplicability", []):
            for node in applicability.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    fields = match.get("criteria", "").split(":")
                    if match.get("vulnerable") and len(fields) > 4:
                        products.add(_cpe_shorthand(fields[2], fields[3], fields[4]))
        for a in c.get("affected", []):
            for cpe in a.get("cpes", []):
                fields = cpe.split(":")
                if len(fields) > 4:
                    products.add(_cpe_shorthand(fields[2], fields[3], fields[4]))
    for a in cna.get("affected", []):
        entry = {
            "vendor": a.get("vendor") or a.get("collectionURL"),
            "product": a.get("product") or a.get("packageName"),
            "versions": [_version_range(v) for v in a.get("versions", []) if v.get("status") == "affected"][:5],
        }
        if entry not in affected:
            affected.append(entry)

    return {
        "id": meta["cveId"],
        "published": meta.get("datePublished"),
        "last_modified": meta.get("dateUpdated"),
        "status": meta.get("state"),
        "title": cna.get("title"),
        "description": description,
        "cvss_score": score,
        "severity": severity,
        "cvss_version": version,
        "vector": vector,
        "cwe": cwes,
        "rce": is_rce(description, cwes, vector),
        "exploit": status,
        "exploit_refs": exploit_refs[:5],
        "affected_products": sorted(products),
        "affected": affected[:10],
        "references": list(refs)[:5],
        "url": f"https://www.cve.org/CVERecord?id={meta['cveId']}",
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{meta['cveId']}",
    }


def _cvelist_zip(url: str, keep_since: str, ttl: float) -> list[dict]:
    """Normalized records from a cvelistV5 release zip, published at or after `keep_since`."""

    def parse(body: bytes) -> list[dict]:
        items = []
        with zipfile.ZipFile(io.BytesIO(body)) as z:
            for name in z.namelist():
                if not name.endswith(".json"):
                    continue
                record = json.loads(z.read(name))
                meta = record.get("cveMetadata", {})
                if meta.get("state") == "PUBLISHED" and meta.get("datePublished", "") >= keep_since:
                    items.append(normalize_cvelist(record))
        return items

    return _get(url, parse, retry_on=(500, 502, 503, 504), ttl=ttl)


def _github_headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token := os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_cvelist_recent(
    days: float = 2,
    keyword: str | list[str] | None = None,
    min_severity: str | None = None,
    limit: int = 50,
    min_score: float | None = None,
    rce: bool = False,
    match_any: bool = False,
    since: str | None = None,
    cpe: str | list[str] | None = None,
    poc: bool = False,
) -> dict:
    """CVEs published in the last `days` days (at most 30), newest first, from the CVE List.

    CVEProject/cvelistV5 publishes a zip of every record changed each day
    (cumulative, hourly for today). Downloading those is a few MB per day and
    has no rate limit, unlike NVD; records show up minutes after publication.
    The zips miss records published shortly after midnight UTC, before the
    day's baseline is cut, so the 30-day delta log is checked for new IDs
    and any not in a zip are fetched one by one.
    Keywords match the description, title, vendor and product (OR-ed); CPEs
    match only where the CNA supplied them, which many do not.
    """
    end = now_utc()
    if since:
        start = datetime.fromisoformat(since).replace(tzinfo=timezone.utc)
    else:
        start = end - timedelta(days=max(days, 1 / 24))
    if end - start > timedelta(days=CVELIST_MAX_DAYS, hours=1):
        raise SourceError(
            f"CVE List daily files cover at most {CVELIST_MAX_DAYS} days; use NVD for longer ranges"
        )

    # Keep later versions of records published in the window (e.g. CISA adding KEV/SSVC)
    keep_since = (start - timedelta(days=1)).strftime("%Y-%m-%d")
    latest = _get_json(CVELIST_LATEST_URL, headers=_github_headers())
    latest_asset = next(
        (a for a in latest.get("assets", []) if "_delta_CVEs_at_" in a["name"]), None
    )
    if latest_asset is None:
        raise SourceError(f"github.com: no delta file in cvelistV5 release {latest.get('tag_name')}")
    latest_day = latest_asset["name"][:10]

    urls: list[tuple[str, float]] = []
    day = start.date()
    while day.isoformat() < latest_day:
        d = day.isoformat()
        # Finished days never change, so keep them cached for a day
        urls.append((f"{CVELIST_RELEASES_URL}/cve_{d}_at_end_of_day/{d}_delta_CVEs_at_end_of_day.zip", 86400))
        day += timedelta(days=1)
    urls.append((latest_asset["browser_download_url"], CACHE_TTL))

    missing: list[str] = []

    def download(entry: tuple[str, float]) -> list[dict]:
        url, ttl = entry
        try:
            return _cvelist_zip(url, keep_since, ttl)
        except SourceError as e:
            if "HTTP 404" not in str(e):
                raise
            missing.append(url.rsplit("/", 1)[-1][:10])
            return []

    found: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=6) as pool:
        for items in pool.map(download, urls):
            for item in items:
                current = found.get(item["id"])
                if current is None or (item["last_modified"] or "") > (current["last_modified"] or ""):
                    found[item["id"]] = item

    start_str = start.strftime("%Y-%m-%dT%H:%M:%S")
    log = _get_json(CVELIST_DELTALOG_URL)
    unzipped = {
        x["cveId"]
        for entry in log
        for x in entry.get("new", [])
        if x.get("dateUpdated", "") >= start_str and x["cveId"] not in found
    }
    with ThreadPoolExecutor(max_workers=16) as pool:
        for item in pool.map(fetch_cvelist_cve, sorted(unzipped)):
            if item and item["status"] == "PUBLISHED":
                found[item["id"]] = item

    items = [i for i in found.values() if (i["published"] or "") >= start_str]

    keywords = [keyword] if isinstance(keyword, str) else list(keyword or [])
    cpes = [cpe] if isinstance(cpe, str) else list(cpe or [])
    if keywords or cpes:
        wanted_kw = [k.lower() for k in keywords]
        wanted_cpe = {":".join(_cpe_match_string(c).split(":")[:5]) for c in cpes}

        def matches(i: dict) -> bool:
            text = " ".join(
                [i["description"], i["title"] or ""]
                + [f"{a['vendor']} {a['product']}" for a in i["affected"]]
            ).lower()
            return any(k in text for k in wanted_kw) or any(
                _cpe_match_string(p) in wanted_cpe for p in i["affected_products"]
            )

        items = [i for i in items if matches(i)]

    in_range = len(items)
    if poc:
        mark_kev_exploited(items)
    items = apply_filters(items, min_severity, min_score, rce, match_any, poc)
    items.sort(key=lambda i: i["published"] or "", reverse=True)
    return {
        "source": f"CVE List V5 ({CVELIST_REPO})",
        "data_as_of": latest.get("tag_name"),
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
        "missing_days": sorted(missing),
        "fetched_individually": len(unzipped),
        "published_in_window": in_range,
        "matching": len(items),
        "cves": items[:limit],
    }


def cvelist_record_url(cve_id: str) -> str:
    """Raw cvelistV5 path: CVE-2026-104596 -> cves/2026/104xxx/CVE-2026-104596.json."""
    m = re.fullmatch(r"CVE-(\d{4})-(\d{4,})", cve_id.strip().upper())
    if not m:
        raise SourceError(f"not a CVE ID: {cve_id!r}")
    year, number = m.groups()
    return f"{CVELIST_RAW_URL}/{year}/{int(number) // 1000}xxx/CVE-{year}-{number}.json"


def fetch_cvelist_cve(cve_id: str) -> dict | None:
    """One CVE as published by its CNA, straight from the CVE List (no NVD rate limit)."""
    try:
        return normalize_cvelist(_get_json(cvelist_record_url(cve_id)))
    except SourceError as e:
        if "HTTP 404" in str(e):
            return None
        raise


def fetch_kev_catalog() -> dict:
    return _get_json(KEV_URL)


def fetch_kev_recent(days: float = 30, limit: int = 100) -> dict:
    """CISA Known Exploited Vulnerabilities added in the last `days` days, newest first."""
    catalog = fetch_kev_catalog()
    since = (now_utc() - timedelta(days=days)).date().isoformat()
    entries = [v for v in catalog.get("vulnerabilities", []) if v.get("dateAdded", "") >= since]
    entries.sort(key=lambda v: (v["dateAdded"], v["cveID"]), reverse=True)
    return {
        "catalog_released": catalog.get("dateReleased"),
        "added_since": since,
        "matching": len(entries),
        "vulnerabilities": [
            {
                "id": v["cveID"],
                "date_added": v["dateAdded"],
                "vendor": v.get("vendorProject"),
                "product": v.get("product"),
                "name": v.get("vulnerabilityName"),
                "description": v.get("shortDescription"),
                "required_action": v.get("requiredAction"),
                "due_date": v.get("dueDate"),
                "ransomware": v.get("knownRansomwareCampaignUse"),
            }
            for v in entries[:limit]
        ],
    }


def kev_ids() -> set[str]:
    return {v["cveID"] for v in fetch_kev_catalog().get("vulnerabilities", [])}


def fetch_epss(cve_ids: list[str]) -> dict[str, dict]:
    """EPSS exploitation probability per CVE ({id: {"epss": float, "percentile": float}})."""
    scores: dict[str, dict] = {}
    for i in range(0, len(cve_ids), 100):
        chunk = ",".join(cve_ids[i : i + 100])
        data = _get_json(f"{EPSS_URL}?{urllib.parse.urlencode({'cve': chunk})}")
        for row in data.get("data", []):
            scores[row["cve"]] = {
                "epss": float(row["epss"]),
                "percentile": float(row["percentile"]),
            }
    return scores


def enrich(cves: list[dict], key: str = "id") -> list[dict]:
    """Add EPSS and KEV membership to items whose CVE ID is under `key`.

    Items that already carry an `epss` value (GHSA does) keep it. Failures degrade to None.
    """
    ids = [c[key] for c in cves if c.get(key) and not c.get("epss")]
    try:
        epss = fetch_epss(ids) if ids else {}
    except SourceError:
        epss = None
    try:
        kev = kev_ids()
    except SourceError:
        kev = None
    for c in cves:
        cve_id = c.get(key)
        if not c.get("epss"):
            c["epss"] = epss.get(cve_id) if epss is not None and cve_id else None
        c["in_cisa_kev"] = (cve_id in kev) if kev is not None and cve_id else None
        if c["in_cisa_kev"]:
            c["exploit"] = "active"
    return cves
