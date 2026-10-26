from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit

import pytest

from cvescout import agent, sources, tools

FIXED_NOW = datetime(2026, 10, 26, 12, 0, 0, tzinfo=timezone.utc)


def _cve(cve_id, published, severity=None, score=None, key="cvssMetricV31", cpes=(), platforms=()):
    metrics = {}
    if severity:
        metrics[key] = [
            {"type": "Secondary", "cvssData": {"baseScore": score, "baseSeverity": severity, "version": "3.1"}}
        ]
    return {
        "cve": {
            "id": cve_id,
            "published": published,
            "lastModified": published,
            "vulnStatus": "Received",
            "descriptions": [{"lang": "es", "value": "x"}, {"lang": "en", "value": f"desc {cve_id}"}],
            "metrics": metrics,
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
            "references": [{"url": "https://example.com"}],
            "configurations": [{"nodes": [{"cpeMatch": [
                *({"vulnerable": True, "criteria": f"cpe:2.3:{c}:*:*:*:*:*:*:*:*"} for c in cpes),
                *({"vulnerable": False, "criteria": f"cpe:2.3:{c}:-:*:*:*:*:*:*:*"} for c in platforms),
            ]}]}],
        }
    }


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    sources._cache.clear()
    monkeypatch.setattr(sources, "now_utc", lambda: FIXED_NOW)
    monkeypatch.setattr(sources.time, "sleep", lambda s: None)


def test_nvd_window_pagination_and_sorting(monkeypatch):
    pages = {
        0: {"totalResults": 3, "vulnerabilities": [_cve("CVE-2026-1", "2026-10-24T10:00:00.000"),
                                                   _cve("CVE-2026-3", "2026-10-26T09:00:00.000")]},
        2: {"totalResults": 3, "vulnerabilities": [_cve("CVE-2026-2", "2026-10-25T10:00:00.000")]},
    }
    calls = []

    def fake_get(url, headers=None):
        q = {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}
        calls.append(q)
        return pages[int(q["startIndex"]) // 1000]

    monkeypatch.setattr(sources, "NVD_PAGE_SIZE", 2000)
    monkeypatch.setattr(sources, "_get_json", fake_get)
    # second page lands at startIndex 2000 -> key 2
    data = sources.fetch_nvd_recent(days=3, limit=10)

    assert calls[0]["pubStartDate"] == "2026-10-23T12:00:00.000Z"
    assert calls[0]["pubEndDate"] == "2026-10-26T12:00:00.000Z"
    assert [c["startIndex"] for c in calls] == ["0", "2000"]
    assert [c["id"] for c in data["cves"]] == ["CVE-2026-3", "CVE-2026-2", "CVE-2026-1"]
    assert data["cves"][0]["description"] == "desc CVE-2026-3"


def test_nvd_window_is_capped_at_120_days(monkeypatch):
    seen = {}

    def fake_get(url, headers=None):
        seen.update({k: v[0] for k, v in parse_qs(urlsplit(url).query).items()})
        return {"totalResults": 0, "vulnerabilities": []}

    monkeypatch.setattr(sources, "_get_json", fake_get)
    sources.fetch_nvd_recent(days=400)
    assert seen["pubStartDate"] == "2026-06-28T12:00:00.000Z"


def test_min_severity_filter_includes_v4_only_scores(monkeypatch):
    vulns = [
        _cve("CVE-2026-10", "2026-10-26T01:00:00.000", "CRITICAL", 9.8),
        _cve("CVE-2026-11", "2026-10-26T02:00:00.000", "HIGH", 8.1, key="cvssMetricV40"),
        _cve("CVE-2026-12", "2026-10-26T03:00:00.000", "LOW", 2.0),
        _cve("CVE-2026-13", "2026-10-26T04:00:00.000"),
    ]
    monkeypatch.setattr(sources, "_get_json", lambda url, headers=None: {"totalResults": 4, "vulnerabilities": vulns})
    data = sources.fetch_nvd_recent(days=1, min_severity="HIGH")
    assert [c["id"] for c in data["cves"]] == ["CVE-2026-11", "CVE-2026-10"]
    assert data["published_in_window"] == 4


def test_kev_filters_by_date_added_not_catalog_order(monkeypatch):
    catalog = {
        "dateReleased": "2026-10-23T19:30:18Z",
        "vulnerabilities": [
            {"cveID": "CVE-2026-500", "dateAdded": "2026-10-20"},
            {"cveID": "CVE-2014-1", "dateAdded": "2026-10-22"},  # old CVE, newly exploited
            {"cveID": "CVE-2020-29583", "dateAdded": "2021-11-03"},
        ],
    }
    monkeypatch.setattr(sources, "_get_json", lambda url, headers=None: catalog)
    data = sources.fetch_kev_recent(days=30)
    assert data["added_since"] == "2026-09-26"
    assert [v["id"] for v in data["vulnerabilities"]] == ["CVE-2014-1", "CVE-2026-500"]


def test_enrich_degrades_when_sources_fail(monkeypatch):
    def boom(*a, **k):
        raise sources.SourceError("down")

    monkeypatch.setattr(sources, "_get_json", boom)
    cves = sources.enrich([{"id": "CVE-2026-1"}])
    assert cves[0]["epss"] is None and cves[0]["in_cisa_kev"] is None


def test_find_unsourced_cves():
    tools.seen_cve_ids.clear()
    tools.seen_cve_ids.update({"CVE-2026-114820"})
    text = "New: CVE-2026-114820. Also remember cve-2021-44228 (Log4Shell)."
    assert agent.find_unsourced_cves(text) == {"CVE-2021-44228"}


def _adv(ghsa_id, cve_id, published, severity="high", epss=None):
    return {
        "ghsa_id": ghsa_id,
        "cve_id": cve_id,
        "html_url": f"https://github.com/advisories/{ghsa_id}",
        "summary": f"summary {ghsa_id}",
        "type": "reviewed",
        "severity": severity,
        "published_at": published,
        "updated_at": published,
        "vulnerabilities": [
            {"package": {"ecosystem": "pip", "name": "filelock"},
             "vulnerable_version_range": ">= 4.1.0, <= 4.2.0", "first_patched_version": "4.2.1"}
        ],
        "cvss_severities": {"cvss_v3": {"vector_string": "CVSS:3.1/AV:L", "score": 6.1},
                            "cvss_v4": {"vector_string": None, "score": 0.0}},
        "cwes": [{"cwe_id": "CWE-367", "name": "TOCTOU"}],
        "epss": epss,
    }


def test_normalize_ghsa_prefers_scored_cvss_and_maps_epss():
    a = sources.normalize_ghsa(_adv("GHSA-1", "CVE-2026-1", "2026-10-25T00:00:00Z",
                                    epss={"percentage": 0.0016, "percentile": 0.05}))
    assert a["cvss_score"] == 6.1 and a["vector"] == "CVSS:3.1/AV:L"
    assert a["severity"] == "HIGH"
    assert a["packages"] == [{"ecosystem": "pip", "name": "filelock",
                              "vulnerable": ">= 4.1.0, <= 4.2.0", "patched": "4.2.1"}]
    assert a["epss"] == {"epss": 0.0016, "percentile": 0.05}


def test_ghsa_queries_each_severity_and_filters_window(monkeypatch):
    by_sev = {
        "high": [_adv("GHSA-h", "CVE-2026-2", "2026-10-25T10:00:00Z", "high"),
                 # same calendar day as the window start but before it -> dropped
                 _adv("GHSA-old", None, "2026-10-19T08:00:00Z", "high")],
        "critical": [_adv("GHSA-c", "CVE-2026-3", "2026-10-26T10:00:00Z", "critical")],
    }
    calls = []

    def fake_get(url, headers=None, retry_on=()):
        q = {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}
        calls.append(q)
        return by_sev[q["severity"]]

    monkeypatch.setattr(sources, "_get_json", fake_get)
    data = sources.fetch_ghsa_recent(days=7, ecosystem="PIP", min_severity="HIGH")

    assert [c["severity"] for c in calls] == ["high", "critical"]
    assert all(c["published"] == ">=2026-10-19" and c["type"] == "reviewed" and c["ecosystem"] == "pip"
               for c in calls)
    assert [a["id"] for a in data["advisories"]] == ["GHSA-c", "GHSA-h"]


def test_ghsa_rate_limit_is_not_retried(monkeypatch):
    seen = {}

    def fake_get(url, headers=None, retry_on=()):
        seen["retry_on"] = retry_on
        seen["auth"] = (headers or {}).get("Authorization")
        raise sources.SourceError("api.github.com: HTTP 403")

    monkeypatch.setenv("GITHUB_TOKEN", "t0k")
    monkeypatch.setattr(sources, "_get_json", fake_get)
    with pytest.raises(sources.SourceError, match="GITHUB_TOKEN"):
        sources.fetch_ghsa_recent(days=1)
    assert 403 not in seen["retry_on"] and seen["auth"] == "Bearer t0k"


def test_enrich_keeps_existing_epss_and_handles_missing_cve(monkeypatch):
    monkeypatch.setattr(sources, "fetch_epss", lambda ids: {i: {"epss": 0.5, "percentile": 0.9} for i in ids})
    monkeypatch.setattr(sources, "kev_ids", lambda: {"CVE-2026-2"})
    items = [
        {"cve_id": "CVE-2026-1", "epss": {"epss": 0.1, "percentile": 0.2}},
        {"cve_id": "CVE-2026-2", "epss": None},
        {"cve_id": None, "epss": None},
    ]
    sources.enrich(items, key="cve_id")
    assert items[0]["epss"]["epss"] == 0.1 and items[0]["in_cisa_kev"] is False
    assert items[1]["epss"]["epss"] == 0.5 and items[1]["in_cisa_kev"] is True
    assert items[2]["epss"] is None and items[2]["in_cisa_kev"] is None


@pytest.mark.parametrize(
    "text,cwes,vector,expected",
    [
        ("Allows remote code execution via crafted request.", [], "CVSS:3.1/AV:N/AC:L", True),
        ("An attacker can execute arbitrary OS commands.", [], None, True),
        ("Unauthenticated RCE in the admin panel.", [], None, True),
        ("Improper input handling.", ["CWE-78"], "CVSS:3.1/AV:N/AC:L", True),
        ("Local user can execute arbitrary code.", [], "CVSS:3.1/AV:L/AC:L", False),
        ("Reflected XSS in search page.", ["CWE-79"], "CVSS:3.1/AV:N/AC:L", False),
        ("SQL injection leads to data disclosure.", ["CWE-89"], None, False),
    ],
)
def test_is_rce(text, cwes, vector, expected):
    assert sources.is_rce(text, cwes, vector) is expected


def _item(i, score, rce, severity=None):
    return {"id": i, "cvss_score": score, "rce": rce, "severity": severity}


def test_apply_filters_all_vs_any():
    items = [
        _item("rce-low", 6.5, True, "MEDIUM"),
        _item("high-score", 8.8, False, "HIGH"),
        _item("both", 9.8, True, "CRITICAL"),
        _item("neither", 5.0, False, "MEDIUM"),
        _item("unscored-rce", None, True),
    ]
    ids = lambda xs: [x["id"] for x in xs]
    assert ids(sources.apply_filters(items, min_score=8, rce=True)) == ["both"]
    assert ids(sources.apply_filters(items, min_score=8, rce=True, match_any=True)) == [
        "rce-low", "high-score", "both", "unscored-rce"]
    assert ids(sources.apply_filters(items, min_score=8)) == ["high-score", "both"]
    assert sources.apply_filters(items) == items


def test_ghsa_match_any_skips_server_side_severity(monkeypatch):
    calls = []

    def fake_get(url, headers=None, retry_on=()):
        calls.append({k: v[0] for k, v in parse_qs(urlsplit(url).query).items()})
        return []

    monkeypatch.setattr(sources, "_get_json", fake_get)
    sources.fetch_ghsa_recent(days=7, min_severity="HIGH", rce=True, match_any=True, limit=5)
    assert len(calls) == 1 and "severity" not in calls[0] and calls[0]["per_page"] == "100"


def test_long_range_with_keywords_queries_without_dates_and_ors(monkeypatch):
    by_kw = {
        "node.js": [_cve("CVE-2019-1", "2019-12-31T23:00:00.000"), _cve("CVE-2021-5", "2021-03-01T00:00:00.000"),
                    _cve("CVE-2024-9", "2024-05-01T00:00:00.000")],
        "cpe:2.3:a:haxx:curl": [_cve("CVE-2024-9", "2024-05-01T00:00:00.000", cpes=["a:haxx:curl"]),
                                _cve("CVE-2023-7", "2023-01-01T00:00:00.000", cpes=["a:haxx:curl"])],
    }
    calls = []

    def fake_get(url, headers=None):
        q = {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}
        calls.append(q)
        vulns = by_kw[q.get("keywordSearch") or q.get("virtualMatchString")]
        return {"totalResults": len(vulns), "vulnerabilities": vulns}

    monkeypatch.setattr(sources, "_get_json", fake_get)
    data = sources.fetch_nvd_recent(since="2020-01-01", keyword=["node.js"], cpe=["haxx:curl"])

    assert all("pubStartDate" not in c for c in calls) and len(calls) == 2
    assert [c["id"] for c in data["cves"]] == ["CVE-2024-9", "CVE-2023-7", "CVE-2021-5"]


def test_long_range_without_filter_is_rejected(monkeypatch):
    monkeypatch.setattr(sources, "_get_json", lambda *a, **k: pytest.fail("no request expected"))
    with pytest.raises(sources.SourceError, match="120 days"):
        sources.fetch_nvd_recent(since="2020-01-01")


def test_xss_is_not_rce():
    text = "Reflected cross site scripting may allow an attacker to execute arbitrary JavaScript code in the victim's browser."
    assert sources.is_rce(text, ["CWE-79", "CWE-94"], "CVSS:3.1/AV:N/AC:L") is False


def test_exploit_status_signals():
    base = _cve("CVE-2026-1", "2026-10-26T00:00:00.000")["cve"]
    assert sources.exploit_status(base) == (None, [])

    tagged = {**base, "references": [{"url": "https://exploit-db.com/x", "tags": ["Exploit", "Third Party Advisory"]},
                                     {"url": "https://vendor/patch", "tags": ["Patch"]}]}
    assert sources.exploit_status(tagged) == ("poc", ["https://exploit-db.com/x"])

    ssvc = {**base, "metrics": {"ssvcV203": [{"ssvcData": {"options": [{"exploitation": "active"}]}}]}}
    assert sources.exploit_status(ssvc)[0] == "active"

    v4 = {**base, "metrics": {"cvssMetricV40": [{"cvssData": {"vectorString": "CVSS:4.0/AV:N/E:P"}}]}}
    assert sources.exploit_status(v4)[0] == "poc"


def test_poc_filter_counts_kev_as_exploited(monkeypatch):
    vulns = [_cve("CVE-2026-1", "2026-10-26T01:00:00.000"), _cve("CVE-2026-2", "2026-10-26T02:00:00.000")]
    vulns[0]["cve"]["references"] = [{"url": "https://poc", "tags": ["Exploit"]}]
    monkeypatch.setattr(sources, "_get_json", lambda url, headers=None: {"totalResults": 2, "vulnerabilities": vulns})
    monkeypatch.setattr(sources, "kev_ids", lambda: {"CVE-2026-2"})
    data = sources.fetch_nvd_recent(days=1, poc=True)
    assert {c["id"]: c["exploit"] for c in data["cves"]} == {"CVE-2026-2": "active", "CVE-2026-1": "poc"}


@pytest.mark.parametrize(
    "short,full",
    [
        ("haxx:curl", "cpe:2.3:a:haxx:curl"),
        ("o:linux:linux_kernel", "cpe:2.3:o:linux:linux_kernel"),
        ("h:cisco:asa_5505", "cpe:2.3:h:cisco:asa_5505"),
        ("cpe:2.3:a:nodejs:node.js", "cpe:2.3:a:nodejs:node.js"),
    ],
)
def test_cpe_match_string(short, full):
    assert sources._cpe_match_string(short) == full


def _cpe_entry(name, title, deprecated=False, replaced_by=None):
    e = {"cpeName": name, "deprecated": deprecated, "titles": [{"title": title, "lang": "en"}]}
    if replaced_by:
        e["deprecatedBy"] = [{"cpeName": replaced_by}]
    return {"cpe": e}


def test_find_cpe_groups_versions_and_ranks_name_match_first(monkeypatch):
    entries = [
        # many versions of an unrelated "for Node.js" package must not outrank the runtime
        *[_cpe_entry(f"cpe:2.3:a:droppy_project:droppy:5.{i}:*:*:*:*:*:*:*", f"droppy 5.{i} for Node.js") for i in range(9)],
        _cpe_entry("cpe:2.3:a:nodejs:node.js:20.1.0:*:*:*:*:*:*:*", "nodejs Node.js 20.1.0"),
        _cpe_entry("cpe:2.3:a:nodejs:node.js:22.0.0:*:*:*:*:*:*:*", "nodejs Node.js 22.0.0"),
        _cpe_entry("cpe:2.3:a:joyent:node.js:0.6.1:*:*:*:*:*:*:*", "Joyent Node.js 0.6.1",
                   deprecated=True, replaced_by="cpe:2.3:a:nodejs:node.js:0.6.1:*:*:*:*:*:*:*"),
        _cpe_entry("cpe:2.3:o:linux:linux_kernel:6.1:*:*:*:*:*:*:*", "Linux Kernel 6.1 node.js"),
    ]
    seen = {}

    def fake_get(url, headers=None):
        seen["url"] = url
        return {"totalResults": 20000, "products": entries}

    monkeypatch.setattr(sources, "_get_json", fake_get)
    data = sources.find_cpe("node.js")

    assert seen["url"].startswith(sources.NVD_CPE_URL)
    assert data["scanned"] == len(entries) and data["dictionary_entries"] == 20000
    cpes = [p["cpe"] for p in data["products"]]
    assert cpes[:2] == ["nodejs:node.js", "joyent:node.js"]  # exact name; live before deprecated
    assert data["products"][0] == {"cpe": "nodejs:node.js", "type": "application", "title": "nodejs Node.js",
                                   "versions": 2, "deprecated": False, "replaced_by": None}
    assert data["products"][1]["deprecated"] and data["products"][1]["replaced_by"] == "nodejs:node.js"
    assert "o:linux:linux_kernel" in cpes


def test_long_range_large_product_switches_to_date_windows(monkeypatch):
    k = "o:linux:linux_kernel"
    calls = []

    def fake_get(url, headers=None):
        q = {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}
        calls.append(q)
        if "pubStartDate" not in q:  # whole-history probe: too many to fit in one page
            return {"totalResults": 5000, "vulnerabilities": [_cve("CVE-2010-1", "2010-01-01T00:00:00.000", cpes=[k])]}
        if q["pubStartDate"].startswith("2026-05"):
            return {"totalResults": 1, "vulnerabilities": [_cve("CVE-2026-8", "2026-08-01T00:00:00.000", cpes=[k])]}
        return {"totalResults": 2, "vulnerabilities": [
            _cve("CVE-2026-2", "2026-02-01T00:00:00.000", cpes=[k]),
            # an app that only runs on Linux: kernel listed as non-vulnerable platform
            _cve("CVE-2026-3", "2026-02-02T00:00:00.000", cpes=["a:zammad:zammad"], platforms=[k]),
        ]}

    monkeypatch.setattr(sources, "_get_json", fake_get)
    data = sources.fetch_nvd_recent(since="2026-01-01", cpe="o:linux:linux_kernel")

    windows = [(c["pubStartDate"][:10], c["pubEndDate"][:10]) for c in calls[1:]]
    assert windows == [("2026-01-01", "2026-05-01"), ("2026-05-01", "2026-08-29"), ("2026-08-29", "2026-10-26")]
    assert all(c["virtualMatchString"] == "cpe:2.3:o:linux:linux_kernel" for c in calls)
    assert [c["id"] for c in data["cves"]] == ["CVE-2026-8", "CVE-2026-2"]  # probe's old CVE not kept


def test_affected_products_ignores_platforms():
    cve = _cve("CVE-2026-1", "2026-10-26T00:00:00.000", cpes=["a:zammad:zammad", "o:linux:linux_kernel"],
               platforms=["a:docker:docker"])["cve"]
    assert sources.affected_products(cve) == ["o:linux:linux_kernel", "zammad:zammad"]


def test_full_cpe_with_version_still_matches_product(monkeypatch):
    vulns = [_cve("CVE-2023-7", "2023-01-01T00:00:00.000", cpes=["a:haxx:curl"])]
    monkeypatch.setattr(sources, "_get_json", lambda url, headers=None: {"totalResults": 1, "vulnerabilities": vulns})
    data = sources.fetch_nvd_recent(since="2020-01-01", cpe="cpe:2.3:a:haxx:curl:7.88.0:*:*:*:*:*:*:*")
    assert [c["id"] for c in data["cves"]] == ["CVE-2023-7"]


def _rec(cve_id, published, updated=None, score=None, kev=False, product="widget", desc=None, state="PUBLISHED"):
    cna = {
        "title": f"title {cve_id}",
        "descriptions": [{"lang": "en-US", "value": desc or f"desc {cve_id}"}],
        "affected": [{"vendor": "Acme", "product": product,
                      "versions": [{"version": "1.0", "lessThan": "1.4", "status": "affected"},
                                   {"version": "1.4", "status": "unaffected"}]}],
        "references": [{"url": "https://example.com/advisory", "tags": ["vendor-advisory"]}],
    }
    if score is not None:
        cna["metrics"] = [{"cvssV3_1": {"baseScore": score, "baseSeverity": "HIGH" if score < 9 else "CRITICAL",
                                        "vectorString": "CVSS:3.1/AV:N/AC:L", "version": "3.1"}}]
    adp = [{"metrics": [{"other": {"type": "kev", "content": {"dateAdded": "2026-10-25"}}}]}] if kev else []
    return {
        "cveMetadata": {"cveId": cve_id, "state": state, "datePublished": published,
                        "dateUpdated": updated or published},
        "containers": {"cna": cna, "adp": adp},
    }


def _zip(*records):
    import io
    import json
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for r in records:
            z.writestr(f"deltaCves/{r['cveMetadata']['cveId']}.json", json.dumps(r))
    return buf.getvalue()


def test_normalize_cvelist_merges_cna_and_adp():
    rec = _rec("CVE-2026-7", "2026-10-26T09:00:00.000Z", kev=True)
    rec["containers"]["cna"]["problemTypes"] = [{"descriptions": [{"cweId": "CWE-78", "type": "CWE"}]}]
    rec["containers"]["adp"].append({
        "metrics": [{"cvssV2_0": {"baseScore": 7.5, "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P", "version": "2.0"}}],
        "references": [{"url": "https://example.com/poc", "tags": ["exploit"]}],
        "affected": [{"cpes": ["cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"]}],
    })
    c = sources.normalize_cvelist(rec)
    assert (c["cvss_score"], c["severity"], c["cvss_version"]) == (7.5, "HIGH", "2.0")
    assert c["exploit"] == "active" and c["exploit_refs"] == ["https://example.com/poc"]
    assert c["rce"] and c["cwe"] == ["CWE-78"]
    assert c["affected_products"] == ["acme:widget"]
    assert c["affected"] == [
        {"vendor": "Acme", "product": "widget", "versions": ["1.0 - <1.4"], "default_status": None}
    ]


@pytest.mark.parametrize("cve_id, path", [
    ("CVE-2026-104596", "2026/104xxx/CVE-2026-104596.json"),
    ("cve-2021-1234", "2021/1xxx/CVE-2021-1234.json"),
    ("CVE-2014-0160", "2014/0xxx/CVE-2014-0160.json"),
])
def test_cvelist_record_url(cve_id, path):
    assert sources.cvelist_record_url(cve_id) == f"{sources.CVELIST_RAW_URL}/{path}"


def test_cvelist_record_url_rejects_garbage():
    with pytest.raises(sources.SourceError):
        sources.cvelist_record_url("GHSA-xxxx-yyyy")


def _fake_cvelist(monkeypatch, zips, log=(), records=None):
    """zips: {url suffix: zip bytes or None (404)}; records: {cve_id: record} for raw fetches."""
    requested = []

    def fake_get(url, parse, headers=None, retries=3, retry_on=(), ttl=0):
        requested.append(url)
        if url == sources.CVELIST_LATEST_URL:
            return {"tag_name": "cve_2026-10-26_1100Z", "assets": [
                {"name": "2026-10-26_all_CVEs_at_midnight.zip.zip", "browser_download_url": "all.zip"},
                {"name": "2026-10-26_delta_CVEs_at_1100Z.zip", "browser_download_url": "latest.zip"},
            ]}
        if url == sources.CVELIST_DELTALOG_URL:
            return list(log)
        if url == sources.KEV_URL:
            return {"vulnerabilities": []}
        for suffix, body in zips.items():
            if url.endswith(suffix):
                if body is None:
                    raise sources.SourceError("github.com: HTTP 404")
                return parse(body)
        for cve_id, rec in (records or {}).items():
            if url == sources.cvelist_record_url(cve_id):
                return rec
        raise AssertionError(f"unexpected url {url}")

    monkeypatch.setattr(sources, "_get", fake_get)
    return requested


def test_cvelist_recent_merges_days_and_fills_gaps_from_delta_log(monkeypatch):
    zips = {
        "2026-10-24_delta_CVEs_at_end_of_day.zip": _zip(
            _rec("CVE-2026-1", "2026-10-24T10:00:00.000Z"),  # before the window
            _rec("CVE-2026-2", "2026-10-24T13:00:00.000Z", score=9.8),
        ),
        "2026-10-25_delta_CVEs_at_end_of_day.zip": _zip(
            # later version of CVE-2026-2: CISA added it to KEV
            _rec("CVE-2026-2", "2026-10-24T13:00:00.000Z", "2026-10-25T08:00:00.000Z", score=9.8, kev=True),
            _rec("CVE-2026-9", "2026-10-25T09:00:00.000Z", state="REJECTED"),
        ),
        "latest.zip": _zip(_rec("CVE-2026-3", "2026-10-26T09:00:00.000Z", score=5.0)),
    }
    log = [{"new": [
        {"cveId": "CVE-2026-3", "dateUpdated": "2026-10-26T09:00:00.000Z"},
        {"cveId": "CVE-2026-1004", "dateUpdated": "2026-10-26T00:30:00.000Z"},  # missing from every zip
        {"cveId": "CVE-2026-1005", "dateUpdated": "2026-10-20T00:30:00.000Z"},  # before the window
    ]}]
    records = {"CVE-2026-1004": _rec("CVE-2026-1004", "2026-10-26T00:30:00.000Z")}
    requested = _fake_cvelist(monkeypatch, zips, log, records)

    data = sources.fetch_cvelist_recent(days=2)
    assert [c["id"] for c in data["cves"]] == ["CVE-2026-3", "CVE-2026-1004", "CVE-2026-2"]
    assert data["cves"][2]["exploit"] == "active"
    assert data["fetched_individually"] == 1 and data["missing_days"] == []
    assert data["data_as_of"] == "cve_2026-10-26_1100Z"
    assert "all.zip" not in requested

    data = sources.fetch_cvelist_recent(days=2, min_score=9, poc=True)
    assert [c["id"] for c in data["cves"]] == ["CVE-2026-2"]


def test_cvelist_keywords_match_products_and_missing_day_is_reported(monkeypatch):
    zips = {
        "2026-10-25_delta_CVEs_at_end_of_day.zip": None,
        "latest.zip": _zip(
            _rec("CVE-2026-20", "2026-10-26T09:00:00.000Z", product="NGINX Plus"),
            _rec("CVE-2026-21", "2026-10-26T10:00:00.000Z", desc="Bug in libcurl before 8.20"),
            _rec("CVE-2026-22", "2026-10-26T11:00:00.000Z"),
        ),
    }
    _fake_cvelist(monkeypatch, zips)
    data = sources.fetch_cvelist_recent(days=1, keyword=["nginx", "CURL"])
    assert [c["id"] for c in data["cves"]] == ["CVE-2026-21", "CVE-2026-20"]
    assert data["missing_days"] == ["2026-10-25"]


def test_cvelist_rejects_ranges_over_30_days():
    with pytest.raises(sources.SourceError, match="30 days"):
        sources.fetch_cvelist_recent(since="2026-09-01")


def test_cve_details_falls_back_to_cvelist_when_nvd_is_down(monkeypatch):
    def nvd_down(cve_id):
        raise sources.SourceError("services.nvd.nist.gov: HTTP 503")

    monkeypatch.setattr(sources, "fetch_nvd_cve", nvd_down)
    monkeypatch.setattr(sources, "fetch_cvelist_cve",
                        lambda cve_id: sources.normalize_cvelist(_rec(cve_id, "2026-10-26T09:00:00.000Z")))
    monkeypatch.setattr(sources, "enrich", lambda items, key="id": items)
    monkeypatch.setattr(sources, "fetch_ghsa_for_cve", lambda cve_id: [])
    import json

    data = json.loads(tools.get_cve_details.func("CVE-2026-30"))
    assert data["id"] == "CVE-2026-30" and "NVD unavailable" in data["note"]
    assert data["affected"][0]["versions"] == ["1.0 - <1.4"]


def test_mcp_server_exposes_all_tools_read_only():
    import asyncio

    from mcp import Client

    from cvescout.mcp_server import server

    async def list_tools():
        async with Client(server) as client:
            return (await client.list_tools()).tools

    listed = {t.name: t for t in asyncio.run(list_tools())}
    assert set(listed) == {t.name for t in tools.ALL_TOOLS}
    assert "source" in listed["search_recent_cves"].input_schema["properties"]
    assert all(t.annotations.read_only_hint for t in listed.values())


def test_nvd_searches_skip_rejected_cves(monkeypatch):
    calls = []

    def fake_get(url, headers=None):
        calls.append(parse_qs(urlsplit(url).query, keep_blank_values=True))
        return {"totalResults": 0, "vulnerabilities": []}

    monkeypatch.setattr(sources, "_get_json", fake_get)
    sources.fetch_nvd_recent(days=2)
    sources.fetch_nvd_recent(since="2020-01-01", cpe="haxx:curl")
    sources.fetch_nvd_cve("CVE-2026-1234")  # a direct lookup still shows a rejection
    assert [("noRejected" in q) for q in calls] == [True, True, False]


@pytest.mark.parametrize("item, score, priority", [
    # exploited now beats everything, even with a low CVSS
    ({"cvss_score": 5.0, "exploit": "active", "in_cisa_kev": True, "epss": {"epss": 0.002}}, 70, "critical"),
    ({"cvss_score": 9.8, "exploit": "poc", "rce": True, "epss": {"epss": 0.01}}, 84, "high"),
    # high EPSS alone counts like a PoC
    ({"cvss_score": 8.0, "epss": {"epss": 0.5}}, 67, "high"),
    ({"cvss_score": 9.8, "rce": True, "epss": {"epss": 0.0004}}, 49, "high"),
    ({"cvss_score": 9.8, "epss": {"epss": 0.0004}}, 39, "medium"),
    ({"cvss_score": 4.3, "exploit": "poc", "epss": {"epss": 0.001}}, 52, "medium"),
    ({"cvss_score": 4.3, "epss": None}, 17, "low"),
    ({"cvss_score": None, "exploit": "poc", "epss": None}, 55, "high"),
])
def test_risk(item, score, priority):
    r = sources.risk(item)
    assert (r["score"], r["priority"]) == (score, priority)


def test_risk_factors_explain_the_score():
    r = sources.risk({"cvss_score": None, "exploit": "active", "in_cisa_kev": True, "rce": True,
                      "epss": {"epss": 0.99981}})
    assert r["factors"] == ["actively exploited (CISA KEV)", "EPSS 99.98%", "no CVSS (counted as 5.0)", "likely RCE"]


def test_add_risk_sorts_by_priority_then_score(monkeypatch):
    monkeypatch.setattr(sources, "enrich", lambda items, key="id": items)
    items = [
        {"id": "CVE-2026-1", "published": "2026-10-26", "cvss_score": 10.0, "epss": {"epss": 0.001}},
        {"id": "CVE-2026-2", "published": "2026-10-20", "cvss_score": 6.5, "exploit": "active", "epss": None},
        {"id": "CVE-2026-3", "published": "2026-10-25", "cvss_score": 8.1, "exploit": "poc", "epss": None},
    ]
    ranked = [i["id"] for i in sources.add_risk(items, sort=True)]
    assert ranked == ["CVE-2026-2", "CVE-2026-3", "CVE-2026-1"]


def test_epss_uses_bulk_file_for_many_cves(monkeypatch):
    import gzip

    body = gzip.compress(b"#model_version:v1,score_date:2026-10-26\ncve,epss,percentile\nCVE-2026-1000,0.5,0.99\n")
    urls = []

    def fake_get(url, parse, headers=None, retries=3, retry_on=(), ttl=0):
        urls.append(url)
        return parse(body)

    monkeypatch.setattr(sources, "_get", fake_get)
    ids = [f"CVE-2026-{n}" for n in range(1000, 1000 + sources.EPSS_BULK_THRESHOLD + 1)]
    scores = sources.fetch_epss(ids)
    assert urls == [sources.EPSS_BULK_URL]
    assert scores == {"CVE-2026-1000": {"epss": 0.5, "percentile": 0.99}}


def test_feed_sort_risk_ranks_all_matches_before_limit(monkeypatch, capsys):
    from cvescout.__main__ import main

    seen = {}

    def fake_fetch(**kwargs):
        seen.update(kwargs)
        return {"window_start": "2026-10-19T12:00", "window_end": "2026-10-26T12:00",
                "published_in_window": 2, "matching": 2, "cves": [
                    {"id": "CVE-2026-1", "published": "2026-10-26", "cvss_score": 9.0, "severity": "CRITICAL",
                     "rce": False, "exploit": None, "epss": {"epss": 0.001}, "description": "newest"},
                    {"id": "CVE-2026-2", "published": "2026-10-20", "cvss_score": 7.0, "severity": "HIGH",
                     "rce": False, "exploit": "active", "epss": {"epss": 0.3}, "description": "exploited"},
                ]}

    monkeypatch.setattr(sources, "fetch_nvd_recent", fake_fetch)
    monkeypatch.setattr(sources, "enrich", lambda items, key="id": items)
    assert main(["feed", "--days", "7", "--sort", "risk", "--limit", "1"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert seen["limit"] > 1
    assert len(out) == 2 and "CVE-2026-2" in out[1] and "critical" in out[1]
