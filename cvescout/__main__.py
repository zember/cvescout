"""CLI: `python -m cvescout feed ...` (no LLM) and `python -m cvescout ask "..."` (agent)."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date

from . import sources


def _exploit_tag(item: dict) -> str:
    return {"active": " EXPLOITED", "poc": " PoC"}.get(item.get("exploit") or "", "")


def _feed(args: argparse.Namespace) -> int:
    if args.since and (args.kev or args.ghsa):
        # KEV and GHSA filter by days; GHSA returns at most the newest 100 per severity
        args.days = (sources.now_utc().date() - date.fromisoformat(args.since)).days
    try:
        if args.kev:
            data = sources.fetch_kev_recent(days=args.days, limit=args.limit)
        elif args.ghsa:
            data = sources.fetch_ghsa_recent(
                days=args.days,
                ecosystem=args.ecosystem,
                package=args.package,
                min_severity=args.severity,
                include_unreviewed=args.unreviewed,
                limit=args.limit,
                min_score=args.min_score,
                rce=args.rce,
                match_any=args.any,
                poc=args.poc,
            )
            if args.enrich:
                sources.enrich(data["advisories"], key="cve_id")
        else:
            data = sources.fetch_nvd_recent(
                days=args.days,
                keyword=args.keyword,
                min_severity=args.severity,
                limit=args.limit,
                min_score=args.min_score,
                rce=args.rce,
                match_any=args.any,
                since=args.since,
                cpe=args.cpe,
                poc=args.poc,
            )
            if args.enrich:
                sources.enrich(data["cves"])
    except sources.SourceError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return 0

    if args.kev:
        print(f"CISA KEV (catalog {data['catalog_released']}), added since {data['added_since']}: {data['matching']}")
        for v in data["vulnerabilities"]:
            print(f"{v['date_added']}  {v['id']:<18} {v['vendor']} {v['product']} - {v['name']}")
        return 0

    if args.ghsa:
        print(f"GitHub Advisory Database, published since {data['published_since']}, newest {data['returned']}:")
        for a in data["advisories"]:
            score = f"{a['cvss_score']:>4}" if a["cvss_score"] is not None else "   -"
            pkgs = ", ".join(
                f"{p['ecosystem']}:{p['name']} {p['vulnerable']} -> {p['patched'] or 'no fix'}"
                for p in a["packages"][:2]
            )
            extra = (" RCE" if a["rce"] else "") + _exploit_tag(a)
            print(
                f"{a['published'][:16]}  {a['id']:<20} {a['cve_id'] or '-':<18} {score} "
                f"{(a['severity'] or 'N/A'):<8}{extra}  {pkgs or a['summary'][:80]}"
            )
        return 0

    print(
        f"NVD {data['window_start'][:16]} -> {data['window_end'][:16]} UTC: "
        f"{data['published_in_window']} published, {data['matching']} matching, showing {len(data['cves'])}"
    )
    for c in data["cves"]:
        score = f"{c['cvss_score']:>4}" if c["cvss_score"] is not None else "   -"
        sev = (c["severity"] or "N/A")[:8]
        extra = (" RCE" if c["rce"] else "") + _exploit_tag(c)
        if args.enrich and c.get("epss"):
            extra += f" EPSS={c['epss']['epss']:.3f}"
        desc = c["description"].replace("\n", " ")[:100]
        print(f"{c['published'][:16]}  {c['id']:<18} {score} {sev:<8}{extra}  {desc}")
    return 0


def _cpe(args: argparse.Namespace) -> int:
    try:
        data = sources.find_cpe(" ".join(args.query), limit=args.limit)
    except sources.SourceError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return 0

    if not data["products"]:
        print(f"No CPE products found for {data['query']!r}.")
        return 0
    scanned = (
        f" (first {data['scanned']} of {data['dictionary_entries']} entries scanned)"
        if data["scanned"] < data["dictionary_entries"]
        else ""
    )
    print(f"CPE products for {data['query']!r}{scanned}:")
    width = max(len(p["cpe"]) for p in data["products"])
    for p in data["products"]:
        note = ""
        if p["deprecated"]:
            note = f"  [deprecated -> {p['replaced_by']}]" if p["replaced_by"] else "  [deprecated]"
        print(f"  {p['cpe']:<{width}}  {p['versions']:>5} ver.  {p['title']}{note}")
    print(f"\nUse: cvescout feed --cpe {data['products'][0]['cpe']} --since 2020-01-01")
    return 0


def _ask(args: argparse.Namespace) -> int:
    from .agent import ask

    print(ask(" ".join(args.question), verbose=args.verbose))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cvescout", description="Find the latest CVEs from live sources.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    feed = sub.add_parser("feed", help="list recently published CVEs (no LLM)")
    feed.add_argument("--days", type=float, default=2, help="look-back window in days (default 2)")
    feed.add_argument("--since", metavar="YYYY-MM-DD", help="start date instead of --days, e.g. 2020-01-01")
    feed.add_argument("--keyword", action="append", help="NVD keyword filter, e.g. openssl; repeat for OR")
    feed.add_argument(
        "--cpe", action="append", metavar="VENDOR:PRODUCT",
        help="NVD exact product, e.g. haxx:curl or nodejs:node.js; repeat for OR",
    )
    feed.add_argument("--severity", choices=list(sources.SEVERITY_ORDER), help="minimum severity")
    feed.add_argument("--min-score", type=float, metavar="N", help="minimum CVSS base score, e.g. 8")
    feed.add_argument("--rce", action="store_true", help="only likely remote code execution")
    feed.add_argument("--poc", action="store_true", help="only with a public exploit (PoC) or active exploitation")
    feed.add_argument("--any", action="store_true", help="match ANY of --severity/--min-score/--rce/--poc instead of all")
    feed.add_argument("--limit", type=int, default=30, help="max rows to show (default 30)")
    source = feed.add_mutually_exclusive_group()
    source.add_argument("--kev", action="store_true", help="CISA Known Exploited Vulnerabilities instead of NVD")
    source.add_argument("--ghsa", action="store_true", help="GitHub Advisory Database instead of NVD")
    feed.add_argument("--ecosystem", choices=sources.GHSA_ECOSYSTEMS, help="GHSA: package ecosystem")
    feed.add_argument("--package", help="GHSA: package name, e.g. lodash")
    feed.add_argument("--unreviewed", action="store_true", help="GHSA: include unreviewed advisories")
    feed.add_argument("--enrich", action="store_true", help="add EPSS and KEV status")
    feed.add_argument("--json", action="store_true")
    feed.set_defaults(func=_feed)

    cpe = sub.add_parser("cpe", help="find the CPE vendor:product name to use with feed --cpe")
    cpe.add_argument("query", nargs="+", help="product name, e.g. curl, node.js, apache http server")
    cpe.add_argument("--limit", type=int, default=15, help="max products to show (default 15)")
    cpe.add_argument("--json", action="store_true")
    cpe.set_defaults(func=_cpe)

    ask = sub.add_parser("ask", help="ask the agent (requires Anthropic credentials)")
    ask.add_argument("question", nargs="+")
    ask.add_argument("-v", "--verbose", action="store_true", help="show tool calls")
    ask.set_defaults(func=_ask)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
