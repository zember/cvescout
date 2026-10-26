"""CLI: `python -m cvescout feed ...` (no LLM), `python -m cvescout ask "..."` (agent)
and `python -m cvescout mcp` (MCP server for other agents)."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date

from . import sources


def _exploit_tag(item: dict) -> str:
    return {"active": " EXPLOITED", "poc": " PoC"}.get(item.get("exploit") or "", "")


def _risk_tag(item: dict) -> str:
    r = item.get("risk")
    return f"{r['score']:>3} {r['priority']:<8} " if r else ""


def _feed(args: argparse.Namespace) -> int:
    if args.url and not args.cvelist:
        print("error: --url works only with --cvelist", file=sys.stderr)
        return 1
    by_risk = args.sort == "risk"
    # Ranking by risk needs every match, not just the newest `limit`
    fetch_limit = 100_000 if by_risk else args.limit
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
                limit=100 if by_risk else args.limit,
                min_score=args.min_score,
                rce=args.rce,
                match_any=args.any,
                poc=args.poc,
            )
            if args.enrich or by_risk:
                sources.add_risk(data["advisories"], key="cve_id", sort=by_risk)
                data["advisories"] = data["advisories"][: args.limit]
        else:
            fetch = sources.fetch_cvelist_recent if args.cvelist else sources.fetch_nvd_recent
            data = fetch(
                **({"url": args.url} if args.cvelist else {}),
                days=args.days,
                keyword=args.keyword,
                min_severity=args.severity,
                limit=fetch_limit,
                min_score=args.min_score,
                rce=args.rce,
                match_any=args.any,
                since=args.since,
                cpe=args.cpe,
                poc=args.poc,
            )
            if args.enrich or by_risk:
                sources.add_risk(data["cves"], sort=by_risk)
                data["cves"] = data["cves"][: args.limit]
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
                f"{(a['severity'] or 'N/A'):<8} {_risk_tag(a)}{extra.strip():<14} {pkgs or a['summary'][:80]}"
            )
        return 0

    name = f"CVE List (data as of {data['data_as_of']})" if args.cvelist else "NVD"
    print(
        f"{name} {data['window_start'][:16]} -> {data['window_end'][:16]} UTC: "
        f"{data['published_in_window']} published, {data['matching']} matching, showing {len(data['cves'])}"
    )
    if data.get("missing_days"):
        print(f"warning: no CVE List file for {', '.join(data['missing_days'])}", file=sys.stderr)
    for c in data["cves"]:
        score = f"{c['cvss_score']:>4}" if c["cvss_score"] is not None else "   -"
        sev = (c["severity"] or "N/A")[:8]
        extra = (" RCE" if c["rce"] else "") + _exploit_tag(c)
        if args.enrich and c.get("epss"):
            extra += f" EPSS={c['epss']['epss']:.3f}"
        desc = c["description"].replace("\n", " ")[:100]
        print(f"{c['published'][:16]}  {c['id']:<18} {score} {sev:<8} {_risk_tag(c)}{extra.strip():<14} {desc}")
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


def _watch(args: argparse.Namespace) -> int:
    from pathlib import Path

    from . import watch

    path = Path(args.config).expanduser() if args.config else watch.default_config_path()
    if args.action == "init":
        if watch.init(path):
            print(f"Created {path}\nEdit the [[watch]] sections, then try: cvescout watch run --dry-run")
        else:
            print(f"{path} already exists; edit it or pass --config to use another file.")
        return 0
    if args.action == "schedule":
        print(watch.schedule_help(path))
        return 0
    try:
        if args.action == "list":
            rows = watch.list_alerts(path, limit=args.limit)
            if args.json:
                print(json.dumps(rows, indent=2, ensure_ascii=False))
            for r in [] if args.json else rows:
                print(f"{(r['published'] or '')[:16]}  {r['cve_id']:<18} {r['score']:>3} {r['priority']:<8} {r['watch']}")
            return 0
        result = watch.run(path, dry_run=args.dry_run)
    except (watch.WatchError, sources.SourceError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    note = " (dry run: nothing stored or sent)" if result["dry_run"] else ""
    print(f"Checked since {result['checked_since'][:16]} UTC: {result['matched']} matching CVEs, "
          f"{len(result['alerts'])} alert(s){note}")
    for a in result["alerts"]:
        print(watch.format_alert(a))
    return 0


def _mcp(args: argparse.Namespace) -> int:
    from .mcp_server import server

    server.run()
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
    feed.add_argument(
        "--url", action="append", metavar="TEXT",
        help="--cvelist: part of a reference link, e.g. nodejs.org/en/blog/vulnerability; repeat for OR",
    )
    feed.add_argument("--severity", choices=list(sources.SEVERITY_ORDER), help="minimum severity")
    feed.add_argument("--min-score", type=float, metavar="N", help="minimum CVSS base score, e.g. 8")
    feed.add_argument("--rce", action="store_true", help="only likely remote code execution")
    feed.add_argument("--poc", action="store_true", help="only with a public exploit (PoC) or active exploitation")
    feed.add_argument("--any", action="store_true", help="match ANY of --severity/--min-score/--rce/--poc instead of all")
    feed.add_argument("--limit", type=int, default=30, help="max rows to show (default 30)")
    feed.add_argument(
        "--sort", choices=["published", "risk"], default="published",
        help="newest first (default) or highest patch priority first (adds EPSS/KEV and risk)",
    )
    source = feed.add_mutually_exclusive_group()
    source.add_argument("--kev", action="store_true", help="CISA Known Exploited Vulnerabilities instead of NVD")
    source.add_argument("--ghsa", action="store_true", help="GitHub Advisory Database instead of NVD")
    source.add_argument(
        "--cvelist", action="store_true",
        help="CVEProject CVE List instead of NVD: last 30 days, no rate limit, about an hour ahead of NVD",
    )
    feed.add_argument("--ecosystem", choices=sources.GHSA_ECOSYSTEMS, help="GHSA: package ecosystem")
    feed.add_argument("--package", help="GHSA: package name, e.g. lodash")
    feed.add_argument("--unreviewed", action="store_true", help="GHSA: include unreviewed advisories")
    feed.add_argument("--enrich", action="store_true", help="add EPSS, KEV status and risk score")
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

    watch = sub.add_parser("watch", help="alerts about new CVEs for your products (runs only when you call it)")
    watch.add_argument(
        "action", choices=["init", "run", "list", "schedule"],
        help="init: create the config; run: check once; list: past alerts; schedule: print a cron/Task Scheduler line",
    )
    watch.add_argument("--config", metavar="PATH", help="config file (default: ~/.config/cvescout/watch.toml, "
                       "Windows: %%APPDATA%%\\cvescout\\watch.toml)")
    watch.add_argument("--dry-run", action="store_true", help="run: show alerts without storing or sending them")
    watch.add_argument("--limit", type=int, default=50, help="list: max rows (default 50)")
    watch.add_argument("--json", action="store_true")
    watch.set_defaults(func=_watch)

    mcp = sub.add_parser("mcp", help="run as an MCP server on stdio, for Claude Code, Claude Desktop and other agents")
    mcp.set_defaults(func=_mcp)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
