"""Alerts about new CVEs for watched products: `cvescout watch init|run|list|schedule`.

Nothing here runs on its own. `watch run` does one check and exits; scheduling
it (cron, launchd, Windows Task Scheduler) is left to the user, see `watch schedule`.
State lives in SQLite next to the config file, so each CVE is alerted once and
again only if its priority rises (e.g. when CISA adds it to KEV).
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import sys
import tomllib
import urllib.request
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import sources

EXAMPLE_CONFIG = """\
# cvescout watch - alerts about new CVEs for your products.
# Nothing runs on its own: run `cvescout watch run` by hand, or schedule it
# (`cvescout watch schedule` prints the command for cron / Task Scheduler).

# Where to look: "cvelist" (fresh, no rate limit, up to 30 days back) or "nvd"
source = "cvelist"
# Alert from this priority up: critical, high, medium or low (see README, "Wynik ryzyka")
min_priority = "high"
# How far back the first run looks, in days
initial_days = 7

# One [[watch]] per product; any one match is enough:
# - keywords: description, title, vendor or product name (case-insensitive)
# - cpes: products NVD or the vendor marked vulnerable (find names with `cvescout cpe <product>`)
# - urls: part of a reference link, always searched in the CVE List. The product's own
#   advisory page catches CVEs filed under a library it bundles (e.g. Brotli in Node.js).

[[watch]]
name = "curl"
keywords = ["curl"]

# Broad words catch too much: "node.js" matches every "... is a Node.js CMS".
# An exact CPE is precise, but only NVD has CPEs for most products, a few days after publication.
[[watch]]
name = "Node.js"
cpes = ["nodejs:node.js"]
urls = ["nodejs.org/en/blog/vulnerability"]
source = "nvd"            # per-product override (for keywords and cpes)
# min_priority = "medium"   # per-product override

[notify]
# Besides printing, POST alerts to a webhook (Slack/Teams/Discord incoming webhook or your own endpoint)
# webhook_url = "https://hooks.slack.com/services/..."
# webhook_format = "slack"   # slack, discord or json
"""

SCHEMA = """
CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT NOT NULL,
    watch TEXT NOT NULL,
    published TEXT,
    priority TEXT NOT NULL,
    score INTEGER NOT NULL,
    notified_priority TEXT,
    first_seen TEXT NOT NULL,
    data TEXT NOT NULL,
    PRIMARY KEY (cve_id, watch)
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""

# Stored CVEs are re-scored for this long, so a later KEV listing still raises an alert
RECHECK_DAYS = 30


class WatchError(RuntimeError):
    """Bad or missing watch configuration."""


def default_config_path() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "cvescout" / "watch.toml"


def load_config(path: Path) -> dict:
    if not path.exists():
        raise WatchError(f"no config at {path}; create one with `cvescout watch init`")
    try:
        config = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as e:
        raise WatchError(f"{path}: {e}") from e
    watches = config.get("watch") or []
    if not watches:
        raise WatchError(f"{path}: add at least one [[watch]] section")
    for w in [config, *watches]:
        if w.get("min_priority", "high") not in sources.PRIORITY_ORDER:
            raise WatchError(f"{path}: min_priority must be one of {', '.join(sources.PRIORITY_ORDER)}")
    for w in watches:
        if not w.get("name") or not (w.get("keywords") or w.get("cpes") or w.get("urls")):
            raise WatchError(f"{path}: every [[watch]] needs a name and keywords, cpes or urls")
    for w in [config, *watches]:
        if w.get("source", "cvelist") not in ("cvelist", "nvd"):
            raise WatchError(f'{path}: source must be "cvelist" or "nvd"')
    return config


def _connect(config_path: Path) -> sqlite3.Connection:
    db = sqlite3.connect(config_path.with_suffix(".db"))
    db.row_factory = sqlite3.Row
    db.executescript(SCHEMA)
    return db


def _rank(priority: str | None) -> int:
    return sources.PRIORITY_ORDER.get(priority or "", -1)


def run(config_path: Path, dry_run: bool = False) -> dict:
    """One check: fetch, score, store; return the alerts that are due.

    With dry_run nothing is stored or sent, so the same alerts come back next time.
    """
    config = load_config(config_path)
    with closing(_connect(config_path)) as db:
        return _run(config, db, dry_run)


def _run(config: dict, db: sqlite3.Connection, dry_run: bool) -> dict:
    now = sources.now_utc()

    last_run = db.execute("SELECT value FROM meta WHERE key = 'last_run'").fetchone()
    if last_run:
        # Overlap the previous window: records can carry a publish time a little before they appear
        start = datetime.fromisoformat(last_run["value"]) - timedelta(hours=1)
    else:
        start = now - timedelta(days=config.get("initial_days", 7))

    found: dict[tuple[str, str], dict] = {}
    for w in config["watch"]:
        if w.get("source", config.get("source", "cvelist")) == "nvd":
            fetch, since = sources.fetch_nvd_recent, start
        else:
            fetch = sources.fetch_cvelist_recent
            since = max(start, now - timedelta(days=sources.CVELIST_MAX_DAYS))
        items = []
        if w.get("keywords") or w.get("cpes"):
            items += fetch(since=since.isoformat(), keyword=w.get("keywords"), cpe=w.get("cpes"), limit=100_000)["cves"]
        if w.get("urls"):
            since = max(start, now - timedelta(days=sources.CVELIST_MAX_DAYS))
            items += sources.fetch_cvelist_recent(since=since.isoformat(), url=w["urls"], limit=100_000)["cves"]
        for item in items:
            found.setdefault((item["id"], w["name"]), item)

    # Re-score what was seen recently: EPSS and KEV change after publication
    since = (now - timedelta(days=RECHECK_DAYS)).isoformat()
    for row in db.execute("SELECT cve_id, watch, data FROM cves WHERE first_seen >= ?", (since,)):
        found.setdefault((row["cve_id"], row["watch"]), json.loads(row["data"]))

    items = list(found.values())
    for item in items:
        item.pop("epss", None)  # stored copies carry yesterday's EPSS and PoC list
        item.pop("github_pocs", None)
    sources.add_risk(items)

    thresholds = {w["name"]: w.get("min_priority", config.get("min_priority", "high")) for w in config["watch"]}
    alerts, updates = [], []
    for (cve_id, watch), item in found.items():
        if watch not in thresholds:  # watch removed from the config
            continue
        risk = item["risk"]
        row = db.execute(
            "SELECT notified_priority FROM cves WHERE cve_id = ? AND watch = ?", (cve_id, watch)
        ).fetchone()
        notified = row["notified_priority"] if row else None
        due = _rank(risk["priority"]) >= _rank(thresholds[watch]) and _rank(risk["priority"]) > _rank(notified)
        if due:
            alerts.append({"watch": watch, "escalated_from": notified, **item})
        updates.append((cve_id, watch, item, risk, risk["priority"] if due else notified))

    alerts.sort(
        key=lambda a: (sources.PRIORITY_ORDER[a["risk"]["priority"]], a["risk"]["score"], a.get("published") or ""),
        reverse=True,
    )
    result = {
        "checked_since": start.isoformat(),
        "checked_at": now.isoformat(),
        "matched": len(found),
        "alerts": alerts,
        "dry_run": dry_run,
    }
    if dry_run:
        return result

    notify = config.get("notify", {})
    if alerts and notify.get("webhook_url"):
        # Raises on failure, so nothing is marked notified and the alerts are retried next run
        send_webhook(notify["webhook_url"], notify.get("webhook_format", "json"), alerts)

    with db:
        for cve_id, watch, item, risk, notified in updates:
            db.execute(
                """INSERT INTO cves (cve_id, watch, published, priority, score, notified_priority, first_seen, data)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT (cve_id, watch) DO UPDATE SET
                     priority = excluded.priority, score = excluded.score,
                     notified_priority = excluded.notified_priority, data = excluded.data""",
                (cve_id, watch, item.get("published"), risk["priority"], risk["score"], notified,
                 now.isoformat(), json.dumps(item, ensure_ascii=False)),
            )
        db.execute(
            "INSERT INTO meta (key, value) VALUES ('last_run', ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            (now.isoformat(),),
        )
    return result


def format_alert(a: dict) -> str:
    r = a["risk"]
    change = f" (was {a['escalated_from']})" if a.get("escalated_from") else ""
    return (
        f"[{r['priority'].upper()}{change}] {a['watch']}: {a['id']} - {', '.join(r['factors'])}\n"
        f"    {a['description'][:200]}\n    {a.get('nvd_url') or a['url']}"
    )


def send_webhook(url: str, fmt: str, alerts: list[dict]) -> None:
    text = f"cvescout: {len(alerts)} new CVE alert(s)\n\n" + "\n\n".join(format_alert(a) for a in alerts)
    if fmt == "slack":
        payload = {"text": text}
    elif fmt == "discord":
        payload = {"content": text[:2000]}
    else:
        payload = {"alerts": [{k: a.get(k) for k in ("watch", "id", "published", "description", "risk",
                                                      "escalated_from", "url")} for a in alerts]}
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=30):
            pass
    except OSError as e:
        raise sources.SourceError(f"webhook: {e}") from e


def list_alerts(config_path: Path, limit: int = 50) -> list[dict]:
    with closing(_connect(config_path)) as db:
        rows = db.execute(
            """SELECT cve_id, watch, published, priority, score, notified_priority FROM cves
               WHERE notified_priority IS NOT NULL ORDER BY published DESC LIMIT ?""",
            (limit,),
        )
        return [dict(r) for r in rows]


def init(config_path: Path) -> bool:
    """Write the example config; False if one already exists."""
    if config_path.exists():
        return False
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(EXAMPLE_CONFIG, encoding="utf-8")
    return True


def schedule_help(config_path: Path) -> str:
    exe = shutil.which("cvescout") or str(Path(sys.argv[0]).resolve())
    cfg = "" if config_path == default_config_path() else f' --config "{config_path}"'
    log = config_path.with_suffix(".log")
    if os.name == "nt":
        return (
            "Run every hour with Windows Task Scheduler (cmd):\n\n"
            f'  schtasks /Create /SC HOURLY /TN cvescout-watch /TR "\\"{exe}\\" watch run{cfg}"\n\n'
            "Remove it with:  schtasks /Delete /TN cvescout-watch"
        )
    return (
        "Run every hour with cron: `crontab -e` and add the line\n\n"
        f'  0 * * * * "{exe}" watch run{cfg} >> "{log}" 2>&1\n\n'
        "Remove the line again to stop it."
    )
