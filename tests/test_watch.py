import json
from datetime import datetime, timezone

import pytest

from cvescout import sources, watch
from cvescout.__main__ import main

NOW = datetime(2026, 10, 26, 12, 0, 0, tzinfo=timezone.utc)

CONFIG = """
source = "cvelist"
min_priority = "high"
initial_days = 7

[[watch]]
name = "curl"
keywords = ["curl"]

[[watch]]
name = "Node.js"
cpes = ["nodejs:node.js"]
min_priority = "medium"
source = "nvd"
"""


def _item(cve_id, score=9.8, rce=True, exploit=None):
    return {"id": cve_id, "published": "2026-10-25T10:00:00Z", "description": f"desc {cve_id}",
            "cvss_score": score, "rce": rce, "exploit": exploit,
            "url": f"https://www.cve.org/CVERecord?id={cve_id}"}


@pytest.fixture
def env(monkeypatch, tmp_path):
    """Fake sources: `feed` maps a watch's keyword/CPE to items; `kev` and `epss` drive enrich."""
    state = {"feed": {}, "kev": set(), "epss": {}, "calls": []}
    monkeypatch.setattr(sources, "now_utc", lambda: NOW)

    def fake_fetch(source, since, keyword=None, cpe=None, limit=50):
        state["calls"].append({"source": source, "since": since, "keyword": keyword, "cpe": cpe})
        key = (keyword or cpe)[0]
        return {"cves": [dict(i) for i in state["feed"].get(key, [])]}

    def fake_enrich(items, key="id"):
        for i in items:
            i.setdefault("epss", state["epss"].get(i["id"]))
            i["in_cisa_kev"] = i["id"] in state["kev"]
            if i["in_cisa_kev"]:
                i["exploit"] = "active"
        return items

    monkeypatch.setattr(sources, "fetch_cvelist_recent", lambda **kw: fake_fetch(source="cvelist", **kw))
    monkeypatch.setattr(sources, "fetch_nvd_recent", lambda **kw: fake_fetch(source="nvd", **kw))
    monkeypatch.setattr(sources, "enrich", fake_enrich)
    path = tmp_path / "watch.toml"
    path.write_text(CONFIG)
    state["path"] = path
    return state


def test_alerts_once_per_cve_and_respects_thresholds(env):
    env["feed"] = {
        "curl": [_item("CVE-2026-1001"), _item("CVE-2026-1002", score=7.5, rce=True)],  # high, medium
        "nodejs:node.js": [_item("CVE-2026-1003", score=7.5, rce=True)],  # medium, Node.js alerts from medium
    }
    first = watch.run(env["path"])
    assert [(a["watch"], a["id"]) for a in first["alerts"]] == [("curl", "CVE-2026-1001"), ("Node.js", "CVE-2026-1003")]
    assert [(c["source"], c["since"]) for c in env["calls"]] == [
        ("cvelist", "2026-10-19T12:00:00+00:00"), ("nvd", "2026-10-19T12:00:00+00:00")
    ]

    second = watch.run(env["path"])
    assert second["alerts"] == []
    # the next run starts at the previous one, with an hour of overlap
    assert env["calls"][-1]["since"] == "2026-10-26T11:00:00+00:00"


def test_alerts_again_when_priority_rises(env):
    env["feed"] = {"curl": [_item("CVE-2026-1002", score=7.5)]}
    assert watch.run(env["path"])["alerts"] == []  # medium is below curl's threshold

    env["feed"] = {}  # no longer in the fetch window, still re-scored from the database
    env["kev"] = {"CVE-2026-1002"}
    alerts = watch.run(env["path"])["alerts"]
    assert [(a["id"], a["risk"]["priority"], a["escalated_from"]) for a in alerts] == [
        ("CVE-2026-1002", "critical", None)
    ]
    assert watch.run(env["path"])["alerts"] == []


def test_escalation_from_an_alerted_priority_is_labelled(env):
    env["feed"] = {"curl": [_item("CVE-2026-1001")]}
    watch.run(env["path"])
    env["kev"] = {"CVE-2026-1001"}
    alerts = watch.run(env["path"])["alerts"]
    assert alerts[0]["escalated_from"] == "high"
    assert "[CRITICAL (was high)] curl: CVE-2026-1001" in watch.format_alert(alerts[0])


def test_dry_run_stores_nothing(env):
    env["feed"] = {"curl": [_item("CVE-2026-1001")]}
    assert len(watch.run(env["path"], dry_run=True)["alerts"]) == 1
    assert len(watch.run(env["path"], dry_run=True)["alerts"]) == 1
    assert watch.list_alerts(env["path"]) == []


def test_failed_webhook_keeps_alerts_for_next_run(env, monkeypatch):
    env["path"].write_text(CONFIG + '\n[notify]\nwebhook_url = "https://hooks.example/x"\nwebhook_format = "slack"\n')
    env["feed"] = {"curl": [_item("CVE-2026-1001")]}
    sent = []

    def down(req, timeout=30):
        raise OSError("connection refused")

    monkeypatch.setattr(watch.urllib.request, "urlopen", down)
    with pytest.raises(sources.SourceError, match="webhook"):
        watch.run(env["path"])

    class Ok:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def ok(req, timeout=30):
        sent.append(json.loads(req.data))
        return Ok()

    monkeypatch.setattr(watch.urllib.request, "urlopen", ok)
    assert len(watch.run(env["path"])["alerts"]) == 1
    assert "CVE-2026-1001" in sent[0]["text"]
    assert [r["cve_id"] for r in watch.list_alerts(env["path"])] == ["CVE-2026-1001"]


@pytest.mark.parametrize("config, message", [
    ('min_priority = "urgent"\n[[watch]]\nname = "x"\nkeywords = ["x"]', "min_priority"),
    ('[[watch]]\nname = "x"', "keywords or cpes"),
    ('source = "osv"\n[[watch]]\nname = "x"\nkeywords = ["x"]', "source"),
    ("source = ", "watch.toml"),
])
def test_bad_config_is_reported(tmp_path, config, message):
    path = tmp_path / "watch.toml"
    path.write_text(config)
    with pytest.raises(watch.WatchError, match=message):
        watch.load_config(path)


def test_init_writes_a_valid_example_once(tmp_path, capsys):
    path = tmp_path / "sub" / "watch.toml"
    assert main(["watch", "init", "--config", str(path)]) == 0
    assert [w["name"] for w in watch.load_config(path)["watch"]] == ["curl", "Node.js"]
    assert main(["watch", "init", "--config", str(path)]) == 0
    assert "already exists" in capsys.readouterr().out


def test_missing_config_is_an_error_not_a_crash(tmp_path, capsys):
    assert main(["watch", "run", "--config", str(tmp_path / "none.toml")]) == 1
    assert "cvescout watch init" in capsys.readouterr().err


def test_schedule_only_prints_instructions(tmp_path, capsys):
    path = tmp_path / "watch.toml"
    assert main(["watch", "schedule", "--config", str(path)]) == 0
    out = capsys.readouterr().out
    assert "watch run" in out and str(path) in out
    assert not path.exists()


def test_cvelist_window_is_capped_at_30_days_but_nvd_is_not(env):
    env["path"].write_text(CONFIG.replace("initial_days = 7", "initial_days = 90"))
    watch.run(env["path"])
    assert [(c["source"], c["since"][:10]) for c in env["calls"]] == [("cvelist", "2026-09-26"), ("nvd", "2026-07-28")]
