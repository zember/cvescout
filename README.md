# cvescout

**English** | [Polski](README.pl.md)

[![tests](https://github.com/zember/cvescout/actions/workflows/tests.yml/badge.svg)](https://github.com/zember/cvescout/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Find the **latest** CVEs from live sources, rank them by patch priority, and get alerts for your products. Includes a Claude
agent that is not allowed to answer from memory, and an MCP server so any agent can use the same live data.

Why: a language model only knows the CVEs that existed before its training cutoff, so when asked for the "latest" ones it
lists old ones. `cvescout` fetches the data at query time, in a time window counted from today:

| Source | What it gives |
|---|---|
| [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) | CVEs from the last N days or since a date, CVSS, CWE, exploit links |
| [CVE List V5](https://github.com/CVEProject/cvelistV5) | the official CVE list: last 30 days with no rate limit, about an hour ahead of NVD, vendor-supplied affected versions |
| [GitHub Advisory Database](https://github.com/advisories) | advisories for open-source packages: package, vulnerable range, patched version |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | vulnerabilities exploited in the wild (filtered by `dateAdded`) |
| [FIRST EPSS](https://www.first.org/epss/) | probability of exploitation in the next 30 days |

The agent (`claude-opus-5-5`) has tools for these sources, a prompt that forbids citing CVEs from memory, and a hard
post-check: any CVE in its answer that no tool returned is flagged with a warning. The same tools are exposed by the
[MCP server](#mcp-server), so Claude Code, Claude Desktop, Codex or your own agent can use them without a separate API key.

## Installation

Requires Python 3.11 or newer.

macOS / Linux:

```bash
git clone https://github.com/zember/cvescout.git && cd cvescout
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
```

Windows (cmd):

```bat
git clone https://github.com/zember/cvescout.git && cd cvescout
python -m venv .venv
.venv\Scripts\pip install -e .[dev]
```

API keys are all optional except `ANTHROPIC_API_KEY` for `ask`. In cmd use `set` instead of `export` (or `setx` to keep it):

```bash
export NVD_API_KEY=...        # 50 instead of 5 requests / 30 s: https://nvd.nist.gov/developers/request-an-api-key
export GITHUB_TOKEN=...       # 5000 instead of 60 requests / h for GHSA, e.g. $(gh auth token)
export ANTHROPIC_API_KEY=...  # only for `cvescout ask` (or `ant auth login`); the MCP server does not need it
```

## Running without `activate`

- **Windows:** the project folder contains `cvescout.cmd`. Run `C:\path\to\cvescout\cvescout.cmd feed --days 2`, or add
  the project folder to PATH so that `cvescout feed --days 2` works in any cmd window.
- **macOS / Linux:** `ln -s "$PWD/.venv/bin/cvescout" ~/.local/bin/cvescout` (`~/.local/bin` must be on PATH).
- **Any system:** `pipx install -e .` installs `cvescout` globally in its own environment.

## Usage

```bash
cvescout feed --days 2                               # CVEs from the last 48 h, newest first
cvescout feed --days 7 --severity CRITICAL --enrich  # this week's critical ones + EPSS/KEV/risk
cvescout feed --days 7 --sort risk                   # this week, most urgent to patch first
cvescout feed --days 30 --keyword fortinet
cvescout feed --days 30 --kev                        # added to CISA KEV in the last month
cvescout feed --days 1 --json
```

### Output: for people or for agents

| Mode | For | Contents |
|---|---|---|
| `cvescout feed`, `cvescout cpe` | people | table: date, ID, CVSS, `RCE`/`PoC`/`EXPLOITED` tags, description cut to 100 characters |
| `cvescout feed --json`, `cvescout cpe --json` | scripts, other agents, pipelines | full data: whole description, CWE, CVSS vector, links, `exploit_refs`, `affected_products`, EPSS/KEV (with `--enrich`) |
| `cvescout ask` | people | the Claude agent's answer, in the language of the question |
| `cvescout mcp` | agents (Claude Code, Claude Desktop, other MCP clients) | tools returning JSON, as in `ask` |

The table may change and truncates data, so programs should read `--json`. Errors go to stderr with exit code 1, so a
script can detect failures. The agent behind `ask` does not read the table; its tools get JSON directly.

### Filters

| Option | Meaning |
|---|---|
| `--min-score 8` | CVSS ≥ 8 |
| `--severity HIGH` | severity at least HIGH (≥ 7.0) |
| `--rce` | likely remote code execution (heuristic: code/command-injection CWE or wording, network vector `AV:N`, no XSS) |
| `--poc` | known public exploit (PoC) or active exploitation |
| `--any` | **one** of the conditions above is enough (by default **all** must hold) |
| `--since 2020-01-01` | from a date instead of `--days` |
| `--keyword X` | word in the description; repeat for OR |
| `--cpe vendor:product` | exact product in NVD, e.g. `haxx:curl`, `nodejs:node.js`, `o:linux:linux_kernel`; repeat for OR. `cvescout cpe` finds the name |

```bash
cvescout feed --days 7 --rce --min-score 8                  # RCE and CVSS >= 8
cvescout feed --days 7 --rce --min-score 8 --any            # RCE or CVSS >= 8
cvescout feed --days 7 --min-score 8 --poc                  # CVSS >= 8 with a public exploit
cvescout feed --since 2020-01-01 --cpe nodejs:node.js --cpe haxx:curl --rce          # RCE in Node.js or curl since 2020
cvescout feed --since 2020-01-01 --keyword node.js --keyword curl --rce --limit 100  # broader, by description words
```

The column after the score shows `RCE`, `PoC` (public exploit) or `EXPLOITED` (exploited in the wild).

- NVD accepts date ranges of up to 120 days. A longer range (`--since`) needs `--keyword` or `--cpe`: the product's
  whole history is fetched and trimmed locally.
- `--cpe` is more precise than `--keyword`: it returns only CVEs where NVD marked the product as **vulnerable** (it
  skips e.g. applications that merely "run on" Linux). It only covers CVEs NVD has already analyzed, which takes days
  to weeks, so for the newest CVEs use `--keyword`, or `--cvelist` with `--url` (below).
- `--poc` uses references NVD tagged "Exploit", CISA SSVC, CVSS v4 exploit maturity and CISA KEV. No tag does not mean
  there is no exploit: exploits published only in blog posts are often missed.
- `--rce` is a heuristic: treat results as "likely RCE" and read the description.
- Rejected CVEs (REJECTED: duplicates, IDs assigned by mistake, reports that turned out not to be vulnerabilities) are
  skipped. `get_cve_details` for a single CVE still shows the rejection.

### Risk score: what to patch first

```bash
cvescout feed --days 7 --sort risk --limit 20                  # this week, most urgent first
cvescout feed --cvelist --days 3 --sort risk --keyword php
cvescout feed --ghsa --days 30 --ecosystem npm --sort risk
```

`--sort risk` adds EPSS and KEV, scores **all** matching CVEs (not just the newest `--limit`) and sorts them by priority.
`--enrich` adds the same score without reordering. In `--json` every CVE has
`risk: {score, priority, factors}`, and `factors` explains the rating (e.g. `actively exploited (CISA KEV)`,
`EPSS 34.00%`, `CVSS 9.8`).

| Priority | When |
|---|---|
| `critical` | exploited in the wild (CISA KEV, SSVC "active", CVSS v4 `E:A`) |
| `high` | public exploit or EPSS ≥ 10% with CVSS ≥ 7 (or unknown), or likely RCE with CVSS ≥ 9 |
| `medium` | public exploit or EPSS ≥ 10% (with lower CVSS), or CVSS ≥ 9, or CVSS ≥ 7 together with likely RCE **or** EPSS ≥ 1% |
| `low` | the rest, e.g. CVSS 7–8.9 without RCE, without an exploit and with EPSS < 1% |

For `medium`, likely RCE **or** EPSS ≥ 1% is enough. To see only RCE, add the filter: `cvescout feed --days 7 --sort risk --rce`.

`score` (0–100) orders CVEs within a priority: 50% threat (exploited 1.0, PoC 0.7, EPSS scaled so that 10% counts like a
PoC) + 40% CVSS + 10% likely RCE. Threat weighs most because most CVEs, even critical ones, are never exploited. This
is cvescout's heuristic, not an official rating. New CVEs have no EPSS yet (`no EPSS yet`), so their score rests on CVSS
and known exploits. On one week of NVD data (4061 CVEs) this gave 4 critical, 219 high, 735 medium and 3103 low.

### Vendor-supplied affected versions

The `affected` field (CVE List, `get_cve_details`) shows the versions the vendor (CNA) reported, and `default_status`
what the vendor says about all other versions (`affected`, `unaffected`, `unknown` or missing).
**Vendors usually list only supported branches.** Example: CVE-2026-109618 in PHP lists 8.2–8.5 with
`default_status: unaffected`, although older, unsupported versions (e.g. 7.x) may have the same bug: nobody checked
them and they will get no fix. A version missing from the list is not a safe version; the agent and the MCP server
have this in their instructions and get the warning in the `affected_note` field.

### CPE names: `cvescout cpe`

A CPE name has the form `vendor:product`, and the vendor often differs from the common name (curl is `haxx:curl`, after
Haxx AB, the company of curl's author). `cvescout cpe` looks it up in the NVD CPE dictionary:

```
$ cvescout cpe nginx
CPE products for 'nginx':
  f5:nginx                       582 ver.  F5 NGINX
  nginx:nginx                    543 ver.  Nginx  [deprecated -> f5:nginx]
  igor_sysoev:nginx              383 ver.  Nginx  [deprecated -> nginx:nginx]
  ...
Use: cvescout feed --cpe f5:nginx --since 2020-01-01
```

Products whose name matches come first. Deprecated names show what replaced them. Operating systems have the `o:`
prefix (e.g. `o:linux:linux_kernel`), hardware `h:`.

### CVE List (CVEProject/cvelistV5)

```bash
cvescout feed --cvelist --days 1                          # everything from the last 24 h, no NVD rate limit
cvescout feed --cvelist --days 7 --rce --min-score 8      # the same filters as for NVD
cvescout feed --cvelist --days 3 --keyword nginx --json   # word in the description, title, vendor or product name
cvescout feed --cvelist --days 7 --url nodejs.org/en/blog/vulnerability   # CVEs linked from Node.js advisories
```

`--url` matches part of a reference link. The vendor's security advisory page works best: it also finds CVEs filed
under a **library bundled with the product**. Example: CVE-2026-111497 was filed by Google for Brotli. Its description
never mentions Node.js, NVD has not assigned CPEs yet, and the only trace is a link to the Node.js security release.
`--keyword node.js` and `--cpe nodejs:node.js` miss it; `--url nodejs.org/en/blog/vulnerability` finds it.

`--cvelist` reads the official CVE list instead of NVD: the daily change files from
[GitHub Releases](https://github.com/CVEProject/cvelistV5/releases) (a few MB per day), completed with the `deltaLog.json` index.

- **Faster:** a week of data downloads in seconds, without the 5 requests / 30 s limit; CVEs show up about an hour before NVD.
- **Last 30 days only.** For longer ranges (`--since 2020-01-01`) use NVD.
- **Data from the CNA** (the vendor or other CVE issuer) and CISA Vulnrichment (SSVC, KEV), without NVD analysis: the
  CVSS score sometimes differs, and `--cpe` only works where the issuer supplied CPEs, so prefer `--keyword` or `--url`.
- In `--json` every CVE has an `affected` field: vendor, product and vulnerable versions (e.g. `1.0 - <1.4`).
- `get_cve_details` (agent and MCP) adds `affected` from the CVE List to the NVD data, and when NVD is down or does not
  have the CVE yet, returns the CVE List record.

### GitHub Advisory Database

```bash
cvescout feed --ghsa --days 7 --ecosystem npm --severity HIGH   # advisories for npm packages
cvescout feed --ghsa --days 30 --package django --rce
```

GitHub "reviewed" advisories (the default) appear later than NVD because GitHub checks them by hand; `--unreviewed`
adds the unreviewed ones, usually NVD copies without package data. `--ghsa` returns at most the newest 100 advisories
per query, so long ranges (`--since`) are incomplete.

### Agent

```bash
cvescout ask -v "Which critical CVEs were published in the last 3 days?"
cvescout ask "Show RCE in Node.js or curl since 2020 with a public exploit"
```

The agent picks the filters itself (RCE, CVSS threshold, PoC, products, dates), looks up CPE names when needed and
says which filters it applied.

Long ranges for large products (e.g. the Linux kernel since 2020) need many NVD requests: without `NVD_API_KEY` this
takes a few minutes.

## Alerts about new CVEs: `cvescout watch`

`cvescout watch` checks for new CVEs in the products you choose, rates them with the
[risk score](#risk-score-what-to-patch-first) and reports each CVE **once**, again only if its priority rises (e.g.
when CISA adds it to KEV). **Nothing runs on its own:** each `watch run` is a single check; you schedule it yourself.

```bash
cvescout watch init             # creates an example config
cvescout watch run --dry-run    # shows alerts without storing or sending them
cvescout watch run              # checks, stores state, sends alerts
cvescout watch list             # past alerts
cvescout watch schedule         # prints a cron / Task Scheduler line (installs nothing)
```

Config: `~/.config/cvescout/watch.toml` (Windows: `%APPDATA%\cvescout\watch.toml`), or any file with `--config`.
State (SQLite) is kept next to it, in `watch.db`.

```toml
source = "cvelist"        # "cvelist" (fresh, up to 30 days back) or "nvd"
min_priority = "high"     # critical, high, medium or low
initial_days = 7          # how far back the first run looks

[[watch]]
name = "curl"
keywords = ["curl"]

[[watch]]
name = "Node.js"
cpes = ["nodejs:node.js"]
urls = ["nodejs.org/en/blog/vulnerability"]   # always searched in the CVE List
source = "nvd"            # per-product override (applies to keywords and cpes)
min_priority = "medium"

[notify]
webhook_url = "https://hooks.slack.com/services/..."
webhook_format = "slack"  # slack, discord or json
```

- One match is enough: `keywords`, `cpes` or `urls`.
- `keywords` are broad: `node.js` matches every "… is a Node.js CMS". For such products use `cpes` (find the name with
  `cvescout cpe`) and `source = "nvd"`, because the CVE List has CPEs from only some vendors. NVD assigns CPEs a few
  days late, but without false matches.
- `urls` (part of a reference link, always from the CVE List) catches CVEs right away, including those in libraries the
  product bundles: the Node.js advisory page links the Brotli CVE. In the week of 19–26 Oct 2026 only `urls` found the
  10 Node.js CVEs, because NVD had not assigned them CPEs yet.
- Each run starts where the previous one ended (with an hour of overlap) and re-scores CVEs from the last 30 days (EPSS
  and KEV change after publication), so you also get an alert when an older CVE has just been added to KEV.
- Alerts always go to stdout (`--json` for scripts), and with `webhook_url` also to the webhook. If the webhook does not
  answer, the alerts are not marked as sent and come again on the next run.
- Some vendors (e.g. curl) publish no CVSS: until NVD scores the CVE, the risk score counts the missing CVSS as 5.0.

### Turning on periodic checks

`cvescout watch schedule` prints the command with the right paths. macOS / Linux (cron, every hour):

```bash
crontab -e
# add:
0 * * * * "/path/to/cvescout/.venv/bin/cvescout" watch run >> "$HOME/.config/cvescout/watch.log" 2>&1
```

Windows (cmd, Task Scheduler, every hour):

```bat
schtasks /Create /SC HOURLY /TN cvescout-watch /TR "\"C:\path\to\cvescout\.venv\Scripts\cvescout.exe\" watch run"
schtasks /Delete /TN cvescout-watch
```

To turn it off, remove the line from `crontab -e` or delete the `cvescout-watch` task.

## MCP server

`cvescout mcp` runs an [MCP](https://modelcontextprotocol.io) server (stdio) with the same tools as the `ask` agent:
`get_current_datetime`, `search_recent_cves` (NVD or `source="cvelist"`, `sort_by="risk"`, `reference_urls`),
`search_github_advisories`, `find_cpe_name`, `get_cve_details`, `get_recent_exploited`. All tools are read-only. The
server never calls a model, so it needs no `ANTHROPIC_API_KEY`: the client answers the questions (e.g. Claude Code on
your subscription). The server's instructions forbid the client to cite CVEs from memory or to follow instructions
found inside CVE data; the hard post-check of `ask` is not available here, because the client writes the answer.

**Claude Code** (for all projects; a new session sees the `mcp__cvescout__*` tools):

```bash
claude mcp add --scope user cvescout -- "$PWD/.venv/bin/cvescout" mcp
```

```bat
claude mcp add --scope user cvescout -- C:\path\to\cvescout\.venv\Scripts\cvescout.exe mcp
```

**Claude Desktop**, in `claude_desktop_config.json` (macOS: `~/Library/Application Support/Claude/`,
Windows: `%APPDATA%\Claude\`):

```json
{
  "mcpServers": {
    "cvescout": {
      "command": "/Users/you/dev/cvescout/.venv/bin/cvescout",
      "args": ["mcp"]
    }
  }
}
```

On Windows use `"command": "C:\\path\\to\\cvescout\\.venv\\Scripts\\cvescout.exe"`. `NVD_API_KEY` and `GITHUB_TOKEN`
can be passed in an `"env"` field of the same section (or with `claude mcp add -e NVD_API_KEY=...`).

**OpenAI Codex CLI:**

```bash
codex mcp add cvescout -- "$PWD/.venv/bin/cvescout" mcp
```

```bat
codex mcp add cvescout -- C:\path\to\cvescout\.venv\Scripts\cvescout.exe mcp
```

Keys go in with `--env NVD_API_KEY=...`. Long NVD queries (large products over several years, without `NVD_API_KEY`)
can take minutes, longer than Codex's default tool timeout, so raise it in `~/.codex/config.toml`:

```toml
[mcp_servers.cvescout]
command = "/Users/you/dev/cvescout/.venv/bin/cvescout"
args = ["mcp"]
tool_timeout_sec = 300
```

The server works with any MCP client that speaks stdio; it was checked with protocol versions 2025-03-26 through the
current one. How strictly a client follows the server's instructions (no CVEs from memory) depends on the client.

**Your own agent (Python):**

```python
from mcp import Client, StdioServerParameters

async with Client(StdioServerParameters(command=".venv/bin/cvescout", args=["mcp"])) as client:
    result = await client.call_tool("search_recent_cves", {"days": 1, "source": "cvelist", "rce_only": True})
    print(result.content[0].text)  # JSON
```

## Security notes

- CVE descriptions, titles and references are written by third parties. cvescout strips terminal control characters
  from them, and the agent and MCP instructions tell the model to treat them as data, never as instructions. If you
  feed `--json` output into your own LLM pipeline, do the same.
- cvescout only reads public data; the only thing it sends anywhere is the optional `watch` webhook, to the URL you configure.
- To report a vulnerability in cvescout itself, see [SECURITY.md](SECURITY.md).

## Tests

```bash
.venv/bin/pytest
```

## License

[MIT](LICENSE)
