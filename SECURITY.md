# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems in cvescout.

Report them privately through GitHub:
[Security → Report a vulnerability](https://github.com/zember/cvescout/security/advisories/new).
Include what you found, how to reproduce it and what an attacker could do with it.

You can expect a first reply within 7 days. Confirmed issues are fixed on `main`, and the advisory is published
once a fix is available, with credit to the reporter unless you prefer otherwise.

Polish or English are both fine.

## Scope

In scope: the code in this repository (the CLI, the `watch` alerts, the agent and the MCP server), for example
handling of untrusted data from the CVE sources, the webhook, or the local SQLite state.

Out of scope: vulnerabilities in the data sources themselves (NVD, CVE List, GitHub Advisory Database, CISA KEV,
EPSS) or in the CVEs cvescout reports; please report those to their owners.

## Supported versions

Only the latest commit on `main` is supported.
