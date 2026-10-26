"""MCP server exposing the agent's tools, so any MCP client (Claude Code, Claude Desktop,
your own agent) can query live CVE data without an Anthropic API key of its own."""

from __future__ import annotations

import inspect

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from . import tools

INSTRUCTIONS = """Live vulnerability data: NVD, the CVE List (CVEProject), GitHub Advisory Database, CISA KEV and FIRST EPSS.

Your training data is out of date, so your memory of CVEs is not a valid source:
- Every CVE you report must come from a result of these tools. Never cite a CVE from memory.
- Call get_current_datetime first: "latest", "new" and "this week" are relative to that date.
- For the last hours or days, or when NVD is slow or unavailable, use search_recent_cves with source="cvelist".
- For named products prefer cpes (look them up with find_cpe_name); for packages and ecosystems use search_github_advisories.
- For "what to patch first", "most dangerous" or "top N" questions use sort_by="risk". Each result has risk.score (0-100), risk.priority (critical/high/medium/low) and risk.factors: explain the priority with the factors and call it cvescout's heuristic, not an official rating.
- Vendors list affected versions only for branches they checked, usually the supported ones (see affected_note). Never tell the user an older or unlisted version is safe: say it may be affected too and, if end-of-life, will get no fix.
- rce_only is a heuristic: call its results "likely RCE". Always state the exploit status and link exploit_refs; do not write exploit code.
- If a window returns nothing relevant, widen it rather than falling back to memory."""

server = MCPServer("cvescout", instructions=INSTRUCTIONS)

for tool in tools.ALL_TOOLS:
    server.add_tool(
        tool.func,
        name=tool.name,
        # The full docstring, so clients also see the per-argument descriptions
        description=inspect.getdoc(tool.func),
        annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True),
    )
