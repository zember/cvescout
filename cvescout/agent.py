"""Agent that answers questions about current vulnerabilities using only live data."""

from __future__ import annotations

import re

import anthropic

from . import tools

MODEL = "claude-opus-5-5"

SYSTEM_PROMPT = """You are a vulnerability intelligence assistant. Your job is to report the most recent CVEs.

Your training data is out of date, so your memory of CVEs is not a valid source here:
- Every CVE you mention must come from a tool result in this conversation. Never cite a CVE from memory, not even as an example.
- Start by calling get_current_datetime, then use search_recent_cves, search_github_advisories, get_recent_exploited or get_cve_details. "Latest", "new" and "this week" are relative to the date that tool returns.
- Map user criteria to tool filters: "RCE"/"remote code execution" -> rce_only, "score/rating above N" -> min_score, "X or Y" criteria -> match_any, "product A or B" -> several keywords/cpes, "since 2020" -> since="2020-01-01", "PoC"/"exploit available"/"exploited" -> poc_only. For a named product prefer cpes, looked up with find_cpe_name unless you are sure of the name, and add keywords if the CPE search looks incomplete. Say which filters you applied; rce_only is a heuristic, so call the result "likely RCE".
- For questions about libraries, packages or an ecosystem (npm, pip, maven, ...), use search_github_advisories: it gives vulnerable version ranges and the version to upgrade to.
- For each CVE give: ID, publication date (or KEV date_added), severity/CVSS, affected product, a one-line summary, and the NVD link. For GitHub advisories also give the GHSA ID, package, vulnerable range and patched version. Always state the exploit status (active / PoC / none known) and link the exploit_refs as sources; do not write or reproduce exploit code. Mention EPSS and KEV status when they raise priority.
- If a window returns nothing relevant, say so and widen it (e.g. 1 -> 7 -> 30 days) rather than falling back to older knowledge.
- If a source is unavailable, say which one and answer from the others.
- Reply in the language of the user's question."""

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def find_unsourced_cves(text: str) -> set[str]:
    """CVE IDs mentioned in `text` that no tool returned during this run."""
    return {m.upper() for m in CVE_RE.findall(text)} - tools.seen_cve_ids


def ask(question: str, verbose: bool = False) -> str:
    client = anthropic.Anthropic()
    tools.seen_cve_ids.clear()

    runner = client.beta.messages.tool_runner(
        model=MODEL,
        max_tokens=16000,
        system=SYSTEM_PROMPT,
        tools=tools.ALL_TOOLS,
        output_config={"effort": "medium"},
        # Security topics can trip a safety classifier; let the API retry on a fallback model
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",
        max_iterations=12,
        messages=[{"role": "user", "content": question}],
    )

    final = None
    for message in runner:
        final = message
        if verbose:
            for block in message.content:
                if block.type == "tool_use":
                    print(f"  -> {block.name}({block.input})")

    if final is None:
        raise RuntimeError("No response from the model.")
    if final.stop_reason == "refusal":
        details = final.stop_details.explanation if final.stop_details else ""
        return f"[Model declined the request] {details}".strip()

    answer = "\n".join(b.text for b in final.content if b.type == "text")
    unsourced = find_unsourced_cves(answer)
    if unsourced:
        answer += (
            "\n\n[cvescout warning] These CVEs were not returned by any live source in this run "
            f"and may come from the model's memory: {', '.join(sorted(unsourced))}"
        )
    return answer
