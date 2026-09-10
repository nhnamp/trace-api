RECON_SYSTEM = """\
You are an expert penetration tester performing API reconnaissance on a target system.
Your goal is to systematically discover the target's attack surface: endpoints, methods, \
parameters, authentication schemes, and potential vulnerabilities.

PRIORITY RULE 1 — target URL authority. The user-supplied target URL is the \
AUTHORITATIVE entry point under test. If any HTTP service responds at that URL, that \
service IS the target — regardless of what other open ports a scan reveals. Do not \
redirect recon or plan hypotheses to a different host or port unless direct HTTP \
probes against the given URL fail with a hard network error (connection refused, \
DNS failure, timeout on every path). Extra open ports found by port scans are \
usually noise (ephemeral connections, unrelated host services, tooling processes) \
and MUST NOT override the given target URL.

PRIORITY RULE 2 — product/service identification. Before probing endpoints in depth, \
try to identify the underlying product/service name (and version, if visible). \
This is the single most valuable finding because it unlocks CVE database lookups. \
Look for it in: HTTP Server / X-Powered-By response headers, WWW-Authenticate realms, \
default landing pages, HTML meta generator tags, JS bundle names, JSON error \
payloads that leak framework identifiers, robots.txt, /favicon.ico hash, \
/.well-known paths, and banner grabs on open ports.

PRIORITY RULE 3 — adequate endpoint enumeration. You may NOT declare recon complete \
after only probing `/`. A 200 at the root only proves something answers there — it \
does not map the API surface. You must enumerate the endpoint surface using \
whichever of the following signals are available:

  a. Any URL prefixes, paths, or route names mentioned in the CVE description or \
     RAG context — the CVE knowledge base is direct evidence of the target's real \
     surface and must be probed before generic guesses.
  b. Widely-recognized conventions: `/robots.txt`, `/sitemap.xml`, `/favicon.ico`, \
     `/.well-known/*`, generic API prefixes `/api`, `/api/v1`, `/api/v2`, health \
     endpoints `/health`, `/status`, `/metrics`, and auto-generated API docs \
     `/openapi.json`, `/swagger`, `/swagger.json`, `/redoc`.
  c. Paths visible in previous responses — HTML anchor hrefs, JS bundle references, \
     Location / Content-Location / Referer headers, error message paths.
  d. A directory brute-force pass with a general-purpose wordlist (e.g. \
     `gobuster dir`, `ffuf`, `feroxbuster` with `common.txt` or `raft-medium`).

Do not invent or assume CVE-specific paths that are not backed by one of these \
signals. Do not hardcode routes from your training data.

You work in iterations. Each iteration you analyze current knowledge and decide what \
commands to run next. You have access to standard tools: curl, nmap, nikto, gobuster, \
ffuf, and custom scripts.

Always output valid JSON as specified in the user prompt. No other text."""


def recon_command_prompt(
    target_url: str,
    cve_id: str | None,
    graph_summary: str,
    previous_findings: str,
    iteration: int,
    max_iterations: int,
    rag_context: str,
) -> str:
    cve_line = f"Known CVE: {cve_id}" if cve_id else "No specific CVE known."
    return f"""\
Target: {target_url}   ← authoritative entry point. Every probe below MUST go against
                        this exact host:port. Do NOT substitute other ports found by
                        scans, and do NOT skip probing this URL because "port scan
                        showed something else". If the target does not respond at
                        all, retry it directly with curl -v before pivoting.
{cve_line}

Current API knowledge:
{graph_summary if graph_summary else "No endpoints discovered yet."}

Previous findings:
{previous_findings if previous_findings else "No findings yet — this is the first iteration."}

Relevant CVE knowledge from database:
{rag_context if rag_context else "No relevant CVE matches found yet."}

Iteration {iteration}/{max_iterations}.

Generate reconnaissance commands to run. Focus on discovering:
- Product/service name and version (HIGHEST PRIORITY — headers, banners, error pages)
- The API surface via the signals listed in PRIORITY RULE 3 (RAG-derived paths,
  standard conventions, response-visible paths, or a wordlist brute-force)
- Authentication requirements
- Request/response patterns
- Potential vulnerabilities

Only run a full-range port scan if you have a specific reason. Most "open" ports
found by port scans against localhost or shared hosts are noise (ephemeral
connections, unrelated services) and MUST NOT be treated as candidate targets —
probe {target_url} directly instead.

Path enumeration guidance (per PRIORITY RULE 3):
- An automated directory brute-force (built-in enumerator, general-purpose
  wordlist) has ALREADY been run against the target before this loop. Any paths
  it discovered appear above under "Current API knowledge" / "Previous findings"
  with their status codes and were `discovered_by: dir_enum`. TREAT THESE AS THE
  GROUND-TRUTH SURFACE — build on them; do not re-run a broad brute-force.
- If the RAG context or CVE description references specific URL prefixes or paths,
  probe THOSE next — they are direct evidence for this target. Combine them with
  the discovered prefixes (e.g. if enumeration found a `/<prefix>` and the CVE
  targets an admin route, try `/<prefix>/<admin-route>`).
- Follow up on interesting discovered paths: request them in full (headers + body),
  probe their sub-paths, and test the specific behavior the CVE describes.
- Do NOT set `continue_recon=false` in the follow-up interpretation until you have
  followed up on the discovered surface and confirmed the target's real prefixes.

Output JSON:
{{
  "commands": [
    {{"command_id": "recon-N", "command": "<shell command>", "purpose": "<what this discovers>", "tool": "<tool name>"}}
  ],
  "reasoning": "<why these commands were chosen>"
}}

Generate 1-3 focused commands. Prefer targeted probing over broad scans. \
Do not repeat commands that have already been run."""


def recon_interpret_prompt(
    target_url: str,
    command_results: str,
    graph_summary: str,
    iteration: int,
    max_iterations: int,
) -> str:
    return f"""\
Target: {target_url}
Iteration {iteration}/{max_iterations}.

Commands executed and their outputs:
{command_results}

Current API knowledge:
{graph_summary if graph_summary else "Empty graph."}

Interpret the command results. Extract all discovered information about the target's API.

Rules:
- Every discovered endpoint MUST be attributed to the target URL above, not to a
  sibling port from a scan. Ephemeral or unrelated ports are noise, not
  candidate targets.
- Do NOT set `continue_recon=false` until you have adequately enumerated the API
  surface. A single probe of `/` is never enough. Adequate enumeration means at
  least one of: (a) every path or prefix mentioned in the RAG/CVE context has
  been probed at this target URL, (b) a broad convention sweep has been run,
  (c) a wordlist-based directory brute-force has completed. If none of these
  hold, set `continue_recon=true` and state in `reasoning` which signal is still
  unexplored.

Output JSON:
{{
  "findings": [
    {{
      "finding_id": "finding-N",
      "finding_type": "<endpoint|auth_scheme|parameter|response_pattern|weakness|technology|service>",
      "data": {{<structured data about the finding>}},
      "raw_evidence": "<relevant portion of command output>"
    }}
  ],
  "graph_updates": [
    {{
      "action": "add_endpoint",
      "path": "/api/v1/example",
      "base_url": "{target_url}",
      "methods": ["GET", "POST"],
      "discovered_by": "recon-N"
    }}
  ],
  "continue_recon": <true if more recon would be valuable, false if sufficient>,
  "reasoning": "<what was learned and what gaps remain>"
}}

For graph_updates, supported actions:
- add_product: name (canonical product/service name, lowercase, hyphen-separated, no version), version (optional string), confidence (low/medium/high), evidence (the exact text you saw)
- add_endpoint: path, base_url, methods (list), discovered_by
- add_parameter: endpoint_path, method, name, location (query/path/header/body), param_type
- add_auth: endpoint_path, method, auth_type (bearer/basic/api_key/cookie), location
- add_response: endpoint_path, method, status_code, content_type, body_sample
- add_weakness: endpoint_path, method, weakness_type, confidence (low/medium/high), evidence
- add_hypothesis: description, target_endpoint, target_method, cve_ref

Emit add_product AS SOON AS you have any signal — even low confidence — so downstream \
CVE lookups can start. For example, if a response includes `Server: nginx/1.24.0`, \
emit \
{{"action":"add_product","name":"nginx","version":"1.24.0","confidence":"high","evidence":"Server: nginx/1.24.0"}}. \
The name is always the canonical vendor/product slug lowercased, with no version.

Be precise. Only report findings supported by the command output."""
