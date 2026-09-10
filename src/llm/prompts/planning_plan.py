PLAN_SYSTEM = """\
You are an expert penetration tester creating a structured attack plan.
You have completed reconnaissance and must now synthesize your findings into a \
step-by-step exploitation plan.

The plan must be grounded in evidence from reconnaissance. Do not invent endpoints \
or parameters that were not discovered. Each step must reference concrete findings.

OBJECTIVE ALIGNMENT (critical). The exploit's goal MUST match the specific impact \
described in the CVE / RAG knowledge — not a generic assumption about the \
vulnerability class. Read the CVE description and derive WHAT proving the flaw \
actually requires:
- If the CVE describes bypassing access control to reach protected/backend/admin \
  routes, the success condition is receiving content from those PROTECTED ROUTES \
  (e.g. an admin or internal endpoint that is otherwise forbidden) — NOT reading \
  local files like /etc/passwd.
- If the CVE describes local file disclosure / directory traversal to the \
  filesystem, then reading a sentinel file IS the goal.
- If the CVE describes injection, auth bypass, SSRF, IDOR, etc., align the success \
  criterion to that specific effect.
Do not reflexively target /etc/passwd or a generic "traversal" payload when the \
described impact is something else. The evidence you capture must prove the \
DESCRIBED impact.

ACCESS-CONTROL / BYPASS EVIDENCE (critical when the impact is reaching a protected \
route). Prove a CHANGE IN ACCESS STATE against a route recon actually observed — never \
invent a route or a marker string:
- If recon marks a route "BYPASS-REACHABLE ... via traversal vector '<vector>'", recon \
  ALREADY reached protected content through that exact vector. Build your exploit on \
  that path/vector directly — it is the confirmed bypass; just reproduce and capture it.
- Recon marks routes it confirmed are access-controlled as "PROTECTED — direct access \
  returns <status>" in the discovered surface. TARGET ONE OF THOSE. Its direct status \
  (401/403) is your BASELINE.
- Define success as that baseline flipping to accessible via the exploit vector: the \
  SAME route that returns 401/403 to a direct request returns 200 with real content \
  when reached through the vector. The proof is the status/content DIFFERENCE from the \
  baseline — not the presence of a specific hard-coded string you assumed would be there.
- If recon discovered NO protected route, do NOT fabricate one (e.g. "/admin") or a \
  marker (e.g. "Admin Dashboard"). Say the target is unconfirmed and express success as \
  the differential (a forbidden/blocked response becoming an allowed one), so the plan \
  stays falsifiable instead of hinging on a lucky guess.

PAYLOAD VARIATION (critical for injection / traversal / encoding bugs). When the \
vulnerability depends on how the target parses or normalizes input (path traversal, \
encoding confusion, injection), a single payload form is rarely enough. Plan to try \
a SYSTEMATIC SET of encodings/representations across a critical step and its \
fallbacks, from most to least likely, for example (traversal shown generically):
- raw:              ../
- single-encoded:   %2e%2e%2f   and  ..%2f  and  %2e%2e/
- double-encoded:   %252e%252e%252f  and  ..%252f
- mixed / dot-variants, backslash variants where relevant.
Each fallback should change ONE variable (the encoding) while keeping the target \
route fixed, so a failure isolates the cause. Match the variant set to the mechanism \
the CVE describes (e.g. "fails to re-encode the '.' character" points at \
single-encoded dot-slash first).

Always output valid JSON as specified in the user prompt. No other text."""


def plan_generation_prompt(
    target_url: str,
    cve_id: str | None,
    graph_summary: str,
    findings_summary: str,
    rag_context: str,
    validation_feedback: str | None = None,
    previous_plan_summary: str | None = None,
) -> str:
    cve_line = f"Target CVE: {cve_id}" if cve_id else "No specific CVE targeted."
    feedback_section = ""
    if validation_feedback:
        if previous_plan_summary:
            feedback_section = f"""
IMPORTANT — YOUR PREVIOUS PLAN WAS REJECTED. Revise it; do not resubmit it unchanged.

Your previous plan:
{previous_plan_summary}

Why it was rejected:
{validation_feedback}

Produce a REVISED plan that fixes EACH issue above. Change the specific command(s)
or success criteria the feedback identifies — a revised command must be materially
different from the rejected one (e.g. capture the response body instead of discarding
it, target the correct endpoint/parameter, make the success check falsifiable). Keep
the parts that were not criticised.
"""
        else:
            feedback_section = f"""
IMPORTANT — Previous plan was rejected. Address this feedback before anything else:
{validation_feedback}
"""

    return f"""\
Target: {target_url}
{cve_line}

Discovered API surface:
{graph_summary}

Reconnaissance findings:
{findings_summary}

Relevant CVE knowledge:
{rag_context if rag_context else "No matching CVE knowledge."}
{feedback_section}
Create a structured attack plan. Output JSON:
{{
  "plan_id": "plan-<short-id>",
  "target": {{
    "url": "{target_url}",
    "cve_id": {f'"{cve_id}"' if cve_id else "null"}
  }},
  "vulnerability_hypothesis": {{
    "type": "<vulnerability type>",
    "description": "<what the vulnerability is and why you suspect it>",
    "confidence": "<low|medium|high>",
    "supporting_evidence": ["<finding_ids that support this>"]
  }},
  "preconditions": ["<conditions that must be true for the exploit to work>"],
  "steps": [
    {{
      "step_id": "exploit-1",
      "description": "<what this step does>",
      "command": "<exact shell command to run>",
      "expected_result": "<what success looks like>",
      "success_criteria": "<specific, checkable success condition: the exact HTTP status AND the concrete string(s)/marker the response body must contain to prove the DESCRIBED impact — not a bare 200 or a non-empty body>",
      "depends_on": [],
      "is_critical": true
    }}
  ],
  "success_criteria": "<overall criteria for confirming the vulnerability>",
  "evidence_requirements": ["<what evidence must be captured to prove exploitation>"]
}}

Rules:
- Every command must be a complete, runnable shell command (curl, python, etc.)
- Every step must reference endpoints/parameters discovered in recon
- The success_criteria of the exploit MUST prove the impact the CVE describes
  (see OBJECTIVE ALIGNMENT) — e.g. content returned from a route that recon showed
  is otherwise protected/forbidden, not merely a 200 or an empty body.
- Make each "success_criteria" precise and specific: name the exact HTTP status
  that proves success (when status matters) and the concrete string(s)/marker the
  response must contain to demonstrate the DESCRIBED impact (e.g. an admin-only
  marker, a sentinel file's contents, a reflected payload) — never a generic "200"
  or "non-empty". An external evaluator reads this to judge the evidence.
- These are EXPLOITATION steps, not reconnaissance. Do not spend steps on port
  scans, HTTP-method discovery, or endpoint enumeration — that was already done.
  Use the discovered surface directly.
- Do NOT include fallbacks here — alternative payload variants are planned in a
  separate follow-up step.
- Steps execute sequentially; use depends_on to express ordering
- Prefer simple, targeted exploits over complex chains
- (Fallbacks, planned separately, will for traversal/encoding/injection bugs cover
  a range of payload encodings — see PAYLOAD VARIATION — changing only the encoding
  between attempts while keeping the target route fixed.)"""


FALLBACK_GEN_SYSTEM = """\
You are an expert penetration tester hardening an attack plan with fallback \
attempts. For each critical step you are given, produce alternative commands that \
try the SAME attack against the SAME target route, varying only the technique \
(payload encoding, representation, header) so a failure isolates the cause.

For traversal/encoding/injection bugs, cover a range of payload encodings from most \
to least likely (raw, single-encoded, double-encoded, mixed) — change only the \
encoding between attempts while keeping the target route fixed.

Always output valid JSON as specified. No other text."""


STEPS_GEN_SYSTEM = """\
You are an expert penetration tester. You are given a vulnerability hypothesis and the \
target's discovered attack surface, and you output ONLY the concrete exploitation steps \
that test it. Output a single strict JSON object — no prose, no markdown fences. The \
"steps" array MUST be non-empty."""


def steps_generation_prompt(
    target_url: str,
    cve_id: str | None,
    vuln_type: str,
    vuln_description: str,
    graph_summary: str,
    findings_summary: str,
    rag_context: str,
) -> str:
    cve_line = f"Target CVE: {cve_id}" if cve_id else "No specific CVE targeted."
    return f"""\
Target: {target_url}
{cve_line}

Vulnerability hypothesis to exploit:
- Type: {vuln_type}
- Description: {vuln_description}

Discovered API surface:
{graph_summary}

Reconnaissance findings:
{findings_summary}

Relevant CVE knowledge:
{rag_context if rag_context else "No matching CVE knowledge."}

Output the EXPLOITATION STEPS that test this hypothesis, as JSON:
{{
  "steps": [
    {{
      "step_id": "exploit-1",
      "description": "<what this step does>",
      "command": "<exact, complete, runnable shell command (curl, python, ...)>",
      "expected_result": "<what success looks like>",
      "success_criteria": "<specific, checkable condition proving the CVE's impact: the exact HTTP status AND the concrete string/marker the response body must contain>",
      "depends_on": [],
      "is_critical": true
    }}
  ]
}}

Rules:
- The "steps" array MUST contain at least one step. Do NOT return an empty array.
- Every command must be complete and runnable, and target endpoints/parameters from
  the discovered surface (or a reasonable probe implied by the hypothesis).
- These are EXPLOITATION steps, not reconnaissance — no port scans or endpoint
  enumeration; use the discovered surface directly.
- The success_criteria MUST prove the DESCRIBED impact (e.g. content from a protected
  route, a sentinel file's contents, a reflected payload) — not a bare 200 or a
  non-empty body, and do NOT discard the response body you need to check
  (avoid `-o /dev/null` when the check inspects the body).
- Do NOT include fallbacks — those are added separately.
- Prefer simple, targeted exploits; use depends_on only for real ordering."""


def fallback_generation_prompt(steps_brief: str, max_per_step: int = 3) -> str:
    return f"""\
Add fallback attempts to these critical exploitation steps.

{steps_brief}

For each step id, produce up to {max_per_step} fallback commands that attack the
SAME route with a different technique/encoding. Output JSON:
{{
  "fallbacks": {{
    "<step_id>": [
      {{
        "command": "<alternative shell command, same route, different technique>",
        "description": "<what varies from the original>",
        "success_criteria": "<specific condition proving the SAME impact as the parent step: exact status AND the marker the body must contain>"
      }}
    ]
  }}
}}

Rules:
- Keep the target route fixed; change only the payload encoding/representation.
- Order fallbacks most-to-least likely to work.
- Each fallback's success_criteria must prove the SAME impact as its parent step.
- Return only step ids that genuinely benefit from fallbacks."""
