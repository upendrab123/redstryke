from __future__ import annotations
import logging
from typing import Any

from core.agents.base import GroqAgent

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are an expert penetration testing planner. Given a threat model from the ANALYST agent, you must generate a targeted, ordered attack plan.

You MUST return ONLY valid JSON with this exact schema:
{
  "attack_phases": [
    {
      "phase_name": "string (e.g., Injection Testing, Authentication Testing)",
      "priority": 1-10,
      "test_cases": [
        {
          "id": "TC-001 (sequential)",
          "vulnerability_class": "SQLi/XSS/SSRF/SSTI/Command Injection/Open Redirect/Path Traversal/Auth Bypass/IDOR/Info Disclosure",
          "target": "string (URL parameter, form field, endpoint, header, cookie)",
          "rationale": "string explaining why this test is relevant based on analyst data",
          "technique": "brief description of the testing technique",
          "severity_if_found": "Critical/High/Medium/Low"
        }
      ]
    }
  ],
  "overall_strategy": "A paragraph describing the testing strategy",
  "priority_matrix": "A summary of which vulnerability classes to test first based on likelihood and impact"
}"""


class PlannerAgent(GroqAgent):
    name = "PLANNER"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    async def run(self, context: dict) -> dict:
        analyst_data = context.get("analyst", {})

        self.emit_running("Generating attack plan from analyst threat model...")

        user_prompt = f"""Generate a targeted attack plan based on this threat model:

{self._fmt(analyst_data)}

Return ONLY valid JSON matching the schema."""

        raw = self._call_groq(SYSTEM_PROMPT, user_prompt, temperature=0.4)
        parsed = self._parse_json(raw)

        if parsed:
            phases = parsed.get("attack_phases", [])
            total_tests = sum(len(p.get("test_cases", [])) for p in phases)
            self.emit_complete(f"Planner complete: {len(phases)} phases, {total_tests} test cases")
            return parsed
        else:
            fallback = self._fallback_plan(analyst_data)
            self.emit_complete("Planner complete (fallback plan)")
            return fallback

    def _fmt(self, data: dict) -> str:
        import json
        return json.dumps(data, indent=2, default=str)[:4000]

    def _fallback_plan(self, analyst: dict) -> dict:
        tech = analyst.get("technology_stack", {})
        threat = analyst.get("threat_model", {})
        test_cases = [
            {"id": "TC-001", "vulnerability_class": "XSS", "target": "URL parameters", "rationale": "Universal test", "technique": "Reflected XSS payload injection", "severity_if_found": "High"},
            {"id": "TC-002", "vulnerability_class": "SQLi", "target": "URL parameters", "rationale": "Database backend suspected", "technique": "Error-based SQLi probes", "severity_if_found": "Critical"},
            {"id": "TC-003", "vulnerability_class": "Open Redirect", "target": "redirect parameters", "rationale": "Common in web apps", "technique": "URL manipulation", "severity_if_found": "Medium"},
            {"id": "TC-004", "vulnerability_class": "Exposed Files", "target": "common paths", "rationale": "Check for .env, .git, etc.", "technique": "Path probing", "severity_if_found": "Critical"},
            {"id": "TC-005", "vulnerability_class": "Info Disclosure", "target": "HTML source", "rationale": "Check for secrets in source", "technique": "Source analysis", "severity_if_found": "High"},
            {"id": "TC-006", "vulnerability_class": "SSTI", "target": "URL parameters", "rationale": "Framework dependent", "technique": "SSTI probe strings", "severity_if_found": "Critical"},
            {"id": "TC-007", "vulnerability_class": "Path Traversal", "target": "URL parameters", "rationale": "Check for file read", "technique": "Encoded path sequences", "severity_if_found": "High"},
            {"id": "TC-008", "vulnerability_class": "Auth Weakness", "target": "login forms", "rationale": "Check auth mechanisms", "technique": "Form analysis", "severity_if_found": "Critical"},
        ]
        return {
            "attack_phases": [{
                "phase_name": "Comprehensive Security Testing",
                "priority": 1,
                "test_cases": test_cases,
            }],
            "overall_strategy": f"Testing based on {tech.get('web_server','?')} stack. Prioritizing injection and exposure.",
            "priority_matrix": "XSS=High, SQLi=Critical, ExposedFiles=Critical",
        }
