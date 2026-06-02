from __future__ import annotations
import logging
from typing import Any

from core.agents.base import GroqAgent

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are an expert web security analyst. Your task is to analyze reconnaissance data from SCOUT (DNS enumeration) and FINGERPRINT (HTTP probing) agents and produce a structured threat model.

You MUST return ONLY valid JSON with this exact schema:
{
  "technology_stack": {
    "web_server": "string or null",
    "programming_language": "string or null",
    "framework": "string or null",
    "cms": "string or null",
    "cdn_waf": "string or null",
    "cloud_provider": "string or null",
    "database": "string or null (inferred from headers/tech)"
  },
  "attack_surface": {
    "total_subdomains_found": "int",
    "total_ip_addresses": "int",
    "services_exposed": ["list of strings describing exposed services"],
    "third_party_dependencies": "int (estimated from headers)"
  },
  "threat_model": {
    "overall_risk_level": "Critical/High/Medium/Low/Info",
    "highest_risk_vectors": ["list of strings"],
    "recommended_focus_areas": ["list of strings"],
    "likely_vulnerabilities": [
      {
        "vulnerability": "string",
        "rationale": "string explaining why this is likely based on the data",
        "priority": 1-10 (10 is highest)
      }
    ]
  },
  "summary": "A one-paragraph strategic assessment"
}"""


class AnalystAgent(GroqAgent):
    name = "ANALYST"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    async def run(self, context: dict) -> dict:
        scout_data = context.get("scout", {})
        fingerprint_data = context.get("fingerprint", {})

        self.emit_running("Analyzing reconnaissance data...")

        user_prompt = f"""Analyze the following reconnaissance data and produce a threat model.

SCOUT (DNS/Network Reconnaissance):
{self._fmt(scout_data)}

FINGERPRINT (HTTP/Application Reconnaissance):
{self._fmt(fingerprint_data)}

Return ONLY valid JSON matching the schema."""

        raw = self._call_groq(SYSTEM_PROMPT, user_prompt, temperature=0.3)
        parsed = self._parse_json(raw)

        if parsed:
            self.emit_complete(f"Analyst complete: {parsed.get('threat_model',{}).get('overall_risk_level','?')} risk, {len(parsed.get('threat_model',{}).get('likely_vulnerabilities',[]))} likely vulns")
            return parsed
        else:
            fallback = self._fallback_analysis(scout_data, fingerprint_data)
            self.emit_complete("Analyst complete (fallback analysis)")
            return fallback

    def _fmt(self, data: dict) -> str:
        import json
        return json.dumps(data, indent=2, default=str)[:3000]

    def _fallback_analysis(self, scout: dict, fingerprint: dict) -> dict:
        findings = scout.get("findings", []) + fingerprint.get("findings", [])
        vulns = []
        for f in findings:
            vulns.append({
                "vulnerability": f.get("type", "unknown"),
                "rationale": f.get("detail", "Detected during reconnaissance"),
                "priority": 7,
            })
        return {
            "technology_stack": {
                "web_server": fingerprint.get("server_headers", {}).get("server", None),
                "programming_language": fingerprint.get("server_headers", {}).get("x-powered-by", None),
                "cdn_waf": scout.get("cdn_waf", None),
            },
            "attack_surface": {
                "total_subdomains_found": len(scout.get("subdomains", [])),
                "total_ip_addresses": len(scout.get("a_records", [])),
                "services_exposed": [f.get("detail", "") for f in findings],
                "third_party_dependencies": 0,
            },
            "threat_model": {
                "overall_risk_level": "High" if len(findings) > 3 else "Medium",
                "highest_risk_vectors": [f.get("type", "unknown") for f in findings[:3]],
                "recommended_focus_areas": [
                    "Review server header disclosure",
                    "Check for missing security headers",
                    "Validate CORS configuration",
                ],
                "likely_vulnerabilities": vulns[:8],
            },
            "summary": f"Found {len(findings)} issues during reconnaissance. {len(scout.get('subdomains',[]))} subdomains, {len(scout.get('a_records',[]))} IPs, {fingerprint.get('cdn_waf') or 'no'} WAF detected.",
        }
