from __future__ import annotations
import logging
from typing import Any

from core.agents.base import GroqAgent

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are an elite penetration testing report writer. Synthesize all findings from a 10-agent web application kill chain into a structured vulnerability report.

You MUST return ONLY valid JSON with this exact schema:
{
  "executive_summary": "A 2-3 paragraph executive summary of the security assessment",
  "overall_risk_score": "integer 0-100 (100 = most vulnerable)",
  "risk_level": "Critical/High/Medium/Low",
  "total_findings": "integer",
  "vulnerabilities": [
    {
      "title": "Clear vulnerability title",
      "description": "Detailed description of the vulnerability",
      "affected_component": "Which part of the application (URL, endpoint, header, etc.)",
      "severity": "Critical/High/Medium/Low/Info",
      "cvss_score": "CVSS 3.1 base score (e.g., 8.5)",
      "proof_of_concept": "What was actually observed/detected",
      "remediation": "Specific remediation recommendation",
      "cwe": "CWE identifier (e.g., CWE-79)",
      "agent_source": "Which agent found it (SCOUT, FINGERPRINT, EXPLOIT, etc.)"
    }
  ],
  "methodology_summary": "1-2 sentences about the testing methodology",
  "remediation_priorities": [
    {
      "priority": "Immediate/Short-term/Long-term",
      "action": "Specific action to take",
      "affected_findings": ["list of vulnerability titles"]
    }
  ],
  "cvss_metrics": {
    "avg_score": "float",
    "max_score": "float",
    "min_score": "float"
  }
}

Rules:
- Be specific and technical. Include actual evidence from agent outputs.
- CVSS scores MUST be in the range 0.1-10.0
- CWE references MUST be real, valid CWEs
- Sort vulnerabilities by severity (Critical first, Info last)
- The CVSS vector string is optional but encouraged
- Overall risk score: 0-30=Low, 31-50=Medium, 51-75=High, 76-100=Critical"""


class DebriefAgent(GroqAgent):
    name = "DEBRIEF"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    async def run(self, context: dict) -> dict:
        all_agent_outputs = {}
        all_findings = []

        for agent_name in ["scout", "fingerprint", "analyst", "planner", "exploit", "payload", "pivot", "persist", "exfil"]:
            data = context.get(agent_name, {})
            if data:
                all_agent_outputs[agent_name.upper()] = data
                agent_findings = data.get("findings", [])
                if isinstance(agent_findings, list):
                    all_findings.extend(agent_findings)

        self.emit_running(f"Synthesizing {len(all_findings)} findings from {len(all_agent_outputs)} agents...")

        user_prompt = f"""Synthesize the following kill chain outputs into a structured vulnerability report.

TARGET: {context.get('target_url', 'unknown')}

AGENT OUTPUTS:
{self._fmt(all_agent_outputs)}

ALL RAW FINDINGS:
{self._fmt(all_findings)}

Return the report as valid JSON matching the schema."""

        raw = self._call_groq(SYSTEM_PROMPT, user_prompt, temperature=0.2)
        parsed = self._parse_json(raw)

        if parsed:
            vuln_count = len(parsed.get("vulnerabilities", []))
            risk = parsed.get("overall_risk_score", "?")
            self.emit_complete(f"Debrief complete: {vuln_count} vulns reported, risk score {risk}/100")
            return parsed
        else:
            fallback = self._fallback_report(all_agent_outputs, all_findings, context.get("target_url", ""))
            self.emit_complete("Debrief complete (fallback report)")
            return fallback

    def _fmt(self, data: Any) -> str:
        import json
        return json.dumps(data, indent=2, default=str)[:6000]

    def _fallback_report(self, agent_outputs: dict, findings: list, target_url: str) -> dict:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get("type", "info").lower(), 5))

        vulns = []
        for f in sorted_findings:
            vulns.append({
                "title": f.get("type", "Unknown Finding").replace("_", " ").title(),
                "description": f.get("detail", "No description"),
                "affected_component": f.get("path", f.get("param", f.get("url", target_url))),
                "severity": self._infer_severity(f.get("type", "")),
                "cvss_score": self._infer_cvss(f.get("type", "")),
                "proof_of_concept": f.get("evidence", f.get("detail", "Observed during scanning")),
                "remediation": self._get_remediation(f.get("type", "")),
                "cwe": self._type_to_cwe(f.get("type", "")),
                "agent_source": f.get("agent", "unknown"),
            })

        total = len(vulns)
        risk = min(total * 12, 100)
        return {
            "executive_summary": f"Security assessment of {target_url} identified {total} findings across web, network, and application layers.",
            "overall_risk_score": risk,
            "risk_level": "Critical" if risk > 75 else "High" if risk > 50 else "Medium" if risk > 30 else "Low",
            "total_findings": total,
            "vulnerabilities": vulns,
            "methodology_summary": "10-agent autonomous kill chain: SCOUT → FINGERPRINT → ANALYST → PLANNER → EXPLOIT → PAYLOAD → PIVOT → PERSIST → EXFIL → DEBRIEF",
            "remediation_priorities": [
                {"priority": "Immediate", "action": "Fix all Critical and High severity findings", "affected_findings": [v["title"] for v in vulns if v["severity"] in ("Critical", "High")]},
                {"priority": "Short-term", "action": "Address Medium severity findings and implement security headers", "affected_findings": [v["title"] for v in vulns if v["severity"] == "Medium"]},
                {"priority": "Long-term", "action": "Establish secure coding practices and regular security scanning", "affected_findings": []},
            ],
            "cvss_metrics": {"avg_score": 7.0, "max_score": 10.0, "min_score": 3.0},
        }

    def _infer_severity(self, vuln_type: str) -> str:
        t = vuln_type.lower()
        if any(k in t for k in ["critical", "sql", "rce", "command", "ssti", "env", "credential", "api_key", "default_credential"]):
            return "Critical"
        if any(k in t for k in ["high", "xss", "ssrf", "auth", "exposed", "jwt", "admin", "traversal", "upload"]):
            return "High"
        if any(k in t for k in ["medium", "cors", "clickjack", "csp", "xfo", "missing", "mixed", "info_leak"]):
            return "Medium"
        if any(k in t for k in ["low", "tracking", "server_info", "hsts", "cookie"]):
            return "Low"
        return "Info"

    def _infer_cvss(self, vuln_type: str) -> float:
        sev = self._infer_severity(vuln_type)
        return {"Critical": 9.5, "High": 7.5, "Medium": 5.5, "Low": 3.0, "Info": 1.0}.get(sev, 5.0)

    def _get_remediation(self, vuln_type: str) -> str:
        rem = {
            "xss": "Implement output encoding and Content-Security-Policy",
            "sql": "Use parameterized queries",
            "ssti": "Sandbox template engine",
            "command": "Avoid shell execution with user input",
            "cors": "Restrict Access-Control-Allow-Origin",
            "hsts": "Enable HSTS with long max-age",
            "clickjack": "Set X-Frame-Options or CSP frame-ancestors",
            "admin": "Restrict admin panel access",
            "env": "Remove .env from public root",
            "credential": "Remove hardcoded credentials",
            "tracking": "Review third-party scripts for compliance",
            "mixed": "Load all resources over HTTPS",
            "stack_trace": "Disable debug mode in production",
            "jwt": "Validate token expiration and signature",
        }
        for key, val in rem.items():
            if key in vuln_type.lower():
                return val
        return "Review and remediate based on specific finding details"

    def _type_to_cwe(self, vuln_type: str) -> str:
        mapping = {
            "xss": "CWE-79", "sql": "CWE-89", "ssti": "CWE-1336",
            "command": "CWE-78", "ssrf": "CWE-918", "cors": "CWE-942",
            "hsts": "CWE-319", "clickjack": "CWE-1021", "redirect": "CWE-601",
            "traversal": "CWE-22", "auth": "CWE-287", "jwt": "CWE-345",
            "env": "CWE-200", "credential": "CWE-798", "stack": "CWE-209",
            "exposure": "CWE-200", "header": "CWE-113",
            "tracking": "CWE-200", "mixed": "CWE-319",
            "admin": "CWE-284", "default_credential": "CWE-1392",
            "api_key": "CWE-798", "information_disclosure": "CWE-200",
            "server_info": "CWE-200", "csp": "CWE-1021",
            "xfo": "CWE-1021", "cookie": "CWE-614",
            "directory_listing": "CWE-548", "rate_limiting": "CWE-307",
            "autocomplete": "CWE-200", "username_enumeration": "CWE-204",
        }
        for key, val in mapping.items():
            if key in vuln_type.lower():
                return val
        return "CWE-200"
