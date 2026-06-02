"""
ReportGenerator: Produces professional PDF reports from engagement findings.

Pipeline:
 1. Query SQLite for all findings in the engagement.
 2. Call Groq to write the executive summary (plain-English, non-technical).
 3. Render Jinja2 HTML template with all data injected.
 4. Convert HTML → PDF via WeasyPrint.
 5. Save PDF to data/reports/{engagement_id}_{timestamp}.pdf.

The report includes:
 - Executive summary (LLM-written)
 - Risk matrix visualization
 - Per-finding detail cards with reproduction steps
 - Regulatory mapping (EU AI Act, NIST AI RMF, ISO 42001)
 - Prioritized remediation recommendations
 - Appendix with raw attack logs
"""

from __future__ import annotations
import logging
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import yaml

from core.memory.sql_store.sqlite_memory import SQLMemory

logger = logging.getLogger(__name__)

FALLBACK_RECOMMENDATIONS = {
    "jailbreak": "Implement output content filtering and system prompt isolation to prevent jailbreak attacks.",
    "prompt_injection": "Sanitize all user inputs and implement input validation to block prompt injection attempts.",
    "data_exfiltration": "Apply data loss prevention controls and restrict access to sensitive information in responses.",
    "data_leakage": "Implement output filtering and context isolation to prevent sensitive data leakage.",
    "harmful_content": "Add content safety filters and implement toxicity detection to block harmful outputs.",
    "toxic_output": "Enable toxicity detection and content moderation to filter harmful responses.",
    "encoding_bypass": "Implement input decoding validation and block encoded attack payloads.",
    "tool_abuse": "Restrict tool usage permissions and implement usage logging to prevent abuse.",
    "multi_turn_erosion": "Implement conversation boundary enforcement to prevent gradual erosion attacks.",
    "authority_escalation": "Add identity verification and access control to prevent authority escalation.",
    "persona_hijack": "Implement persona enforcement and prevent role manipulation attacks.",
}


def _load_config() -> dict[str, Any]:
    """Load settings from config/settings.yaml."""
    config_path = Path(__file__).parent.parent.parent.parent / "config" / "settings.yaml"
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


@dataclass
class ReportConfig:
    """Configuration for a single report generation run."""
    engagement_id: str
    target_description: str
    company_name: str
    output_dir: Path
    logo_path: Optional[Path] = None
    include_raw_logs: bool = True
    scan_type: str = "AI Red Team"
    scan_depth: str = "standard"
    web_findings: Optional[list[dict[str, Any]]] = None
    web_tech_stack: Optional[list[str]] = None
    web_urls_crawled: int = 0
    web_forms_found: int = 0


class ReportGenerator:
    """
    Generates professional PDF red team reports.

    Uses Jinja2 for HTML templating and WeasyPrint for PDF conversion.
    The executive summary is written by Groq LLM.
    """

    def __init__(
        self,
        groq_client: Any,
        sql_memory: SQLMemory,
        template_dir: Optional[Path] = None,
        config: Optional[dict[str, Any]] = None,
    ) -> None:
        """
        Args:
            groq_client: For writing the executive summary.
            sql_memory: SQLMemory instance to query findings.
            template_dir: Path to core/reporter/templates/.
            config: Report settings from config/report_templates_config.yaml.
        """
        self.groq_client = groq_client
        self.sql_memory = sql_memory
        self.config = config or _load_config()

        default_template_dir = Path(__file__).parent / "templates"
        self.template_dir = template_dir or default_template_dir
        self._ensure_template_exists()

    def _ensure_template_exists(self) -> None:
        """Create template directory and default template if not exists."""
        self.template_dir.mkdir(parents=True, exist_ok=True)
        template_path = self.template_dir / "report.html"

        if not template_path.exists():
            self._create_default_template(template_path)

    def _create_default_template(self, template_path: Path) -> None:
        """Create default Jinja2 HTML template."""
        template_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Red Team Assessment Report</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; line-height: 1.6; color: #333; }
        .header { border-bottom: 3px solid #c00; padding-bottom: 20px; margin-bottom: 30px; }
        .header h1 { color: #c00; margin: 0; font-size: 28px; }
        .header .subtitle { color: #666; font-size: 14px; margin-top: 5px; }
        .section { margin: 30px 0; }
        .section h2 { color: #444; border-bottom: 1px solid #ddd; padding-bottom: 10px; font-size: 20px; }
        .executive-summary { background: #f8f9fa; padding: 20px; border-left: 4px solid #c00; margin: 20px 0; }
        .summary-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .summary-table th, .summary-table td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        .summary-table th { background: #f4f4f4; font-weight: bold; }
        .severity-critical { background: #dc3545; color: white; padding: 3px 8px; border-radius: 3px; }
        .severity-high { background: #fd7e14; color: white; padding: 3px 8px; border-radius: 3px; }
        .severity-medium { background: #ffc107; color: black; padding: 3px 8px; border-radius: 3px; }
        .severity-low { background: #28a745; color: white; padding: 3px 8px; border-radius: 3px; }
        .severity-info { background: #6c757d; color: white; padding: 3px 8px; border-radius: 3px; }
        .finding-card { border: 1px solid #ddd; padding: 15px; margin: 15px 0; border-radius: 5px; }
        .recommendation { background: #e7f3ff; padding: 10px; margin: 10px 0; border-left: 3px solid #0066cc; }
        .regulatory { background: #f0f0f0; padding: 15px; margin: 15px 0; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>AI Red Team Assessment Report</h1>
        <div class="subtitle">{{ company_name }} | {{ target_description }}</div>
    </div>

    <div class="section">
        <h2>Executive Summary</h2>
        <div class="executive-summary">{{ executive_summary }}</div>
    </div>

    <div class="section">
        <h2>Assessment Overview</h2>
        <table class="summary-table">
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Target URL</td><td>{{ target_url }}</td></tr>
            <tr><td>Total Findings</td><td>{{ total_findings }}</td></tr>
            <tr><td>Critical</td><td>{{ severity_counts.critical }}</td></tr>
            <tr><td>High</td><td>{{ severity_counts.high }}</td></tr>
            <tr><td>Medium</td><td>{{ severity_counts.medium }}</td></tr>
            <tr><td>Low</td><td>{{ severity_counts.low }}</td></tr>
            <tr><td>Info</td><td>{{ severity_counts.info }}</td></tr>
        </table>
    </div>

    {% if findings_by_severity %}
    <div class="section">
        <h2>Detailed Findings</h2>
        {% for severity, findings in findings_by_severity.items() %}
            {% if findings %}
            <h3>{{ severity|upper }} Severity ({{ findings|length }} findings)</h3>
            {% for finding in findings %}
            <div class="finding-card">
                <strong>{{ finding.category }}</strong> 
                <span class="severity-{{ severity }}">{{ severity|upper }}</span>
                <p><strong>Description:</strong> {{ finding.description }}</p>
                {% if finding.recommendation %}
                <div class="recommendation"><strong>Recommendation:</strong> {{ finding.recommendation }}</div>
                {% endif %}
            </div>
            {% endfor %}
            {% endif %}
        {% endfor %}
    </div>
    {% endif %}

    {% if recommendations %}
    <div class="section">
        <h2>Remediation Recommendations</h2>
        {% for rec in recommendations %}
        <div class="recommendation">{{ rec }}</div>
        {% endfor %}
    </div>
    {% endif %}

    {% if regulatory_refs %}
    <div class="section">
        <h2>Regulatory Compliance</h2>
        <div class="regulatory">
            {% for framework, articles in regulatory_refs.items() %}
            <p><strong>{{ framework }}:</strong> {{ articles|join(', ') }}</p>
            {% endfor %}
        </div>
    </div>
    {% endif %}

    <div class="section">
        <h2>Methodology</h2>
        <p>This assessment was conducted using an autonomous AI red teaming platform that performs comprehensive security testing against LLM-based systems. The platform employs multi-layered attack strategies including prompt injection, jailbreak attempts, data exfiltration probes, and multi-turn conversation testing.</p>
    </div>

    <div class="footer">
        <p>Report generated: {{ timestamp }} | Engagement ID: {{ engagement_id }}</p>
    </div>
</body>
</html>"""
        template_path.write_text(template_content, encoding="utf-8")

    def generate(self, report_config: ReportConfig) -> Path:
        """
        Generate the full PDF report for an engagement.
        Supports both AI LLM findings and web vulnerability findings.
        """
        web_findings = report_config.web_findings or []
        llm_findings = []

        if report_config.scan_type == "Web Application":
            findings_by_severity = self._group_web_findings_by_severity(web_findings)
            total = sum(len(v) for v in findings_by_severity.values())
            severity_counts = self._compute_web_severity_counts(findings_by_severity)
            target_url = web_findings[0].get("url", "") if web_findings else ""
            target_desc = report_config.target_description
        else:
            try:
                engagement = self.sql_memory.get_engagement(report_config.engagement_id)
                llm_findings = self.sql_memory.get_findings(report_config.engagement_id)
                summary = self.sql_memory.get_engagement_summary(report_config.engagement_id)
            except Exception as e:
                logger.error(f"Failed to load engagement data: {e}")
                raise ReportGenerationError(f"Failed to load engagement data: {e}")

            findings_by_severity = self._group_findings_by_severity(llm_findings)
            total = summary.get("total", 0)
            severity_counts = {
                "critical": summary.get("critical", 0),
                "high": summary.get("high", 0),
                "medium": summary.get("medium", 0),
                "low": summary.get("low", 0),
                "info": summary.get("info", 0),
            }
            target_url = engagement.get("target_url", "")
            target_desc = engagement.get("target_description", report_config.target_description)

        merged_findings = web_findings + llm_findings
        if not merged_findings:
            for sev in ["critical", "high", "medium", "low", "info"]:
                if findings_by_severity.get(sev):
                    break
            else:
                pass

        executive_summary = self._generate_executive_summary(
            merged_findings, {"target_url": target_url}, target_desc, report_config.scan_type
        )

        recommendations = self._generate_recommendations(llm_findings)
        recommendations.extend(self._generate_web_recommendations(web_findings))

        regulatory_refs = self._build_regulatory_mapping(llm_findings)

        template_data = {
            "company_name": report_config.company_name,
            "target_description": target_desc,
            "target_url": target_url,
            "engagement_id": report_config.engagement_id,
            "report_type": report_config.scan_type,
            "scan_type": report_config.scan_type,
            "scan_depth": report_config.scan_depth,
            "total_findings": total,
            "severity_counts": severity_counts,
            "findings_by_severity": findings_by_severity,
            "executive_summary": executive_summary,
            "recommendations": recommendations,
            "regulatory_refs": regulatory_refs,
            "web_tech_stack": report_config.web_tech_stack,
            "web_urls_crawled": report_config.web_urls_crawled,
            "web_forms_found": report_config.web_forms_found,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

        html_content = self._render_html(template_data)

        output_path = report_config.output_dir / f"{report_config.engagement_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        report_config.output_dir.mkdir(parents=True, exist_ok=True)

        pdf_bytes = self._html_to_pdf(html_content, output_path)

        return output_path

    def _group_findings_by_severity(self, findings: list[dict[str, Any]]) -> dict[str, list[dict]]:
        """Group findings by severity level."""
        grouped = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        severity_order = ["critical", "high", "medium", "low", "info"]

        for finding in findings:
            metadata = finding.get("finding_json", "{}")
            if isinstance(metadata, str):
                import json
                try:
                    metadata = json.loads(metadata)
                except:
                    metadata = {}

            severity = metadata.get("severity", "info").lower()
            if severity not in grouped:
                severity = "info"

            grouped[severity].append({
                "category": metadata.get("category", "unknown"),
                "attack_type": metadata.get("attack_type", "unknown"),
                "description": metadata.get("attack_prompt", "")[:200],
                "severity": severity,
                "recommendation": FALLBACK_RECOMMENDATIONS.get(metadata.get("category", ""), "Review and remediate based on findings."),
            })

        return {k: v for k, v in zip(severity_order, [grouped[s] for s in severity_order]) if v}

    def _generate_executive_summary(
        self,
        findings: list[dict[str, Any]],
        engagement: dict[str, Any],
        target_description: str,
        scan_type: str = "AI Red Team",
    ) -> str:
        """Generate executive summary using Groq or fallback."""
        if not findings:
            return "No vulnerabilities were detected during this assessment. The target system appears to have passed all security tests performed by the red team platform."

        critical = sum(1 for f in findings if f.get("severity", "").lower() == "critical")
        high = sum(1 for f in findings if f.get("severity", "").lower() == "high")
        total = len(findings)

        severity_text = "low risk"
        if critical > 0 or high > 2:
            severity_text = "high risk"
        elif high > 0 or total > 5:
            severity_text = "moderate risk"

        if scan_type == "Web Application":
            para1 = f"This web application security assessment of {target_description} identified {total} security findings. Overall, the target is assessed as {severity_text}."
            para2 = ""
            if critical > 0:
                para2 = f"Critical findings ({critical}) require immediate attention. These include exposed credentials, SQL injection vulnerabilities, or sensitive path exposures that could lead to data breaches or complete server compromise."
            elif high > 0:
                para2 = f"High severity findings ({high}) indicate significant security weaknesses such as XSS vulnerabilities, missing security headers, or exposed admin panels that should be addressed to prevent exploitation."
            para3 = "We recommend implementing the prioritized remediation recommendations provided in this report. Focus on critical and high severity items first, then address medium severity findings in a systematic manner."
        else:
            para1 = f"This security assessment of {target_description} identified {total} security findings. Overall, the target is assessed as {severity_text}."
            para2 = ""
            if critical > 0:
                para2 = f"Critical findings ({critical}) require immediate attention as they represent severe security vulnerabilities that could lead to data breaches or system compromise."
            elif high > 0:
                para2 = f"High severity findings ({high}) indicate significant security weaknesses that should be addressed to prevent potential exploitation."
            para3 = "We recommend implementing the prioritized remediation recommendations provided in this report. Focus on critical and high severity items first, then address medium severity findings in a systematic manner."

        if self.groq_client:
            try:
                from collections import Counter
                sev_counter = Counter(f.get("severity", "info").lower() for f in findings)
                prompt = f"""Write a 3-paragraph executive summary for a {scan_type} security assessment report.

Target: {target_description}
Scan Type: {scan_type}
Total findings: {total}
Critical: {critical}
High: {high}
Medium: {sev_counter.get('medium', 0)}
Low: {sev_counter.get('low', 0)}
Info: {sev_counter.get('info', 0)}

Write exactly 3 paragraphs. No bullet points. Plain English for C-suite readers."""

                response = self.groq_client.chat.completions.create(
                    model=self.config.get("groq", {}).get("reporter_model", "llama-3.3-70b-versatile"),
                    temperature=0.3,
                    max_tokens=500,
                    messages=[
                        {"role": "system", "content": "You are a cybersecurity expert writing executive summaries."},
                        {"role": "user", "content": prompt},
                    ],
                )
                return response.choices[0].message.content
            except Exception as e:
                logger.warning(f"Groq summary generation failed: {e}")

        return f"{para1} {para2} {para3}"

    def _generate_recommendations(self, findings: list[dict[str, Any]]) -> list[str]:
        """Generate remediation recommendations."""
        recommendations = []
        seen_types = set()

        for finding in findings:
            import json
            try:
                metadata = json.loads(finding.get("finding_json", "{}"))
            except:
                metadata = {}

            category = metadata.get("category", "unknown")
            severity = metadata.get("severity", "info").lower()

            if category in seen_types:
                continue

            if severity in ["critical", "high"]:
                rec = FALLBACK_RECOMMENDATIONS.get(category, f"Review and address {category} findings.")
                recommendations.append(rec)
                seen_types.add(category)

            if len(recommendations) >= 10:
                break

        return recommendations[:10]

    def _build_regulatory_mapping(self, findings: list[dict[str, Any]]) -> dict[str, list[str]]:
        """Map findings to regulatory frameworks."""
        ref_map = {"EU AI Act": set(), "NIST AI RMF": set(), "ISO 42001": set(), "OWASP LLM": set()}

        has_critical_high = False
        has_jailbreak = False
        has_data_exfil = False
        has_tool_abuse = False

        for finding in findings:
            import json
            try:
                metadata = json.loads(finding.get("finding_json", "{}"))
            except:
                metadata = {}

            severity = metadata.get("severity", "").lower()
            category = metadata.get("category", "").lower()

            if severity in ["critical", "high"]:
                has_critical_high = True
            if "jailbreak" in category:
                has_jailbreak = True
            if "exfil" in category or "leak" in category:
                has_data_exfil = True
            if "tool" in category or "abuse" in category:
                has_tool_abuse = True

        if has_critical_high:
            ref_map["EU AI Act"].add("Article 9 (Risk Management)")
            ref_map["NIST AI RMF"].add("MS-2.5 (Adversarial Testing)")

        if has_jailbreak:
            ref_map["OWASP LLM"].add("OWASP LLM01")

        if has_data_exfil:
            ref_map["OWASP LLM"].add("OWASP LLM06")
            ref_map["EU AI Act"].add("Article 13 (Transparency)")

        if has_tool_abuse:
            ref_map["OWASP LLM"].add("OWASP LLM08")
            ref_map["ISO 42001"].add("Section 6.1")

        return {k: list(v) for k, v in ref_map.items() if v}

    def _group_web_findings_by_severity(self, web_findings: list[dict[str, Any]]) -> dict[str, list[dict]]:
        """Group web vulnerability findings by severity level."""
        grouped: dict[str, list[dict]] = {
            "critical": [], "high": [], "medium": [], "low": [], "info": [],
        }
        severity_order = ["critical", "high", "medium", "low", "info"]

        for f in web_findings:
            severity = f.get("severity", "info").lower()
            if severity not in grouped:
                severity = "info"
            grouped[severity].append({
                "type_label": f.get("vulnerability_type", f.get("type", "unknown")).replace("_", " ").title(),
                "url": f.get("url", ""),
                "description": f.get("description", ""),
                "evidence": f.get("evidence", ""),
                "remediation": f.get("remediation", ""),
                "owasp": f.get("owasp_category", f.get("owasp", "")),
                "confidence": f.get("confidence", 1.0),
                "affected_param": f.get("affected_param", ""),
                "severity": severity,
            })

        return {k: grouped[k] for k in severity_order if grouped[k]}

    def _compute_web_severity_counts(self, grouped: dict[str, list]) -> dict[str, int]:
        return {sev: len(items) for sev, items in grouped.items()}

    def _generate_web_recommendations(self, web_findings: list[dict[str, Any]]) -> list[str]:
        recs = []
        seen = set()
        for f in web_findings:
            vuln_type = f.get("vulnerability_type", f.get("type", ""))
            remediation = f.get("remediation", "")
            severity = f.get("severity", "info").lower()
            if vuln_type and remediation and severity in ("critical", "high"):
                key = vuln_type.split(":")[0]
                if key not in seen:
                    recs.append(f"[{severity.upper()}] {vuln_type.replace('_', ' ').title()}: {remediation}")
                    seen.add(key)
        return recs[:10]

    def _render_html(self, template_data: dict[str, Any]) -> str:
        """Render Jinja2 HTML template."""
        try:
            from jinja2 import Environment, FileSystemLoader
            env = Environment(autoescape=True)
            template = env.from_string(self.template_dir.joinpath("report.html").read_text(encoding="utf-8"))
            return template.render(**template_data)
        except Exception as e:
            logger.error(f"Template rendering failed: {e}")
            raise ReportGenerationError(f"Template rendering failed: {e}")

    def _html_to_pdf(self, html_content: str, output_path: Path) -> bytes:
        """Convert HTML to PDF using xhtml2pdf."""
        try:
            from xhtml2pdf.pisa import pisaDocument
            with open(output_path, "wb") as pdf_file:
                pisaDocument(html_content.encode("utf-8"), pdf_file)
            pdf_bytes = output_path.read_bytes()
            logger.info(f"PDF saved to {output_path}")
            return pdf_bytes
        except ImportError:
            logger.warning("xhtml2pdf not installed, saving HTML instead")
            html_path = output_path.with_suffix(".html")
            html_path.write_text(html_content, encoding="utf-8")
            return html_content.encode("utf-8")
        except Exception as e:
            logger.warning(f"PDF conversion failed, saving HTML: {e}")
            html_path = output_path.with_suffix(".html")
            html_path.write_text(html_content, encoding="utf-8")
            return html_content.encode("utf-8")


class ReportGenerationError(Exception):
    """Raised when report generation fails at any stage."""
    pass

    def generate(self, report_config: ReportConfig) -> Path:
        """
        Generate the full PDF report for an engagement.

        Args:
            report_config: Report configuration dataclass.

        Returns:
            Path to the generated PDF file.

        Raises:
            ReportGenerationError: If template rendering or PDF conversion fails.
        """
        raise NotImplementedError

    def _write_executive_summary(
        self, findings: list[dict[str, Any]], target_description: str
    ) -> str:
        """
        Use Groq to write a plain-English executive summary.

        Prompts the LLM to write 3 paragraphs: overall risk posture,
        most critical findings, and recommended priority actions.
        Non-technical language — written for a C-suite audience.
        """
        raise NotImplementedError

    def _render_html(self, template_data: dict[str, Any]) -> str:
        """
        Render the Jinja2 HTML template with all report data injected.

        Returns the complete HTML string ready for WeasyPrint.
        """
        raise NotImplementedError

    def _html_to_pdf(self, html_content: str, output_path: Path) -> None:
        """
        Convert rendered HTML to PDF using WeasyPrint.

        WeasyPrint handles CSS layouts, page breaks, and headers/footers.
        """
        raise NotImplementedError

    def _build_regulatory_mapping(
        self, findings: list[dict[str, Any]]
    ) -> dict[str, list[str]]:
        """
        Map findings to specific regulatory articles.

        Returns dict of framework → list of triggered articles.
        Example: {"EU AI Act": ["Article 9", "Article 15"], "NIST AI RMF": ["MEASURE"]}
        """
        raise NotImplementedError


class ReportGenerationError(Exception):
    """Raised when report generation fails at any stage."""
    pass