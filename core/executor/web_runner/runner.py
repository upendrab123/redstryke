from __future__ import annotations
import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any

from core.scanner.orchestrator import WebScanOrchestrator, WebScanResult
from core.scanner.web.finding import WebFinding, WebSeverity, WebVulnType

logger = logging.getLogger(__name__)


@dataclass
class WebAttackTask:
    task_id: str
    target_url: str
    description: str = ""
    depth: str = "standard"
    categories: list[str] = field(default_factory=list)
    custom_checks: list[str] = field(default_factory=list)


class WebRunner:
    def __init__(self, memory_manager: Any, config: dict[str, Any] | None = None):
        self.memory_manager = memory_manager
        self.config = config or {}
        self._orchestrator: WebScanOrchestrator | None = None

    async def run(
        self,
        target_url: str,
        depth: str = "standard",
    ) -> WebScanResult:
        orchestrator = WebScanOrchestrator(self.config)
        try:
            result = await orchestrator.run_scan(target_url, depth)
            return result
        finally:
            await orchestrator.close()

    def run_sync(
        self,
        target_url: str,
        depth: str = "standard",
    ) -> WebScanResult:
        return asyncio.run(self.run(target_url, depth))

    async def run_task(self, task: WebAttackTask) -> WebScanResult:
        return await self.run(task.target_url, task.depth)

    def get_findings_for_report(self, result: WebScanResult) -> list[dict[str, Any]]:
        report_data = []
        for f in result.findings:
            report_data.append({
                "id": f.finding_id,
                "url": f.url,
                "type": f.vulnerability_type.value,
                "severity": f.severity.value,
                "description": f.description,
                "evidence": f.evidence,
                "remediation": f.remediation,
                "owasp": f.owasp_category,
                "confidence": f.confidence,
                "affected_param": f.affected_param,
            })
        return report_data

    def get_summary_stats(self, result: WebScanResult) -> dict[str, Any]:
        return {
            "total": result.total_findings,
            "by_severity": result.severity_counts,
            "by_type": self._group_by_type(result.findings),
            "tech_stack": list(result.tech_stack.keys()),
            "urls_scanned": result.urls_crawled,
            "forms_tested": result.forms_found,
            "duration_seconds": result.scan_duration_seconds,
        }

    def _group_by_type(self, findings: list[WebFinding]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            vt = f.vulnerability_type.value
            counts[vt] = counts.get(vt, 0) + 1
        return counts
