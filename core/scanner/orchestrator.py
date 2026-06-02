from __future__ import annotations
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx

from core.scanner.web.finding import (
    WebFinding, WebSeverity, WebVulnType, SEVERITY_MAP,
)
from core.scanner.web.recon import ReconEngine
from core.scanner.web.checks.injection import InjectionScanner
from core.scanner.web.checks.security_headers import SecurityHeadersScanner
from core.scanner.web.checks.exposure import ExposureScanner
from core.scanner.web.checks.credentials import CredentialScanner
from core.scanner.web.checks.privacy import PrivacyScanner

logger = logging.getLogger(__name__)


@dataclass
class WebScanResult:
    scan_id: str
    target_url: str
    scan_depth: str
    findings: list[WebFinding] = field(default_factory=list)
    tech_stack: dict[str, str] = field(default_factory=dict)
    urls_crawled: int = 0
    forms_found: int = 0
    scripts_found: int = 0
    exposed_paths: list[str] = field(default_factory=list)
    tracking_domains: list[str] = field(default_factory=list)
    scan_duration_seconds: float = 0.0
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            if sev in counts:
                counts[sev] += 1
        return counts

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    def to_summary_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "scan_depth": self.scan_depth,
            "total_findings": self.total_findings,
            "severity_counts": self.severity_counts,
            "tech_stack": list(self.tech_stack.keys()),
            "urls_crawled": self.urls_crawled,
            "forms_found": self.forms_found,
            "exposed_paths": len(self.exposed_paths),
            "tracking_domains": len(self.tracking_domains),
            "scan_duration_seconds": self.scan_duration_seconds,
        }


class WebScanOrchestrator:
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.scan_config = self.config.get("web_scanner", {})
        self.concurrency = self.scan_config.get("max_concurrent_requests", 10)
        self._http: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._http is None or self._http.is_closed:
            limits = httpx.Limits(max_keepalive_connections=self.concurrency, max_connections=self.concurrency * 2)
            self._http = httpx.AsyncClient(
                limits=limits,
                timeout=httpx.Timeout(30.0),
                follow_redirects=True,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                },
            )
        return self._http

    async def close(self):
        if self._http and not self._http.is_closed:
            await self._http.aclose()

    async def run_scan(
        self,
        target_url: str,
        depth: str = "standard",
    ) -> WebScanResult:
        import time
        start_time = time.time()
        scan_id = str(uuid.uuid4())
        result = WebScanResult(scan_id=scan_id, target_url=target_url, scan_depth=depth)

        client = await self._get_client()
        parsed = urlparse(target_url)
        base_domain = parsed.netloc
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        logger.info(f"[WEB SCAN] Starting scan of {target_url} (depth={depth})")

        try:
            html, status, headers = await self._fetch_home(client, target_url)
            if not html and status != 200:
                logger.warning(f"Target unreachable: {target_url} (status={status})")
                result.findings.append(WebFinding.create(
                    url=target_url,
                    vuln_type=WebVulnType.UNKNOWN,
                    evidence=f"HTTP {status}: target did not return valid content",
                    description=f"Target returned status {status} — scan may be incomplete",
                    severity=WebSeverity.INFO,
                    response_status=status,
                    confidence=1.0,
                ))
                result.scan_duration_seconds = time.time() - start_time
                return result
        except Exception as e:
            logger.error(f"Failed to reach target: {e}")
            result.scan_duration_seconds = time.time() - start_time
            return result

        recon = ReconEngine(client, self.config)
        injection = InjectionScanner(client, self.config)
        headers_scanner = SecurityHeadersScanner(client, self.config)
        exposure = ExposureScanner(client, self.config)
        cred_scanner = CredentialScanner(self.config)
        privacy = PrivacyScanner(self.config)

        logger.info("[WEB SCAN] Phase 1: Reconnaissance")
        recon_result = await recon.run(target_url, depth)
        result.findings.extend(recon_result.findings)
        result.tech_stack = recon_result.tech_stack
        result.urls_crawled = len(recon_result.urls)
        result.forms_found = len(recon_result.forms)
        result.exposed_paths = recon_result.exposed_paths
        result.tracking_domains = recon_result.tracking_domains

        logger.info(f"[WEB SCAN] Found {len(recon_result.urls)} URLs, {len(recon_result.forms)} forms, {len(recon_result.tech_stack)} techs")

        logger.info("[WEB SCAN] Phase 2: Security Headers")
        header_findings = await headers_scanner.scan_url(target_url)
        result.findings.extend(header_findings)

        logger.info("[WEB SCAN] Phase 3: Injection Testing")
        inj_findings = await injection.scan(target_url, recon_result.forms, recon_result.urls, depth)
        result.findings.extend(inj_findings)

        logger.info("[WEB SCAN] Phase 4: Exposure Testing")
        exp_findings = await exposure.scan(base_url, depth)
        result.findings.extend(exp_findings)

        if depth in ("standard", "deep"):
            logger.info("[WEB SCAN] Phase 5: Credential Scanning")
            for script_url in recon_result.scripts[:20]:
                try:
                    resp = await client.get(script_url, timeout=10)
                    if resp.status_code == 200:
                        creds = cred_scanner.scan_url_content(script_url, resp.text, resp.headers.get("content-type", ""))
                        result.findings.extend(creds)
                except Exception:
                    pass

            logger.info("[WEB SCAN] Phase 6: Privacy Scanning")
            for page_url in recon_result.urls[:20]:
                try:
                    resp = await client.get(page_url, timeout=10)
                    if resp.status_code == 200:
                        privacy_findings = privacy.scan(page_url, resp.text, base_domain)
                        result.findings.extend(privacy_findings)
                except Exception:
                    pass

        if depth == "deep":
            logger.info("[WEB SCAN] Phase 7: Deep scan — JS credential scan on main page")
            body_creds = cred_scanner.scan_url_content(target_url, html)
            result.findings.extend(body_creds)

            logger.info("[WEB SCAN] Phase 8: Deep scan — PII scan on main page")
            pii_findings = privacy.scan(target_url, html, base_domain)
            result.findings.extend(pii_findings)

        result.findings = self._deduplicate_findings(result.findings)

        result.scan_duration_seconds = time.time() - start_time
        logger.info(f"[WEB SCAN] Complete: {result.total_findings} findings in {result.scan_duration_seconds:.1f}s")
        return result

    async def _fetch_home(self, client: httpx.AsyncClient, url: str) -> tuple[str, int, Any]:
        try:
            resp = await client.get(url, timeout=30)
            return resp.text, resp.status_code, resp.headers
        except httpx.TimeoutException:
            return "", 408, {}
        except Exception as e:
            logger.debug(f"Fetch home failed: {e}")
            return "", 0, {}

    def _deduplicate_findings(self, findings: list[WebFinding]) -> list[WebFinding]:
        seen: set[str] = set()
        unique: list[WebFinding] = []
        for f in findings:
            key = f"{f.vulnerability_type.value}:{f.url}:{f.affected_param}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
