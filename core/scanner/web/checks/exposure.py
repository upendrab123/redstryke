from __future__ import annotations
import asyncio
import logging
from typing import Any
from urllib.parse import urljoin

import httpx

from core.scanner.web.finding import WebFinding, WebSeverity, WebVulnType

logger = logging.getLogger(__name__)

EXPOSURE_CHECKS = [
    (".git/config", WebVulnType.EXPOSED_GIT, WebSeverity.CRITICAL, "Git repository config exposed"),
    (".env", WebVulnType.EXPOSED_ENV, WebSeverity.CRITICAL, "Environment file with secrets exposed"),
    (".env.local", WebVulnType.EXPOSED_ENV, WebSeverity.CRITICAL, "Environment file with secrets exposed"),
    (".env.production", WebVulnType.EXPOSED_ENV, WebSeverity.CRITICAL, "Environment file with secrets exposed"),
    (".env.dev", WebVulnType.EXPOSED_ENV, WebSeverity.CRITICAL, "Environment file with secrets exposed"),
    (".env.staging", WebVulnType.EXPOSED_ENV, WebSeverity.CRITICAL, "Environment file with secrets exposed"),
    ("backup/", WebVulnType.EXPOSED_BACKUP, WebSeverity.HIGH, "Backup directory exposed"),
    ("backup.zip", WebVulnType.EXPOSED_BACKUP, WebSeverity.HIGH, "Backup zip file exposed"),
    ("backup.sql", WebVulnType.EXPOSED_BACKUP, WebSeverity.HIGH, "Backup SQL file exposed"),
    ("db_backup.sql", WebVulnType.EXPOSED_BACKUP, WebSeverity.HIGH, "Database backup exposed"),
    ("dump.sql", WebVulnType.EXPOSED_BACKUP, WebSeverity.HIGH, "Database dump exposed"),
    ("admin/", WebVulnType.EXPOSED_ADMIN, WebSeverity.HIGH, "Admin panel exposed"),
    ("wp-admin/", WebVulnType.EXPOSED_ADMIN, WebSeverity.HIGH, "WordPress admin panel exposed"),
    ("administrator/", WebVulnType.EXPOSED_ADMIN, WebSeverity.HIGH, "Admin panel exposed"),
    ("phpmyadmin/", WebVulnType.EXPOSED_ADMIN, WebSeverity.HIGH, "phpMyAdmin panel exposed"),
    ("debug/", WebVulnType.EXPOSED_DEBUG, WebSeverity.MEDIUM, "Debug endpoint exposed"),
    ("api/docs", WebVulnType.EXPOSED_DEBUG, WebSeverity.MEDIUM, "API documentation exposed"),
    ("swagger/", WebVulnType.EXPOSED_DEBUG, WebSeverity.MEDIUM, "Swagger/OpenAPI docs exposed"),
    ("swagger.json", WebVulnType.EXPOSED_DEBUG, WebSeverity.MEDIUM, "Swagger spec file exposed"),
    ("openapi.json", WebVulnType.EXPOSED_DEBUG, WebSeverity.MEDIUM, "OpenAPI spec file exposed"),
    ("graphql", WebVulnType.EXPOSED_DEBUG, WebSeverity.MEDIUM, "GraphQL endpoint exposed"),
    ("phpinfo.php", WebVulnType.EXPOSED_DEBUG, WebSeverity.MEDIUM, "PHP info endpoint exposed"),
    ("info.php", WebVulnType.EXPOSED_DEBUG, WebSeverity.MEDIUM, "PHP info endpoint exposed"),
    ("test.php", WebVulnType.EXPOSED_DEBUG, WebSeverity.MEDIUM, "Test script exposed"),
    (".svn/", WebVulnType.EXPOSED_GIT, WebSeverity.HIGH, "SVN metadata exposed"),
    (".DS_Store", WebVulnType.INFO_LEAK, WebSeverity.LOW, "macOS metadata file exposed"),
    ("robots.txt", WebVulnType.INFO_LEAK, WebSeverity.INFO, "Robots.txt may reveal hidden paths"),
    ("sitemap.xml", WebVulnType.INFO_LEAK, WebSeverity.INFO, "Sitemap may reveal all site URLs"),
    ("crossdomain.xml", WebVulnType.INFO_LEAK, WebSeverity.MEDIUM, "Cross-domain policy file exposed"),
    ("server-status", WebVulnType.EXPOSED_DEBUG, WebSeverity.HIGH, "Apache server-status exposed"),
    ("server-info", WebVulnType.EXPOSED_DEBUG, WebSeverity.HIGH, "Apache server-info exposed"),
    ("config/", WebVulnType.EXPOSED_DEBUG, WebSeverity.HIGH, "Configuration directory exposed"),
    ("config.php", WebVulnType.EXPOSED_DEBUG, WebSeverity.HIGH, "Configuration file exposed"),
    ("configuration.php", WebVulnType.EXPOSED_DEBUG, WebSeverity.HIGH, "Configuration file exposed"),
]

SENSITIVE_CONTENT_PATTERNS = {
    WebVulnType.EXPOSED_GIT: [
        b"[branch", b"[core]", b"repositoryformatversion",
        b"ref: refs/", b"worktree",
    ],
    WebVulnType.EXPOSED_ENV: [
        b"APP_KEY", b"DB_PASSWORD", b"API_KEY", b"SECRET",
        b"DB_HOST", b"DB_USERNAME", b"PASSWORD", b"TOKEN",
    ],
    WebVulnType.EXPOSED_BACKUP: [
        b"CREATE TABLE", b"INSERT INTO", b"DROP TABLE",
        b"---", b"<?php", b"<?xml",
    ],
}


class ExposureScanner:
    def __init__(self, http_client: httpx.AsyncClient, config: dict[str, Any] | None = None):
        self.http = http_client
        self.config = config or {}
        self.scan_config = self.config.get("web_scanner", {})
        self.timeout = self.scan_config.get("request_timeout", 10)

    async def scan(self, base_url: str, depth: str = "standard") -> list[WebFinding]:
        findings: list[WebFinding] = []
        max_checks = {"quick": 15, "standard": 40, "deep": len(EXPOSURE_CHECKS)}.get(depth, 40)
        checks = EXPOSURE_CHECKS[:max_checks]

        async def check(path: str, vuln_type: WebVulnType, severity: WebSeverity, desc: str) -> WebFinding | None:
            url = urljoin(base_url.rstrip("/") + "/", path)
            try:
                resp = await self.http.get(url, timeout=self.timeout, follow_redirects=True)
                if resp.status_code == 200 and len(resp.content) > 0:
                    if self._has_sensitive_content(resp.content, vuln_type):
                        return WebFinding.create(
                            url=url, vuln_type=vuln_type,
                            evidence=f"Exposed: {path} ({len(resp.content)} bytes)",
                            description=f"{desc}: {path}",
                            severity=severity,
                            response_status=resp.status_code,
                            response_body_preview=resp.text[:300],
                            confidence=0.95,
                        )
                    if vuln_type in (WebVulnType.INFO_LEAK, WebVulnType.EXPOSED_ADMIN, WebVulnType.EXPOSED_DEBUG):
                        return WebFinding.create(
                            url=url, vuln_type=vuln_type,
                            evidence=f"Accessible: {path} (status {resp.status_code})",
                            description=f"{desc}: {path}",
                            severity=severity,
                            response_status=resp.status_code,
                            confidence=0.7,
                        )
            except httpx.TimeoutException:
                pass
            except Exception as e:
                logger.debug(f"Exposure check failed for {url}: {e}")
            return None

        tasks = [check(p, vt, sv, d) for p, vt, sv, d in checks]
        results = await asyncio.gather(*tasks)
        for r in results:
            if r:
                findings.append(r)

        if depth == "deep":
            dir_listing = await self._check_directory_listing(base_url)
            if dir_listing:
                findings.append(dir_listing)

        return findings

    def _has_sensitive_content(self, content: bytes, vuln_type: WebVulnType) -> bool:
        patterns = SENSITIVE_CONTENT_PATTERNS.get(vuln_type, [])
        if not patterns:
            return len(content) > 50
        lower = content.lower()
        return any(p in lower for p in patterns)

    async def _check_directory_listing(self, base_url: str) -> WebFinding | None:
        test_paths = ["/", "/images/", "/css/", "/js/", "/static/"]
        for path in test_paths:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            try:
                resp = await self.http.get(url, timeout=self.timeout)
                if resp.status_code == 200:
                    lower = resp.text.lower()
                    if ("index of" in lower or "directory listing" in lower
                            or "parent directory" in lower):
                        return WebFinding.create(
                            url=url, vuln_type=WebVulnType.DIRECTORY_LISTING,
                            evidence="Directory listing enabled",
                            description=f"Directory listing enabled at {path}",
                            response_status=resp.status_code,
                            response_body_preview=resp.text[:300],
                        )
            except Exception:
                pass
        return None
