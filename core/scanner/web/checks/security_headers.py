from __future__ import annotations
import logging
from typing import Any

import httpx

from core.scanner.web.finding import WebFinding, WebSeverity, WebVulnType

logger = logging.getLogger(__name__)

SECURITY_HEADERS = {
    "content-security-policy": {
        "name": "Content-Security-Policy",
        "severity": WebSeverity.MEDIUM,
        "description": "CSP helps prevent XSS and data injection attacks by controlling resource loading",
        "remediation": "Set a Content-Security-Policy header restricting script sources, object sources, and form actions.",
    },
    "strict-transport-security": {
        "name": "Strict-Transport-Security",
        "severity": WebSeverity.LOW,
        "description": "HSTS ensures the browser only connects over HTTPS",
        "remediation": "Set Strict-Transport-Security header with max-age=31536000 and includeSubDomains.",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "severity": WebSeverity.MEDIUM,
        "description": "X-Frame-Options prevents clickjacking by controlling iframe embedding",
        "remediation": "Set X-Frame-Options to DENY or SAMEORIGIN.",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "severity": WebSeverity.LOW,
        "description": "Prevents MIME-type sniffing by the browser",
        "remediation": "Set X-Content-Type-Options: nosniff.",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "severity": WebSeverity.LOW,
        "description": "Controls what referrer information is sent with requests",
        "remediation": "Set Referrer-Policy: strict-origin-when-cross-origin.",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "severity": WebSeverity.LOW,
        "description": "Restricts browser features like camera, microphone, geolocation",
        "remediation": "Set Permissions-Policy header restricting unnecessary features.",
    },
    "x-xss-protection": {
        "name": "X-XSS-Protection",
        "severity": WebSeverity.LOW,
        "description": "Older XSS filter, largely deprecated in modern browsers",
        "remediation": "Set X-XSS-Protection: 1; mode=block (deprecated, CSP is preferred).",
    },
}


class SecurityHeadersScanner:
    def __init__(self, http_client: httpx.AsyncClient, config: dict[str, Any] | None = None):
        self.http = http_client
        self.config = config or {}

    async def scan_url(self, url: str) -> list[WebFinding]:
        findings: list[WebFinding] = []
        try:
            resp = await self.http.get(url, timeout=10, follow_redirects=True)
            headers = {k.lower(): v for k, v in resp.headers.items()}

            for header_key, info in SECURITY_HEADERS.items():
                value = headers.get(header_key, "")
                if not value:
                    findings.append(WebFinding.create(
                        url=url,
                        vuln_type=self._header_to_vuln_type(header_key),
                        evidence=f"Missing security header: {info['name']}",
                        description=info["description"],
                        severity=info["severity"],
                        response_headers=dict(resp.headers),
                        response_status=resp.status_code,
                        confidence=1.0,
                    ))

            cors_origin = headers.get("access-control-allow-origin", "")
            if cors_origin == "*":
                findings.append(WebFinding.create(
                    url=url, vuln_type=WebVulnType.CORS_MISCONFIG,
                    evidence="Access-Control-Allow-Origin: *",
                    description="CORS allows any origin, enabling cross-origin data theft",
                    response_headers=dict(resp.headers),
                    response_status=resp.status_code,
                ))
            elif cors_origin:
                findings.append(WebFinding.create(
                    url=url, vuln_type=WebVulnType.CORS_MISCONFIG,
                    evidence=f"Access-Control-Allow-Origin: {cors_origin}",
                    description=f"CORS allows origin: {cors_origin} — verify this is intentional",
                    severity=WebSeverity.INFO,
                    response_headers=dict(resp.headers),
                    response_status=resp.status_code,
                    confidence=0.5,
                ))

            server = headers.get("server", "")
            if server:
                findings.append(WebFinding.create(
                    url=url, vuln_type=WebVulnType.SERVER_INFO,
                    evidence=f"Server header: {server}",
                    description=f"Server banner discloses: {server}",
                    severity=WebSeverity.LOW,
                    response_headers=dict(resp.headers),
                    response_status=resp.status_code,
                ))

            cookies_raw = headers.get("set-cookie", "")
            if cookies_raw:
                for cookie_part in self._split_cookies(cookies_raw):
                    finding = self._check_cookie(cookie_part, url, dict(resp.headers), resp.status_code)
                    if finding:
                        findings.append(finding)

        except httpx.TimeoutException:
            logger.debug(f"Timeout checking headers for {url}")
        except Exception as e:
            logger.debug(f"Header check failed for {url}: {e}")

        return findings

    def _header_to_vuln_type(self, header_key: str) -> WebVulnType:
        mapping = {
            "content-security-policy": WebVulnType.MISSING_CSP,
            "strict-transport-security": WebVulnType.MISSING_HSTS,
            "x-frame-options": WebVulnType.MISSING_XFO,
            "x-content-type-options": WebVulnType.MISSING_CT,
        }
        return mapping.get(header_key, WebVulnType.INFO_LEAK)

    def _split_cookies(self, raw: str) -> list[str]:
        parts = []
        buffer = ""
        depth = 0
        for ch in raw:
            if ch == "," and depth == 0:
                parts.append(buffer.strip())
                buffer = ""
            else:
                if ch == "=":
                    pass
                buffer += ch
        if buffer.strip():
            parts.append(buffer.strip())
        return parts or [raw]

    def _check_cookie(
        self, cookie_str: str, url: str,
        headers: dict, status: int,
    ) -> WebFinding | None:
        lower = cookie_str.lower()
        name = cookie_str.split("=")[0].strip() if "=" in cookie_str else "unknown"
        if not lower:
            return None
        if "httponly" not in lower:
            return WebFinding.create(
                url=url, vuln_type=WebVulnType.COOKIE_NO_HTTPONLY,
                evidence=f"Cookie '{name}' missing HttpOnly flag",
                description=f"Cookie '{name}' accessible via JavaScript",
                response_headers=headers, response_status=status,
            )
        if "secure" not in lower:
            return WebFinding.create(
                url=url, vuln_type=WebVulnType.COOKIE_NO_SECURE,
                evidence=f"Cookie '{name}' missing Secure flag",
                description=f"Cookie '{name}' transmitted over unencrypted connections",
                response_headers=headers, response_status=status,
            )
        if "samesite=" not in lower:
            return WebFinding.create(
                url=url, vuln_type=WebVulnType.COOKIE_NO_SAMESITE,
                evidence=f"Cookie '{name}' missing SameSite attribute",
                description=f"Cookie '{name}' vulnerable to CSRF attacks",
                response_headers=headers, response_status=status,
                confidence=0.8,
            )
        return None

    async def scan_basic_auth(self, url: str) -> WebFinding | None:
        try:
            parsed = __import__("urllib.parse").urlparse(url)
            basic_url = f"{parsed.scheme}://admin:admin@{parsed.netloc}{parsed.path}"
            resp = await self.http.get(
                url, auth=("admin", "admin"),
                timeout=10, follow_redirects=False,
            )
            if resp.status_code == 200:
                return WebFinding.create(
                    url=url, vuln_type=WebVulnType.DEFAULT_CREDENTIALS,
                    evidence="Default credentials admin:admin accepted",
                    description="Default admin credentials accepted by the server",
                    response_status=resp.status_code,
                    confidence=0.9,
                )
        except Exception:
            pass
        return None
