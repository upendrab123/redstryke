from __future__ import annotations
import asyncio
import logging
import re
import socket
import ssl
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse

import httpx

from core.scanner.web.finding import WebFinding, WebSeverity, WebVulnType

logger = logging.getLogger(__name__)

COMMON_DIRECTORIES = [
    ".git/", ".env", ".env.local", ".env.production", "backup/", "admin/",
    "wp-admin/", "wp-content/", "administrator/", "config/", "config.php",
    "db/", "debug/", "api/", "swagger/", "docs/", "robots.txt", "sitemap.xml",
    "crossdomain.xml", ".htaccess", ".htpasswd", "phpinfo.php",
    "info.php", "test.php", "dump/", "sql/", "phpmyadmin/",
    ".svn/", ".DS_Store", "conf/", "log/", "logs/", "error/",
    "server-status", "server-info", ".well-known/",
]

COMMON_PORTS = [21, 22, 80, 443, 8080, 8443, 3000, 5000, 8000, 9000]

TECH_PATTERNS: dict[str, list[str]] = {
    "nginx": [r"nginx/?[\d.]*"],
    "apache": [r"Apache(?:/[\d.]+)?"],
    "iis": [r"IIS(?:/[\d.]+)?"],
    "cloudflare": [r"cloudflare"],
    "wordpress": [r"wp-content", r"wp-includes", r"/wp-json/"],
    "drupal": [r"Drupal", r"drupal.js", r"sites/default"],
    "joomla": [r"joomla", r"com_content", r"com_user"],
    "laravel": [r"laravel", r"_token"],
    "django": [r"django", r"csrfmiddlewaretoken", r"__admin__"],
    "flask": [r"flask", r"jinja"],
    "react": [r"react", r"react-dom", r"__NEXT_DATA__"],
    "vue": [r"vue", r"__vue__"],
    "angular": [r"angular", r"ng-app", r"ng-version"],
    "jquery": [r"jquery"],
    "bootstrap": [r"bootstrap"],
    "express": [r"express", r"connect.sid"],
    "tomcat": [r"tomcat", r"catalina"],
    "jetty": [r"jetty"],
    "ruby": [r"rails", r"ruby"],
    "asp.net": [r"asp\.net", r"__viewstate", r"aspnet"],
    "python": [r"python", r"wsgi"],
    "php": [r"php", r"phpsessid"],
}

TRACKING_DOMAINS = [
    "google-analytics.com", "googletagmanager.com", "facebook.net",
    "facebook.com/tr", "doubleclick.net", "hotjar.com",
    "mixpanel.com", "amplitude.com", "segment.io",
    "newrelic.com", "datadoghq.com", "fullstory.com",
    "crazyegg.com", "optimizely.com", "hubspot.com",
    "linkedin.com/insight", "twitter.com/scribe", "pinterest.com",
    "quantserve.com", "scorecardresearch.com", "chartbeat.com",
]


@dataclass
class ReconResult:
    urls: list[str] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    tech_stack: dict[str, str] = field(default_factory=dict)
    open_ports: list[int] = field(default_factory=list)
    dns_records: dict[str, list[str]] = field(default_factory=dict)
    exposed_paths: list[str] = field(default_factory=list)
    tracking_domains: list[str] = field(default_factory=list)
    cookies: list[dict[str, Any]] = field(default_factory=list)
    findings: list[WebFinding] = field(default_factory=list)


class ReconEngine:
    def __init__(self, http_client: httpx.AsyncClient, config: dict[str, Any] | None = None):
        self.http = http_client
        self.config = config or {}
        self.scan_config = self.config.get("web_scanner", {})
        self.timeout = self.scan_config.get("request_timeout", 10)

    async def run(self, target_url: str, depth: str = "standard") -> ReconResult:
        result = ReconResult()
        max_urls = {"quick": 30, "standard": 100, "deep": 500}.get(depth, 100)

        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        html, status, headers = await self._fetch(target_url)
        if not html:
            logger.warning(f"Cannot fetch {target_url}, status={status}")
            return result

        result.forms = self._extract_forms(html, base_url)
        result.scripts = self._extract_scripts(html, base_url)
        result.tech_stack = self._fingerprint_tech(html, headers)
        result.cookies = self._parse_cookies(headers)
        result.tracking_domains = self._find_tracking(html)

        result.urls = await self._crawl(base_url, html, max_urls)

        for cookie in result.cookies:
            finding = self._check_cookie_security(cookie, target_url)
            if finding:
                result.findings.append(finding)

        xfo = headers.get("x-frame-options", "")
        if not xfo:
            result.findings.append(WebFinding.create(
                url=target_url, vuln_type=WebVulnType.MISSING_XFO,
                evidence="X-Frame-Options header not set",
                description="Page is vulnerable to clickjacking attacks",
                response_headers=dict(headers), response_status=status,
            ))

        ct = headers.get("x-content-type-options", "")
        if ct.lower() != "nosniff":
            result.findings.append(WebFinding.create(
                url=target_url, vuln_type=WebVulnType.MISSING_CT,
                evidence=f"X-Content-Type-Options: {ct or 'not set'}",
                description="Browser may MIME-sniff responses",
                response_headers=dict(headers), response_status=status,
            ))

        csp = headers.get("content-security-policy", "")
        if not csp:
            result.findings.append(WebFinding.create(
                url=target_url, vuln_type=WebVulnType.MISSING_CSP,
                evidence="Content-Security-Policy header missing",
                description="No CSP header increases risk of XSS and data injection",
                response_headers=dict(headers), response_status=status,
            ))

        hsts = headers.get("strict-transport-security", "")
        if not hsts:
            result.findings.append(WebFinding.create(
                url=target_url, vuln_type=WebVulnType.MISSING_HSTS,
                evidence="Strict-Transport-Security header missing",
                description="No HSTS policy, susceptible to SSL stripping",
                response_headers=dict(headers), response_status=status,
            ))

        cors_origin = headers.get("access-control-allow-origin", "")
        if cors_origin == "*":
            result.findings.append(WebFinding.create(
                url=target_url, vuln_type=WebVulnType.CORS_MISCONFIG,
                evidence=f"Access-Control-Allow-Origin: {cors_origin}",
                description="CORS allows all origins, enabling cross-origin data theft",
                response_headers=dict(headers), response_status=status,
            ))

        server = headers.get("server", "")
        if server:
            result.findings.append(WebFinding.create(
                url=target_url, vuln_type=WebVulnType.SERVER_INFO,
                evidence=f"Server: {server}",
                description=f"Server header discloses: {server}",
                response_headers=dict(headers), response_status=status,
            ))

        result.exposed_paths = await self._brute_force_dirs(base_url, depth)

        return result

    async def _fetch(self, url: str) -> tuple[str, int, httpx.Headers]:
        try:
            resp = await self.http.get(url, timeout=self.timeout, follow_redirects=True)
            return resp.text, resp.status_code, resp.headers
        except httpx.TimeoutException:
            return "", 0, httpx.Headers({})
        except Exception as e:
            logger.debug(f"Fetch failed for {url}: {e}")
            return "", 0, httpx.Headers({})

    def _extract_forms(self, html: str, base_url: str) -> list[dict[str, Any]]:
        forms = []
        for m in re.finditer(
            r'<form[^>]*?action=["\']([^"\']*)["\'][^>]*?>(.*?)</form>',
            html, re.IGNORECASE | re.DOTALL,
        ):
            action = m.group(1) or base_url
            if action.startswith("/"):
                action = urljoin(base_url, action)
            form_html = m.group(2)
            inputs = re.findall(
                r'<input[^>]*?name=["\']([^"\']*)["\'][^>]*>',
                form_html, re.IGNORECASE,
            )
            methods = re.findall(r'method=["\'](get|post)["\']', m.group(0), re.IGNORECASE)
            forms.append({
                "action": action,
                "method": methods[0].lower() if methods else "get",
                "inputs": inputs,
                "has_password": bool(re.search(r'type=["\']password["\']', form_html, re.IGNORECASE)),
            })
        return forms

    def _extract_scripts(self, html: str, base_url: str) -> list[str]:
        scripts = []
        for m in re.finditer(
            r'<script[^>]*?src=["\']([^"\']*)["\']',
            html, re.IGNORECASE,
        ):
            src = m.group(1)
            if src.startswith("/"):
                src = urljoin(base_url, src)
            scripts.append(src)
        return scripts

    def _fingerprint_tech(self, html: str, headers: httpx.Headers) -> dict[str, str]:
        tech = {}
        text = html.lower() + str(dict(headers)).lower()
        for name, patterns in TECH_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    tech[name] = "detected"
                    break
        return tech

    def _parse_cookies(self, headers: httpx.Headers) -> list[dict[str, Any]]:
        cookies = []
        raw = headers.get("set-cookie", "")
        if not raw:
            return cookies
        for part in raw.split(","):
            part = part.strip()
            if "=" not in part:
                continue
            name = part.split("=")[0].strip()
            cookie = {"name": name, "httponly": False, "secure": False, "samesite": None}
            lower = part.lower()
            if "httponly" in lower:
                cookie["httponly"] = True
            if "secure" in lower:
                cookie["secure"] = True
            for s in ["lax", "strict", "none"]:
                if f"samesite={s}" in lower:
                    cookie["samesite"] = s
            cookies.append(cookie)
        return cookies

    def _check_cookie_security(self, cookie: dict, url: str) -> WebFinding | None:
        if not cookie.get("httponly"):
            return WebFinding.create(
                url=url, vuln_type=WebVulnType.COOKIE_NO_HTTPONLY,
                evidence=f"Cookie '{cookie['name']}' missing HttpOnly flag",
                description=f"Cookie '{cookie['name']}' accessible via JavaScript",
                confidence=1.0,
            )
        if not cookie.get("secure"):
            return WebFinding.create(
                url=url, vuln_type=WebVulnType.COOKIE_NO_SECURE,
                evidence=f"Cookie '{cookie['name']}' missing Secure flag",
                description=f"Cookie '{cookie['name']}' transmitted over unencrypted HTTP",
                confidence=1.0,
            )
        if not cookie.get("samesite"):
            return WebFinding.create(
                url=url, vuln_type=WebVulnType.COOKIE_NO_SAMESITE,
                evidence=f"Cookie '{cookie['name']}' missing SameSite attribute",
                description=f"Cookie '{cookie['name']}' vulnerable to CSRF",
                confidence=0.8,
            )
        return None

    def _find_tracking(self, html: str) -> list[str]:
        found = []
        for domain in TRACKING_DOMAINS:
            if domain in html.lower():
                found.append(domain)
        return found

    async def _crawl(self, base_url: str, html: str, max_urls: int) -> list[str]:
        urls = set()
        urls.add(base_url)
        for m in re.finditer(
            r'href=["\']([^"\']*)["\']',
            html, re.IGNORECASE,
        ):
            href = m.group(1)
            if href.startswith("#") or href.startswith("javascript:"):
                continue
            if href.startswith("/"):
                href = urljoin(base_url, href)
            elif not href.startswith("http"):
                href = urljoin(base_url + "/", href)
            parsed = urlparse(href)
            if parsed.netloc == urlparse(base_url).netloc:
                clean = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
                urls.add(clean)
                if len(urls) >= max_urls:
                    break
        return list(urls)

    async def _brute_force_dirs(self, base_url: str, depth: str) -> list[str]:
        found = []
        max_checks = {"quick": 15, "standard": 40, "deep": len(COMMON_DIRECTORIES)}.get(depth, 40)
        targets = COMMON_DIRECTORIES[:max_checks]

        async def check(path: str) -> str | None:
            url = urljoin(base_url + "/", path)
            try:
                resp = await self.http.get(url, timeout=self.timeout)
                if resp.status_code in (200, 301, 302, 403):
                    return url
            except Exception:
                pass
            return None

        tasks = [check(p) for p in targets]
        results = await asyncio.gather(*tasks)
        for r in results:
            if r:
                found.append(r)
        return found

    @staticmethod
    def detect_exposed_credentials_in_js(body: str, url: str) -> list[WebFinding]:
        findings = []
        patterns = {
            "AWS Access Key": (r"AKIA[0-9A-Z]{16}", WebSeverity.CRITICAL),
            "AWS Secret": (r"(?i)aws(?:_secret|_access|secret.?key).{0,20}[\"'][A-Za-z0-9/+=]{20,}", WebSeverity.CRITICAL),
            "GitHub Token": (r"gh[pousr]_[A-Za-z0-9_]{36,}", WebSeverity.CRITICAL),
            "JWT Token": (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", WebSeverity.HIGH),
            "Slack Token": (r"xox[baprs]-[A-Za-z0-9-]{10,}", WebSeverity.CRITICAL),
            "Google API Key": (r"AIza[0-9A-Za-z_-]{35}", WebSeverity.HIGH),
            "Private Key": (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", WebSeverity.CRITICAL),
            "Bearer Token": (r"(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}", WebSeverity.HIGH),
            "Generic Secret": (r"(?i)(secret|password|api.?key|token)\s*[=:]\s*[\"'][A-Za-z0-9_\-\.!@#$%^&*+=]{16,}[\"']", WebSeverity.HIGH),
            "Slack Webhook": (r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}", WebSeverity.CRITICAL),
            "Google OAuth": (r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", WebSeverity.HIGH),
        }
        for name, (pattern, severity) in patterns.items():
            for match in re.finditer(pattern, body):
                findings.append(WebFinding.create(
                    url=url,
                    vuln_type=WebVulnType.CREDENTIAL_LEAK,
                    evidence=f"Potential {name} found: {match.group()[:60]}...",
                    description=f"Exposed credential: {name}",
                    confidence=0.7,
                ))
        return findings

    @staticmethod
    def detect_pii(body: str, url: str) -> list[WebFinding]:
        findings = []
        pii_patterns = {
            "Email": (r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", WebSeverity.MEDIUM),
            "Phone (US)": (r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", WebSeverity.MEDIUM),
            "SSN": (r"\b\d{3}-\d{2}-\d{4}\b", WebSeverity.CRITICAL),
            "Credit Card": (r"\b(?:\d{4}[ -]?){3}\d{4}\b", WebSeverity.CRITICAL),
            "IP Address (Internal)": (r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b", WebSeverity.LOW),
        }
        for name, (pattern, severity) in pii_patterns.items():
            for match in re.finditer(pattern, body):
                findings.append(WebFinding.create(
                    url=url,
                    vuln_type=WebVulnType.PII_EXPOSED,
                    evidence=f"Potential {name}: {match.group()}",
                    description=f"PII exposure detected: {name}",
                    severity=severity,
                    confidence=0.6,
                ))
        return findings
