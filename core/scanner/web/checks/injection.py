from __future__ import annotations
import asyncio
import logging
import re
import urllib.parse
from typing import Any

import httpx

from core.scanner.web.finding import WebFinding, WebSeverity, WebVulnType

logger = logging.getLogger(__name__)

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><script>alert(1)</script>",
    "';alert(1);//",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "javascript:alert(1)",
    "\"><img src=x onerror=alert(1)>",
]

SQLI_PAYLOADS = [
    "'",
    "''",
    "1' OR '1'='1",
    "1' OR '1'='1' --",
    "1' OR '1'='1' #",
    "' OR 1=1 --",
    "' OR 1=1 #",
    "' OR '1'='1",
    "' OR 1=1/*",
    "1' AND 1=1 --",
    "1' AND 1=2 --",
    "' UNION SELECT NULL --",
    "' UNION SELECT 1,2,3 --",
    "' AND SLEEP(5) --",
    "' AND 1=1 AND SLEEP(5) --",
    "'; WAITFOR DELAY '00:00:05' --",
]

SSTI_PAYLOADS = [
    "{{7*7}}",
    "{{7*'7'}}",
    "${7*7}",
    "#{7*7}",
    "*{7*7}",
    "{{config}}",
    "{{self}}",
    "{{_self.env.registerUndefinedFilterCallback('exec')}}",
    "{{['foo']|join('bar')}}",
    "<%= 7*7 %>",
    "${{7*7}}",
]

CMD_INJECTION_PAYLOADS = [
    "; id",
    "| id",
    "` id`",
    "$(id)",
    "& id &",
    "; whoami",
    "| whoami",
    "`whoami`",
    "& ping -n 1 127.0.0.1 &",
    "| ping -c 1 127.0.0.1",
]

SSRF_TEST_URLS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost:22",
    "http://127.0.0.1:8080",
    "http://0.0.0.0:80",
    "file:///etc/passwd",
    "http://[::1]:22",
]

SQL_ERROR_PATTERNS = [
    "sql", "mysql", "syntax error", "unclosed quotation", "odbc",
    "driver", "db2", "sqlite", "postgresql", "ora-", "microsoft ole db",
    "warning: mysql", "supplied argument is not a valid mysql",
    "column count", "unexpected token", "you have an error in your sql",
]


def _has_sql_error(body: str) -> bool:
    lower = body.lower()
    return any(p in lower for p in SQL_ERROR_PATTERNS)


class InjectionScanner:
    def __init__(self, http_client: httpx.AsyncClient, config: dict[str, Any] | None = None):
        self.http = http_client
        self.config = config or {}
        self.scan_config = self.config.get("web_scanner", {})
        self.timeout = self.scan_config.get("request_timeout", 10)

    async def scan(
        self,
        target_url: str,
        forms: list[dict[str, Any]],
        urls: list[str],
        depth: str = "standard",
    ) -> list[WebFinding]:
        findings: list[WebFinding] = []
        tasks = []

        targets = urls[:]
        for form in forms:
            if form["action"] not in targets:
                targets.append(form["action"])

        max_targets = {"quick": 5, "standard": 20, "deep": len(targets)}.get(depth, 20)
        targets = targets[:max_targets]

        for url in targets:
            parsed = urllib.parse.urlparse(url)
            if parsed.query:
                params = urllib.parse.parse_qs(parsed.query)
                for param in params:
                    tasks.append(self._test_xss(url, param, params[param][0]))
                    tasks.append(self._test_sqli(url, param, params[param][0]))
                    tasks.append(self._test_ssti(url, param, params[param][0]))
                    tasks.append(self._test_cmd_injection(url, param, params[param][0]))

            tasks.append(self._test_open_redirect(url))

        for form in forms:
            for inp in form["inputs"]:
                if form["method"] == "get":
                    test_url = f"{form['action']}?{inp}=test"
                    tasks.append(self._test_xss(test_url, inp, "test"))
                    tasks.append(self._test_sqli(test_url, inp, "test"))

        if depth == "deep":
            for url in targets[:10]:
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                for param in params:
                    tasks.append(self._test_ssrf(url, param, params[param][0]))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, WebFinding):
                findings.append(r)
            elif isinstance(r, list):
                findings.extend(r)

        return findings

    async def _test_xss(self, url: str, param: str, original: str) -> WebFinding | None:
        for payload in XSS_PAYLOADS[:5]:
            parsed = list(urllib.parse.urlparse(url))
            qs = urllib.parse.parse_qs(parsed[4], keep_blank_values=True)
            qs[param] = [payload]
            parsed[4] = urllib.parse.urlencode(qs, doseq=True)
            attack_url = urllib.parse.urlunparse(parsed)
            try:
                resp = await self.http.get(attack_url, timeout=self.timeout)
                if payload in resp.text and resp.status_code == 200:
                    return WebFinding.create(
                        url=url, vuln_type=WebVulnType.XSS_REFLECTED,
                        evidence=f"Payload '{payload[:40]}...' reflected in response",
                        description=f"Reflected XSS in parameter '{param}'",
                        affected_param=param,
                        response_status=resp.status_code,
                        response_body_preview=resp.text[:300],
                        confidence=0.9,
                    )
            except Exception:
                pass
        return None

    async def _test_sqli(self, url: str, param: str, original: str) -> list[WebFinding] | None:
        results = []
        base_parsed = list(urllib.parse.urlparse(url))
        baseline_qs = urllib.parse.parse_qs(base_parsed[4], keep_blank_values=True)
        baseline_qs[param] = [original + "test"]
        base_parsed[4] = urllib.parse.urlencode(baseline_qs, doseq=True)
        baseline_url = urllib.parse.urlunparse(base_parsed)
        try:
            base_resp = await self.http.get(baseline_url, timeout=self.timeout)
            baseline_len = len(base_resp.text)
        except Exception:
            baseline_len = 0

        for payload in SQLI_PAYLOADS:
            parsed = list(urllib.parse.urlparse(url))
            qs = urllib.parse.parse_qs(parsed[4], keep_blank_values=True)
            qs[param] = [payload]
            parsed[4] = urllib.parse.urlencode(qs, doseq=True)
            attack_url = urllib.parse.urlunparse(parsed)
            try:
                resp = await self.http.get(attack_url, timeout=10)
                body = resp.text
                if _has_sql_error(body):
                    results.append(WebFinding.create(
                        url=url, vuln_type=WebVulnType.SQL_INJECTION,
                        evidence=f"SQL error detected with payload '{payload}'",
                        description=f"SQL injection in parameter '{param}'",
                        affected_param=param,
                        response_status=resp.status_code,
                        response_body_preview=body[:300],
                        confidence=0.85,
                    ))
                    break
                if baseline_len > 0 and abs(len(body) - baseline_len) > 50:
                    pass
            except Exception:
                pass
        return results if results else None

    async def _test_ssti(self, url: str, param: str, original: str) -> WebFinding | None:
        for payload in ["{{7*7}}", "{{7*'7'}}", "${7*7}"]:
            parsed = list(urllib.parse.urlparse(url))
            qs = urllib.parse.parse_qs(parsed[4], keep_blank_values=True)
            qs[param] = [payload]
            parsed[4] = urllib.parse.urlencode(qs, doseq=True)
            attack_url = urllib.parse.urlunparse(parsed)
            try:
                resp = await self.http.get(attack_url, timeout=self.timeout)
                if "49" in resp.text or "7777777" in resp.text:
                    return WebFinding.create(
                        url=url, vuln_type=WebVulnType.SSTI,
                        evidence=f"SSTI detected with payload '{payload}' -> evaluated in response",
                        description=f"Server-Side Template Injection in parameter '{param}'",
                        affected_param=param,
                        response_status=resp.status_code,
                        confidence=0.9,
                    )
            except Exception:
                pass
        return None

    async def _test_cmd_injection(self, url: str, param: str, original: str) -> WebFinding | None:
        for payload in CMD_INJECTION_PAYLOADS:
            parsed = list(urllib.parse.urlparse(url))
            qs = urllib.parse.parse_qs(parsed[4], keep_blank_values=True)
            qs[param] = [payload]
            parsed[4] = urllib.parse.urlencode(qs, doseq=True)
            attack_url = urllib.parse.urlunparse(parsed)
            try:
                resp = await self.http.get(attack_url, timeout=self.timeout)
                lower = resp.text.lower()
                if any(kw in lower for kw in ["uid=", "gid=", "root:", "bin/", "www-data", "admin;"]):
                    return WebFinding.create(
                        url=url, vuln_type=WebVulnType.COMMAND_INJECTION,
                        evidence=f"Command injection with payload '{payload}'",
                        description=f"Command injection in parameter '{param}'",
                        affected_param=param,
                        response_status=resp.status_code,
                        response_body_preview=resp.text[:300],
                        confidence=0.85,
                    )
            except Exception:
                pass
        return None

    async def _test_ssrf(self, url: str, param: str, original: str) -> WebFinding | None:
        for payload in SSRF_TEST_URLS[:3]:
            parsed = list(urllib.parse.urlparse(url))
            qs = urllib.parse.parse_qs(parsed[4], keep_blank_values=True)
            qs[param] = [payload]
            parsed[4] = urllib.parse.urlencode(qs, doseq=True)
            attack_url = urllib.parse.urlunparse(parsed)
            try:
                resp = await self.http.get(attack_url, timeout=5)
                if resp.status_code == 200 and len(resp.text) > 0:
                    lower = resp.text.lower()
                    if "ami-" in lower or "meta-data" in lower or "e2e" in lower:
                        return WebFinding.create(
                            url=url, vuln_type=WebVulnType.SSRF,
                            evidence=f"SSRF to {payload} returned data",
                            description=f"SSRF vulnerability in parameter '{param}'",
                            affected_param=param,
                            response_status=resp.status_code,
                            confidence=0.7,
                        )
            except Exception:
                pass
        return None

    async def _test_open_redirect(self, url: str) -> WebFinding | None:
        test_urls = {
            "//evil.com": "https://evil.com",
            "https://evil.com": "https://evil.com",
            "//evil.com/test": "https://evil.com/test",
        }
        for raw_param, expected in test_urls.items():
            parsed = list(urllib.parse.urlparse(url))
            qs = urllib.parse.parse_qs(parsed[4], keep_blank_values=True)
            if not qs:
                continue
            param = list(qs.keys())[0]
            qs[param] = [raw_param]
            parsed[4] = urllib.parse.urlencode(qs, doseq=True)
            attack_url = urllib.parse.urlunparse(parsed)
            try:
                resp = await self.http.get(attack_url, timeout=self.timeout, follow_redirects=False)
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location", "")
                    if "evil.com" in location:
                        return WebFinding.create(
                            url=url, vuln_type=WebVulnType.OPEN_REDIRECT,
                            evidence=f"Redirect to {location} via parameter '{param}'",
                            description=f"Open redirect vulnerability in parameter '{param}'",
                            affected_param=param,
                            response_status=resp.status_code,
                            response_headers=dict(resp.headers),
                            confidence=0.9,
                        )
            except Exception:
                pass
        return None
