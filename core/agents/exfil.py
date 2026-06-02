from __future__ import annotations
import asyncio
import logging
import re
from typing import Any
from urllib.parse import urlparse

import httpx

from core.agents.base import BaseAgent

logger = logging.getLogger(__name__)

EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
INTERNAL_IP_PATTERNS = [
    (r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}", "private (10.x.x.x)"),
    (r"172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}", "private (172.16-31.x.x)"),
    (r"192\.168\.\d{1,3}\.\d{1,3}", "private (192.168.x.x)"),
    (r"127\.\d{1,3}\.\d{1,3}\.\d{1,3}", "loopback"),
    (r"169\.254\.\d{1,3}\.\d{1,3}", "link-local"),
]

STACK_TRACE_PATTERNS = [
    r"at\s+\S+\.\S+\(.*\)", r"in\s+\S+:\w+\s+\(line\s+\d+\)",
    r"File\s+\"[^\"]+\",\s+line\s+\d+", r"Traceback\s+\(most\s+recent\s+call\s+last\)",
    r"Stack trace:", r"Stacktrace:", r"Error:\s+\w+Exception",
    r"#\d+\s+\w+\.\w+\(.*\)", r"\s+at\s+.*\(.*\.java:\d+\)",
]

API_KEY_PATTERNS = [
    (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key"),
    (r'sk-[0-9a-fA-F]{32,}', "Secret Key (generic)"),
    (r'sk_live_[0-9a-zA-Z]{24,}', "Stripe Live Secret Key"),
    (r'pk_live_[0-9a-zA-Z]{24,}', "Stripe Live Publishable Key"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
    (r'sq0atp-[0-9A-Za-z\-_]{22}', "Square Access Token"),
    (r'ghp_[0-9a-zA-Z]{36}', "GitHub Personal Access Token"),
    (r'gho_[0-9a-zA-Z]{36}', "GitHub OAuth Token"),
    (r'xox[baprs]-[0-9a-zA-Z\-]{10,}', "Slack Token"),
    (r'[Ff][Aa][Kk][Ee]_[A-Za-z0-9]{32,}', "Fake/Test Key"),
]

SENSITIVE_COMMENT_PATTERNS = [
    r"<!--.*?(TODO|FIXME|HACK|BUG|XXX|SECURITY|PASSWORD|SECRET|KEY|TOKEN).*?-->",
    r"//\s*(TODO|FIXME|HACK|BUG|XXX|SECURITY|PASSWORD|SECRET|KEY|TOKEN)",
    r"#\s*(TODO|FIXME|HACK|BUG|XXX|SECURITY|PASSWORD|SECRET|KEY|TOKEN)",
    r"/\*.*?(TODO|FIXME|HACK|BUG|XXX|SECURITY|PASSWORD|SECRET|KEY|TOKEN).*?\*/",
]

VERSION_STRINGS = [
    r"(?:wordpress|wp)[\s-]?v?(\d+\.\d+[\.\d]*)",
    r"drupal[\s-]?v?(\d+\.\d+[\.\d]*)",
    r"joomla[\s-]?v?(\d+\.\d+[\.\d]*)",
    r"php\s+v?(\d+\.\d+[\.\d]*)",
    r"nginx/(\d+\.\d+[\.\d]*)",
    r"apache/(\d+\.\d+[\.\d]*)",
    r"python/(\d+\.\d+[\.\d]*)",
    r"django/(\d+\.\d+[\.\d]*)",
    r"flask/(\d+\.\d+[\.\d]*)",
    r"express/(\d+\.\d+[\.\d]*)",
    r"next\.?js[\s-/]?v?(\d+\.\d+[\.\d]*)",
    r"react[\s-/]?v?(\d+\.\d+[\.\d]*)",
    r"angular[\s-/]?v?(\d+\.\d+[\.\d]*)",
    r"vue[\s-/]?v?(\d+\.\d+[\.\d]*)",
    r"jquery[\s-/]?v?(\d+\.\d+[\.\d]*)",
    r"bootstrap[\s-/]?v?(\d+\.\d+[\.\d]*)",
]

ERROR_PAGE_SIGS = [
    "internal server error", "500 error", "fatal error", "uncaught exception",
    "stack trace", "debug mode", "debug is true", "app.debug",
    "you can see this because", "whoops!", "looks like something went wrong",
    "application error", "runtime error", "server error in",
]


class ExfilAgent(BaseAgent):
    name = "EXFIL"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    async def run(self, context: dict) -> dict:
        target_url = context.get("target_url", "")
        parsed = urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        result: dict[str, Any] = {
            "base_url": base,
            "emails": [],
            "internal_ips": [],
            "stack_traces": [],
            "api_keys": [],
            "sensitive_comments": [],
            "version_strings": [],
            "verbose_errors": False,
            "findings": [],
        }

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(10.0),
            follow_redirects=True,
            verify=False,
        ) as client:

            html = ""
            self.emit_running("Fetching main page...")
            try:
                resp = await client.get(target_url)
                html = resp.text
                self.emit_running(f"Fetched {len(html)} bytes")
            except Exception as e:
                self.emit_error(f"Failed to fetch page: {e}")

            if html:
                self.emit_running("Scanning for email addresses...")
                emails = self._find_emails(html)
                result["emails"] = emails
                if emails:
                    self.emit_running(f"Emails found: {len(emails)}")
                    result.setdefault("findings", []).append({
                        "type": "email_disclosure",
                        "detail": f"Email addresses exposed: {', '.join(emails[:5])}",
                        "count": len(emails),
                    })

                self.emit_running("Scanning for internal IP addresses...")
                ips = self._find_internal_ips(html)
                result["internal_ips"] = ips
                if ips:
                    self.emit_running(f"Internal IPs found: {ips}")
                    result.setdefault("findings", []).append({
                        "type": "internal_ip_disclosure",
                        "detail": f"Internal IPs exposed: {', '.join(ips[:5])}",
                    })

                self.emit_running("Scanning for stack traces...")
                traces = self._find_stack_traces(html)
                result["stack_traces"] = traces
                if traces:
                    self.emit_running("Stack traces detected!")
                    result.setdefault("findings", []).append({
                        "type": "stack_trace_disclosure",
                        "detail": f"Stack traces detected ({len(traces)} lines)",
                    })

                self.emit_running("Scanning for API keys and secrets...")
                keys = self._find_api_keys(html)
                result["api_keys"] = keys
                if keys:
                    self.emit_running(f"Potential secrets found: {len(keys)}")
                    for k in keys:
                        result.setdefault("findings", []).append({
                            "type": "api_key_exposed",
                            "detail": f"Potential {k['type']}: {k['match'][:30]}...",
                        })

                self.emit_running("Scanning for sensitive HTML comments...")
                comments = self._find_sensitive_comments(html)
                result["sensitive_comments"] = comments
                if comments:
                    self.emit_running(f"Sensitive comments: {len(comments)}")
                    for c in comments:
                        result.setdefault("findings", []).append({
                            "type": "sensitive_comment",
                            "detail": f"Sensitive comment: {c[:120]}",
                        })

                self.emit_running("Extracting version strings...")
                versions = self._find_version_strings(html)
                result["version_strings"] = versions
                if versions:
                    self.emit_running(f"Version strings: {versions}")

                self.emit_running("Checking for verbose error pages...")
                if self._check_verbose_errors(html):
                    result["verbose_errors"] = True
                    result.setdefault("findings", []).append({
                        "type": "verbose_error_page",
                        "detail": "Verbose error page detected — may leak sensitive information",
                    })

            self.emit_running("Probing error-inducing URLs...")
            error_findings = await self._probe_error_paths(client, base)
            result.setdefault("findings", []).extend(error_findings)

        self.emit_complete(f"Exfil complete: {len(result.get('findings',[]))} findings")
        return result

    def _find_emails(self, text: str) -> list[str]:
        emails = EMAIL_PATTERN.findall(text)
        filtered = [e for e in emails if not e.endswith((".png", ".jpg", ".gif", ".css", ".js", ".svg", ".ico"))]
        return sorted(set(filtered))[:20]

    def _find_internal_ips(self, text: str) -> list[str]:
        ips = set()
        for pattern, label in INTERNAL_IP_PATTERNS:
            for m in re.finditer(pattern, text):
                ip = m.group()
                if not any(ip.startswith(prefix) for prefix in ["0.", "255."]):
                    ips.add(ip)
        return sorted(ips)[:10]

    def _find_stack_traces(self, text: str) -> list[str]:
        lines = []
        for i, line in enumerate(text.split("\n")):
            for pattern in STACK_TRACE_PATTERNS:
                if re.search(pattern, line):
                    lines.append(line.strip()[:150])
                    break
        return lines[:20]

    def _find_api_keys(self, text: str) -> list[dict]:
        keys = []
        for pattern, key_type in API_KEY_PATTERNS:
            for m in re.finditer(pattern, text):
                keys.append({"type": key_type, "match": m.group()})
                if len(keys) >= 20:
                    return keys
        return keys

    def _find_sensitive_comments(self, html: str) -> list[str]:
        comments = []
        for pattern in SENSITIVE_COMMENT_PATTERNS:
            for m in re.finditer(pattern, html, re.IGNORECASE | re.DOTALL):
                c = m.group().strip()
                if len(c) > 5 and len(c) < 500:
                    comments.append(c)
        return comments[:15]

    def _find_version_strings(self, text: str) -> list[dict]:
        versions = []
        for pattern in VERSION_STRINGS:
            for m in re.finditer(pattern, text, re.IGNORECASE):
                versions.append({"pattern": pattern.pattern[:30], "version": m.group(1)})
        seen = set()
        unique = []
        for v in versions:
            key = f"{v['pattern']}:{v['version']}"
            if key not in seen:
                seen.add(key)
                unique.append(v)
        return unique[:15]

    def _check_verbose_errors(self, text: str) -> bool:
        body = text.lower()
        return any(sig in body for sig in ERROR_PAGE_SIGS)

    async def _probe_error_paths(self, client: httpx.AsyncClient, base: str) -> list[dict]:
        findings = []
        error_paths = ["/error", "/error/", "/500", "/debug", "/test", "/phpinfo.php", "/info.php", "/status", "/health", "/healthz", "/api/health", "/api/error", "/api/debug"]
        for path in error_paths:
            try:
                resp = await client.get(f"{base}{path}")
                if resp.status_code in (200, 500, 403, 401):
                    body = resp.text.lower()
                    if self._check_verbose_errors(body) or len(resp.text) > 500:
                        findings.append({
                            "type": "verbose_error_page",
                            "detail": f"Error page accessible at {path} (status {resp.status_code})",
                        })
                        break
            except Exception:
                pass
        return findings
