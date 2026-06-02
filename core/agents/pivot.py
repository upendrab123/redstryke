from __future__ import annotations
import asyncio
import logging
import re
from typing import Any
from urllib.parse import urlparse, urljoin

import httpx

from core.agents.base import BaseAgent

logger = logging.getLogger(__name__)

KNOWN_VULNERABLE_LIBS: dict[str, list[str]] = {
    "jquery": ["1.", "2.", "3.0", "3.1", "3.2", "3.3", "3.4"],
    "angular": ["1.", "2.0", "2.1", "2.2", "2.3", "2.4"],
    "react": ["0.", "15.", "16.0", "16.1", "16.2"],
    "vue": ["1.", "2.0", "2.1", "2.2", "2.3"],
    "bootstrap": ["2.", "3.", "4.0"],
    "lodash": ["4.17.4", "4.17.3"],
    "moment": ["2.29.0"],
    "dojo": ["1."],
    "prototype": ["1."],
    "mootools": ["1."],
    "backbone": ["0.", "1.0", "1.1"],
    "ember": ["1.", "2.0", "2.1", "2.2"],
}

TRACKING_DOMAINS = [
    "google-analytics.com", "googletagmanager.com", "facebook.net",
    "fbcdn.net", "doubleclick.net", "hotjar.com", "crazyegg.com",
    "mouseflow.com", "fullstory.com", "mixpanel.com", "amplitude.com",
    "segment.io", "segment.com", "optimizely.com", "vwo.com",
    "adroll.com", "quantserve.com", "scorecardresearch.com",
    "chartbeat.com", "comscore.com", "newrelic.com",
    "datadoghq.com", "sentry.io", "rollbar.com",
]

JS_LIB_PATTERNS = [
    (r"/jquery[.-]?([\d.]+)\.min\.js", "jquery"),
    (r"/angular[.-]?([\d.]+)\.min\.js", "angular"),
    (r"/react[.-]?([\d.]+)\.min\.js", "react"),
    (r"/vue[.-]?([\d.]+)\.min\.js", "vue"),
    (r"/bootstrap[.-]?([\d.]+)\.min\.js", "bootstrap"),
    (r"/lodash[.-]?([\d.]+)\.min\.js", "lodash"),
    (r"/moment[.-]?([\d.]+)\.min\.js", "moment"),
    (r"/dojo[.-]?([\d.]+)\.min\.js", "dojo"),
    (r"/prototype[.-]?([\d.]+)\.js", "prototype"),
    (r"/mootools[.-]?([\d.]+)\.js", "mootools"),
    (r"/backbone[.-]?([\d.]+)\.min\.js", "backbone"),
    (r"/ember[.-]?([\d.]+)\.min\.js", "ember"),
]

API_ENDPOINT_PATTERNS = [
    r'["\'](/api/[^"\']+)["\']',
    r'["\'](/v\d+/[^"\']+)["\']',
    r'["\'](/graphql[^"\']*)["\']',
    r'["\'](/rest/[^"\']+)["\']',
    r'url\s*[:=]\s*["\']([^"\']+)["\']',
    r'fetch\(["\']([^"\']+)["\']',
    r'axios\.\w+\(["\']([^"\']+)["\']',
    r'\$\.(?:get|post|ajax)\(["\']([^"\']+)["\']',
]


class PivotAgent(BaseAgent):
    name = "PIVOT"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    async def run(self, context: dict) -> dict:
        target_url = context.get("target_url", "")
        parsed = urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        domain = parsed.netloc.split(":")[0]

        result: dict[str, Any] = {
            "base_url": base,
            "third_party_libs": [],
            "vulnerable_libs": [],
            "api_endpoints": [],
            "external_domains": [],
            "mixed_content": [],
            "findings": [],
        }

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(10.0),
            follow_redirects=True,
            verify=False,
        ) as client:

            self.emit_running("Fetching main page for JS analysis...")
            html = ""
            try:
                resp = await client.get(target_url)
                html = resp.text
                self.emit_running(f"Fetched {len(html)} bytes")
            except Exception as e:
                self.emit_error(f"Failed to fetch page: {e}")
                return result

            self.emit_running("Detecting third-party JS libraries...")
            libs = self._detect_js_libs(html)
            result["third_party_libs"] = libs
            if libs:
                self.emit_running(f"Libraries found: {[l['name'] for l in libs]}")

            self.emit_running("Checking library versions against known vulnerabilities...")
            vuln = self._check_vulnerable_versions(libs)
            result["vulnerable_libs"] = vuln
            for v in vuln:
                self.emit_running(f"Vulnerable: {v['name']} {v['version']}")
                result.setdefault("findings", []).append(v)

            self.emit_running("Extracting API endpoints from JS source...")
            endpoints = self._extract_api_endpoints(html)
            result["api_endpoints"] = endpoints
            if endpoints:
                self.emit_running(f"API endpoints: {endpoints[:5]}")

            self.emit_running("Detecting external domains...")
            external = self._extract_external_domains(html, domain)
            result["external_domains"] = external
            tracking = [d for d in external if any(t in d for t in TRACKING_DOMAINS)]
            if tracking:
                self.emit_running(f"Tracking domains: {tracking}")
                for t in tracking:
                    result.setdefault("findings", []).append({
                        "type": "tracking_domain",
                        "detail": f"Third-party tracking: {t}",
                    })

            self.emit_running("Checking for mixed content (HTTP on HTTPS pages)...")
            if parsed.scheme == "https":
                mixed = self._check_mixed_content(html)
                result["mixed_content"] = mixed
                if mixed:
                    self.emit_running(f"Mixed content issues: {len(mixed)}")
                    for m in mixed:
                        result.setdefault("findings", []).append(m)

        self.emit_complete(f"Pivot complete: {len(result.get('findings',[]))} findings, {len(libs)} libs, {len(endpoints)} endpoints")
        return result

    def _detect_js_libs(self, html: str) -> list[dict]:
        libs = []
        for pattern, name in JS_LIB_PATTERNS:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for m in matches:
                libs.append({"name": name, "version": m, "source": "html_script"})
        script_srcs = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', html, re.IGNORECASE)
        for src in script_srcs:
            src_lower = src.lower()
            for lib_name in KNOWN_VULNERABLE_LIBS:
                if lib_name in src_lower:
                    ver_match = re.search(r'[\d]+\.[\d]+\.[\d]+', src)
                    if ver_match:
                        libs.append({"name": lib_name, "version": ver_match.group(), "source": src})
        seen = set()
        unique = []
        for lib in libs:
            key = f"{lib['name']}@{lib['version']}"
            if key not in seen:
                seen.add(key)
                unique.append(lib)
        return unique

    def _check_vulnerable_versions(self, libs: list[dict]) -> list[dict]:
        vuln = []
        for lib in libs:
            name = lib["name"].lower()
            version = lib["version"]
            if name in KNOWN_VULNERABLE_LIBS:
                bad_versions = KNOWN_VULNERABLE_LIBS[name]
                for bad in bad_versions:
                    if version.startswith(bad):
                        vuln.append({
                            "type": "vulnerable_library",
                            "name": name,
                            "version": version,
                            "known_vulnerable_versions": bad_versions,
                            "detail": f"Library {name} version {version} may have known vulnerabilities",
                        })
                        break
        return vuln

    def _extract_api_endpoints(self, html: str) -> list[str]:
        endpoints = []
        for pattern in API_ENDPOINT_PATTERNS:
            matches = re.findall(pattern, html)
            for m in matches:
                if len(m) > 3 and not m.startswith("//") and " " not in m:
                    endpoints.append(m)
        return sorted(set(endpoints))[:30]

    def _extract_external_domains(self, html: str, base_domain: str) -> list[str]:
        domains = set()
        for src in re.findall(r'(?:src|href)="(https?://[^"/]+)', html, re.IGNORECASE):
            try:
                d = urlparse(src).netloc
                if d and d != base_domain:
                    domains.add(d)
            except Exception:
                pass
        for src in re.findall(r'//([^"/\s]+)', html):
            if src and src != base_domain and "." in src and " " not in src and src[-1] != ".":
                domains.add(src)
        return sorted(domains)

    def _check_mixed_content(self, html: str) -> list[dict]:
        issues = []
        http_resources = re.findall(r'src="http://([^"]+)"', html, re.IGNORECASE)
        http_resources += re.findall(r'href="http://([^"]+)"', html, re.IGNORECASE)
        for res in http_resources[:20]:
            if "evil.com" not in res:
                issues.append({
                    "type": "mixed_content",
                    "detail": f"Mixed content (HTTP resource on HTTPS page): http://{res[:80]}",
                })
        return issues
