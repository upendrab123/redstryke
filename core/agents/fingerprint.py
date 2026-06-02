from __future__ import annotations
import asyncio
import logging
import ssl
from typing import Any
from urllib.parse import urlparse

import httpx

from core.agents.base import BaseAgent

logger = logging.getLogger(__name__)

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE"]

ORIGIN_TEST_VALUES = [
    "https://evil.com",
    "null",
    "https://attacker.com",
    "http://evil.com",
]

TLS_PORT_MAP: list[tuple[str, int]] = [
    ("https", 443),
    ("https", 8443),
    ("https", 4433),
]


class FingerprintAgent(BaseAgent):
    name = "FINGERPRINT"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    async def run(self, context: dict) -> dict:
        target_url = context.get("target_url", "")
        parsed = urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        domain = parsed.netloc.split(":")[0]

        self.emit_running(f"HTTP fingerprinting {base}")

        result: dict[str, Any] = {
            "base_url": base,
            "domain": domain,
            "server_headers": {},
            "tls_info": {},
            "http_methods": [],
            "cookie_flags": [],
            "hsts": None,
            "cors": {},
            "clickjacking": {},
            "http_redirect": {},
            "findings": [],
        }

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(15.0),
            follow_redirects=False,
            verify=False,
        ) as client:

            https_url = f"https://{domain}"
            http_url = f"http://{domain}"

            self.emit_running("Probing HTTPS...")
            https_ok = False
            try:
                resp = await client.get(https_url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
                result["server_headers"] = dict(resp.headers)
                https_ok = True
                self._check_headers(resp, result)
                self.emit_running(f"HTTPS: {resp.status_code}, Server: {resp.headers.get('server','?')}")
            except Exception as e:
                self.emit_running(f"HTTPS unavailable: {e}")

            self.emit_running("Probing HTTP (redirect check)...")
            try:
                resp_http = await client.get(http_url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
                result["http_redirect"] = {
                    "status": resp_http.status_code,
                    "location": resp_http.headers.get("location", ""),
                    "has_redirect": 300 <= resp_http.status_code < 400,
                }
                if result["http_redirect"]["has_redirect"]:
                    self.emit_running(f"HTTP -> {resp_http.status_code} -> {resp_http.headers.get('location','?')}")
            except Exception as e:
                result["http_redirect"] = {"status": 0, "location": "", "has_redirect": False}
                self.emit_running(f"HTTP unavailable: {e}")

            if https_ok:
                self.emit_running("Testing HTTP methods (OPTIONS)...")
                try:
                    opts = await client.options(https_url)
                    allow = opts.headers.get("allow", "")
                    if not allow:
                        allow = opts.headers.get("Access-Control-Allow-Methods", "")
                    result["http_methods"] = [m.strip() for m in allow.split(",") if m.strip()]
                    if result["http_methods"]:
                        self.emit_running(f"Allowed methods: {result['http_methods']}")
                    dangerous = [m for m in result["http_methods"] if m.upper() in ("PUT", "DELETE", "PATCH", "TRACE")]
                    if dangerous:
                        self.emit_running(f"Dangerous methods allowed: {dangerous}")
                        result.setdefault("findings", []).append({
                            "type": "dangerous_http_methods",
                            "detail": f"Dangerous HTTP methods enabled: {dangerous}",
                            "methods": dangerous,
                        })
                except Exception as e:
                    self.emit_running(f"OPTIONS probe failed: {e}")

                self.emit_running("Testing CORS misconfiguration...")
                for origin in ORIGIN_TEST_VALUES:
                    try:
                        resp = await client.get(https_url, headers={"Origin": origin})
                        acao = resp.headers.get("access-control-allow-origin", "")
                        acac = resp.headers.get("access-control-allow-credentials", "")
                        if acao:
                            result["cors"][origin] = {
                                "allow_origin": acao,
                                "allow_credentials": acac,
                            }
                            if acao == origin or acao == "*":
                                result.setdefault("findings", []).append({
                                    "type": "cors_misconfiguration",
                                    "detail": f"CORS allows origin: {acao} (tested with: {origin})",
                                    "origin_tested": origin,
                                    "allow_origin": acao,
                                })
                    except Exception:
                        pass
                if result["cors"]:
                    self.emit_running(f"CORS findings: {len(result['cors'])}")

                self.emit_running("Testing TLS...")
                tls_info = await self._check_tls(domain)
                result["tls_info"] = tls_info
                if tls_info.get("weak_ciphers"):
                    result.setdefault("findings", []).append({
                        "type": "weak_tls",
                        "detail": f"Weak TLS: {', '.join(tls_info['weak_ciphers'])}",
                    })

        self.emit_complete(f"Fingerprint complete: {len(result.get('findings',[]))} findings")
        return result

    def _check_headers(self, resp: httpx.Response, result: dict):
        headers = resp.headers
        h = {k.lower(): v for k, v in headers.items()}

        server = h.get("server", "")
        if server:
            result.setdefault("findings", []).append({
                "type": "server_info_disclosure",
                "detail": f"Server header: {server}",
                "header": "Server",
                "value": server,
            })

        x_powered = h.get("x-powered-by", "")
        if x_powered:
            result.setdefault("findings", []).append({
                "type": "tech_info_disclosure",
                "detail": f"X-Powered-By: {x_powered}",
                "header": "X-Powered-By",
                "value": x_powered,
            })

        if "strict-transport-security" in h:
            result["hsts"] = h["strict-transport-security"]
            hsts_val = h["strict-transport-security"].lower()
            if "max-age=" in hsts_val:
                import re
                m = re.search(r"max-age=(\d+)", hsts_val)
                if m:
                    age = int(m.group(1))
                    if age < 31536000:
                        result.setdefault("findings", []).append({
                            "type": "weak_hsts",
                            "detail": f"HSTS max-age too short: {age}s (< 1 year)",
                            "max_age": age,
                        })
        else:
            result["hsts"] = None
            result.setdefault("findings", []).append({
                "type": "missing_hsts",
                "detail": "No Strict-Transport-Security header",
            })

        if "x-frame-options" in h:
            result["clickjacking"] = {"x-frame-options": h["x-frame-options"]}
        else:
            csp = h.get("content-security-policy", "")
            if "frame-ancestors" in csp:
                result["clickjacking"] = {"csp_frame_ancestors": True}
            else:
                result["clickjacking"] = {"vulnerable": True}
                result.setdefault("findings", []).append({
                    "type": "clickjacking_vulnerable",
                    "detail": "No X-Frame-Options or CSP frame-ancestors",
                })

        if "access-control-allow-origin" in h:
            result["cors"]["*"] = {
                "allow_origin": h["access-control-allow-origin"],
                "allow_credentials": h.get("access-control-allow-credentials", ""),
            }

        cookies = headers.get_list("set-cookie")
        if cookies:
            parsed_cookies = []
            for c in cookies:
                flags = {}
                parts = c.split(";")
                flags["name"] = parts[0].split("=")[0] if "=" in parts[0] else parts[0]
                flags["secure"] = any("secure" in p.lower().strip() for p in parts)
                flags["httponly"] = any("httponly" in p.lower().strip() for p in parts)
                flags["samesite"] = next((p.split("=")[1].strip() for p in parts if "samesite" in p.lower()), None)
                parsed_cookies.append(flags)
                if not flags["secure"]:
                    result.setdefault("findings", []).append({
                        "type": "cookie_no_secure",
                        "detail": f"Cookie '{flags['name']}' missing Secure flag",
                    })
                if not flags["httponly"]:
                    result.setdefault("findings", []).append({
                        "type": "cookie_no_httponly",
                        "detail": f"Cookie '{flags['name']}' missing HttpOnly flag",
                    })
                if not flags["samesite"]:
                    result.setdefault("findings", []).append({
                        "type": "cookie_no_samesite",
                        "detail": f"Cookie '{flags['name']}' missing SameSite flag",
                    })
            result["cookie_flags"] = parsed_cookies

        via = h.get("via", "")
        if via:
            result.setdefault("findings", []).append({
                "type": "proxy_detected",
                "detail": f"Via header: {via}",
            })

    async def _check_tls(self, domain: str) -> dict:
        info = {"weak_ciphers": [], "protocols": []}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(domain, 443, ssl=ctx),
                timeout=10,
            )
            sock = writer.get_extra_info("ssl_object")
            if sock:
                cipher = sock.cipher()
                if cipher:
                    info["cipher"] = cipher[0]
                    info["tls_version"] = sock.version()
                    weak = ["RC4", "DES", "MD5", "3DES", "EXPORT", "NULL", "TLSv1.0", "TLSv1.1"]
                    for w in weak:
                        if w.lower() in cipher[0].lower() or w.lower() in (sock.version() or "").lower():
                            info["weak_ciphers"].append(f"{cipher[0]} ({sock.version()})")
                            break
            writer.close()
        except Exception as e:
            info["error"] = str(e)
        return info
