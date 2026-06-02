from __future__ import annotations
import asyncio
import logging
import re
from typing import Any
from urllib.parse import urlparse

import httpx

from core.agents.base import BaseAgent

logger = logging.getLogger(__name__)

LOGIN_FORM_PATTERNS = [
    r'<input[^>]*type=["\']password["\']',
    r'<form[^>]*action=["\'][^"\']*login[^"\']*["\']',
    r'<form[^>]*action=["\'][^"\']*signin[^"\']*["\']',
    r'<form[^>]*action=["\'][^"\']*auth[^"\']*["\']',
    r'name=["\'](?:login|signin|auth)["\']',
]

USERNAME_ENUM_PATTERNS = [
    r"(?:user|username|email|login).*(?:not found|doesn't exist|invalid)",
    r"(?:user|username|email|login).*(?:found|exists|valid)",
    r"(?:incorrect|wrong).*(?:password|credentials)",
    r"(?:password|credentials).*(?:incorrect|wrong)",
]

UNAUTH_PATTERNS = [
    r"(?:login|signin|auth)/",
    r"401 unauthorized",
    r"403 forbidden",
    r"access denied",
    r"please log in",
    r"authentication required",
    r"login first",
]


class PersistAgent(BaseAgent):
    name = "PERSIST"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    async def run(self, context: dict) -> dict:
        target_url = context.get("target_url", "")
        parsed = urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        result: dict[str, Any] = {
            "base_url": base,
            "login_forms": [],
            "auth_endpoints": [],
            "autocomplete_flags": [],
            "username_enumeration": [],
            "rate_limiting": None,
            "jwt_detected": False,
            "session_cookies": [],
            "findings": [],
        }

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(10.0),
            follow_redirects=False,
            verify=False,
        ) as client:

            self.emit_running("Fetching main page for auth analysis...")
            html = ""
            try:
                resp = await client.get(target_url)
                html = resp.text
                self.emit_running(f"Fetched {len(html)} bytes (status {resp.status_code})")
            except Exception as e:
                self.emit_error(f"Failed to fetch page: {e}")
                return result

            self.emit_running("Detecting login forms...")
            forms = self._find_login_forms(html)
            result["login_forms"] = forms
            if forms:
                self.emit_running(f"Login forms: {len(forms)}")
                for f in forms:
                    result.setdefault("findings", []).append({
                        "type": "login_form_detected",
                        "detail": f"Login form: {f.get('action','?')}",
                        **f,
                    })
                    if not f.get("autocomplete_off"):
                        result.setdefault("findings", []).append({
                            "type": "autocomplete_missing",
                            "detail": f"Login form at {f.get('action','?')} missing autocomplete=off",
                        })

            self.emit_running("Detecting JWT tokens in cookies and headers...")
            jwt = self._check_jwt(resp.headers, html)
            result["jwt_detected"] = jwt
            if jwt:
                self.emit_running("JWT detected in cookies/headers")
                result.setdefault("findings", []).append({
                    "type": "jwt_detected",
                    "detail": "JWT token found. Check token expiration, signature verification, and claims.",
                })

            self.emit_running("Analyzing session cookies...")
            cookies = self._analyze_session_cookies(resp.headers)
            result["session_cookies"] = cookies
            for c in cookies:
                if not c.get("secure"):
                    result.setdefault("findings", []).append({
                        "type": "weak_session_cookie",
                        "detail": f"Session cookie '{c['name']}' missing Secure flag",
                    })
                if not c.get("httponly"):
                    result.setdefault("findings", []).append({
                        "type": "weak_session_cookie",
                        "detail": f"Session cookie '{c['name']}' missing HttpOnly flag",
                    })

            self.emit_running("Probing auth endpoints for missing rate limiting...")
            auth_endpoints = self._find_auth_endpoints(html)
            result["auth_endpoints"] = auth_endpoints
            rl = await self._check_rate_limiting(client, auth_endpoints)
            result["rate_limiting"] = rl
            if rl and rl.get("vulnerable"):
                result.setdefault("findings", []).append({
                    "type": "missing_rate_limiting",
                    "detail": f"No rate limiting detected on auth endpoints: {rl.get('endpoints_tested',[])}",
                })
            elif rl:
                self.emit_running(f"Rate limiting detected")

            self.emit_running("Testing username enumeration...")
            enum = await self._test_username_enumeration(client, base, auth_endpoints)
            result["username_enumeration"] = enum
            for e in enum:
                result.setdefault("findings", []).append({
                    "type": "username_enumeration",
                    "detail": e.get("detail", "Possible username enumeration"),
                })

        self.emit_complete(f"Persist complete: {len(result.get('findings',[]))} findings")
        return result

    def _find_login_forms(self, html: str) -> list[dict]:
        forms = []
        form_pattern = re.compile(r'<form[^>]*>.*?</form>', re.IGNORECASE | re.DOTALL)
        for fm in form_pattern.findall(html):
            if re.search(LOGIN_FORM_PATTERNS[0], fm, re.IGNORECASE):
                action = re.search(r'action=["\']([^"\']*)["\']', fm)
                autocomplete = 'autocomplete="off"' in fm or "autocomplete=off" in fm
                forms.append({
                    "action": action.group(1) if action else "?",
                    "autocomplete_off": autocomplete,
                    "has_password": bool(re.search(r'type=["\']password["\']', fm, re.IGNORECASE)),
                })
        return forms

    def _find_auth_endpoints(self, html: str) -> list[str]:
        endpoints = set()
        for fm in re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', html, re.IGNORECASE):
            if any(k in fm.lower() for k in ["login", "signin", "auth", "logon", "authenticate"]):
                endpoints.add(fm)
        common = ["/login", "/signin", "/auth", "/api/login", "/api/auth", "/logon", "/authenticate"]
        endpoints.update(common)
        return sorted(endpoints)[:10]

    def _check_jwt(self, headers: dict, html: str) -> bool:
        for k, v in headers.items():
            if "jwt" in v.lower() or "bearer" in v.lower():
                return True
        for c in headers.get("set-cookie", "").split(";"):
            if "jwt" in c.lower() or "token" in c.lower():
                if self._looks_like_jwt(c):
                    return True
        for m in re.findall(r'["\']([\w-]+\.[\w-]+\.[\w-]+)["\']', html):
            if self._looks_like_jwt(m):
                return True
        return False

    def _looks_like_jwt(self, token: str) -> bool:
        return bool(re.match(r'^[\w-]+\.[\w-]+\.[\w-]+$', token.strip()))

    def _analyze_session_cookies(self, headers: dict) -> list[dict]:
        cookies = []
        for c in headers.get("set-cookie", "").split("\n"):
            c = c.strip()
            if not c:
                continue
            parts = c.split(";")
            name = parts[0].split("=")[0].strip()
            flags = {
                "name": name,
                "secure": "secure" in [p.strip().lower() for p in parts],
                "httponly": "httponly" in [p.strip().lower() for p in parts],
                "samesite": None,
            }
            for p in parts:
                if "samesite" in p.lower():
                    flags["samesite"] = p.split("=")[1].strip() if "=" in p else "true"
            cookies.append(flags)
        return cookies

    async def _check_rate_limiting(self, client: httpx.AsyncClient, endpoints: list[str]) -> dict:
        results = {"vulnerable": False, "endpoints_tested": []}
        for ep in endpoints[:3]:
            try:
                url = f"{self.output.get('base_url', '')}{ep}" if ep.startswith("/") else ep
                if not url.startswith("http"):
                    continue
                statuses = []
                for _ in range(5):
                    resp = await client.post(url, json={"username": "test", "password": "test"}, timeout=5)
                    statuses.append(resp.status_code)
                    await asyncio.sleep(0.1)
                all_same = len(set(statuses)) == 1
                if all_same and statuses[0] != 429:
                    results["vulnerable"] = True
                    results["endpoints_tested"].append(ep)
            except Exception:
                pass
        return results

    async def _test_username_enumeration(self, client: httpx.AsyncClient, base: str, endpoints: list[str]) -> list[dict]:
        findings = []
        test_users = ["admin", "root", "nonexistent_user_xyz_123", "test"]
        for ep in endpoints[:2]:
            responses = []
            for user in test_users:
                try:
                    url = f"{base}{ep}" if ep.startswith("/") else ep
                    if not url.startswith("http"):
                        continue
                    resp = await client.post(url, json={"username": user, "password": "wrong_password"}, timeout=5)
                    responses.append({"user": user, "status": resp.status_code, "body_len": len(resp.text), "body": resp.text[:200]})
                except Exception:
                    pass
            if len(responses) >= 2:
                body_lens = set(r["body_len"] for r in responses)
                if len(body_lens) > 1:
                    findings.append({
                        "detail": f"Response size differs per username on {ep} — possible username enumeration",
                        "endpoint": ep,
                        "responses": responses,
                    })
        return findings
