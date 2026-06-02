from __future__ import annotations
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class WebSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class WebVulnType(str, Enum):
    XSS_REFLECTED = "xss_reflected"
    XSS_STORED = "xss_stored"
    XSS_DOM = "xss_dom"
    SQL_INJECTION = "sql_injection"
    SQLI_ERROR_BASED = "sqli_error_based"
    SQLI_BOOLEAN = "sqli_boolean"
    SQLI_TIME = "sqli_time"
    SSTI = "ssti"
    COMMAND_INJECTION = "command_injection"
    SSRF = "ssrf"
    OPEN_REDIRECT = "open_redirect"
    CORS_MISCONFIG = "cors_misconfiguration"
    MISSING_CSP = "missing_csp"
    MISSING_HSTS = "missing_hsts"
    MISSING_XFO = "missing_x_frame_options"
    MISSING_CT = "missing_content_type_options"
    COOKIE_NO_HTTPONLY = "cookie_no_httponly"
    COOKIE_NO_SECURE = "cookie_no_secure"
    COOKIE_NO_SAMESITE = "cookie_no_samesite"
    EXPOSED_GIT = "exposed_git"
    EXPOSED_ENV = "exposed_env"
    EXPOSED_BACKUP = "exposed_backup"
    EXPOSED_ADMIN = "exposed_admin_panel"
    EXPOSED_DEBUG = "exposed_debug_endpoint"
    CREDENTIAL_LEAK = "credential_leak"
    API_KEY_EXPOSED = "api_key_exposed"
    PII_EXPOSED = "pii_exposed"
    TRACKING_SCRIPT = "tracking_script"
    BASIC_AUTH_INSECURE = "basic_auth_insecure"
    DEFAULT_CREDENTIALS = "default_credentials"
    INSECURE_FORM = "insecure_form"
    WEAK_PASSWORD_POLICY = "weak_password_policy"
    INFO_LEAK = "information_disclosure"
    DIRECTORY_LISTING = "directory_listing"
    SERVER_INFO = "server_info_disclosure"
    UNKNOWN = "unknown"


OWASP_MAPPING = {
    WebVulnType.XSS_REFLECTED: "A03:2021-Injection",
    WebVulnType.XSS_STORED: "A03:2021-Injection",
    WebVulnType.XSS_DOM: "A03:2021-Injection",
    WebVulnType.SQL_INJECTION: "A03:2021-Injection",
    WebVulnType.SQLI_ERROR_BASED: "A03:2021-Injection",
    WebVulnType.SQLI_BOOLEAN: "A03:2021-Injection",
    WebVulnType.SQLI_TIME: "A03:2021-Injection",
    WebVulnType.SSTI: "A03:2021-Injection",
    WebVulnType.COMMAND_INJECTION: "A03:2021-Injection",
    WebVulnType.SSRF: "A10:2021-SSRF",
    WebVulnType.OPEN_REDIRECT: "A03:2021-Injection",
    WebVulnType.CORS_MISCONFIG: "A05:2021-SecurityMisconfiguration",
    WebVulnType.MISSING_CSP: "A05:2021-SecurityMisconfiguration",
    WebVulnType.MISSING_HSTS: "A05:2021-SecurityMisconfiguration",
    WebVulnType.MISSING_XFO: "A05:2021-SecurityMisconfiguration",
    WebVulnType.MISSING_CT: "A05:2021-SecurityMisconfiguration",
    WebVulnType.COOKIE_NO_HTTPONLY: "A05:2021-SecurityMisconfiguration",
    WebVulnType.COOKIE_NO_SECURE: "A05:2021-SecurityMisconfiguration",
    WebVulnType.COOKIE_NO_SAMESITE: "A05:2021-SecurityMisconfiguration",
    WebVulnType.EXPOSED_GIT: "A05:2021-SecurityMisconfiguration",
    WebVulnType.EXPOSED_ENV: "A05:2021-SecurityMisconfiguration",
    WebVulnType.EXPOSED_BACKUP: "A05:2021-SecurityMisconfiguration",
    WebVulnType.EXPOSED_ADMIN: "A01:2021-BrokenAccessControl",
    WebVulnType.EXPOSED_DEBUG: "A05:2021-SecurityMisconfiguration",
    WebVulnType.CREDENTIAL_LEAK: "A04:2021-InsecureDesign",
    WebVulnType.API_KEY_EXPOSED: "A04:2021-InsecureDesign",
    WebVulnType.PII_EXPOSED: "A04:2021-InsecureDesign",
    WebVulnType.BASIC_AUTH_INSECURE: "A07:2021-IdentificationAuthFailures",
    WebVulnType.DEFAULT_CREDENTIALS: "A07:2021-IdentificationAuthFailures",
    WebVulnType.INSECURE_FORM: "A04:2021-InsecureDesign",
    WebVulnType.DIRECTORY_LISTING: "A05:2021-SecurityMisconfiguration",
    WebVulnType.SERVER_INFO: "A05:2021-SecurityMisconfiguration",
}


REMEDIATION_MAP = {
    WebVulnType.XSS_REFLECTED: "Sanitize all user inputs, use output encoding, implement Content-Security-Policy, and validate input on server side.",
    WebVulnType.SQL_INJECTION: "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.",
    WebVulnType.SSTI: "Avoid rendering user input in templates. If required, sandbox the template engine and use context-aware escaping.",
    WebVulnType.COMMAND_INJECTION: "Avoid shell execution with user input. Use language-specific APIs instead of system calls.",
    WebVulnType.SSRF: "Restrict outbound requests from the server. Validate and whitelist URLs. Use a deny-by-default firewall policy.",
    WebVulnType.CORS_MISCONFIG: "Restrict Access-Control-Allow-Origin to specific trusted origins. Avoid reflecting the Origin header.",
    WebVulnType.MISSING_CSP: "Set a Content-Security-Policy header to restrict which resources can be loaded and executed.",
    WebVulnType.MISSING_HSTS: "Set Strict-Transport-Security header with a long max-age and includeSubDomains.",
    WebVulnType.MISSING_XFO: "Set X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking.",
    WebVulnType.MISSING_CT: "Set X-Content-Type-Options: nosniff to prevent MIME-type sniffing.",
    WebVulnType.COOKIE_NO_HTTPONLY: "Set HttpOnly flag on all cookies containing session identifiers.",
    WebVulnType.COOKIE_NO_SECURE: "Set Secure flag on all cookies to ensure transmission over HTTPS only.",
    WebVulnType.COOKIE_NO_SAMESITE: "Set SameSite=Lax or SameSite=Strict on all session cookies.",
    WebVulnType.EXPOSED_GIT: "Remove .git directory from production web root. Block access via web server configuration.",
    WebVulnType.EXPOSED_ENV: "Remove .env file from public web root. Store secrets in environment variables or a secrets manager.",
    WebVulnType.EXPOSED_BACKUP: "Remove backup files from public web root. Store backups in secure, non-public locations.",
    WebVulnType.EXPOSED_ADMIN: "Restrict admin panel access to specific IPs, implement MFA, and use strong authentication.",
    WebVulnType.EXPOSED_DEBUG: "Disable debug endpoints and error detail display in production environments.",
    WebVulnType.CREDENTIAL_LEAK: "Remove hardcoded credentials from code. Use environment variables or a secrets manager.",
    WebVulnType.API_KEY_EXPOSED: "Rotate exposed keys immediately. Use environment variables and never hardcode keys in client-side code.",
    WebVulnType.PII_EXPOSED: "Implement data classification and ensure PII is not exposed in client-side responses or URLs.",
    WebVulnType.BASIC_AUTH_INSECURE: "Replace Basic authentication with strong token-based authentication over HTTPS.",
    WebVulnType.DEFAULT_CREDENTIALS: "Change all default credentials immediately. Enforce strong password policies.",
    WebVulnType.INSECURE_FORM: "Submit forms over HTTPS only. Add CSRF tokens to all state-changing forms.",
    WebVulnType.DIRECTORY_LISTING: "Disable directory listing in web server configuration.",
    WebVulnType.SERVER_INFO: "Remove server version banners from HTTP response headers.",
    WebVulnType.OPEN_REDIRECT: "Whitelist valid redirect URLs or avoid user-controlled redirect parameters.",
    WebVulnType.TRACKING_SCRIPT: "Review third-party tracking scripts for compliance with privacy regulations.",
    WebVulnType.WEAK_PASSWORD_POLICY: "Enforce minimum password length 8+, complexity requirements, and rate-limit login attempts.",
}


SEVERITY_MAP = {
    WebVulnType.XSS_REFLECTED: WebSeverity.HIGH,
    WebVulnType.SQL_INJECTION: WebSeverity.CRITICAL,
    WebVulnType.SSTI: WebSeverity.CRITICAL,
    WebVulnType.COMMAND_INJECTION: WebSeverity.CRITICAL,
    WebVulnType.SSRF: WebSeverity.HIGH,
    WebVulnType.CORS_MISCONFIG: WebSeverity.MEDIUM,
    WebVulnType.MISSING_CSP: WebSeverity.MEDIUM,
    WebVulnType.MISSING_HSTS: WebSeverity.LOW,
    WebVulnType.MISSING_XFO: WebSeverity.MEDIUM,
    WebVulnType.MISSING_CT: WebSeverity.LOW,
    WebVulnType.COOKIE_NO_HTTPONLY: WebSeverity.HIGH,
    WebVulnType.COOKIE_NO_SECURE: WebSeverity.HIGH,
    WebVulnType.COOKIE_NO_SAMESITE: WebSeverity.MEDIUM,
    WebVulnType.EXPOSED_GIT: WebSeverity.CRITICAL,
    WebVulnType.EXPOSED_ENV: WebSeverity.CRITICAL,
    WebVulnType.EXPOSED_BACKUP: WebSeverity.HIGH,
    WebVulnType.EXPOSED_ADMIN: WebSeverity.HIGH,
    WebVulnType.EXPOSED_DEBUG: WebSeverity.MEDIUM,
    WebVulnType.CREDENTIAL_LEAK: WebSeverity.CRITICAL,
    WebVulnType.API_KEY_EXPOSED: WebSeverity.CRITICAL,
    WebVulnType.PII_EXPOSED: WebSeverity.HIGH,
    WebVulnType.BASIC_AUTH_INSECURE: WebSeverity.HIGH,
    WebVulnType.DEFAULT_CREDENTIALS: WebSeverity.CRITICAL,
    WebVulnType.INSECURE_FORM: WebSeverity.MEDIUM,
    WebVulnType.DIRECTORY_LISTING: WebSeverity.MEDIUM,
    WebVulnType.SERVER_INFO: WebSeverity.LOW,
    WebVulnType.OPEN_REDIRECT: WebSeverity.MEDIUM,
    WebVulnType.TRACKING_SCRIPT: WebSeverity.LOW,
    WebVulnType.WEAK_PASSWORD_POLICY: WebSeverity.MEDIUM,
}


@dataclass
class WebFinding:
    finding_id: str
    url: str
    vulnerability_type: WebVulnType
    severity: WebSeverity
    evidence: str
    description: str
    remediation: str
    owasp_category: str
    affected_param: str
    request_headers: dict[str, str] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)
    response_status: int = 0
    response_body_preview: str = ""
    confidence: float = 1.0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        url: str,
        vuln_type: WebVulnType,
        evidence: str,
        description: str,
        affected_param: str = "",
        request_headers: dict | None = None,
        response_headers: dict | None = None,
        response_status: int = 0,
        response_body_preview: str = "",
        confidence: float = 1.0,
        **metadata,
    ) -> WebFinding:
        severity = SEVERITY_MAP.get(vuln_type, WebSeverity.MEDIUM)
        remediation = REMEDIATION_MAP.get(vuln_type, "Review and remediate based on findings.")
        owasp = OWASP_MAPPING.get(vuln_type, "A99:2021-Unknown")
        return cls(
            finding_id=str(uuid.uuid4()),
            url=url,
            vulnerability_type=vuln_type,
            severity=severity,
            evidence=evidence,
            description=description,
            remediation=remediation,
            owasp_category=owasp,
            affected_param=affected_param,
            request_headers=request_headers or {},
            response_headers=response_headers or {},
            response_status=response_status,
            response_body_preview=response_body_preview[:500],
            confidence=confidence,
            metadata=metadata,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "url": self.url,
            "vulnerability_type": self.vulnerability_type.value,
            "severity": self.severity.value,
            "evidence": self.evidence[:500],
            "description": self.description,
            "remediation": self.remediation,
            "owasp_category": self.owasp_category,
            "affected_param": self.affected_param,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "response_status": self.response_status,
        }
