from __future__ import annotations
import logging
import re
from typing import Any

from core.scanner.web.finding import WebFinding, WebSeverity, WebVulnType

logger = logging.getLogger(__name__)

CREDENTIAL_PATTERNS: list[tuple[str, str, WebSeverity, float]] = [
    ("AWS Access Key ID", r"AKIA[0-9A-Z]{16}", WebSeverity.CRITICAL, 0.95),
    ("AWS Secret Access Key", r"(?i)aws.{0,20}(?:secret|access).{0,20}[\"'][A-Za-z0-9/+=]{40}[\"']", WebSeverity.CRITICAL, 0.9),
    ("GitHub Personal Access Token", r"ghp_[A-Za-z0-9]{36}", WebSeverity.CRITICAL, 0.95),
    ("GitHub OAuth Token", r"gho_[A-Za-z0-9]{36}", WebSeverity.CRITICAL, 0.95),
    ("GitHub App Token", r"ghu_[A-Za-z0-9]{36}", WebSeverity.CRITICAL, 0.95),
    ("GitLab Token", r"glpat-[A-Za-z0-9\-]{20,}", WebSeverity.CRITICAL, 0.95),
    ("Slack Token", r"xox[baprs]-[A-Za-z0-9\-]{10,}", WebSeverity.CRITICAL, 0.95),
    ("Slack Webhook", r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}", WebSeverity.CRITICAL, 0.95),
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}", WebSeverity.HIGH, 0.9),
    ("Google OAuth Client ID", r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", WebSeverity.HIGH, 0.9),
    ("Firebase URL", r".+\.firebaseio\.com", WebSeverity.HIGH, 0.8),
    ("JWT Token", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", WebSeverity.HIGH, 0.85),
    ("Bearer Token", r"(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}", WebSeverity.HIGH, 0.8),
    ("Heroku API Key", r"[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}", WebSeverity.CRITICAL, 0.85),
    ("RSA Private Key", r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", WebSeverity.CRITICAL, 1.0),
    ("SSH Private Key", r"-----BEGIN OPENSSH PRIVATE KEY-----", WebSeverity.CRITICAL, 1.0),
    ("PGP Private Key", r"-----BEGIN PGP PRIVATE KEY BLOCK-----", WebSeverity.CRITICAL, 1.0),
    ("Password in Code", r"(?i)(?:password|passwd|pwd)\s*[=:]\s*[\"'][^\"']{6,}[\"']", WebSeverity.HIGH, 0.7),
    ("API Key in Code", r"(?i)(?:api[_-]?key|apikey|api_key)\s*[=:]\s*[\"'][A-Za-z0-9_\-\.]{16,}[\"']", WebSeverity.HIGH, 0.8),
    ("Secret in Code", r"(?i)(?:secret|token)\s*[=:]\s*[\"'][A-Za-z0-9_\-\.!@#$%^&*+=]{16,}[\"']", WebSeverity.HIGH, 0.7),
    ("MongoDB Connection String", r"mongodb(?:\+srv)?://[A-Za-z0-9]+:[A-Za-z0-9]+@", WebSeverity.CRITICAL, 0.95),
    ("MySQL Connection String", r"mysql://[A-Za-z0-9]+:[A-Za-z0-9]+@", WebSeverity.CRITICAL, 0.9),
    ("PostgreSQL Connection String", r"postgres(?:ql)?://[A-Za-z0-9]+:[A-Za-z0-9]+@", WebSeverity.CRITICAL, 0.9),
    ("Redis Connection String", r"redis://[A-Za-z0-9]+:[A-Za-z0-9]+@", WebSeverity.CRITICAL, 0.9),
    ("S3 Bucket URL", r"s3://[A-Za-z0-9\-\.]+", WebSeverity.MEDIUM, 0.7),
    ("Stripe API Key (Live)", r"sk_live_[A-Za-z0-9]{24,}", WebSeverity.CRITICAL, 0.95),
    ("Stripe API Key (Test)", r"sk_test_[A-Za-z0-9]{24,}", WebSeverity.MEDIUM, 0.9),
    ("Twilio API Key", r"SK[A-Za-z0-9]{32}", WebSeverity.HIGH, 0.85),
    ("Mailgun API Key", r"key-[A-Za-z0-9]{32}", WebSeverity.HIGH, 0.85),
    ("SendGrid API Key", r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}", WebSeverity.HIGH, 0.9),
    ("NPM Token", r"npm_[A-Za-z0-9]{36}", WebSeverity.HIGH, 0.9),
    ("Docker Password", r"(?i)docker.*password.*[\"'][A-Za-z0-9]{16,}[\"']", WebSeverity.HIGH, 0.7),
    ("Hardcoded IP/Password", r"(?i)(?:admin|root)\s*:\s*[A-Za-z0-9!@#$%^&*()_+]{4,20}@\d+\.\d+\.\d+\.\d+", WebSeverity.HIGH, 0.8),
]


class CredentialScanner:
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}

    def scan_url_content(self, url: str, body: str, content_type: str = "") -> list[WebFinding]:
        findings: list[WebFinding] = []
        if not body or len(body) > 5_000_000:
            return findings

        for name, pattern, severity, confidence in CREDENTIAL_PATTERNS:
            try:
                for match in re.finditer(pattern, body):
                    matched = match.group()
                    if self._is_false_positive(matched, body):
                        continue
                    findings.append(WebFinding.create(
                        url=url,
                        vuln_type=WebVulnType.CREDENTIAL_LEAK,
                        evidence=f"Potential {name} detected",
                        description=f"Exposed credential: {name}",
                        severity=severity,
                        confidence=confidence,
                        response_body_preview=matched[:200],
                    ))
            except re.error:
                continue

        return findings

    def _is_false_positive(self, matched: str, body: str) -> bool:
        lower = body.lower()
        fp_indicators = [
            "example.com", "example.org", "example.net",
            "your-api-key", "your-api-key-here", "your_secret",
            "placeholder", "changeme", "xxxxx",
        ]
        for fp in fp_indicators:
            if fp in lower:
                return True
        return False
