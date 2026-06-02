from __future__ import annotations
import logging
import re
from typing import Any
from urllib.parse import urlparse

from core.scanner.web.finding import WebFinding, WebSeverity, WebVulnType

logger = logging.getLogger(__name__)

PII_PATTERNS: list[tuple[str, str, WebSeverity, float]] = [
    ("Email Address", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", WebSeverity.MEDIUM, 0.7),
    ("US Phone Number", r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", WebSeverity.MEDIUM, 0.6),
    ("US Social Security Number", r"\b\d{3}-\d{2}-\d{4}\b", WebSeverity.CRITICAL, 0.9),
    ("Credit Card Number", r"\b(?:\d{4}[ -]?){3}\d{4}\b", WebSeverity.CRITICAL, 0.85),
    ("IP Address", r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", WebSeverity.LOW, 0.5),
    ("Internal IP", r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b", WebSeverity.MEDIUM, 0.7),
    ("Date of Birth", r"\b\d{2}[/-]\d{2}[/-]\d{4}\b", WebSeverity.HIGH, 0.6),
    ("ZIP Code", r"\b\d{5}(?:-\d{4})?\b", WebSeverity.LOW, 0.4),
    ("Password Field", r'<input[^>]*type=["\']password["\']', WebSeverity.INFO, 1.0),
]

TRACKING_PATTERNS: list[tuple[str, str, WebSeverity]] = [
    ("Google Analytics", r"google-analytics\.com/ga\.js|gtag\(|GoogleAnalyticsObject", WebSeverity.LOW),
    ("Google Tag Manager", r"googletagmanager\.com/gtm\.js", WebSeverity.LOW),
    ("Facebook Pixel", r"facebook\.com/tr\?|fbq\(", WebSeverity.LOW),
    ("Hotjar", r"hotjar\.com/hotjar-", WebSeverity.LOW),
    ("Mixpanel", r"mixpanel\.com/track", WebSeverity.LOW),
    ("Amplitude", r"amplitude\.com/analytics", WebSeverity.LOW),
    ("Segment", r"cdn\.segment\.com/analytics", WebSeverity.LOW),
    ("New Relic", r"newrelic\.com/nr-", WebSeverity.LOW),
    ("Datadog", r"datadog-rum|dd_rl|DATADOG", WebSeverity.LOW),
    ("FullStory", r"fullstory\.com/s/fs\.js", WebSeverity.LOW),
    ("LinkedIn Insight", r"linkedin\.com/insight", WebSeverity.LOW),
    ("Twitter Pixel", r"static\.ads-twitter\.com/uwt\.js", WebSeverity.LOW),
    ("HubSpot", r"js\.hs-scripts\.com|hubspot\.com/__hctrc", WebSeverity.LOW),
    ("AdRoll", r"adroll\.com/j/roundtrip", WebSeverity.LOW),
    ("Criteo", r"criteo\.net/", WebSeverity.LOW),
    ("Pinterest", r"ct\.pinterest\.com/", WebSeverity.LOW),
    ("TikTok Pixel", r"analytics\.tiktok\.com/i18n/pixel", WebSeverity.LOW),
    ("Snapchat Pixel", r"sc\.snapchat\.com/", WebSeverity.LOW),
    ("Reddit Pixel", r"alb\.reddit\.com/rpixel", WebSeverity.LOW),
    ("Bing Ads", r"bat\.bing\.com/bat\.js", WebSeverity.LOW),
]

EXTERNAL_FORM_DOMAINS = [
    "formsubmit.co", "formspree.io", "formcarry.com",
    "getform.io", "submit-form.com", "web3forms.com",
    "google.com/forms", "typeform.com", "jotform.com",
]


class PrivacyScanner:
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}

    def scan(self, url: str, html: str, base_domain: str) -> list[WebFinding]:
        findings: list[WebFinding] = []

        findings.extend(self._scan_pii(url, html))
        findings.extend(self._scan_tracking(url, html))
        findings.extend(self._scan_external_forms(url, html, base_domain))

        return findings

    def _scan_pii(self, url: str, body: str) -> list[WebFinding]:
        findings = []
        if not body or len(body) > 5_000_000:
            return findings

        for name, pattern, severity, confidence in PII_PATTERNS:
            try:
                matches = re.finditer(pattern, body)
                seen = set()
                for match in matches:
                    matched = match.group()
                    if matched in seen:
                        continue
                    seen.add(matched)
                    if len(seen) > 5:
                        break
                    if self._is_false_positive_pii(matched, name):
                        continue
                    findings.append(WebFinding.create(
                        url=url,
                        vuln_type=WebVulnType.PII_EXPOSED,
                        evidence=f"Potential {name}: {matched}",
                        description=f"PII exposure: {name} found in page content",
                        severity=severity,
                        confidence=confidence,
                        response_body_preview=matched,
                    ))
            except re.error:
                continue

        return findings

    def _is_false_positive_pii(self, matched: str, name: str) -> bool:
        if name == "Email Address":
            fp_domains = ["example.com", "example.org", "example.net", "test.com"]
            if any(d in matched for d in fp_domains):
                return True
        if name == "Credit Card Number":
            if int(matched.replace(" ", "").replace("-", "")[:6]) < 400000:
                return True
        return False

    def _scan_tracking(self, url: str, body: str) -> list[WebFinding]:
        findings = []
        if not body:
            return findings

        for name, pattern, severity in TRACKING_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                findings.append(WebFinding.create(
                    url=url,
                    vuln_type=WebVulnType.TRACKING_SCRIPT,
                    evidence=f"Third-party tracker detected: {name}",
                    description=f"Page includes {name} tracking script",
                    severity=severity,
                    confidence=1.0,
                ))

        return findings

    def _scan_external_forms(self, url: str, html: str, base_domain: str) -> list[WebFinding]:
        findings = []
        if not html:
            return findings

        for m in re.finditer(
            r'<form[^>]*?action=["\'](https?://[^"\']*)["\']',
            html, re.IGNORECASE,
        ):
            action = m.group(1)
            try:
                parsed = urlparse(action)
                if parsed.netloc and parsed.netloc != base_domain:
                    for ext_domain in EXTERNAL_FORM_DOMAINS:
                        if ext_domain in parsed.netloc:
                            findings.append(WebFinding.create(
                                url=url,
                                vuln_type=WebVulnType.INFO_LEAK,
                                evidence=f"Form submits to external domain: {action}",
                                description=f"Form data sent to external service: {parsed.netloc}",
                                severity=WebSeverity.MEDIUM,
                                confidence=0.8,
                            ))
                            break
            except Exception:
                continue

        return findings
