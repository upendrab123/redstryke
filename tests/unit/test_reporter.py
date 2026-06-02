"""Unit tests for ReportGenerator."""
import json
import uuid
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.executor.garak_runner.runner import Finding, Severity
from core.evaluator.evaluator import EvaluationResult
from core.memory.sql_store.sqlite_memory import SQLMemory
from core.reporter.generator import ReportConfig, ReportGenerationError, ReportGenerator


class TestReportGenerator:
    """Tests for ReportGenerator."""

    @pytest.fixture
    def sqlite_memory(self):
        """Create in-memory SQLite for testing."""
        return SQLMemory(":memory:")

    @pytest.fixture
    def engagement_id(self, sqlite_memory):
        """Create a test engagement."""
        return sqlite_memory.create_engagement(
            target_url="https://api.test.com/chat",
            target_description="Test chatbot",
            scan_depth="standard",
        )

    @pytest.fixture
    def findings(self, sqlite_memory, engagement_id):
        """Add test findings."""
        eval_result = EvaluationResult(
            finding_id=str(uuid.uuid4()),
            success=True,
            severity=Severity.HIGH,
            severity_score=7.0,
            reason="Test",
            reproduction_steps="Test steps",
            regulatory_refs=["NIST AI RMF MS-2.5"],
            confidence=0.8,
            raw_response="{}",
        )

        finding1 = Finding(
            finding_id=str(uuid.uuid4()),
            target_url="https://api.test.com",
            attack_type="garak",
            category="jailbreak",
            probe_name="dan",
            attack_prompt="Ignore instructions",
            model_response="Okay bypassed",
            success=True,
            severity=Severity.CRITICAL,
            severity_score=9.0,
        )
        sqlite_memory.save_finding(finding1, eval_result, engagement_id)

        finding2 = Finding(
            finding_id=str(uuid.uuid4()),
            target_url="https://api.test.com",
            attack_type="garak",
            category="prompt_injection",
            probe_name="inject",
            attack_prompt="Test injection",
            model_response="Injected",
            success=True,
            severity=Severity.MEDIUM,
            severity_score=5.0,
        )
        sqlite_memory.save_finding(finding2, eval_result, engagement_id)

        return engagement_id

    @pytest.fixture
    def report_config(self, findings, tmp_path):
        """Create report config."""
        return ReportConfig(
            engagement_id=findings,
            target_description="Test chatbot",
            company_name="Test Corp",
            output_dir=tmp_path / "reports",
        )

    @pytest.fixture
    def generator(self, sqlite_memory):
        """Create report generator with mocked Groq."""
        mock_groq = MagicMock()
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="Executive summary test"))]
        mock_groq.chat.completions.create.return_value = mock_response

        return ReportGenerator(
            groq_client=mock_groq,
            sql_memory=sqlite_memory,
            config={"groq": {"reporter_model": "llama-3.3-70b-versatile"}},
        )

    def test_generate_creates_pdf(self, generator, report_config):
        """generate() creates a PDF file."""
        try:
            import xhtml2pdf
            with patch("xhtml2pdf.pisa.pisaDocument"):
                output_path = generator.generate(report_config)
                assert output_path.exists()
        except (ModuleNotFoundError, OSError):
            pytest.skip("xhtml2pdf not installed")

    def test_generate_with_xhtml2pdf_failure_saves_html(self, generator, report_config):
        """xhtml2pdf failure saves HTML instead."""
        try:
            import xhtml2pdf
            with patch("xhtml2pdf.pisa.pisaDocument", side_effect=ImportError("No xhtml2pdf")):
                output_path = generator.generate(report_config)
                html_files = list(report_config.output_dir.glob("*.html"))
                assert len(html_files) > 0
        except (ModuleNotFoundError, OSError):
            pytest.skip("xhtml2pdf not installed")

    def test_executive_summary_uses_fallback_when_no_api_key(self, sqlite_memory, findings):
        """Fallback summary when no API key."""
        generator = ReportGenerator(
            groq_client=None,
            sql_memory=sqlite_memory,
        )

        findings_list = sqlite_memory.get_findings(findings)
        engagement = {"id": findings, "target_url": "https://api.test.com"}

        summary = generator._generate_executive_summary(findings_list, engagement, "Test target")

        assert len(summary) > 0

    def test_empty_findings_produces_clean_bill_report(self, sqlite_memory):
        """Empty findings produces clean bill of health report."""
        engagement_id = sqlite_memory.create_engagement(
            target_url="https://api.test.com",
            target_description="Test",
            scan_depth="quick",
        )

        generator = ReportGenerator(
            groq_client=None,
            sql_memory=sqlite_memory,
        )

        findings = sqlite_memory.get_findings(engagement_id)
        engagement = {"target_url": "https://api.test.com"}

        summary = generator._generate_executive_summary(findings, engagement, "Test")

        assert "no vulnerabilities" in summary.lower() or "passed" in summary.lower()

    def test_regulatory_refs_for_critical_findings(self, sqlite_memory, findings):
        """Regulatory refs appear for correct finding types."""
        generator = ReportGenerator(
            groq_client=None,
            sql_memory=sqlite_memory,
        )

        findings_list = sqlite_memory.get_findings(findings)
        refs = generator._build_regulatory_mapping(findings_list)

        assert "EU AI Act" in refs or "NIST AI RMF" in str(refs)

    def test_recommendations_generated_from_findings(self, sqlite_memory, findings):
        """Recommendations generated from findings."""
        generator = ReportGenerator(
            groq_client=None,
            sql_memory=sqlite_memory,
        )

        findings_list = sqlite_memory.get_findings(findings)
        recommendations = generator._generate_recommendations(findings_list)

        assert len(recommendations) > 0
        assert isinstance(recommendations[0], str)

    def test_group_findings_by_severity(self, sqlite_memory, findings):
        """Findings grouped by severity correctly."""
        generator = ReportGenerator(
            groq_client=None,
            sql_memory=sqlite_memory,
        )

        findings_list = sqlite_memory.get_findings(findings)
        grouped = generator._group_findings_by_severity(findings_list)

        assert "critical" in grouped or "high" in grouped


class TestReportConfig:
    """Tests for ReportConfig dataclass."""

    def test_report_config_creation(self):
        """ReportConfig can be created with all fields."""
        config = ReportConfig(
            engagement_id="test-123",
            target_description="Test chatbot",
            company_name="Test Corp",
            output_dir=Path("/tmp/reports"),
            logo_path=Path("/tmp/logo.png"),
            include_raw_logs=True,
        )

        assert config.engagement_id == "test-123"
        assert config.include_raw_logs is True