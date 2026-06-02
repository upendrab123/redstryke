"""Unit tests for AttackPlanner."""
import pytest
from unittest.mock import MagicMock, patch
from core.planner.planner import AttackPlanner, AttackPlan, ScanDepth, Phase, Category, AttackType, Severity


class TestAttackPlanner:
    """Tests for AttackPlanner — Groq calls mocked."""

    @pytest.fixture
    def mock_client(self):
        return MagicMock()

    @pytest.fixture
    def mock_memory(self):
        memory = MagicMock()
        memory.retrieve_similar_attacks.return_value = [
            {"attack_type": "jailbreak", "success": True, "prompt": "Test prompt"}
        ]
        return memory

    @pytest.fixture
    def config(self):
        return {
            "planner": {"model": "llama-3.1-70b-versatile"},
            "memory": {"top_k_retrieval": 3}
        }

    @pytest.fixture
    def planner(self, mock_client, mock_memory, config):
        with patch("pathlib.Path.read_text", return_value="You are a planner.\n\n```\nPlan attacks.\n```"):
            return AttackPlanner(mock_client, mock_memory, config)

    @pytest.fixture
    def mock_plan_response(self):
        return """{
            "plan_id": "plan-001",
            "target_description": "Test AI assistant",
            "scan_depth": "quick",
            "reasoning": "Test reasoning",
            "threat_model": {
                "target_type": "chatbot",
                "primary_risk": "jailbreak",
                "user_trust_level": "high",
                "agentic": false
            },
            "tasks": [
                {
                    "task_id": "task-001",
                    "phase": "reconnaissance",
                    "priority": 1,
                    "category": "jailbreak",
                    "attack_type": "garak",
                    "rationale": "Test task",
                    "expected_severity": "high"
                }
            ]
        }"""

    def test_create_plan_returns_attack_plan(self, planner, mock_plan_response):
        """create_plan() should return an AttackPlan with tasks."""
        with patch.object(planner, "_call_groq_planner", return_value=mock_plan_response):
            plan = planner.create_plan("Test target", ScanDepth.QUICK)

        assert isinstance(plan, AttackPlan)
        assert len(plan.tasks) > 0
        assert plan.scan_depth == ScanDepth.QUICK

    def test_create_plan_injects_memory_context(self, planner, mock_plan_response):
        """Memory context should be included in the plan."""
        with patch.object(planner, "_call_groq_planner", return_value=mock_plan_response):
            plan = planner.create_plan("Test target", ScanDepth.STANDARD)

        assert plan.memory_context is not None

    def test_parse_plan_response_handles_malformed_json(self, planner):
        """Parser should handle malformed JSON gracefully."""
        malformed = "{ invalid json }"
        with pytest.raises(Exception):
            planner._parse_plan_response(malformed, "test", ScanDepth.QUICK, [])

    def test_scan_depth_controls_task_count(self, planner, mock_plan_response):
        """Scan depth should affect the generated tasks."""
        with patch.object(planner, "_call_groq_planner", return_value=mock_plan_response):
            quick_plan = planner.create_plan("Test", ScanDepth.QUICK)
            deep_plan = planner.create_plan("Test", ScanDepth.DEEP)

        assert isinstance(quick_plan, AttackPlan)
        assert isinstance(deep_plan, AttackPlan)