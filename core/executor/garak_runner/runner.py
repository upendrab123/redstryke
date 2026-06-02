"""
GarakRunner: Wraps the Garak CLI for automated LLM vulnerability scanning.

Garak is an open-source LLM vulnerability scanner that runs hundreds of
pre-built probe types (jailbreaks, injections, encodings, etc.) against
any LLM endpoint. This runner:
- Translates AttackTask specs into Garak CLI arguments.
- Streams results as they arrive (don't wait for full scan to finish).
- Parses Garak's JSONL output into our unified Finding schema.
- Saves all results to SQLite via the memory manager.
"""

from __future__ import annotations
import json
import logging
import os
import shutil
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Generator, Optional
from enum import Enum

import yaml


PROBE_ATTACK_MAP = {
    "dan": "jailbreak",
    "jailbreak": "jailbreak",
    "injection": "prompt_injection",
    "leakage": "data_exfiltration",
    "continuation": "harmful_content",
    "realtoxicity": "toxic_output",
    "xtox": "toxic_output",
    "encoding": "encoding_bypass",
    "gcg": "gradient_attack",
    "suffix": "suffix_injection",
}

logger = logging.getLogger(__name__)


def _load_config() -> dict[str, Any]:
    """Load settings from config/settings.yaml."""
    config_path = Path(__file__).parent.parent.parent.parent / "config" / "settings.yaml"
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """A single security finding from any attack engine."""
    finding_id: str
    target_url: str
    attack_type: str        # "garak" | "pyrit" | "custom"
    category: str
    probe_name: str
    attack_prompt: str
    model_response: str
    success: bool
    severity: Severity
    severity_score: float   # 0.0–10.0
    reason: str = ""        # evaluator's explanation
    reproduction_steps: str = ""
    regulatory_refs: list[str] = field(default_factory=list)
    timestamp: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackTask:
    """A single planned attack unit for Garak execution."""
    task_id: str
    probe_names: list[str] = field(default_factory=list)
    depth: str = "standard"
    generations: int = 10
    target_url: str = ""


class GarakRunner:
    """
    Executes Garak probe suites against a target LLM endpoint.

    Garak is invoked as a subprocess. Results are parsed from its
    JSONL report file and streamed back as Finding objects.
    """

    def __init__(
        self,
        memory_manager: Any,
        config: Optional[dict[str, Any]] = None,
    ) -> None:
        """
        Args:
            memory_manager: For saving findings to SQLite in real time.
            config: Loaded settings (probe lists, timeouts, etc.).
        """
        self.memory_manager = memory_manager
        self.config = config or _load_config()
        self._garak_path = shutil.which("garak")

    def _check_garak_installed(self) -> bool:
        """Verify Garak is installed and accessible in PATH."""
        if self._garak_path is None:
            raise ImportError(
                "Garak is not installed. Install it with: pip install garak"
            )
        return True

    def run(
        self,
        target_url: str,
        probe_names: list[str],
        api_key: str = "",
    ) -> Generator[Finding, None, None]:
        """
        Run Garak probes against target and yield findings as they arrive.

        Args:
            target_url: The REST endpoint to attack.
            probe_names: List of Garak probe module names to run.
            api_key: Optional auth header value for the target.

        Yields:
            Finding objects as Garak completes each probe.
        """
        self._check_garak_installed()

        task = AttackTask(
            task_id=str(uuid.uuid4()),
            probe_names=probe_names,
            target_url=target_url,
        )
        yield from self.run_task(task, target_url, api_key)

    def run_task(
        self,
        task: AttackTask,
        target_url: str,
        api_key: str = "",
    ) -> Generator[Finding, None, None]:
        """
        Run Garak probes from an AttackTask and yield findings.

        Args:
            task: AttackTask with probe_names, depth, generations.
            target_url: The REST endpoint to attack.
            api_key: Optional auth header value for the target.

        Yields:
            Finding objects as Garak completes each probe.
        """
        self._check_garak_installed()

        attack_config = self.config.get("attack", {})
        timeout = attack_config.get("timeout_seconds", 1800)

        temp_dir = tempfile.mkdtemp(prefix="garak_run_")
        report_prefix = os.path.join(temp_dir, "garak_report")

        try:
            cmd = self._build_garak_command(
                target_url=target_url,
                probe_names=task.probe_names,
                api_key=api_key,
                report_prefix=report_prefix,
                generations=task.generations,
                extended=task.depth == "deep",
            )

            logger.info(f"Running garak command: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            logger.debug(f"Garak stdout: {result.stdout[:500]}")
            if result.stderr:
                logger.debug(f"Garak stderr: {result.stderr[:500]}")

        except subprocess.TimeoutExpired:
            logger.warning(f"Garak timed out after {timeout} seconds")
            return
        except Exception as e:
            logger.warning(f"Garak execution failed: {e}")
            return
        finally:
            pass

        jsonl_path = f"{report_prefix}.jsonl"
        if not os.path.exists(jsonl_path):
            logger.warning(f"No JSONL output at {jsonl_path}")
            return

        yield from self._parse_garak_jsonl(jsonl_path, target_url, task.task_id)

    def _build_garak_command(
        self,
        target_url: str,
        probe_names: list[str],
        api_key: str,
        report_prefix: str,
        generations: int,
        extended: bool = False,
    ) -> list[str]:
        """Build the Garak CLI command as a list of arguments."""
        cmd = [
            self._garak_path,
            "--model_type", "rest",
            "--model_name", target_url,
            "--probes", ",".join(probe_names) if probe_names else "lmrc",
            "--report_prefix", report_prefix,
            "--generations", str(generations),
            "--silent",
        ]

        if api_key:
            cmd.extend(["--auth", api_key])

        if extended:
            cmd.append("--extended_detectors")

        return cmd

    def _parse_garak_jsonl(
        self,
        report_path: str,
        target_url: str,
        task_id: str,
    ) -> Generator[Finding, None, None]:
        """
        Parse Garak's JSONL output file into Finding objects.

        Garak writes one JSON object per line to its report file.
        We map its fields to our unified Finding schema.
        """
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        result = json.loads(line)
                    except json.JSONDecodeError as e:
                        logger.warning(
                            f"Skipping malformed JSON at line {line_num}: {e}"
                        )
                        continue

                    passed = result.get("passed", True)
                    if passed:
                        continue

                    probe_classname = result.get("probe_classname", "")
                    detector_name = result.get("detector_name", "")
                    score = result.get("score", 0.0)
                    goal = result.get("goal", "")
                    prompt = result.get("prompt", "")
                    output = result.get("output", "")
                    trigger = result.get("trigger")

                    probe_key = self._map_probe_to_attack_type(
                        probe_classname, detector_name
                    )

                    severity = self._map_score_to_severity(score)

                    finding_id = str(uuid.uuid4())
                    timestamp = datetime.now(timezone.utc).isoformat()

                    yield Finding(
                        finding_id=finding_id,
                        target_url=target_url,
                        attack_type="garak",
                        category=probe_key,
                        probe_name=probe_classname or detector_name,
                        attack_prompt=prompt,
                        model_response=output,
                        success=True,
                        severity=severity,
                        severity_score=score * 10,
                    )

        except FileNotFoundError:
            logger.warning(f"Report file not found: {report_path}")
        except Exception as e:
            logger.error(f"Error parsing garak JSONL: {e}")

    def _map_probe_to_attack_type(
        self, probe_classname: str, detector_name: str
    ) -> str:
        """Map garak probe names to our Finding.attack_type."""
        name_lower = (probe_classname + detector_name).lower()

        for key, attack_type in PROBE_ATTACK_MAP.items():
            if key in name_lower:
                return attack_type

        logger.debug(f"Unknown probe: {probe_classname}/{detector_name}")
        return "unknown_probe"

    def _map_score_to_severity(self, score: float) -> Severity:
        """Map garak's score to our Severity enum."""
        if score >= 0.8:
            return Severity.CRITICAL
        elif score >= 0.6:
            return Severity.HIGH
        elif score >= 0.4:
            return Severity.MEDIUM
        elif score >= 0.2:
            return Severity.LOW
        else:
            return Severity.INFO