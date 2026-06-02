from __future__ import annotations
import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlparse

from core.agents.base import BaseAgent, make_event
from core.agents.scout import ScoutAgent
from core.agents.fingerprint import FingerprintAgent
from core.agents.analyst import AnalystAgent
from core.agents.planner import PlannerAgent
from core.agents.exploit import ExploitAgent
from core.agents.payload import PayloadAgent
from core.agents.pivot import PivotAgent
from core.agents.persist import PersistAgent
from core.agents.exfil import ExfilAgent
from core.agents.debrief import DebriefAgent

logger = logging.getLogger(__name__)


@dataclass
class KillChainResult:
    target_url: str
    target_domain: str
    total_duration_seconds: float = 0.0
    total_findings: int = 0
    overall_risk_score: int = 0
    risk_level: str = "Unknown"
    agent_outputs: dict[str, Any] = field(default_factory=dict)
    events: list[dict] = field(default_factory=list)
    report: dict | None = None

    def to_dict(self) -> dict:
        return {
            "target_url": self.target_url,
            "target_domain": self.target_domain,
            "total_duration_seconds": round(self.total_duration_seconds, 1),
            "total_findings": self.total_findings,
            "overall_risk_score": self.overall_risk_score,
            "risk_level": self.risk_level,
            "agent_outputs": {k: self._summarize(v) for k, v in self.agent_outputs.items()},
            "events_count": len(self.events),
            "has_report": self.report is not None,
        }

    def _summarize(self, data: Any) -> Any:
        if isinstance(data, dict):
            findings = data.get("findings", [])
            return {
                "findings_count": len(findings) if isinstance(findings, list) else 0,
                "summary": {k: v for k, v in data.items() if k != "findings"}
            }
        return str(data)[:200]


class KillChainOrchestrator:
    def __init__(
        self,
        config: dict | None = None,
        on_event: Callable[[dict], None] | None = None,
    ):
        self.config = config or {}
        self.on_event = on_event or (lambda e: None)
        self.events: list[dict] = []
        self.context: dict[str, Any] = {}
        self.agents: dict[str, BaseAgent] = {}

    def _event_handler(self, event: dict):
        self.events.append(event)
        self.on_event(event)

    async def run(self, target_url: str, depth: str = "standard") -> KillChainResult:
        start_time = time.time()
        parsed = urlparse(target_url)
        domain = parsed.netloc.split(":")[0]
        scheme = parsed.scheme or "https"

        self.context = {
            "target_url": target_url,
            "target_domain": domain,
            "target_scheme": scheme,
            "depth": depth,
        }

        self._emit("ORCHESTRATOR", "running", f"Kill chain started for {target_url} (depth={depth})")

        self.agents = {
            "scout": ScoutAgent(on_event=self._event_handler, config=self.config),
            "fingerprint": FingerprintAgent(on_event=self._event_handler, config=self.config),
            "analyst": AnalystAgent(on_event=self._event_handler, config=self.config),
            "planner": PlannerAgent(on_event=self._event_handler, config=self.config),
            "exploit": ExploitAgent(on_event=self._event_handler, config=self.config),
            "payload": PayloadAgent(on_event=self._event_handler, config=self.config),
            "pivot": PivotAgent(on_event=self._event_handler, config=self.config),
            "persist": PersistAgent(on_event=self._event_handler, config=self.config),
            "exfil": ExfilAgent(on_event=self._event_handler, config=self.config),
            "debrief": DebriefAgent(on_event=self._event_handler, config=self.config),
        }

        try:
            await self._execute_phase1()
            await self._execute_phase2()
            await self._execute_phase3()
            await self._execute_phase4()
            await self._execute_phase5()
        except Exception as e:
            self._emit("ORCHESTRATOR", "error", f"Kill chain failed: {e}")
            logger.exception("Kill chain error")

        elapsed = time.time() - start_time

        report = self.context.get("debrief", {})
        all_findings = []
        for agent_name in ["scout", "fingerprint", "exploit", "payload", "pivot", "persist", "exfil"]:
            agent_findings = self.context.get(agent_name, {}).get("findings", [])
            if isinstance(agent_findings, list):
                all_findings.extend(agent_findings)

        result = KillChainResult(
            target_url=target_url,
            target_domain=domain,
            total_duration_seconds=elapsed,
            total_findings=len(all_findings),
            overall_risk_score=report.get("overall_risk_score", 0),
            risk_level=report.get("risk_level", "Unknown"),
            agent_outputs=self.context,
            events=self.events,
            report=report,
        )

        self._emit("ORCHESTRATOR", "complete", f"Kill chain finished in {elapsed:.1f}s: {result.total_findings} findings, risk {result.overall_risk_score}/100")
        return result

    def _emit(self, agent: str, status: str, message: str):
        event = make_event(agent, status, message)
        self.events.append(event)
        self.on_event(event)
        logger.info(f"[{agent}] [{status.upper()}] {message}")

    async def _execute_phase1(self) -> None:
        """Phase 1: SCOUT + FINGERPRINT in parallel (reconnaissance)."""
        self._emit("ORCHESTRATOR", "running", "Phase 1: Reconnaissance (SCOUT + FINGERPRINT)")

        scout_task = self._run_agent("scout", self.context)
        fp_task = self._run_agent("fingerprint", self.context)

        await asyncio.gather(scout_task, fp_task)

        self._emit("ORCHESTRATOR", "running", f"Phase 1 complete: {len(self.context.get('scout',{}).get('findings',[]))} scout findings, {len(self.context.get('fingerprint',{}).get('findings',[]))} fingerprint findings")

    async def _execute_phase2(self) -> None:
        """Phase 2: ANALYST (uses scout + fingerprint)."""
        self._emit("ORCHESTRATOR", "running", "Phase 2: Threat Analysis (ANALYST)")
        await self._run_agent("analyst", self.context)
        risk = self.context.get("analyst", {}).get("threat_model", {}).get("overall_risk_level", "?")
        self._emit("ORCHESTRATOR", "running", f"Phase 2 complete: Risk level assessed as {risk}")

    async def _execute_phase3(self) -> None:
        """Phase 3: PLANNER (uses analyst output)."""
        self._emit("ORCHESTRATOR", "running", "Phase 3: Attack Planning (PLANNER)")
        await self._run_agent("planner", self.context)
        phases = self.context.get("planner", {}).get("attack_phases", [])
        self._emit("ORCHESTRATOR", "running", f"Phase 3 complete: {len(phases)} attack phases planned")

    async def _execute_phase4(self) -> None:
        """Phase 4: EXPLOIT + PAYLOAD + PIVOT + PERSIST + EXFIL in parallel."""
        self._emit("ORCHESTRATOR", "running", "Phase 4: Active Exploitation (EXPLOIT + PAYLOAD + PIVOT + PERSIST + EXFIL)")

        depth = self.context.get("depth", "standard")
        active_agents = ["exploit", "payload", "pivot", "persist", "exfil"]

        if depth == "quick":
            active_agents = ["exploit", "pivot"]

        tasks = [self._run_agent(name, self.context) for name in active_agents]
        await asyncio.gather(*tasks)

        total = sum(len(self.context.get(a, {}).get("findings", [])) for a in active_agents)
        self._emit("ORCHESTRATOR", "running", f"Phase 4 complete: {total} findings from {len(active_agents)} agents")

    async def _execute_phase5(self) -> None:
        """Phase 5: DEBRIEF (synthesizes all agent outputs)."""
        self._emit("ORCHESTRATOR", "running", "Phase 5: Final Synthesis (DEBRIEF)")
        await self._run_agent("debrief", self.context)
        report = self.context.get("debrief", {})
        risk = report.get("overall_risk_score", 0)
        level = report.get("risk_level", "?")
        self._emit("ORCHESTRATOR", "complete", f"Phase 5 complete: Risk score {risk}/100 ({level})")

    async def _run_agent(self, name: str, context: dict) -> None:
        agent = self.agents.get(name)
        if agent is None:
            self._emit("ORCHESTRATOR", "error", f"Agent '{name}' not found")
            return
        try:
            output = await agent.run(context)
            context[name] = output
        except Exception as e:
            self._emit(name.upper(), "error", f"Agent failed: {e}")
            logger.exception(f"Agent {name} failed")
            context[name] = {"error": str(e), "findings": []}
