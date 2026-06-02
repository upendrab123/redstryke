"""
Main CLI entry point for redstryke.

Usage:
    python main.py --target URL --description TEXT [--depth DEPTH] [--mode MODE] [--output DIR]

Modes:
    api   - LLM red teaming (Garak + PyRIT probes against chatbot APIs)
    web   - Full web application vulnerability scanning
    auto  - Auto-detect from URL pattern (default)

Web scan examples:
    python main.py --mode web --target "https://example.com" --description "Corporate website" --depth deep

    python main.py --mode web --target "https://shop.example.com" --description "E-commerce platform" --depth standard

API scan examples:
    python main.py \\
        --target "https://api.example.com/v1/chat" \\
        --description "Customer service chatbot for a retail bank" \\
        --depth standard

    python main.py --mode api \\
        --target "https://api.example.com/v1/chat" \\
        --description "Medical diagnosis assistant" \\
        --depth deep \\
        --output ./my_reports
"""

from __future__ import annotations
import asyncio
import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import click
import yaml
from groq import Groq

from core.agents.kill_chain import KillChainOrchestrator, KillChainResult
from core.evaluator.evaluator import AttackEvaluator
from core.executor.garak_runner.runner import GarakRunner
from core.executor.pyrit_runner.runner import PyritRunner
from core.executor.web_runner.runner import WebRunner
from core.memory.sql_store.sqlite_memory import SQLMemory
from core.memory.vector_store.chroma_memory import ChromaMemory
from core.planner.planner import AttackPlanner, ScanDepth
from core.reporter.generator import ReportConfig, ReportGenerator

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


def _load_config() -> dict:
    """Load configuration from settings.yaml."""
    config_path = Path(__file__).parent / "config" / "settings.yaml"
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


def _validate_url(ctx, param, value):
    """Validate that URL starts with http."""
    if not value:
        raise click.BadParameter("Target URL is required")
    if not value.startswith("http"):
        raise click.BadParameter("Target URL must start with http:// or https://")
    return value


def _init_layers(config: dict, groq_api_key: str = None):
    """Initialize all pipeline layers."""
    print("[FORGE] Initialising all layers...")

    memory_config = config.get("memory", {})
    db_path = memory_config.get("sqlite_path", "data/memory.db")
    db_path = Path(__file__).parent / db_path
    db_path.parent.mkdir(parents=True, exist_ok=True)
    sql_memory = SQLMemory(str(db_path))

    chroma_path = memory_config.get("chroma_path", "data/chroma_db")
    chroma_path = Path(__file__).parent / chroma_path
    chroma_memory = ChromaMemory(persist_dir=str(chroma_path))

    groq_client = None
    if groq_api_key:
        groq_client = Groq(api_key=groq_api_key)

    evaluator = AttackEvaluator(groq_client=groq_client, config=config)

    planner = AttackPlanner(
        groq_client=groq_client,
        memory_manager=chroma_memory,
        config=config,
    )

    garak_runner = GarakRunner(memory_manager=sql_memory, config=config)

    pyrit_runner = PyritRunner(
        groq_client=groq_client,
        memory_manager=sql_memory,
        config=config,
        evaluator=evaluator,
    )

    report_generator = ReportGenerator(
        groq_client=groq_client,
        sql_memory=sql_memory,
    )

    return {
        "sql_memory": sql_memory,
        "chroma_memory": chroma_memory,
        "planner": planner,
        "garak_runner": garak_runner,
        "pyrit_runner": pyrit_runner,
        "evaluator": evaluator,
        "report_generator": report_generator,
    }


async def run_scan(
    target_url: str,
    description: str,
    depth: str = "standard",
    groq_api_key: str = None,
    output_path: str = "./data/reports",
    db_path: str = None,
    no_vector_memory: bool = False,
    attack_engines: list = None,
    engagement_id: str = None,
) -> dict:
    """
    Run the full autonomous red team scan.

    Args:
        target_url: Target LLM API endpoint
        description: Plain-English description of the target
        depth: Scan depth (quick/standard/deep)
        groq_api_key: Optional Groq API key
        output_path: Directory for PDF report
        db_path: Optional path to SQLite database
        no_vector_memory: Skip ChromaDB vector memory
        attack_engines: List of engines to run ["garak", "pyrit"]
        engagement_id: Optional pre-created engagement ID

    Returns:
        Dict with engagement_id, summary, and report_path
    """
    config = _load_config()

    if no_vector_memory:
        os.environ["DISABLE_VECTOR_MEMORY"] = "true"

    layers = _init_layers(config, groq_api_key)

    sql_memory = layers["sql_memory"]
    chroma_memory = layers["chroma_memory"]
    planner = layers["planner"]
    garak_runner = layers["garak_runner"]
    pyrit_runner = layers["pyrit_runner"]
    report_generator = layers["report_generator"]

    engagement_id = sql_memory.create_engagement(
        target_url=target_url,
        target_description=description,
        scan_depth=depth,
    )
    print(f"[FORGE] Engagement {engagement_id[:8]} started")

    scan_depth = ScanDepth(depth)
    context = chroma_memory.get_attack_context("general", description)

    print(f"[FORGE] Generating attack plan...")
    try:
        attack_plan = planner.create_plan(
            target_description=description,
            scan_depth=scan_depth,
        )
    except Exception as e:
        logger.warning(f"Planner failed, using empty plan: {e}")
        from core.planner.planner import AttackPlan
        attack_plan = AttackPlan(
            plan_id=str(uuid.uuid4()),
            target_description=description,
            scan_depth=scan_depth,
            reasoning="",
            memory_insights="",
            threat_model=None,
            tasks=[],
        )

    print(f"[FORGE] Attack plan: {len(attack_plan.tasks)} tasks")

    total_findings = 0
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for task in attack_plan.tasks:
        attack_id = sql_memory.save_attack(
            finding=None,
            engagement_id=engagement_id,
            runner_used=task.attack_type.value if hasattr(task.attack_type, 'value') else str(task.attack_type),
        )
        sql_memory.update_attack_status(attack_id, "running")

        print(f"[→] Running {task.category}...")

        try:
            findings = []

            runner_type = str(task.attack_type).lower() if task.attack_type else "garak"

            if "pyrit" in runner_type or task.scenario_name:
                findings = await pyrit_runner.run_scenarios(
                    scenarios=pyrit_runner.load_scenarios()[:1],
                    target_url=target_url,
                    api_key="",
                )
            elif "garak" in runner_type or not task.scenario_name:
                probe_names = task.probe_names if task.probe_names else ["lmrc"]
                gen = garak_runner.run(target_url, probe_names)
                findings = list(gen)

            for finding in findings:
                sql_memory.save_finding(
                    finding=finding,
                    evaluation=None,
                    engagement_id=engagement_id,
                    attack_id=attack_id,
                )

                if finding.success:
                    chroma_memory.store_successful_attack(
                        finding=finding,
                        target_description=description,
                        engagement_id=engagement_id,
                    )

                sev = str(finding.severity).lower()
                if sev in severity_counts:
                    severity_counts[sev] += 1
                    total_findings += 1
                    print(f"  [!] {sev.upper()}: {finding.category}")

        except Exception as e:
            logger.warning(f"Task failed: {e}")

        sql_memory.update_attack_status(
            attack_id,
            "completed",
            datetime.now(timezone.utc).isoformat(),
        )

    sql_memory.update_engagement_status(
        engagement_id,
        "completed",
        datetime.now(timezone.utc).isoformat(),
    )

    summary = sql_memory.get_engagement_summary(engagement_id)
    print(f"[FORGE] Scan complete: {total_findings} findings")
    print(f"  CRITICAL: {severity_counts['critical']}")
    print(f"  HIGH: {severity_counts['high']}")
    print(f"  MEDIUM: {severity_counts['medium']}")
    print(f"  LOW: {severity_counts['low']}")
    print(f"  INFO: {severity_counts['info']}")

    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    report_config = ReportConfig(
        engagement_id=engagement_id,
        target_description=description,
        company_name="Red Team",
        output_dir=output_dir,
    )

    try:
        pdf_path = report_generator.generate(report_config)
        print(f"[FORGE] Report saved to {pdf_path}")
    except Exception as e:
        logger.warning(f"Report generation failed: {e}")
        pdf_path = None

    return {
        "engagement_id": engagement_id,
        "summary": summary,
        "report_path": str(pdf_path) if pdf_path else None,
    }


async def run_kill_chain(
    target_url: str,
    description: str,
    depth: str = "standard",
    output_path: str = "./data/reports",
) -> dict:
    """
    Run the autonomous 10-agent kill chain against a web target.

    Phases:
      1. SCOUT + FINGERPRINT (parallel reconnaissance)
      2. ANALYST (Groq threat model)
      3. PLANNER (Groq attack plan)
      4. EXPLOIT + PAYLOAD + PIVOT + PERSIST + EXFIL (parallel active checks)
      5. DEBRIEF (Groq synthesized report)
    """
    config = _load_config()
    print("[KILLCHAIN] Initializing 10-agent autonomous kill chain...")
    print(f"[KILLCHAIN] Target: {target_url}")

    events_log: list[dict] = []

    def on_event(event: dict):
        events_log.append(event)
        ts = event.get("timestamp", "")[11:19]
        agent = event.get("agent", "").ljust(12)
        status = event.get("status", "").ljust(8)
        msg = event.get("message", "")
        icon = {"running": ">", "complete": "+", "error": "!"}.get(event.get("status", ""), "*")
        print(f"  {icon} [{ts}] {agent} {status} {msg}")

    orchestrator = KillChainOrchestrator(config=config, on_event=on_event)

    print(f"[KILLCHAIN] Phase 1: Reconnaissance (SCOUT + FINGERPRINT)")
    result = await orchestrator.run(target_url, depth)

    print(f"\n[KILLCHAIN] {'='*50}")
    print(f"[KILLCHAIN] Results for {target_url}")
    print(f"[KILLCHAIN]   Duration: {result.total_duration_seconds:.1f}s")
    print(f"[KILLCHAIN]   Findings: {result.total_findings}")
    print(f"[KILLCHAIN]   Risk Score: {result.overall_risk_score}/100 ({result.risk_level})")

    report = result.report or {}
    vulns = report.get("vulnerabilities", [])
    if vulns:
        print(f"[KILLCHAIN]   Vulnerabilities reported: {len(vulns)}")
        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for v in vulns:
            s = v.get("severity", "Info")
            if s in sev_counts:
                sev_counts[s] += 1
        for sev, cnt in sev_counts.items():
            if cnt > 0:
                print(f"    {sev}: {cnt}")

    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    import json
    report_path = output_dir / f"killchain_{result.target_domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump({
            "target": target_url,
            "domain": result.target_domain,
            "duration_seconds": result.total_duration_seconds,
            "total_findings": result.total_findings,
            "risk_score": result.overall_risk_score,
            "risk_level": result.risk_level,
            "report": report,
            "events": events_log,
        }, f, indent=2, default=str)
    print(f"[KILLCHAIN] JSON report saved to {report_path}")

    return {
        "target_url": target_url,
        "domain": result.target_domain,
        "total_findings": result.total_findings,
        "risk_score": result.overall_risk_score,
        "risk_level": result.risk_level,
        "duration_seconds": result.total_duration_seconds,
        "report_path": str(report_path),
    }


async def run_web_scan(
    target_url: str,
    description: str,
    depth: str = "standard",
    output_path: str = "./data/reports",
    engagement_id: str = None,
) -> dict:
    """
    Run a web application vulnerability scan against a target URL.

    Args:
        target_url: Target website URL
        description: Plain-English description of the target
        depth: Scan depth (quick/standard/deep)
        output_path: Directory for PDF report
        engagement_id: Optional pre-created engagement ID

    Returns:
        Dict with scan_id, severity_counts, and report_path
    """
    config = _load_config()

    sql_memory = SQLMemory()

    engagement_id = engagement_id or sql_memory.create_engagement(
        target_url=target_url,
        target_description=description,
        scan_depth=depth,
    )
    print(f"[FORGE] Engagement {engagement_id[:8]} started for web scan")

    scan_id = sql_memory.save_web_scan(
        target_url=target_url,
        scan_depth=depth,
        engagement_id=engagement_id,
    )
    print(f"[FORGE] Web scan {scan_id[:8]} initialized")

    web_runner = WebRunner(memory_manager=sql_memory, config=config)
    result = await web_runner.run(target_url, depth)

    sql_memory.save_web_findings_batch(
        findings=result.findings,
        scan_id=scan_id,
        engagement_id=engagement_id,
    )

    sql_memory.update_web_scan(
        scan_id=scan_id,
        urls_crawled=result.urls_crawled,
        forms_found=result.forms_found,
        tech_stack=result.tech_stack,
        scan_duration_seconds=result.scan_duration_seconds,
        status="completed",
    )

    sql_memory.update_engagement_status(
        engagement_id,
        "completed",
        datetime.now(timezone.utc).isoformat(),
    )

    counts = result.severity_counts
    print(f"[FORGE] Web scan complete: {result.total_findings} findings in {result.scan_duration_seconds:.1f}s")
    print(f"  CRITICAL: {counts['critical']}")
    print(f"  HIGH: {counts['high']}")
    print(f"  MEDIUM: {counts['medium']}")
    print(f"  LOW: {counts['low']}")
    print(f"  INFO: {counts['info']}")

    if result.tech_stack:
        print(f"  Tech: {', '.join(result.tech_stack.keys())}")

    report_findings = web_runner.get_findings_for_report(result)

    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    report_config = ReportConfig(
        engagement_id=engagement_id,
        target_description=description,
        company_name="Red Team",
        output_dir=output_dir,
        scan_type="Web Application",
        scan_depth=depth,
        web_findings=report_findings,
        web_tech_stack=list(result.tech_stack.keys()),
        web_urls_crawled=result.urls_crawled,
        web_forms_found=result.forms_found,
    )

    groq_config = config.get("groq", {})
    groq_key = os.environ.get("GROQ_API_KEY")
    groq_client = None
    if groq_key:
        from groq import Groq
        groq_client = Groq(api_key=groq_key)

    report_generator = ReportGenerator(
        groq_client=groq_client,
        sql_memory=sql_memory,
    )

    try:
        pdf_path = report_generator.generate(report_config)
        print(f"[FORGE] Report saved to {pdf_path}")
    except Exception as e:
        logger.warning(f"Report generation failed: {e}")
        pdf_path = None

    return {
        "scan_id": scan_id,
        "engagement_id": engagement_id,
        "severity_counts": counts,
        "total_findings": result.total_findings,
        "report_path": str(pdf_path) if pdf_path else None,
    }


@click.command()
@click.option(
    "--target",
    required=True,
    help="Target URL (API endpoint or website).",
    callback=_validate_url,
)
@click.option("--description", required=True, help="Plain-English description of the target AI.")
@click.option(
    "--depth",
    default="standard",
    type=click.Choice(["quick", "standard", "deep"]),
    help="Scan depth (quick=30min, standard=2hr, deep=8hr).",
)
@click.option("--api-key", default="", help="Groq API key (optional, for better planning).")
@click.option("--output", default="./data/reports", help="Directory to save the PDF report.")
@click.option(
    "--target-api-key",
    default="",
    help="Auth key for the target API (if required).",
)
@click.option(
    "--mode",
    default="auto",
    type=click.Choice(["api", "web", "auto"]),
    help="Scan mode: 'api' for LLM endpoints, 'web' for website scanning, 'auto' to detect.",
)
@click.option(
    "--kill-chain",
    is_flag=True,
    default=False,
    help="Run 10-agent autonomous kill chain (DNS recon → HTTP fingerprint → analysis → planning → exploit → payload → pivot → persist → exfil → debrief).",
)
@click.option(
    "--no-vector-memory",
    is_flag=True,
    default=False,
    help="Disable ChromaDB vector memory. Faster startup on low-end hardware.",
)
def main(
    target: str,
    description: str,
    depth: str,
    mode: str,
    api_key: str,
    output: str,
    target_api_key: str,
    kill_chain: bool,
    no_vector_memory: bool,
) -> None:
    """
    Run an autonomous security assessment against a target.

    Supports three modes:
    - api (default/auto): LLM red teaming with Garak + PyRIT probes
    - web: Full web application vulnerability scanning
    - --kill-chain: 10-agent autonomous kill chain

    Kill chain pipeline:
    Phase 1 — SCOUT + FINGERPRINT (parallel): DNS enum, subdomain brute-force,
      HTTP headers, TLS, CORS, cookies, clickjacking
    Phase 2 — ANALYST: Groq-powered tech stack classification & threat model
    Phase 3 — PLANNER: Groq-generated targeted attack plan
    Phase 4 — EXPLOIT + PAYLOAD + PIVOT + PERSIST + EXFIL (parallel):
      Open redirect, XSS, exposed files, SQLi, SSTI, path traversal,
      third-party JS, vulnerable libs, auth weaknesses, JWT, info disclosure
    Phase 5 — DEBRIEF: Groq-synthesized report with CVSS, CWE, risk score (0-100)

    Web mode pipeline:
    1. Reconnaissance (crawl, tech fingerprint, JS analysis)
    2. Injection testing (XSS, SQLi, SSTI, command injection, SSRF)
    3. Security headers & CORS analysis
    4. Path exposure scanning (.git, .env, backups, admin panels)
    5. Credential leak detection (API keys, secrets in responses)
    6. Privacy scanning (PII, tracking scripts)
    7. Generate and save PDF report with OWASP Top 10 mapping.
    """
    if api_key:
        os.environ["GROQ_API_KEY"] = api_key
        groq_key = api_key
    else:
        groq_key = os.environ.get("GROQ_API_KEY")

    if no_vector_memory:
        os.environ["DISABLE_VECTOR_MEMORY"] = "true"

    if kill_chain:
        result = asyncio.run(
            run_kill_chain(
                target_url=target,
                description=description,
                depth=depth,
                output_path=output,
            )
        )
        print(f"\n[KILLCHAIN] Done! Risk: {result['risk_score']}/100 ({result['risk_level']})")
        if result.get("report_path"):
            print(f"[KILLCHAIN] Report saved to {result['report_path']}")
        return

    effective_mode = mode
    if effective_mode == "auto":
        if "/chat/completions" in target or "/v1/" in target or "api." in target:
            effective_mode = "api"
        else:
            effective_mode = "web"

    try:
        if effective_mode == "web":
            result = asyncio.run(
                run_web_scan(
                    target_url=target,
                    description=description,
                    depth=depth,
                    output_path=output,
                )
            )
            print(f"[FORGE] Done! Web scan: {result['scan_id'][:8]}")
            if result.get("report_path"):
                print(f"[FORGE] Report saved to {result['report_path']}")
        else:
            result = asyncio.run(
                run_scan(
                    target_url=target,
                    description=description,
                    depth=depth,
                    groq_api_key=groq_key,
                    output_path=output,
                )
            )
            print(f"[FORGE] Done! Engagement: {result['engagement_id'][:8]}")

    except KeyboardInterrupt:
        print("[FORGE] Scan cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"[ERROR] {e}")
        print("[FORGE] Scan failed — check logs")
        sys.exit(1)


if __name__ == "__main__":
    main()