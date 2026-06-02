"""
REDSTRYKE Tactical API — FastAPI Backend
India's Most Advanced Autonomous AI Red Team.
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks, Query, Request
from pydantic import BaseModel
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, StreamingResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import json
import os
import uuid
import yaml
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import concurrent.futures

from core.memory.sql_store.sqlite_memory import SQLMemory
from core.memory.vector_store.chroma_memory import ChromaMemory
from core.reporter.generator import ReportGenerator, ReportConfig
from core.planner.planner import ScanDepth
from core.executor.pyrit_runner.runner import PYRIT_AVAILABLE

app = FastAPI(title="REDSTRYKE Tactical API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).parent
STATIC_DIR = BASE_DIR / "static"
STATIC_DIR.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

DATA_DIR = BASE_DIR.parent / "data"
DATA_DIR.mkdir(exist_ok=True)

DB_PATH = os.getenv("SQLITE_DB_PATH", str(DATA_DIR / "memory.db"))
CHROMA_PATH = str(DATA_DIR / "chroma_db")
REPORTS_PATH = DATA_DIR / "reports"
REPORTS_PATH.mkdir(exist_ok=True)


def _load_config() -> dict:
    config_path = BASE_DIR.parent / "config" / "settings.yaml"
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


def _get_memory():
    return SQLMemory(DB_PATH)


def _get_chroma():
    try:
        os.environ.setdefault("DISABLE_VECTOR_MEMORY", "false")
        return ChromaMemory(persist_dir=CHROMA_PATH)
    except Exception:
        return None


def _get_report_gen(sql_memory):
    return ReportGenerator(groq_client=None, sql_memory=sql_memory)


@app.on_event("startup")
async def startup_event():
    app.state.sql_memory = _get_memory()
    app.state.chroma = _get_chroma()
    app.state.report_gen = _get_report_gen(app.state.sql_memory)
    app.state.config = _load_config()
    print(f"[REDSTRYKE] Tactical API initialized")
    print(f"  Database: {DB_PATH}")
    print(f"  ChromaDB: {CHROMA_PATH}")


@app.get("/")
async def root():
    return _serve_with_config("index.html")


@app.get("/login")
async def login_page():
    return _serve_with_config("login.html")


@app.get("/signup")
async def signup_page():
    return _serve_with_config("signup.html")


@app.get("/dashboard")
async def dashboard_page():
    return _serve_with_config("dashboard.html")


def _serve_with_config(filename: str) -> HTMLResponse:
    """Inject Supabase config into the HTML response."""
    html_path = STATIC_DIR / filename
    if not html_path.exists():
        raise HTTPException(status_code=404, detail="Page not found")
    html = html_path.read_text(encoding="utf-8")
    # Inject Supabase and Razorpay config into the page
    sup_url = os.getenv("SUPABASE_URL", "")
    sup_key = os.getenv("SUPABASE_ANON_KEY", "")
    config_script = f"""
    <script>
    window.SUPABASE_URL = {json.dumps(sup_url)};
    window.SUPABASE_ANON_KEY = {json.dumps(sup_key)};
    </script>
    """
    html = html.replace("</head>", config_script + "</head>")
    return HTMLResponse(content=html)


@app.get("/health")
async def health_check():
    mem_status = "ok"
    chroma_status = "disabled"
    groq_status = "not_configured"
    garak_status = "installed"

    try:
        sql = _get_memory()
        sql.close()
    except Exception:
        mem_status = "error"

    try:
        chroma = _get_chroma()
        if chroma and not chroma._disabled:
            chroma_status = "ok"
    except Exception:
        pass

    if os.getenv("GROQ_API_KEY"):
        groq_status = "configured"

    try:
        import garak
    except ImportError:
        garak_status = "not_installed"

    return {
        "api": "ok",
        "database": mem_status,
        "vector_memory": chroma_status,
        "groq": groq_status,
        "garak": garak_status,
        "pyrit": "disabled" if not PYRIT_AVAILABLE else "installed",
    }


@app.get("/api/stats")
async def get_stats():
    sql = _get_memory()
    try:
        engagements = sql.get_all_engagements(limit=1000)
        total = len(engagements)
        active = sum(1 for e in engagements if e.get("status") == "running")
        completed = sum(1 for e in engagements if e.get("status") == "completed")
        failed = sum(1 for e in engagements if e.get("status") == "failed")

        findings = sql.get_recent_findings(limit=1000)
        critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high = sum(1 for f in findings if f.get("severity") == "HIGH")
        medium = sum(1 for f in findings if f.get("severity") == "MEDIUM")
        low = sum(1 for f in findings if f.get("severity") == "LOW")

        success_rate = (completed / (completed + failed) * 100) if (completed + failed) > 0 else 0

        return {
            "total_engagements": total,
            "active_scans": active,
            "completed_scans": completed,
            "failed_scans": failed,
            "total_findings": len(findings),
            "critical_findings": critical,
            "high_findings": high,
            "medium_findings": medium,
            "low_findings": low,
            "success_rate": round(success_rate, 1),
        }
    finally:
        sql.close()


@app.get("/api/engagements")
async def get_engagements(limit: int = 20, status: str = "all"):
    sql = _get_memory()
    try:
        if status == "all":
            engagements = sql.get_all_engagements(limit=limit)
        else:
            engagements = sql.get_all_engagements(limit=limit, status=status)

        result = []
        for e in engagements:
            findings = sql.get_findings(e["id"])
            duration = None
            if e.get("started_at") and e.get("completed_at"):
                start = datetime.fromisoformat(e["started_at"].replace("Z", "+00:00"))
                end = datetime.fromisoformat(e["completed_at"].replace("Z", "+00:00"))
                duration = (end - start).total_seconds() / 60

            result.append({
                "id": e["id"],
                "target_url": e.get("target_url", ""),
                "description": e.get("target_description", ""),
                "depth": e.get("scan_depth", ""),
                "status": e.get("status", "pending"),
                "started_at": e.get("started_at", ""),
                "completed_at": e.get("completed_at"),
                "findings_count": len(findings),
                "duration_minutes": round(duration, 1) if duration else None,
            })
        return result
    finally:
        sql.close()


@app.get("/api/engagements/{engagement_id}")
async def get_engagement_detail(engagement_id: str):
    sql = _get_memory()
    try:
        engagement = sql.get_engagement(engagement_id)
        summary = sql.get_engagement_summary(engagement_id)
        findings = sql.get_findings(engagement_id)
        attacks = sql.get_attack_history(engagement_id, limit=50)

        return {
            "engagement": engagement,
            "summary": summary,
            "findings": findings,
            "attacks": attacks,
        }
    except ValueError:
        raise HTTPException(status_code=404, detail="Engagement not found")
    finally:
        sql.close()


@app.get("/api/findings")
async def get_findings(
    severity: str = "all",
    limit: int = 50,
    engagement_id: str = None
):
    sql = _get_memory()
    try:
        if engagement_id:
            findings = sql.get_findings(engagement_id)
        else:
            findings = sql.get_recent_findings(limit=limit * 2)

        if severity != "all":
            findings = [f for f in findings if f.get("severity", "").upper() == severity.upper()]

        return findings[:limit]
    finally:
        sql.close()


@app.get("/api/severity-breakdown")
async def get_severity_breakdown(engagement_id: str = None):
    sql = _get_memory()
    try:
        breakdown = sql.get_severity_breakdown(engagement_id)
        return breakdown
    finally:
        sql.close()


class ScanRequest(BaseModel):
    target_url: str
    description: str
    depth: str = "standard"
    api_key: Optional[str] = None
    no_vector_memory: bool = False
    attack_engines: Optional[list] = None


@app.post("/api/scans/start")
async def start_scan(request: ScanRequest):
    target_url = request.target_url
    description = request.description
    depth = request.depth
    api_key = request.api_key
    no_vector_memory = request.no_vector_memory
    attack_engines = request.attack_engines

    if not target_url.startswith("http"):
        raise HTTPException(status_code=400, detail="Target URL must start with http")

    engagement_id = str(uuid.uuid4())
    sql = _get_memory()
    sql.create_engagement(
        target_url=target_url,
        target_description=description,
        scan_depth=depth,
        engagement_id=engagement_id,
    )
    sql.close()

    if api_key:
        os.environ["GROQ_API_KEY"] = api_key
    if no_vector_memory:
        os.environ["DISABLE_VECTOR_MEMORY"] = "true"

    asyncio.create_task(
        run_scan_background(
            engagement_id=engagement_id,
            target_url=target_url,
            description=description,
            depth=depth,
            no_vector_memory=no_vector_memory,
            attack_engines=attack_engines,
        )
    )

    return {"engagement_id": engagement_id, "status": "started"}


async def run_scan_background(
    engagement_id: str,
    target_url: str,
    description: str,
    depth: str,
    no_vector_memory: bool,
    attack_engines: list,
):
    from main import run_scan as main_run_scan

    try:
        await main_run_scan(
            target_url=target_url,
            description=description,
            depth=depth,
            db_path=DB_PATH,
            no_vector_memory=no_vector_memory,
            attack_engines=attack_engines,
            engagement_id=engagement_id,
        )
    except Exception as e:
        print(f"[FORGE] Scan {engagement_id} failed: {e}")
        sql = _get_memory()
        sql.update_engagement_status(engagement_id, "failed")
        sql.close()


@app.get("/api/scans/{engagement_id}/stream")
async def scan_stream(engagement_id: str):
    async def event_generator():
        while True:
            try:
                sql = _get_memory()
                summary = sql.get_engagement_summary(engagement_id)
                findings = sql.get_findings(engagement_id)
                sql.close()

                status = summary.get("status", "unknown")
                critical = summary.get("critical", 0)
                high = summary.get("high", 0)
                medium = summary.get("medium", 0)
                low = summary.get("low", 0)
                total = critical + high + medium + low

                progress = 0
                if status == "completed":
                    progress = 100
                elif status == "running":
                    progress = min(50 + (total * 5), 90)

                data = {
                    "engagement_id": engagement_id,
                    "status": status,
                    "findings_count": total,
                    "critical": critical,
                    "high": high,
                    "medium": medium,
                    "low": low,
                    "progress": progress,
                    "latest_findings": findings[-3:] if findings else [],
                    "timestamp": datetime.utcnow().isoformat(),
                }

                yield f"data: {json.dumps(data)}\n\n"

                if status in ("completed", "failed", "cancelled"):
                    yield f"data: {json.dumps({'done': True})}\n\n"
                    break

                await asyncio.sleep(2)

            except Exception as e:
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
                break

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/api/scans/{engagement_id}/stop")
async def stop_scan(engagement_id: str):
    sql = _get_memory()
    try:
        sql.update_engagement_status(engagement_id, "cancelled")
        return {"status": "cancelled"}
    finally:
        sql.close()


@app.post("/api/reports/{engagement_id}/generate")
async def generate_report(engagement_id: str):
    sql = _get_memory()
    try:
        engagement = sql.get_engagement(engagement_id)
        report_gen = _get_report_gen(sql)

        report_config = ReportConfig(
            engagement_id=engagement_id,
            target_description=engagement.get("target_description", "Target"),
            company_name="REDSTRYKE Tactical Systems",
            output_dir=REPORTS_PATH,
        )

        output_path = report_gen.generate(report_config)

        return FileResponse(
            path=output_path,
            filename=f"redstryke_report_{engagement_id[:8]}.pdf",
            media_type="application/pdf",
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {e}")
    finally:
        sql.close()


@app.get("/api/targets")
async def get_targets():
    sql = _get_memory()
    try:
        targets = sql.get_targets()
        return targets
    finally:
        sql.close()


@app.post("/api/targets")
async def save_target(name: str, url: str, api_key_hint: str = None, target_type: str = None):
    sql = _get_memory()
    try:
        target_id = str(uuid.uuid4())
        sql.save_target(target_id, name, url, api_key_hint, target_type)
        return {"id": target_id, "status": "saved"}
    finally:
        sql.close()


@app.delete("/api/targets/{target_id}")
async def delete_target(target_id: str):
    sql = _get_memory()
    try:
        sql.delete_target(target_id)
        return {"status": "deleted"}
    finally:
        sql.close()


@app.get("/api/modules")
async def get_attack_modules():
    base_path = BASE_DIR.parent / "data" / "attack_library"
    modules = []

    multi_turn_path = base_path / "multi_turn"
    if multi_turn_path.exists():
        for yaml_file in multi_turn_path.glob("*.yaml"):
            try:
                with open(yaml_file, "r") as f:
                    data = yaml.safe_load(f)
                    modules.append({
                        "name": data.get("name", yaml_file.stem),
                        "description": data.get("description", ""),
                        "attack_type": "pyrit",
                        "category": yaml_file.stem,
                    })
            except Exception:
                pass

    modules.extend([
        {"name": "Garak Probes", "description": "Single-turn prompt injection probes", "attack_type": "garak", "category": "prompt_injection"},
        {"name": "DAN Jailbreak", "description": "Do Anything Now jailbreak attempts", "attack_type": "garak", "category": "jailbreak"},
    ])

    return modules


@app.post("/api/models/download")
async def download_models(background_tasks: BackgroundTasks):
    def run_download():
        import subprocess
        try:
            result = subprocess.run(
                ["python", "scripts/download_models.py"],
                capture_output=True,
                text=True,
                cwd=str(BASE_DIR.parent),
            )
            return result.returncode == 0
        except Exception:
            return False

    background_tasks.add_task(run_download)
    return {"status": "started", "message": "Model download started"}


# ── User Profile & Inquiry Routes ──────────────────────────────

class ProfileUpdate(BaseModel):
    full_name: Optional[str] = None
    organization: Optional[str] = None
    phone: Optional[str] = None


class InquirySubmit(BaseModel):
    tier: str
    message: str


@app.get("/api/me")
async def get_my_profile(request: Request):
    """Return a mock/default operator profile until Supabase auth is wired server-side."""
    return {
        "full_name": "Operator",
        "email": "operator@redstryke.in",
        "organization": "REDSTRYKE Tactical Systems",
        "role": "Security Operator",
        "phone": "",
        "country": "India",
    }


@app.put("/api/me")
async def update_my_profile(update: ProfileUpdate):
    """Update operator profile (currently returns success — wire to Supabase on production)."""
    return {"status": "updated", "updates": update.model_dump(exclude_none=True)}


@app.post("/api/inquiries")
async def submit_inquiry(inquiry: InquirySubmit):
    """Submit a service inquiry (stores to local DB + would trigger webhook in production)."""
    sql = _get_memory()
    try:
        inquiry_id = str(uuid.uuid4())
        # Store as a note/engagement for tracking
        sql.create_engagement(
            target_url=f"inquiry-{inquiry.tier.lower()}",
            target_description=f"Service Inquiry: {inquiry.tier} — {inquiry.message[:100]}",
            scan_depth="standard",
            engagement_id=inquiry_id,
        )
        return {"id": inquiry_id, "status": "submitted"}
    finally:
        sql.close()


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("DASHBOARD_PORT", "7860"))
    uvicorn.run(app, host="0.0.0.0", port=port)