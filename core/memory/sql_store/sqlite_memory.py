"""
SQLMemory: SQLite-backed structured storage for all attack results.

Provides the audit trail and analytics foundation for:
- Generating reports (query all findings for an engagement)
- Dashboard analytics (severity breakdown, attack counts)
- Compliance evidence (timestamped log of all testing activity)
- Failure analysis (which attack types get consistently blocked)

Schema is initialized via init_db() — run once before first use.
"""

from __future__ import annotations
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import yaml

from core.executor.garak_runner.runner import Finding
from core.evaluator.evaluator import EvaluationResult

logger = logging.getLogger(__name__)


def _load_default_db_path() -> str:
    """Get default database path from settings."""
    config_path = Path(__file__).parent.parent.parent.parent / "config" / "settings.yaml"
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
            return config.get("memory", {}).get("sqlite_path", "data/memory.db")
    return "data/memory.db"


class MemoryError(Exception):
    """Raised when a memory operation fails."""
    pass


class SQLMemory:
    """
    SQLite storage for structured attack results and engagement metadata.

    All writes use parameterized queries. Connection is not shared across threads.
    """

    TABLE_ENGAGEMENTS = "engagements"
    TABLE_ATTACKS = "attacks"
    TABLE_FINDINGS = "findings"
    TABLE_WEB_FINDINGS = "web_findings"
    TABLE_WEB_SCANS = "web_scans"

    def __init__(self, db_path: Optional[str] = None) -> None:
        """
        Args:
            db_path: Path to SQLite database file (created if not exists).
        """
        self.db_path = db_path or _load_default_db_path()
        self.connection = None
        self._connect()
        self._create_tables()
        self._create_targets_table()

    def _connect(self) -> None:
        """Create SQLite connection with proper settings."""
        import sqlite3
        self.connection = sqlite3.connect(
            self.db_path,
            check_same_thread=False,
        )
        self.connection.row_factory = sqlite3.Row
        cursor = self.connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        self.connection.commit()

    def _create_tables(self) -> None:
        """Create all tables if they don't exist."""
        cursor = self.connection.cursor()

        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS {self.TABLE_ENGAGEMENTS} (
                id TEXT PRIMARY KEY,
                target_url TEXT NOT NULL,
                target_description TEXT,
                scan_depth TEXT,
                status TEXT DEFAULT 'running',
                started_at TEXT NOT NULL,
                completed_at TEXT,
                findings_count INTEGER DEFAULT 0
            )
        """)

        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS {self.TABLE_ATTACKS} (
                id TEXT PRIMARY KEY,
                engagement_id TEXT NOT NULL,
                attack_type TEXT,
                probe_name TEXT,
                runner_used TEXT,
                status TEXT DEFAULT 'pending',
                task_json TEXT,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                FOREIGN KEY (engagement_id) REFERENCES engagements(id)
            )
        """)

        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS {self.TABLE_FINDINGS} (
                id TEXT PRIMARY KEY,
                engagement_id TEXT NOT NULL,
                attack_id TEXT,
                finding_json TEXT NOT NULL,
                evaluation_json TEXT,
                severity TEXT,
                severity_score REAL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (engagement_id) REFERENCES engagements(id),
                FOREIGN KEY (attack_id) REFERENCES attacks(id)
            )
        """)

        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS {self.TABLE_WEB_SCANS} (
                id TEXT PRIMARY KEY,
                engagement_id TEXT,
                target_url TEXT NOT NULL,
                scan_depth TEXT,
                status TEXT DEFAULT 'running',
                urls_crawled INTEGER DEFAULT 0,
                forms_found INTEGER DEFAULT 0,
                tech_stack TEXT,
                scan_duration_seconds REAL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                FOREIGN KEY (engagement_id) REFERENCES engagements(id)
            )
        """)

        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS {self.TABLE_WEB_FINDINGS} (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                engagement_id TEXT,
                url TEXT NOT NULL,
                vulnerability_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                evidence TEXT,
                description TEXT,
                remediation TEXT,
                owasp_category TEXT,
                affected_param TEXT,
                confidence REAL DEFAULT 1.0,
                request_headers TEXT,
                response_headers TEXT,
                response_status INTEGER,
                response_body_preview TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES web_scans(id),
                FOREIGN KEY (engagement_id) REFERENCES engagements(id)
            )
        """)

        self.connection.commit()

    def init_db(self) -> None:
        """Create all tables if they don't exist. Safe to call multiple times."""
        self._create_tables()

    def create_engagement(
        self,
        target_url: str,
        target_description: str,
        scan_depth: str,
        engagement_id: str = None,
    ) -> str:
        """Record a new engagement. Returns engagement_id (UUID)."""
        engagement_id = engagement_id or str(uuid.uuid4())
        started_at = datetime.now(timezone.utc).isoformat()

        try:
            cursor = self.connection.cursor()
            cursor.execute(
                f"""INSERT INTO {self.TABLE_ENGAGEMENTS}
                    (id, target_url, target_description, scan_depth, status, started_at, findings_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (engagement_id, target_url, target_description, scan_depth, "running", started_at, 0),
            )
            self.connection.commit()
            return engagement_id
        except Exception as e:
            logger.error(f"create_engagement failed: {e}")
            raise MemoryError(f"Failed to create engagement: {e}")

    def save_attack(
        self,
        finding: Finding,
        engagement_id: str,
        runner_used: str = "garak",
    ) -> str:
        """Save a raw attack attempt. Returns attack_id."""
        attack_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc).isoformat()

        task_json = json.dumps({
            "task_id": getattr(finding, "task_id", ""),
            "category": finding.category,
            "attack_type": finding.attack_type,
            "probe_name": finding.probe_name,
        })

        try:
            cursor = self.connection.cursor()
            cursor.execute(
                f"""INSERT INTO {self.TABLE_ATTACKS}
                    (id, engagement_id, attack_type, probe_name, runner_used, status, task_json, started_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (attack_id, engagement_id, finding.attack_type, finding.probe_name, runner_used, "pending", task_json, started_at),
            )
            self.connection.commit()
            return attack_id
        except Exception as e:
            logger.error(f"save_attack failed: {e}")
            raise MemoryError(f"Failed to save attack: {e}")

    def save_finding(
        self,
        finding: Finding,
        evaluation: Optional[EvaluationResult],
        engagement_id: str,
        attack_id: Optional[str] = None,
    ) -> str:
        """Save a confirmed, evaluated finding. Returns finding_id."""
        finding_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()

        finding_json = json.dumps({
            "finding_id": finding.finding_id,
            "target_url": finding.target_url,
            "attack_type": finding.attack_type,
            "category": finding.category,
            "probe_name": finding.probe_name,
            "attack_prompt": finding.attack_prompt,
            "model_response": finding.model_response,
            "success": finding.success,
            "severity": finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
            "severity_score": finding.severity_score,
        })

        evaluation_json = None
        if evaluation:
            evaluation_json = json.dumps({
                "success": evaluation.success,
                "severity": evaluation.severity.value if hasattr(evaluation.severity, 'value') else str(evaluation.severity),
                "severity_score": evaluation.severity_score,
                "reason": evaluation.reason,
                "reproduction_steps": evaluation.reproduction_steps,
                "regulatory_refs": evaluation.regulatory_refs,
                "confidence": evaluation.confidence,
            })

        severity = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)

        try:
            cursor = self.connection.cursor()
            cursor.execute(
                f"""INSERT INTO {self.TABLE_FINDINGS}
                    (id, engagement_id, attack_id, finding_json, evaluation_json, severity, severity_score, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (finding_id, engagement_id, attack_id, finding_json, evaluation_json, severity, finding.severity_score, created_at),
            )

            cursor.execute(
                f"""UPDATE {self.TABLE_ENGAGEMENTS} 
                    SET findings_count = findings_count + 1 
                    WHERE id = ?""",
                (engagement_id,),
            )

            self.connection.commit()
            return finding_id
        except Exception as e:
            logger.error(f"save_finding failed: {e}")
            raise MemoryError(f"Failed to save finding: {e}")

    def get_findings_for_engagement(self, engagement_id: str) -> list[dict[str, Any]]:
        """Retrieve all confirmed findings for a given engagement."""
        try:
            cursor = self.connection.cursor()
            cursor.execute(
                f"""SELECT * FROM {self.TABLE_FINDINGS}
                    WHERE engagement_id = ?
                    ORDER BY severity_score DESC, created_at DESC""",
                (engagement_id,),
            )
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"get_findings_for_engagement failed: {e}")
            raise MemoryError(f"Failed to get findings: {e}")

    def get_severity_breakdown(self, engagement_id: str) -> dict[str, int]:
        """Return count of findings per severity level."""
        try:
            cursor = self.connection.cursor()
            cursor.execute(
                f"""SELECT severity, COUNT(*) as count 
                    FROM {self.TABLE_FINDINGS} 
                    WHERE engagement_id = ?
                    GROUP BY severity""",
                (engagement_id,),
            )
            rows = cursor.fetchall()
            breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for row in rows:
                sev = row["severity"].lower() if row["severity"] else "info"
                if sev in breakdown:
                    breakdown[sev] = row["count"]
            return breakdown
        except Exception as e:
            logger.error(f"get_severity_breakdown failed: {e}")
            raise MemoryError(f"Failed to get severity breakdown: {e}")

    def get_attack_stats(self, engagement_id: str) -> dict[str, Any]:
        """Return aggregate stats: total attacks, success rate, top categories."""
        try:
            cursor = self.connection.cursor()

            cursor.execute(
                f"""SELECT COUNT(*) as total FROM {self.TABLE_ATTACKS} 
                    WHERE engagement_id = ?""",
                (engagement_id,),
            )
            total_attacks = cursor.fetchone()["total"]

            cursor.execute(
                f"""SELECT COUNT(*) as completed FROM {self.TABLE_ATTACKS} 
                    WHERE engagement_id = ? AND status = 'completed'""",
                (engagement_id,),
            )
            completed_attacks = cursor.fetchone()["completed"]

            success_rate = (completed_attacks / total_attacks * 100) if total_attacks > 0 else 0

            cursor.execute(
                f"""SELECT attack_type, COUNT(*) as count 
                    FROM {self.TABLE_ATTACKS} 
                    WHERE engagement_id = ?
                    GROUP BY attack_type 
                    ORDER BY count DESC 
                    LIMIT 5""",
                (engagement_id,),
            )
            top_categories = [{"type": row["attack_type"], "count": row["count"]} for row in cursor.fetchall()]

            return {
                "total_attacks": total_attacks,
                "completed_attacks": completed_attacks,
                "success_rate": round(success_rate, 2),
                "top_categories": top_categories,
            }
        except Exception as e:
            logger.error(f"get_attack_stats failed: {e}")
            raise MemoryError(f"Failed to get attack stats: {e}")

    def get_engagement(self, engagement_id: str) -> dict[str, Any]:
        """SELECT * FROM engagements WHERE id=? Return as dict, raise ValueError if not found."""
        try:
            cursor = self.connection.cursor()
            cursor.execute(
                f"""SELECT * FROM {self.TABLE_ENGAGEMENTS} WHERE id = ?""",
                (engagement_id,),
            )
            row = cursor.fetchone()
            if row is None:
                raise ValueError(f"Engagement not found: {engagement_id}")
            return dict(row)
        except ValueError:
            raise
        except Exception as e:
            logger.error(f"get_engagement failed: {e}")
            raise MemoryError(f"Failed to get engagement: {e}")

    def get_findings(self, engagement_id: str) -> list[dict[str, Any]]:
        """SELECT * FROM findings WHERE engagement_id=? ORDER BY severity DESC, created_at DESC."""
        try:
            cursor = self.connection.cursor()
            cursor.execute(
                f"""SELECT * FROM {self.TABLE_FINDINGS}
                    WHERE engagement_id = ?
                    ORDER BY severity_score DESC, created_at DESC""",
                (engagement_id,),
            )
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"get_findings failed: {e}")
            raise MemoryError(f"Failed to get findings: {e}")

    def get_recent_findings(self, limit: int = 50) -> list[dict[str, Any]]:
        """SELECT findings.*, engagements.target_url FROM findings JOIN engagements..."""
        try:
            cursor = self.connection.cursor()
            cursor.execute(
                f"""SELECT f.*, e.target_url 
                    FROM {self.TABLE_FINDINGS} f
                    JOIN {self.TABLE_ENGAGEMENTS} e ON f.engagement_id = e.id
                    ORDER BY f.created_at DESC LIMIT ?""",
                (limit,),
            )
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"get_recent_findings failed: {e}")
            raise MemoryError(f"Failed to get recent findings: {e}")

    def get_attack_history(self, attack_type: str, limit: int = 20) -> list[dict[str, Any]]:
        """SELECT * FROM attacks WHERE attack_type=? ORDER BY started_at DESC LIMIT?"""
        try:
            cursor = self.connection.cursor()
            cursor.execute(
                f"""SELECT * FROM {self.TABLE_ATTACKS}
                    WHERE attack_type = ?
                    ORDER BY started_at DESC LIMIT ?""",
                (attack_type, limit),
            )
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"get_attack_history failed: {e}")
            raise MemoryError(f"Failed to get attack history: {e}")

    def get_engagement_summary(self, engagement_id: str) -> dict[str, Any]:
        """Returns counts by severity: total, critical, high, medium, low, info plus engagement status, target_url, duration."""
        try:
            cursor = self.connection.cursor()

            cursor.execute(
                f"""SELECT * FROM {self.TABLE_ENGAGEMENTS} WHERE id = ?""",
                (engagement_id,),
            )
            engagement = dict(cursor.fetchone())

            cursor.execute(
                f"""SELECT severity, COUNT(*) as count 
                    FROM {self.TABLE_FINDINGS} 
                    WHERE engagement_id = ?
                    GROUP BY severity""",
                (engagement_id,),
            )

            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            total = 0
            for row in cursor.fetchall():
                sev = row["severity"].lower() if row["severity"] else "info"
                if sev in severity_counts:
                    severity_counts[sev] = row["count"]
                    total += row["count"]

            started = engagement.get("started_at", "")
            completed = engagement.get("completed_at")
            duration = None
            if started and completed:
                try:
                    start_time = datetime.fromisoformat(started)
                    end_time = datetime.fromisoformat(completed)
                    duration = (end_time - start_time).total_seconds()
                except Exception:
                    pass

            return {
                "total": total,
                "critical": severity_counts["critical"],
                "high": severity_counts["high"],
                "medium": severity_counts["medium"],
                "low": severity_counts["low"],
                "info": severity_counts["info"],
                "status": engagement.get("status", "unknown"),
                "target_url": engagement.get("target_url", ""),
                "duration_seconds": duration,
            }
        except Exception as e:
            logger.error(f"get_engagement_summary failed: {e}")
            raise MemoryError(f"Failed to get engagement summary: {e}")

    def search_findings(self, query_text: str) -> list[dict[str, Any]]:
        """SELECT * FROM findings WHERE title LIKE ? OR description LIKE ? Use %query_text% pattern."""
        try:
            cursor = self.connection.cursor()
            pattern = f"%{query_text}%"
            cursor.execute(
                f"""SELECT * FROM {self.TABLE_FINDINGS}
                    WHERE finding_json LIKE ? OR evaluation_json LIKE ?
                    ORDER BY created_at DESC""",
                (pattern, pattern),
            )
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"search_findings failed: {e}")
            raise MemoryError(f"Failed to search findings: {e}")

    def update_attack_status(self, attack_id: str, status: str, completed_at: Optional[str] = None) -> None:
        """UPDATE attacks SET status=?, completed_at=? WHERE id=?"""
        try:
            cursor = self.connection.cursor()
            if completed_at:
                cursor.execute(
                    f"""UPDATE {self.TABLE_ATTACKS} 
                        SET status = ?, completed_at = ? 
                        WHERE id = ?""",
                    (status, completed_at, attack_id),
                )
            else:
                cursor.execute(
                    f"""UPDATE {self.TABLE_ATTACKS} 
                        SET status = ? 
                        WHERE id = ?""",
                    (status, attack_id),
                )
            self.connection.commit()
        except Exception as e:
            logger.error(f"update_attack_status failed: {e}")
            raise MemoryError(f"Failed to update attack status: {e}")

    def update_engagement_status(self, engagement_id: str, status: str, completed_at: Optional[str] = None) -> None:
        """UPDATE engagements SET status=?, completed_at=? WHERE id=?"""
        try:
            cursor = self.connection.cursor()
            if completed_at:
                cursor.execute(
                    f"""UPDATE {self.TABLE_ENGAGEMENTS} 
                        SET status = ?, completed_at = ? 
                        WHERE id = ?""",
                    (status, completed_at, engagement_id),
                )
            else:
                cursor.execute(
                    f"""UPDATE {self.TABLE_ENGAGEMENTS} 
                        SET status = ? 
                        WHERE id = ?""",
                    (status, engagement_id),
                )
            self.connection.commit()
        except Exception as e:
            logger.error(f"update_engagement_status failed: {e}")
            raise MemoryError(f"Failed to update engagement status: {e}")

    def get_all_engagements(self, limit: int = 50, status: str = None) -> list[dict[str, Any]]:
        """SELECT all engagements, optionally filter by status."""
        try:
            cursor = self.connection.cursor()
            if status:
                cursor.execute(
                    f"""SELECT * FROM {self.TABLE_ENGAGEMENTS}
                        WHERE status = ?
                        ORDER BY started_at DESC
                        LIMIT ?""",
                    (status, limit),
                )
            else:
                cursor.execute(
                    f"""SELECT * FROM {self.TABLE_ENGAGEMENTS}
                        ORDER BY started_at DESC
                        LIMIT ?""",
                    (limit,),
                )
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"get_all_engagements failed: {e}")
            raise MemoryError(f"Failed to get engagements: {e}")

    def get_severity_breakdown(self, engagement_id: str = None) -> dict[str, int]:
        """Get count of findings by severity."""
        result = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        try:
            cursor = self.connection.cursor()
            if engagement_id:
                cursor.execute(
                    f"""SELECT severity, COUNT(*) as count
                        FROM {self.TABLE_FINDINGS}
                        WHERE engagement_id = ?
                        GROUP BY severity""",
                    (engagement_id,),
                )
            else:
                cursor.execute(
                    f"""SELECT severity, COUNT(*) as count
                        FROM {self.TABLE_FINDINGS}
                        GROUP BY severity"""
                )
            for row in cursor.fetchall():
                key = row["severity"].lower() if row["severity"] else ""
                if key in result:
                    result[key] = row["count"]
            return result
        except Exception as e:
            logger.error(f"get_severity_breakdown failed: {e}")
            return result

    def save_target(self, target_id: str, name: str, url: str, api_key_hint: str = None, target_type: str = None) -> str:
        """Save a target configuration."""
        created_at = datetime.now(timezone.utc).isoformat()
        try:
            cursor = self.connection.cursor()
            cursor.execute(
                """INSERT OR REPLACE INTO targets (id, name, url, api_key_hint, target_type, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (target_id, name, url, api_key_hint, target_type, created_at),
            )
            self.connection.commit()
            return target_id
        except Exception as e:
            logger.error(f"save_target failed: {e}")
            raise MemoryError(f"Failed to save target: {e}")

    def get_targets(self) -> list[dict[str, Any]]:
        """Get all saved targets."""
        try:
            cursor = self.connection.cursor()
            cursor.execute("""SELECT * FROM targets ORDER BY created_at DESC""")
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"get_targets failed: {e}")
            return []

    def delete_target(self, target_id: str) -> bool:
        """Delete a target by ID."""
        try:
            cursor = self.connection.cursor()
            cursor.execute("DELETE FROM targets WHERE id = ?", (target_id,))
            self.connection.commit()
            return True
        except Exception as e:
            logger.error(f"delete_target failed: {e}")
            return False

    def _create_targets_table(self) -> None:
        """Create targets table if not exists."""
        cursor = self.connection.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS targets (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                api_key_hint TEXT,
                target_type TEXT,
                created_at TEXT,
                last_scanned TEXT
            )
        """)
        self.connection.commit()

    def save_web_scan(
        self,
        target_url: str,
        scan_depth: str,
        scan_id: str = None,
        engagement_id: str = None,
    ) -> str:
        """Save a web scan record. Returns scan_id."""
        scan_id = scan_id or str(uuid.uuid4())
        started_at = datetime.now(timezone.utc).isoformat()
        try:
            cursor = self.connection.cursor()
            cursor.execute(
                f"""INSERT INTO {self.TABLE_WEB_SCANS}
                    (id, engagement_id, target_url, scan_depth, status, started_at)
                    VALUES (?, ?, ?, ?, ?, ?)""",
                (scan_id, engagement_id, target_url, scan_depth, "running", started_at),
            )
            self.connection.commit()
            return scan_id
        except Exception as e:
            logger.error(f"save_web_scan failed: {e}")
            raise MemoryError(f"Failed to save web scan: {e}")

    def update_web_scan(
        self,
        scan_id: str,
        urls_crawled: int = None,
        forms_found: int = None,
        tech_stack: dict = None,
        scan_duration_seconds: float = None,
        status: str = "completed",
    ) -> None:
        """Update web scan completion data."""
        try:
            cursor = self.connection.cursor()
            completed_at = datetime.now(timezone.utc).isoformat()
            updates = ["status = ?", "completed_at = ?"]
            params: list[Any] = [status, completed_at]
            if urls_crawled is not None:
                updates.append("urls_crawled = ?")
                params.append(urls_crawled)
            if forms_found is not None:
                updates.append("forms_found = ?")
                params.append(forms_found)
            if tech_stack is not None:
                import json
                updates.append("tech_stack = ?")
                params.append(json.dumps(tech_stack))
            if scan_duration_seconds is not None:
                updates.append("scan_duration_seconds = ?")
                params.append(scan_duration_seconds)
            params.append(scan_id)
            cursor.execute(
                f"""UPDATE {self.TABLE_WEB_SCANS}
                    SET {', '.join(updates)}
                    WHERE id = ?""",
                params,
            )
            self.connection.commit()
        except Exception as e:
            logger.error(f"update_web_scan failed: {e}")
            raise MemoryError(f"Failed to update web scan: {e}")

    def save_web_finding(self, finding: Any, scan_id: str, engagement_id: str = None) -> str:
        """Save a web vulnerability finding. Returns finding_id."""
        finding_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()
        try:
            import json
            cursor = self.connection.cursor()
            cursor.execute(
                f"""INSERT INTO {self.TABLE_WEB_FINDINGS}
                    (id, scan_id, engagement_id, url, vulnerability_type, severity,
                     evidence, description, remediation, owasp_category, affected_param,
                     confidence, request_headers, response_headers, response_status,
                     response_body_preview, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding_id, scan_id, engagement_id, finding.url,
                    finding.vulnerability_type.value if hasattr(finding.vulnerability_type, 'value') else str(finding.vulnerability_type),
                    finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                    finding.evidence, finding.description, finding.remediation,
                    finding.owasp_category, finding.affected_param, finding.confidence,
                    json.dumps(finding.request_headers) if finding.request_headers else None,
                    json.dumps(finding.response_headers) if finding.response_headers else None,
                    finding.response_status, finding.response_body_preview, created_at,
                ),
            )
            self.connection.commit()
            return finding_id
        except Exception as e:
            logger.error(f"save_web_finding failed: {e}")
            raise MemoryError(f"Failed to save web finding: {e}")

    def save_web_findings_batch(self, findings: list[Any], scan_id: str, engagement_id: str = None) -> list[str]:
        """Save multiple web findings efficiently."""
        ids = []
        for f in findings:
            fid = self.save_web_finding(f, scan_id, engagement_id)
            ids.append(fid)
        return ids

    def get_web_findings(self, scan_id: str = None, engagement_id: str = None) -> list[dict[str, Any]]:
        """Retrieve web findings filtered by scan or engagement."""
        try:
            cursor = self.connection.cursor()
            if scan_id:
                cursor.execute(
                    f"""SELECT * FROM {self.TABLE_WEB_FINDINGS}
                        WHERE scan_id = ?
                        ORDER BY severity DESC, created_at DESC""",
                    (scan_id,),
                )
            elif engagement_id:
                cursor.execute(
                    f"""SELECT * FROM {self.TABLE_WEB_FINDINGS}
                        WHERE engagement_id = ?
                        ORDER BY severity DESC, created_at DESC""",
                    (engagement_id,),
                )
            else:
                cursor.execute(
                    f"""SELECT * FROM {self.TABLE_WEB_FINDINGS}
                        ORDER BY created_at DESC LIMIT 100""",
                )
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"get_web_findings failed: {e}")
            return []

    def get_web_scan_summary(self, scan_id: str) -> dict[str, Any]:
        """Get summary of a web scan with severity counts."""
        try:
            cursor = self.connection.cursor()
            cursor.execute(
                f"""SELECT * FROM {self.TABLE_WEB_SCANS} WHERE id = ?""",
                (scan_id,),
            )
            row = cursor.fetchone()
            scan = dict(row) if row else {}

            cursor.execute(
                f"""SELECT severity, COUNT(*) as count
                    FROM {self.TABLE_WEB_FINDINGS}
                    WHERE scan_id = ?
                    GROUP BY severity""",
                (scan_id,),
            )
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            total = 0
            for row in cursor.fetchall():
                sev = row["severity"].lower() if row["severity"] else "info"
                if sev in severity_counts:
                    severity_counts[sev] = row["count"]
                    total += row["count"]

            return {
                "total": total,
                "severity_counts": severity_counts,
                "target_url": scan.get("target_url", ""),
                "scan_depth": scan.get("scan_depth", ""),
                "status": scan.get("status", ""),
                "urls_crawled": scan.get("urls_crawled", 0),
                "forms_found": scan.get("forms_found", 0),
                "scan_duration_seconds": scan.get("scan_duration_seconds"),
            }
        except Exception as e:
            logger.error(f"get_web_scan_summary failed: {e}")
            return {"total": 0, "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}}

    def close(self) -> None:
        """Close the database connection."""
        if self.connection:
            self.connection.close()