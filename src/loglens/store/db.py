"""SQLite storage layer for triage history, findings, and runs."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from loglens.models import Cluster, Finding, LLMAssessment, Report, ReportMetadata

DEFAULT_DB_PATH = Path.home() / ".config" / "loglens" / "loglens.db"


class StorageManager:
    """Manages SQLite persistence for LogLens triage runs, findings, and clusters."""

    def __init__(self, db_path: Path | str | None = None) -> None:
        if db_path is None:
            db_path = DEFAULT_DB_PATH
        if db_path != ":memory:":
            p = Path(db_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            self.db_path = str(p)
        else:
            self.db_path = ":memory:"

        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._apply_migrations()

    def _apply_migrations(self) -> None:
        """Run schema creation and version migrations."""
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                )
                """
            )
            cursor = self._conn.cursor()
            cursor.execute("SELECT MAX(version) FROM schema_migrations")
            row = cursor.fetchone()
            current_version = row[0] if row and row[0] is not None else 0

            if current_version < 1:
                self._conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS runs (
                        run_id TEXT PRIMARY KEY,
                        generated_at TEXT NOT NULL,
                        log_source TEXT NOT NULL,
                        total_lines INTEGER NOT NULL,
                        parsed_events INTEGER NOT NULL,
                        unparsed_lines INTEGER NOT NULL,
                        total_clusters INTEGER NOT NULL,
                        findings_count INTEGER NOT NULL,
                        stats_json TEXT NOT NULL
                    )
                    """
                )
                self._conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS findings (
                        id TEXT,
                        run_id TEXT NOT NULL,
                        rule_severity TEXT NOT NULL,
                        rule_ids_json TEXT NOT NULL,
                        cluster_ids_json TEXT NOT NULL,
                        llm_summary TEXT,
                        llm_attack_type TEXT,
                        llm_severity TEXT,
                        llm_confidence REAL,
                        llm_evidence_json TEXT,
                        llm_actions_json TEXT,
                        llm_fp_likelihood TEXT,
                        created_at TEXT NOT NULL,
                        PRIMARY KEY (run_id, id),
                        FOREIGN KEY (run_id) REFERENCES runs (run_id) ON DELETE CASCADE
                    )
                    """
                )
                self._conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS clusters (
                        id TEXT,
                        run_id TEXT NOT NULL,
                        template TEXT NOT NULL,
                        count INTEGER NOT NULL,
                        first_seen TEXT NOT NULL,
                        last_seen TEXT NOT NULL,
                        top_fields_json TEXT NOT NULL,
                        PRIMARY KEY (run_id, id),
                        FOREIGN KEY (run_id) REFERENCES runs (run_id) ON DELETE CASCADE
                    )
                    """
                )
                self._conn.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                    (1, datetime.now(UTC).isoformat()),
                )

    def save_run(self, report: Report, run_id: str | None = None) -> str:
        """Persist a complete Report run into SQLite."""
        actual_run_id = run_id or f"run-{uuid.uuid4().hex[:12]}"
        meta = report.metadata

        with self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO runs
                (run_id, generated_at, log_source, total_lines, parsed_events, unparsed_lines,
                 total_clusters, findings_count, stats_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    actual_run_id,
                    meta.generated_at.isoformat(),
                    meta.log_source,
                    meta.total_lines,
                    meta.parsed_events,
                    meta.unparsed_lines,
                    meta.total_clusters,
                    meta.findings_count,
                    json.dumps(report.stats),
                ),
            )

            # Insert findings
            for f in report.findings:
                llm = f.llm
                self._conn.execute(
                    """
                    INSERT OR REPLACE INTO findings
                    (id, run_id, rule_severity, rule_ids_json, cluster_ids_json,
                     llm_summary, llm_attack_type, llm_severity, llm_confidence,
                     llm_evidence_json, llm_actions_json, llm_fp_likelihood, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f.id,
                        actual_run_id,
                        f.rule_severity,
                        json.dumps(f.rule_ids),
                        json.dumps(f.cluster_ids),
                        llm.summary if llm else None,
                        llm.attack_type if llm else None,
                        llm.severity if llm else None,
                        llm.confidence if llm else None,
                        json.dumps(llm.evidence) if llm else None,
                        json.dumps(llm.recommended_actions) if llm else None,
                        llm.false_positive_likelihood if llm else None,
                        meta.generated_at.isoformat(),
                    ),
                )

            # Insert clusters
            for c in report.clusters:
                self._conn.execute(
                    """
                    INSERT OR REPLACE INTO clusters
                    (id, run_id, template, count, first_seen, last_seen, top_fields_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        c.id,
                        actual_run_id,
                        c.template,
                        c.count,
                        c.first_seen.isoformat(),
                        c.last_seen.isoformat(),
                        json.dumps(c.top_fields),
                    ),
                )

        return actual_run_id

    def get_run(self, run_id: str) -> Report | None:
        """Fetch a specific report by run ID."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,))
        run_row = cursor.fetchone()
        if not run_row:
            return None

        # Fetch findings
        cursor.execute("SELECT * FROM findings WHERE run_id = ?", (run_id,))
        finding_rows = cursor.fetchall()
        findings: list[Finding] = []
        for fr in finding_rows:
            llm_assessment = None
            if fr["llm_summary"]:
                llm_assessment = LLMAssessment(
                    summary=fr["llm_summary"],
                    attack_type=fr["llm_attack_type"],
                    severity=fr["llm_severity"],
                    confidence=fr["llm_confidence"],
                    evidence=json.loads(fr["llm_evidence_json"] or "[]"),
                    recommended_actions=json.loads(fr["llm_actions_json"] or "[]"),
                    false_positive_likelihood=fr["llm_fp_likelihood"] or "low",
                )
            findings.append(
                Finding(
                    id=fr["id"],
                    cluster_ids=json.loads(fr["cluster_ids_json"]),
                    rule_ids=json.loads(fr["rule_ids_json"]),
                    rule_severity=fr["rule_severity"],
                    llm=llm_assessment,
                )
            )

        # Fetch clusters
        cursor.execute("SELECT * FROM clusters WHERE run_id = ?", (run_id,))
        cluster_rows = cursor.fetchall()
        clusters: list[Cluster] = []
        for cr in cluster_rows:
            clusters.append(
                Cluster(
                    id=cr["id"],
                    template=cr["template"],
                    count=cr["count"],
                    first_seen=datetime.fromisoformat(cr["first_seen"]),
                    last_seen=datetime.fromisoformat(cr["last_seen"]),
                    top_fields=json.loads(cr["top_fields_json"]),
                )
            )

        metadata = ReportMetadata(
            generated_at=datetime.fromisoformat(run_row["generated_at"]),
            log_source=run_row["log_source"],
            total_lines=run_row["total_lines"],
            parsed_events=run_row["parsed_events"],
            unparsed_lines=run_row["unparsed_lines"],
            total_clusters=run_row["total_clusters"],
            findings_count=run_row["findings_count"],
        )

        return Report(
            metadata=metadata,
            findings=findings,
            clusters=clusters,
            stats=json.loads(run_row["stats_json"] or "{}"),
        )

    def list_runs(self, limit: int = 20) -> list[dict[str, Any]]:
        """List historical runs sorted by generated timestamp descending."""
        cursor = self._conn.cursor()
        cursor.execute(
            """
            SELECT run_id, generated_at, log_source, total_lines, parsed_events,
                   total_clusters, findings_count
            FROM runs
            ORDER BY generated_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [dict(r) for r in cursor.fetchall()]

    def get_findings_since(
        self,
        since_dt: datetime,
        min_severity: str | None = None,
    ) -> list[Finding]:
        """Query findings created since a specific datetime."""
        cursor = self._conn.cursor()
        cursor.execute(
            "SELECT * FROM findings WHERE created_at >= ? ORDER BY created_at DESC",
            (since_dt.isoformat(),),
        )
        rows = cursor.fetchall()

        findings: list[Finding] = []
        for fr in rows:
            llm_assessment = None
            if fr["llm_summary"]:
                llm_assessment = LLMAssessment(
                    summary=fr["llm_summary"],
                    attack_type=fr["llm_attack_type"],
                    severity=fr["llm_severity"],
                    confidence=fr["llm_confidence"],
                    evidence=json.loads(fr["llm_evidence_json"] or "[]"),
                    recommended_actions=json.loads(fr["llm_actions_json"] or "[]"),
                    false_positive_likelihood=fr["llm_fp_likelihood"] or "low",
                )
            findings.append(
                Finding(
                    id=fr["id"],
                    cluster_ids=json.loads(fr["cluster_ids_json"]),
                    rule_ids=json.loads(fr["rule_ids_json"]),
                    rule_severity=fr["rule_severity"],
                    llm=llm_assessment,
                )
            )

        if min_severity:
            sev_levels = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
            min_lvl = sev_levels.get(min_severity.lower(), 1)
            findings = [
                f for f in findings if sev_levels.get(f.rule_severity.lower(), 1) >= min_lvl
            ]

        return findings

    def close(self) -> None:
        """Close SQLite database connection."""
        self._conn.close()
