"""Bounded local storage for analysis results (SQLite, standard library).

Only the newest ``max_stored_analyses`` rows are kept, so disk usage is bounded.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Optional

from backend.config import settings
from backend.models import DiscoveryResult


class AnalysisStore:
    def __init__(self, db_path: Optional[Path] = None, max_items: Optional[int] = None) -> None:
        self.db_path = Path(db_path) if db_path else settings.db_path
        self.max_items = max_items or settings.max_stored_analyses
        self._lock = threading.Lock()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.execute("""CREATE TABLE IF NOT EXISTS analyses (
                id TEXT PRIMARY KEY, created_at TEXT NOT NULL, result TEXT NOT NULL, sbom TEXT)""")

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def save(self, result: DiscoveryResult, sbom: Optional[dict[str, Any]]) -> None:
        with self._lock, self._conn() as c:
            c.execute("INSERT OR REPLACE INTO analyses (id, created_at, result, sbom) VALUES (?,?,?,?)",
                      (result.analysis_id, result.created_at.isoformat(), result.model_dump_json(),
                       json.dumps(sbom) if sbom else None))
            c.execute("DELETE FROM analyses WHERE id NOT IN (SELECT id FROM analyses ORDER BY created_at DESC LIMIT ?)",
                      (self.max_items,))

    def get(self, analysis_id: str) -> Optional[DiscoveryResult]:
        with self._conn() as c:
            row = c.execute("SELECT result FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
        return DiscoveryResult.model_validate_json(row["result"]) if row else None

    def get_sbom(self, analysis_id: str) -> Optional[dict[str, Any]]:
        with self._conn() as c:
            row = c.execute("SELECT sbom FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
        return json.loads(row["sbom"]) if row and row["sbom"] else None

    def count(self) -> int:
        with self._conn() as c:
            return c.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
