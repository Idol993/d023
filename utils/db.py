import os
import sqlite3
import json
from datetime import datetime
from typing import Optional, List, Dict, Any


class Database:
    def __init__(self, config: dict):
        self.db_path = config.get("path", "./data/release_platform.db")
        db_dir = os.path.dirname(self.db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        self._conn: Optional[sqlite3.Connection] = None
        self._init_tables()

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
        return self._conn

    def _init_tables(self):
        conn = self._get_conn()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS release_records (
                release_id TEXT PRIMARY KEY,
                version TEXT NOT NULL,
                previous_version TEXT NOT NULL,
                release_type TEXT NOT NULL,
                status TEXT NOT NULL,
                applicant TEXT DEFAULT '',
                description TEXT DEFAULT '',
                pre_check_report TEXT,
                approval_flow TEXT,
                canary_stages TEXT,
                circuit_breaker_state TEXT DEFAULT 'closed',
                rollback_snapshot TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                completed_at TEXT
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                release_id TEXT NOT NULL,
                action TEXT NOT NULL,
                actor TEXT NOT NULL,
                details TEXT DEFAULT '{}',
                timestamp TEXT NOT NULL,
                electronic_signature TEXT DEFAULT '',
                FOREIGN KEY (release_id) REFERENCES release_records(release_id)
            );

            CREATE TABLE IF NOT EXISTS rollback_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                release_id TEXT NOT NULL,
                version TEXT NOT NULL,
                config_snapshot TEXT NOT NULL,
                created_at TEXT NOT NULL,
                checksum TEXT DEFAULT '',
                FOREIGN KEY (release_id) REFERENCES release_records(release_id)
            );

            CREATE INDEX IF NOT EXISTS idx_release_status ON release_records(status);
            CREATE INDEX IF NOT EXISTS idx_audit_release ON audit_logs(release_id);
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
        """
        )
        conn.commit()

    def save_release_record(self, record_data: Dict[str, Any]):
        conn = self._get_conn()
        existing = conn.execute(
            "SELECT release_id FROM release_records WHERE release_id = ?",
            (record_data["release_id"],),
        ).fetchone()

        serializable = {}
        for key, value in record_data.items():
            if isinstance(value, (dict, list)):
                serializable[key] = json.dumps(value, ensure_ascii=False)
            elif hasattr(value, "value"):
                serializable[key] = value.value
            else:
                serializable[key] = value

        if existing:
            set_clause = ", ".join(f"{k} = ?" for k in serializable if k != "release_id")
            values = [serializable[k] for k in serializable if k != "release_id"]
            values.append(record_data["release_id"])
            conn.execute(
                f"UPDATE release_records SET {set_clause} WHERE release_id = ?",
                values,
            )
        else:
            columns = ", ".join(serializable.keys())
            placeholders = ", ".join("?" for _ in serializable)
            conn.execute(
                f"INSERT INTO release_records ({columns}) VALUES ({placeholders})",
                list(serializable.values()),
            )
        conn.commit()

    def get_release_record(self, release_id: str) -> Optional[Dict[str, Any]]:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM release_records WHERE release_id = ?", (release_id,)
        ).fetchone()
        if row:
            return dict(row)
        return None

    def list_release_records(
        self, status: Optional[str] = None, limit: int = 50
    ) -> List[Dict[str, Any]]:
        conn = self._get_conn()
        if status:
            rows = conn.execute(
                "SELECT * FROM release_records WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                (status, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM release_records ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def add_audit_log(
        self,
        release_id: str,
        action: str,
        actor: str,
        details: Dict[str, Any],
        electronic_signature: str = "",
    ):
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO audit_logs (release_id, action, actor, details, timestamp, electronic_signature) VALUES (?, ?, ?, ?, ?, ?)",
            (
                release_id,
                action,
                actor,
                json.dumps(details, ensure_ascii=False),
                datetime.now().isoformat(),
                electronic_signature,
            ),
        )
        conn.commit()

    def get_audit_logs(
        self, release_id: Optional[str] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        conn = self._get_conn()
        if release_id:
            rows = conn.execute(
                "SELECT * FROM audit_logs WHERE release_id = ? ORDER BY timestamp DESC LIMIT ?",
                (release_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            if "details" in d and isinstance(d["details"], str) and d["details"]:
                try:
                    d["details"] = json.loads(d["details"])
                except (json.JSONDecodeError, TypeError):
                    pass
            results.append(d)
        return results

    def save_rollback_snapshot(
        self, release_id: str, version: str, config_snapshot: Dict[str, Any], checksum: str = ""
    ):
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO rollback_snapshots (release_id, version, config_snapshot, created_at, checksum) VALUES (?, ?, ?, ?, ?)",
            (
                release_id,
                version,
                json.dumps(config_snapshot, ensure_ascii=False),
                datetime.now().isoformat(),
                checksum,
            ),
        )
        conn.commit()

    def get_rollback_snapshot(self, release_id: str) -> Optional[Dict[str, Any]]:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM rollback_snapshots WHERE release_id = ? ORDER BY created_at DESC LIMIT 1",
            (release_id,),
        ).fetchone()
        if row:
            result = dict(row)
            result["config_snapshot"] = json.loads(result["config_snapshot"])
            return result
        return None

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None
