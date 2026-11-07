"""Thread-safe, persistent scan history stored on the local device."""

from __future__ import annotations

import json
import threading
from pathlib import Path


class HistoryManager:
    def __init__(self, file_path: Path, limit: int = 50) -> None:
        self.file_path = Path(file_path)
        self.limit = limit
        self._lock = threading.RLock()
        self._records = self._load()

    def _load(self) -> list[dict]:
        try:
            data = json.loads(self.file_path.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else []
        except (OSError, json.JSONDecodeError):
            return []

    def _save(self) -> None:
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.file_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self._records, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
        temporary.replace(self.file_path)

    def add(self, job) -> dict:
        state = job.snapshot()
        record = {
            "id": job.id,
            "status": state["status"],
            "targetSpec": state.get("targetSpec") or state["targets"],
            "ports": state["ports"],
            "total": state["total"],
            "completed": state["completed"],
            "online": state["online"],
            "openPorts": state["openPorts"],
            "elapsed": state["elapsed"],
            "error": state["error"],
            "createdAt": job.created_at,
            "finishedAt": job.finished_at,
            "results": state["results"],
        }
        with self._lock:
            self._records = [item for item in self._records if item.get("id") != record["id"]]
            self._records.insert(0, record)
            self._records = self._records[:self.limit]
            self._save()
        return record

    def list(self) -> list[dict]:
        with self._lock:
            return [{key: value for key, value in record.items() if key != "results"}
                    for record in self._records]

    def get(self, record_id: str) -> dict | None:
        with self._lock:
            return next((record for record in self._records if record.get("id") == record_id), None)

    def delete(self, record_id: str) -> bool:
        with self._lock:
            remaining = [record for record in self._records if record.get("id") != record_id]
            if len(remaining) == len(self._records):
                return False
            self._records = remaining
            self._save()
            return True

    def clear(self) -> int:
        with self._lock:
            count = len(self._records)
            self._records = []
            self._save()
            return count
