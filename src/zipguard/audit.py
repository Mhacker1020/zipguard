"""Audit logging — records every extraction decision."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Decision(str, Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    RENAMED = "renamed"
    SKIPPED = "skipped"   # directories


@dataclass
class EntryResult:
    name: str
    decision: Decision
    reason: str = ""
    dest: str = ""
    sha256: str = ""
    file_size: int = 0


@dataclass
class ExtractionReport:
    archive: str
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    entries: list[EntryResult] = field(default_factory=list)
    aborted: bool = False
    abort_reason: str = ""

    def add(self, result: EntryResult) -> None:
        self.entries.append(result)

    def finish(self) -> None:
        self.finished_at = time.time()

    def abort(self, reason: str) -> None:
        self.aborted = True
        self.abort_reason = reason
        self.finished_at = time.time()

    @property
    def allowed_count(self) -> int:
        return sum(1 for e in self.entries if e.decision == Decision.ALLOWED)

    @property
    def blocked_count(self) -> int:
        return sum(1 for e in self.entries if e.decision == Decision.BLOCKED)

    @property
    def renamed_count(self) -> int:
        return sum(1 for e in self.entries if e.decision == Decision.RENAMED)

    def to_dict(self) -> dict:
        return {
            "archive": self.archive,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_sec": round(self.finished_at - self.started_at, 3),
            "aborted": self.aborted,
            "abort_reason": self.abort_reason,
            "summary": {
                "total": len(self.entries),
                "allowed": self.allowed_count,
                "blocked": self.blocked_count,
                "renamed": self.renamed_count,
            },
            "entries": [
                {
                    "name": e.name,
                    "decision": e.decision.value,
                    "reason": e.reason,
                    "dest": e.dest,
                    "sha256": e.sha256,
                    "file_size": e.file_size,
                }
                for e in self.entries
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def save(self, path: Path) -> None:
        path.write_text(self.to_json(), encoding="utf-8")
