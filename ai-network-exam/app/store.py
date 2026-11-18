"""Plans and jobs as JSON files with atomic writes (tmp -> os.replace)."""
from __future__ import annotations

import json
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path

from .config import JOBS_DIR, PLANS_DIR

LOCK = threading.RLock()
_DIRS = {"plan": PLANS_DIR, "job": JOBS_DIR}
_ID_RE = re.compile(r"^[0-9a-f-]{32,36}$")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _path(kind: str, rec_id: str) -> Path:
    if not _ID_RE.match(rec_id or ""):
        raise KeyError(rec_id)
    return _DIRS[kind] / f"{rec_id}.json"


def load(kind: str, rec_id: str) -> dict | None:
    try:
        p = _path(kind, rec_id)
    except KeyError:
        return None
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


def save(kind: str, rec: dict) -> dict:
    rec["updated_at"] = now()
    p = _path(kind, rec["id"])
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(rec, indent=2), encoding="utf-8")
    os.replace(tmp, p)
    return rec


def list_all(kind: str) -> list[dict]:
    out = []
    for p in _DIRS[kind].glob("*.json"):
        try:
            out.append(json.loads(p.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            continue
    return sorted(out, key=lambda r: r.get("created_at", ""), reverse=True)
