"""Central configuration. Everything lab-specific comes from .env, never from code."""
from __future__ import annotations

import os
import re
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

DATA_DIR = Path(os.getenv("DATA_DIR", str(BASE_DIR / "data")))
PLANS_DIR = DATA_DIR / "plans"
JOBS_DIR = DATA_DIR / "jobs"
UPLOADS_DIR = DATA_DIR / "uploads"
LOGS_DIR = DATA_DIR / "logs"
for _d in (PLANS_DIR, JOBS_DIR, UPLOADS_DIR, LOGS_DIR):
    _d.mkdir(parents=True, exist_ok=True)

GROQ_MODEL = os.getenv("GROQ_MODEL", "qwen/qwen3.8-27b")
GROQ_BASE_URL = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:39092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "network-config-jobs")
KAFKA_GROUP_ID = os.getenv("KAFKA_GROUP_ID", "ospf-config-workers")

SSH_USERNAME = os.getenv("SSH_USERNAME", "admin")
SSH_PORT = int(os.getenv("SSH_PORT", "22"))
SSH_TIMEOUT = float(os.getenv("SSH_TIMEOUT", "15"))
SSH_KNOWN_HOSTS = Path(os.getenv("SSH_KNOWN_HOSTS", str(DATA_DIR / "known_hosts")))

BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8000")
OSPF_VERIFY_TIMEOUT = int(os.getenv("OSPF_VERIFY_TIMEOUT", "120"))
JOB_STALE_SECONDS = int(os.getenv("JOB_STALE_SECONDS", "900"))


def ssh_password() -> str | None:
    return os.getenv("SSH_PASSWORD") or None


def groq_api_key() -> str | None:
    return os.getenv("GROQ_API_KEY") or None


# ---------------------------------------------------------------- interfaces
_PREFIXES = {
    "fastethernet": "FastEthernet", "fa": "FastEthernet", "f": "FastEthernet",
    "gigabitethernet": "GigabitEthernet", "gi": "GigabitEthernet", "g": "GigabitEthernet",
    "ethernet": "Ethernet", "eth": "Ethernet", "e": "Ethernet",
    "serial": "Serial", "se": "Serial", "s": "Serial",
    "loopback": "Loopback", "lo": "Loopback",
}


def expand_interface(name: str | None) -> str | None:
    """f0/0 / Fa0/0 / 'FastEthernet 0/0' -> FastEthernet0/0."""
    if name is None:
        return None
    s = re.sub(r"\s+", "", str(name))
    if not s:
        return None
    m = re.match(r"^([A-Za-z-]+)(\d+(?:/\d+)*(?:\.\d+)?)$", s)
    if not m:
        return s
    full = _PREFIXES.get(m.group(1).lower())
    return (full or m.group(1)) + m.group(2)


def _split(value: str | None) -> list[str]:
    return [expand_interface(v) for v in (value or "").split(",") if v.strip()]


def router_inventory() -> dict[str, dict]:
    """Routers known to the lab: ROUTERS=R1,R2 or every <NAME>_HOST variable matching R<n>."""
    names = [n.strip() for n in os.getenv("ROUTERS", "").split(",") if n.strip()]
    if not names:
        names = sorted(
            (m.group(1) for k in os.environ if (m := re.match(r"^(R\d+)_HOST$", k))),
            key=lambda n: int(n[1:]),
        )
    inv = {}
    for name in names:
        host = os.getenv(f"{name}_HOST")
        if not host:
            continue
        inv[name] = {
            "host": host,
            "management_interface": expand_interface(os.getenv(f"{name}_MANAGEMENT_INTERFACE")),
            "transit_interfaces": _split(os.getenv(f"{name}_TRANSIT_INTERFACE")),
            "lan_interfaces": _split(os.getenv(f"{name}_LAN_INTERFACE")),
        }
    return inv
