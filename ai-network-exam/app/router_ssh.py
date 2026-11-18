"""Paramiko SSH to Cisco IOS 15.x (legacy algorithms). Credentials only from the environment."""
from __future__ import annotations

import re
import socket
import time

import paramiko

from . import config

PROMPT_RE = re.compile(r"^([A-Za-z0-9_.:/-]+)(?:\([^)]+\))?[>#]\s*$")
IOS_ERROR_RE = re.compile(
    r"^%\s*(Invalid input|Incomplete command|Ambiguous command|Authorization failed|Access denied"
    r"|.*overlaps with|.*not valid|Bad mask)", re.M)


class RouterError(Exception):
    pass


class LegacyCiscoTransport(paramiko.Transport):
    """IOS 15.2 only offers DH group14-sha1, ssh-rsa host keys and CBC ciphers (needs paramiko 3.x)."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        opts = self.get_security_options()
        opts.kex = ("diffie-hellman-group14-sha1",)
        opts.key_types = ("ssh-rsa",)
        opts.ciphers = ("aes128-cbc", "aes256-cbc")


class RouterSession:
    def __init__(self, name: str, host: str, client: paramiko.SSHClient, chan):
        self.name, self.host, self.client, self.chan = name, host, client, chan
        self.hostname = None

    # -- low level
    def _read_until_prompt(self, timeout: float) -> str:
        buf, end = "", time.time() + timeout
        while time.time() < end:
            if self.chan.recv_ready():
                buf += self.chan.recv(65535).decode("utf-8", errors="replace")
                last = buf.replace("\r", "").rstrip(" ").split("\n")[-1]
                m = PROMPT_RE.match(last)
                if m:
                    self.hostname = m.group(1)
                    return buf.replace("\r", "")
            elif self.chan.exit_status_ready() or self.chan.closed:
                raise RouterError(f"{self.name}: SSH channel closed by router")
            else:
                time.sleep(0.05)
        raise RouterError(f"{self.name}: timed out after {timeout:.0f}s waiting for prompt")

    def send(self, command: str, timeout: float = 30) -> str:
        self.chan.send(command + "\n")
        out = self._read_until_prompt(timeout)
        lines = out.split("\n")
        if lines and command.strip() in lines[0]:
            lines = lines[1:]  # drop echo
        return "\n".join(lines[:-1]).strip("\n")  # drop trailing prompt

    def send_config(self, commands: list[str], timeout: float = 30) -> tuple[str, list[str]]:
        """Send commands one by one; return transcript and IOS error lines."""
        transcript, errors = [], []
        for cmd in commands:
            out = self.send(cmd, timeout)
            transcript.append(f"{self.hostname}> {cmd}" + (f"\n{out}" if out else ""))
            for m in IOS_ERROR_RE.finditer(out):
                errors.append(f"'{cmd}': {m.group(0).strip()}")
        return "\n".join(transcript), errors

    def privilege(self) -> int | None:
        m = re.search(r"privilege level is (\d+)", self.send("show privilege"))
        return int(m.group(1)) if m else None

    def close(self):
        try:
            self.client.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def _client(trust_new: bool = False) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    if config.SSH_KNOWN_HOSTS.exists():
        client.load_host_keys(str(config.SSH_KNOWN_HOSTS))
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy() if trust_new else paramiko.RejectPolicy())
    return client


def connect_router(name: str, host: str, timeout: float | None = None, trust_new: bool = False) -> RouterSession:
    password = config.ssh_password()
    if not password:
        raise RouterError("SSH_PASSWORD is not set in .env")
    timeout = timeout or config.SSH_TIMEOUT
    client = _client(trust_new)
    try:
        client.connect(
            host, port=config.SSH_PORT, username=config.SSH_USERNAME, password=password,
            timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
            allow_agent=False, look_for_keys=False, transport_factory=LegacyCiscoTransport,
        )
    except paramiko.AuthenticationException:
        raise RouterError(f"{name} ({host}): authentication failed - check SSH_USERNAME/SSH_PASSWORD")
    except paramiko.BadHostKeyException:
        raise RouterError(f"{name} ({host}): host key changed - re-run lab/check_routers.py --trust")
    except paramiko.SSHException as e:
        if "not found in known_hosts" in str(e):
            raise RouterError(f"{name} ({host}): host key unknown - run lab/check_routers.py --trust")
        raise RouterError(f"{name} ({host}): SSH negotiation failed: {e}")
    except (socket.timeout, TimeoutError):
        raise RouterError(f"{name} ({host}): connection timed out")
    except OSError as e:
        raise RouterError(f"{name} ({host}): unreachable: {e}")
    if trust_new:
        config.SSH_KNOWN_HOSTS.parent.mkdir(parents=True, exist_ok=True)
        client.save_host_keys(str(config.SSH_KNOWN_HOSTS))
    chan = client.invoke_shell(width=250, height=1000)
    session = RouterSession(name, host, client, chan)
    try:
        session._read_until_prompt(timeout)
        session.send("terminal length 0")
        session.send("terminal width 250")
    except Exception:
        session.close()
        raise
    return session


def parse_ip_int_brief(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 6 or parts[0] == "Interface":
            continue
        status = " ".join(parts[4:-1])
        rows.append({"name": parts[0], "ip": None if parts[1] == "unassigned" else parts[1],
                     "status": status, "protocol": parts[-1]})
    return rows
