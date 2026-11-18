#!/usr/bin/env python3
"""Kafka worker: claim job (backend re-checks approval) -> SSH deploy -> verify OSPF -> report.

  python worker.py                     consume network-config-jobs forever
  python worker.py --rollback latest   recovery: remove OSPF + reset data interfaces of the last plan
  python worker.py --rollback <plan_id>
"""
from __future__ import annotations

import argparse
import fcntl
import json
import logging
import re
import socket
import sys
import time
import uuid

import requests
from kafka import KafkaConsumer, TopicPartition

from app import config
from app.ios import config_digest, rollback_commands
from app.router_ssh import RouterError, connect_router

log = logging.getLogger("worker")
WORKER_ID = f"{socket.gethostname()}-{uuid.uuid4().hex[:6]}"
API = config.BACKEND_URL.rstrip("/")
REQUIRED = ("job_id", "plan_id", "device_ids", "config_sha256", "approved_config_ref")


class JobFailed(Exception):
    pass


def api(method: str, path: str, **kw):
    return requests.request(method, API + path, timeout=30, **kw)


def report(job_id, status, stage, device=None, message=None, **extra):
    body = {"status": status, "stage": stage, "device": device, "message": message, **extra}
    try:
        r = api("POST", f"/api/jobs/{job_id}/progress", json=body)
        if r.status_code != 200:
            log.warning("progress %s rejected: %s %s", stage, r.status_code, r.text[:200])
    except requests.RequestException as e:
        log.error("progress %s not delivered: %s", stage, e)
    log.info("[%s] %s %s %s", job_id[:8], status, stage, message or "")


# ---------------------------------------------------------------- deploy
def deploy_router(name: str, host: str, commands: list[str]) -> dict:
    with connect_router(name, host) as s:
        if s.hostname != name:
            raise JobFailed(f"{name}: device at {host} is {s.hostname}, refusing to configure")
        if s.privilege() != 15:
            raise JobFailed(f"{name}: SSH user is not privilege 15")
        backup = s.send("show running-config", timeout=60)
        transcript, errors = s.send_config(commands, timeout=30)
    result = {"host": host, "commands": commands, "backup_running_config": backup,
              "configuration_output": transcript, "ios_errors": errors}
    if errors:
        raise JobFailed(f"{name}: IOS rejected commands: {'; '.join(errors)}") from None
    return result


# ---------------------------------------------------------------- verification
def _check(name: str, dev: dict, ospf: dict, pcs_remote: list[dict], s) -> dict:
    nbr = s.send("show ip ospf neighbor")
    routes = s.send("show ip route ospf")
    protos = s.send("show ip protocols")
    full_route = s.send("show ip route")
    expected_nbrs = dev.get("expected_neighbors", [])
    nbr_state = {rid: any(ln.split()[0] == rid and "FULL" in ln for ln in nbr.splitlines() if ln.split())
                 for rid in expected_nbrs}
    o_lines = [ln for ln in routes.splitlines() if re.match(r"^\s*O", ln)]
    missing = []
    for net in dev.get("remote_networks", []):
        addr = net.split("/")[0]
        if not any(re.search(rf"(?<![\d.]){re.escape(addr)}(?![\d])", ln) for ln in o_lines):
            missing.append(net)
    pid = ospf["process_id"]
    static = [ln.strip() for ln in full_route.splitlines() if re.match(r"^S\s", ln)]  # S* (DHCP default) ok
    res = {
        "neighbor_full": all(nbr_state.values()) if expected_nbrs else True,
        "neighbors_expected": expected_nbrs, "neighbor_state": nbr_state,
        "remote_networks_expected": dev.get("remote_networks", []), "remote_networks_missing": missing,
        "ospf_process_ok": f'"ospf {pid}"' in protos,
        "router_id_ok": bool(re.search(rf"Router ID {re.escape(str(dev['router_id']))}\b", protos)),
        "static_routes_found": static,
        "show_ip_ospf_neighbor": nbr, "show_ip_route_ospf": routes, "show_ip_protocols": protos,
    }
    problems = []
    if not res["neighbor_full"]:
        problems.append(f"OSPF neighbours not FULL: {[k for k, v in nbr_state.items() if not v]}")
    if missing:
        problems.append(f"remote networks not learned via OSPF: {missing}")
    if not res["ospf_process_ok"]:
        problems.append(f"ospf {pid} not running")
    if not res["router_id_ok"]:
        problems.append(f"router ID is not {dev['router_id']}")
    if static:
        problems.append(f"static routes present: {static}")
    res["problems"] = problems
    res["passed"] = not problems
    return res


def verify_router(name: str, dev: dict, ospf: dict, pcs_remote: list[dict]) -> dict:
    deadline = time.time() + config.OSPF_VERIFY_TIMEOUT
    with connect_router(name, dev["host"]) as s:
        while True:
            res = _check(name, dev, ospf, pcs_remote, s)
            if res["passed"] or time.time() > deadline:
                break
            time.sleep(10)
        pings = {}
        for pc in pcs_remote:   # informational: VPCS are configured by hand
            out = s.send(f"ping {pc['ip']} repeat 3 timeout 1", timeout=20)
            m = re.search(r"Success rate is (\d+) percent", out)
            pings[pc["name"]] = {"ip": pc["ip"], "success_percent": int(m.group(1)) if m else 0}
        res["ping_remote_pcs"] = pings
    return res


# ---------------------------------------------------------------- job
def handle(msg: dict) -> None:
    if not isinstance(msg, dict) or any(k not in msg for k in REQUIRED):
        log.error("malformed message ignored: %s", str(msg)[:200])
        return
    job_id = msg["job_id"]
    r = api("POST", f"/api/jobs/{job_id}/claim", json={"config_sha256": msg["config_sha256"], "worker_id": WORKER_ID})
    if r.status_code != 200:
        detail = r.json().get("detail") if r.headers.get("content-type", "").startswith("application/json") else r.text
        log.warning("[%s] not executed: %s", job_id[:8], detail)
        return
    log.info("[%s] claimed (approval re-checked by backend)", job_id[:8])
    try:
        r = api("GET", msg["approved_config_ref"])
        if r.status_code != 200:
            raise JobFailed(f"approved configuration not available: {r.text[:200]}")
        ac = r.json()
        if config_digest(ac["commands_by_router"]) != msg["config_sha256"]:
            raise JobFailed("approved configuration hash mismatch")
        unknown = [d for d in msg["device_ids"] if d not in ac["commands_by_router"]]
        if unknown:
            raise JobFailed(f"devices not in approved configuration: {unknown}")
        inventory = config.router_inventory()
        for dev in msg["device_ids"]:
            if dev not in inventory:
                raise JobFailed(f"{dev} not in worker inventory (.env)")
            ac["devices"][dev]["host"] = inventory[dev]["host"]   # worker trusts its own inventory

        for dev in msg["device_ids"]:
            report(job_id, "RUNNING", "deploying", dev, f"SSH {inventory[dev]['host']}, pushing configuration")
            try:
                res = deploy_router(dev, inventory[dev]["host"], ac["commands_by_router"][dev])
            except RouterError as e:
                raise JobFailed(str(e))
            report(job_id, "RUNNING", "deployed", dev, "configuration applied", router_results={dev: res})

        report(job_id, "RUNNING", "verifying", None, f"waiting up to {config.OSPF_VERIFY_TIMEOUT}s for OSPF")
        verification, ok = {}, True
        for dev in msg["device_ids"]:
            mine = {d["network"] for d in ac["devices"][dev]["data_interfaces"]}
            remote_pcs = [p for p in ac.get("pcs", []) if not any(_in(p["ip"], n) for n in mine)]
            try:
                v = verify_router(dev, ac["devices"][dev], ac["ospf"], remote_pcs)
            except RouterError as e:
                v = {"passed": False, "problems": [str(e)]}
            verification[dev] = v
            ok &= v["passed"]
            report(job_id, "RUNNING", "verified", dev, "passed" if v["passed"] else "; ".join(v["problems"]),
                   verification={dev: v})
        if ok:
            report(job_id, "SUCCESS", "done", None, "deployment and OSPF verification passed")
        else:
            report(job_id, "FAILED", "verification", None, "OSPF verification failed",
                   error="; ".join(f"{d}: {', '.join(v['problems'])}" for d, v in verification.items() if not v["passed"]))
    except JobFailed as e:
        report(job_id, "FAILED", "deploying", None, str(e), error=str(e))
    except Exception as e:  # never leave a job RUNNING
        log.exception("unexpected error")
        report(job_id, "FAILED", "error", None, str(e), error=f"worker error: {e}")


def _in(ip: str, net: str) -> bool:
    import ipaddress
    return ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(net)


# ---------------------------------------------------------------- rollback
def rollback(plan_ref: str) -> int:
    if plan_ref == "latest":
        plans = [p for p in api("GET", "/api/plans").json() if p.get("deployment_status") not in (None, "NOT_DEPLOYED")]
        if not plans:
            print("no deployed plan found")
            return 1
        plan_ref = plans[0]["id"]
    plan = api("GET", f"/api/plans/{plan_ref}").json()
    devices = (plan.get("approved_config") or {}).get("devices") or {}
    if not devices:  # revoked plan: regenerate the device list from its topology
        from app.ios import generate
        devices = generate(plan["topology"], config.router_inventory())["devices"]
    pid = plan["topology"].get("ospf_process_id") or 1
    inventory = config.router_inventory()
    rc = 0
    for name, dev in devices.items():
        cmds = rollback_commands(dict(dev, management_interface=inventory[name]["management_interface"]), pid)
        print(f"--- {name} ({inventory[name]['host']}): {cmds}")
        try:
            with connect_router(name, inventory[name]["host"]) as s:
                if s.hostname != name:
                    raise RouterError(f"hostname is {s.hostname}")
                out, errs = s.send_config(cmds)
                print(out)
                print(s.send("show ip interface brief"))
                if errs:
                    rc = 1
        except RouterError as e:
            print(f"{name}: {e}")
            rc = 1
    return rc


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rollback", metavar="PLAN_ID|latest")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s",
                        stream=sys.stdout)
    if args.rollback:
        return rollback(args.rollback)

    lock = open(config.DATA_DIR / "worker.lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        log.error("another worker is already running")
        return 1
    consumer = KafkaConsumer(
        config.KAFKA_TOPIC, bootstrap_servers=config.KAFKA_BOOTSTRAP_SERVERS, group_id=config.KAFKA_GROUP_ID,
        enable_auto_commit=False, auto_offset_reset="earliest", max_poll_records=1,
        max_poll_interval_ms=1_800_000,
        value_deserializer=lambda b: json.loads(b.decode("utf-8")) if b else None,
    )
    log.info("worker %s consuming %s on %s", WORKER_ID, config.KAFKA_TOPIC, config.KAFKA_BOOTSTRAP_SERVERS)
    for record in consumer:
        log.info("message partition=%s offset=%s key=%s", record.partition, record.offset,
                 record.key.decode() if record.key else None)
        try:
            handle(record.value)
        except requests.RequestException as e:
            log.error("backend unreachable, message will be retried: %s", e)
            time.sleep(5)
            consumer.seek(TopicPartition(record.topic, record.partition), record.offset)
            continue
        consumer.commit()
    return 0


if __name__ == "__main__":
    sys.exit(main())
