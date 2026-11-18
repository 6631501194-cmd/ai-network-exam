"""Turn a validated topology into per-router IOS commands (Jinja2 template)."""
from __future__ import annotations

import hashlib
import ipaddress
import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from .config import expand_interface

_ENV = Environment(
    loader=FileSystemLoader(str(Path(__file__).parent / "templates")),
    undefined=StrictUndefined, trim_blocks=True, lstrip_blocks=True, keep_trailing_newline=False,
)


def parse_cidr(value: str | None):
    """'10.0.0.1/24' -> IPv4Interface, or None if invalid."""
    if not value or "/" not in str(value):
        return None
    try:
        iface = ipaddress.IPv4Interface(str(value).strip())
    except ValueError:
        return None
    return iface


def area_str(area) -> str:
    return str(area).strip() if area is not None else ""


def generate(topology: dict, inventory: dict) -> dict:
    """Return {commands_by_router, devices, errors}. Never touches the management interface."""
    errors: list[str] = []
    pid = topology.get("ospf_process_id")
    area = area_str(topology.get("ospf_area"))
    if not isinstance(pid, int) or not (1 <= pid <= 65535):
        errors.append(f"OSPF process ID must be an integer 1-65535 (got {pid!r}).")
    if not area:
        errors.append("OSPF area is missing.")

    devices: dict[str, dict] = {}
    for router in topology.get("routers", []):
        name = router.get("name")
        inv = inventory.get(name)
        if not inv:
            errors.append(f"{name}: not in the lab inventory (.env {name}_HOST missing).")
            continue
        mgmt = inv.get("management_interface")
        data = []
        for itf in router.get("interfaces", []):
            role = itf.get("role")
            if role not in ("lan", "transit"):
                continue
            ifname = expand_interface(itf.get("name"))
            if not ifname:
                errors.append(f"{name}: a {role} interface has no physical interface name.")
                continue
            if mgmt and ifname == mgmt:
                errors.append(f"{name}: {ifname} is the management (SSH) interface and cannot be used as {role}.")
                continue
            ip = parse_cidr(itf.get("ipv4_cidr"))
            if ip is None:
                errors.append(f"{name} {ifname}: missing or invalid IPv4/prefix {itf.get('ipv4_cidr')!r}.")
                continue
            data.append({
                "name": ifname, "role": role, "cidr": str(ip), "ip": str(ip.ip),
                "mask": str(ip.netmask), "network": str(ip.network),
                "net_addr": str(ip.network.network_address), "wildcard": str(ip.network.hostmask),
            })
        data.sort(key=lambda d: 0 if d["role"] == "lan" else 1)  # LAN first, then transit
        networks = []
        for d in data:
            if d["network"] not in [n["network"] for n in networks]:
                networks.append({"network": d["network"], "net_addr": d["net_addr"], "wildcard": d["wildcard"]})
        devices[name] = {
            "host": inv["host"], "management_interface": mgmt,
            "router_id": router.get("router_id"), "data_interfaces": data,
            "networks": [n["network"] for n in networks], "_networks": networks,
        }

    # expected OSPF neighbours = routers sharing a transit subnet
    for name, dev in devices.items():
        mine = {d["network"] for d in dev["data_interfaces"] if d["role"] == "transit"}
        dev["expected_neighbors"] = sorted(
            {o["router_id"] for on, o in devices.items() if on != name and o["router_id"]
             and mine & {d["network"] for d in o["data_interfaces"] if d["role"] == "transit"}})
        others = set()
        for on, o in devices.items():
            if on != name:
                others.update(o["networks"])
        dev["remote_networks"] = sorted(others - set(dev["networks"]))

    commands: dict[str, list[str]] = {}
    if not errors:
        tpl = _ENV.get_template("router_ospf.j2")
        for name, dev in devices.items():
            text = tpl.render(
                pid=pid, area=area, router_id=dev["router_id"], interfaces=dev["data_interfaces"],
                passive=[d["name"] for d in dev["data_interfaces"] if d["role"] == "lan"],
                active=[d["name"] for d in dev["data_interfaces"] if d["role"] == "transit"],
                networks=dev["_networks"],
            )
            commands[name] = [ln.strip() for ln in text.splitlines() if ln.strip()]
    for dev in devices.values():
        dev.pop("_networks", None)
    return {"commands_by_router": commands, "devices": devices, "errors": errors,
            "ospf": {"process_id": pid, "area": area}}


def config_digest(commands_by_router: dict) -> str:
    blob = json.dumps(commands_by_router, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


def rollback_commands(device: dict, pid: int) -> list[str]:
    """Recovery: remove OSPF and reset data interfaces. Never touches management."""
    cmds = ["configure terminal", f"no router ospf {pid}"]
    for d in device.get("data_interfaces", []):
        if d["name"] == device.get("management_interface"):
            continue
        cmds += [f"default interface {d['name']}", f"interface {d['name']}", "shutdown", "exit"]
    cmds.append("end")
    return cmds
