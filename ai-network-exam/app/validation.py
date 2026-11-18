"""Static + live (read-only SSH) validation of a topology plan."""
from __future__ import annotations

import ipaddress
from concurrent.futures import ThreadPoolExecutor

from . import config
from .config import expand_interface
from .ios import generate, parse_cidr
from .router_ssh import RouterError, connect_router, parse_ip_int_brief


def open_ambiguities(plan: dict) -> list[str]:
    resolved = {r["ambiguity"] for r in plan.get("resolved_ambiguities", [])}
    return [a for a in plan["topology"].get("ambiguities", []) if a not in resolved]


def _valid_ipv4(v) -> bool:
    try:
        ipaddress.IPv4Address(str(v))
        return True
    except ValueError:
        return False


def static_checks(plan: dict, inventory: dict) -> tuple[list[str], list[str], dict]:
    topo = plan["topology"]
    errors, warnings = [], []
    routers = topo.get("routers", [])
    router_names = {r["name"] for r in routers}
    if not routers:
        errors.append("No routers in the plan.")

    # ambiguities must be resolved explicitly by the admin
    for a in open_ambiguities(plan):
        errors.append(f"Unresolved ambiguity: {a}")

    # router IDs
    rids = {}
    for r in routers:
        rid = r.get("router_id")
        if not rid or not _valid_ipv4(rid):
            errors.append(f"{r['name']}: router ID {rid!r} is not a valid dotted IPv4 value.")
        elif rid in rids:
            errors.append(f"{r['name']}: router ID {rid} duplicates {rids[rid]}.")
        else:
            rids[rid] = r["name"]

    # interfaces, addressing
    all_ips: dict[str, str] = {}
    subnets: list[tuple[str, str, str, ipaddress.IPv4Network]] = []  # router, iface, role, net
    for r in routers:
        inv = inventory.get(r["name"], {})
        mgmt = inv.get("management_interface")
        names_seen = set()
        transit_count = 0
        for itf in r.get("interfaces", []):
            name = expand_interface(itf.get("name"))
            role = itf.get("role")
            if name in names_seen:
                errors.append(f"{r['name']}: interface {name} listed twice.")
            names_seen.add(name)
            if role == "management":
                if mgmt and name and name != mgmt:
                    warnings.append(f"{r['name']}: plan marks {name} as management but .env says {mgmt}.")
                if itf.get("ipv4_cidr"):
                    warnings.append(f"{r['name']}: management interface IP is ignored (never configured).")
                continue
            if role == "unknown":
                warnings.append(f"{r['name']} {name or '?'}: role unknown - interface will not be configured.")
                continue
            if role == "transit":
                transit_count += 1
            if name and mgmt and name == mgmt:
                errors.append(f"{r['name']}: {name} carries management SSH and cannot be used as {role}.")
            ip = parse_cidr(itf.get("ipv4_cidr"))
            if not ip:
                continue  # reported by generate()
            net = ip.network
            if net.prefixlen < 8 or net.prefixlen > 30:
                errors.append(f"{r['name']} {name}: prefix /{net.prefixlen} out of range (/8-/30).")
            elif ip.ip in (net.network_address, net.broadcast_address):
                errors.append(f"{r['name']} {name}: {ip.ip} is the network/broadcast address of {net}.")
            key = str(ip.ip)
            if key in all_ips:
                errors.append(f"Duplicate IP {key}: {all_ips[key]} and {r['name']} {name}.")
            all_ips[key] = f"{r['name']} {name}"
            subnets.append((r["name"], name, role, net))
        if len(routers) > 1 and transit_count == 0:
            errors.append(f"{r['name']}: no transit interface - no OSPF adjacency possible.")

    # subnet consistency
    for i, (ra, ia, rola, na) in enumerate(subnets):
        for rb, ib, rolb, nb in subnets[i + 1:]:
            if na != nb and na.overlaps(nb):
                errors.append(f"Overlapping subnets {na} ({ra} {ia}) and {nb} ({rb} {ib}).")
            elif na == nb:
                if ra == rb:
                    errors.append(f"{ra}: {ia} and {ib} are in the same subnet {na}.")
                elif rola == "lan" or rolb == "lan":
                    errors.append(f"Subnet {na} is used on {ra} {ia} ({rola}) and {rb} {ib} ({rolb}); "
                                  "a LAN subnet must be unique to one router.")

    # links
    iface_index = {(r["name"], expand_interface(i.get("name"))): i for r in routers for i in r.get("interfaces", [])}
    linked_transit = set()
    for link in topo.get("links", []):
        a, b = link.get("device_a"), link.get("device_b")
        if a in router_names and b in router_names:
            ia = iface_index.get((a, expand_interface(link.get("interface_a"))))
            ib = iface_index.get((b, expand_interface(link.get("interface_b"))))
            if not ia or not ib:
                errors.append(f"Link {a} {link.get('interface_a')} - {b} {link.get('interface_b')}: "
                              "interface not found in the router tables.")
                continue
            if ia.get("role") != "transit" or ib.get("role") != "transit":
                errors.append(f"Link {a}-{b}: router-to-router interfaces must have role transit.")
            pa, pb = parse_cidr(ia.get("ipv4_cidr")), parse_cidr(ib.get("ipv4_cidr"))
            if pa and pb and pa.network != pb.network:
                errors.append(f"Link {a} {ia['name']} ({pa}) - {b} {ib['name']} ({pb}): not in the same subnet.")
            linked_transit.add((a, expand_interface(ia.get("name"))))
            linked_transit.add((b, expand_interface(ib.get("name"))))
    for rname, iname, role, _ in subnets:
        if role == "transit" and (rname, iname) not in linked_transit:
            errors.append(f"{rname} {iname}: transit interface is not linked to another router.")

    # PCs are optional; when present their values must be consistent
    lan_by_net = {net: (rn, inm, None) for rn, inm, role, net in subnets if role == "lan"}
    lan_ip = {}
    for r in routers:
        for itf in r.get("interfaces", []):
            p = parse_cidr(itf.get("ipv4_cidr"))
            if itf.get("role") == "lan" and p:
                lan_ip[p.network] = str(p.ip)
    for pc in topo.get("pcs", []):
        p = parse_cidr(pc.get("ipv4_cidr"))
        if not pc.get("ipv4_cidr"):
            warnings.append(f"{pc['name']}: no address in plan (PCs are configured by hand on VPCS).")
            continue
        if not p:
            errors.append(f"{pc['name']}: invalid IPv4/prefix {pc.get('ipv4_cidr')!r}.")
            continue
        if p.network not in lan_by_net:
            errors.append(f"{pc['name']} {p}: not inside any router LAN subnet.")
            continue
        if str(p.ip) in all_ips:
            errors.append(f"{pc['name']}: IP {p.ip} duplicates {all_ips[str(p.ip)]}.")
        gw = pc.get("gateway")
        if gw and gw != lan_ip.get(p.network):
            errors.append(f"{pc['name']}: gateway {gw} is not the router LAN IP {lan_ip.get(p.network)}.")
        elif not gw:
            warnings.append(f"{pc['name']}: no gateway in plan (expected {lan_ip.get(p.network)}).")

    gen = generate(topo, inventory)
    errors.extend(gen["errors"])
    if gen["ospf"]["area"] not in ("0", "0.0.0.0"):
        warnings.append(f"OSPF area {gen['ospf']['area']} - the course policy is area 0.")
    return errors, warnings, gen


def _live_one(name: str, inv: dict, dev: dict | None) -> dict:
    res = {"router": name, "host": inv["host"], "reachable": False, "errors": [], "warnings": []}
    try:
        with connect_router(name, inv["host"]) as s:
            res["reachable"] = True
            res["hostname"] = s.hostname
            if s.hostname != name:
                res["errors"].append(f"{name}: device at {inv['host']} reports hostname {s.hostname}.")
            priv = s.privilege()
            res["privilege"] = priv
            if priv != 15:
                res["errors"].append(f"{name}: SSH user has privilege {priv}, 15 required.")
            rows = parse_ip_int_brief(s.send("show ip interface brief"))
            res["interfaces"] = rows
    except RouterError as e:
        res["errors"].append(str(e))
        return res
    names = {r["name"] for r in rows}
    ssh_if = next((r["name"] for r in rows if r["ip"] == inv["host"]), None)
    res["ssh_interface"] = ssh_if
    mgmt = inv.get("management_interface")
    if ssh_if and mgmt and ssh_if != mgmt:
        res["errors"].append(f"{name}: SSH arrives on {ssh_if} but .env says management is {mgmt}.")
    for d in (dev or {}).get("data_interfaces", []):
        if d["name"] not in names:
            res["errors"].append(f"{name}: interface {d['name']} does not exist on the router.")
        if d["name"] in (ssh_if, mgmt):
            res["errors"].append(f"{name}: {d['name']} carries management SSH - refusing to configure it.")
        net = ipaddress.IPv4Network(d["network"])
        for r in rows:
            if r["name"] != d["name"] and r["ip"] and ipaddress.IPv4Address(r["ip"]) in net:
                res["errors"].append(f"{name}: {r['name']} already has {r['ip']} in {net}; "
                                     f"assigning it to {d['name']} would overlap.")
    return res


def live_checks(router_names: list[str], inventory: dict, gen: dict) -> dict:
    with ThreadPoolExecutor(max_workers=max(1, len(router_names))) as pool:
        futs = {n: pool.submit(_live_one, n, inventory[n], gen["devices"].get(n))
                for n in router_names if n in inventory}
        return {n: f.result() for n, f in futs.items()}


def validate_plan(plan: dict, live: bool = True) -> dict:
    inventory = config.router_inventory()
    errors, warnings, gen = static_checks(plan, inventory)
    result = {"static_errors": list(errors), "warnings": warnings, "live": {}}
    if live:
        names = [r["name"] for r in plan["topology"].get("routers", [])]
        result["live"] = live_checks(names, inventory, gen)
        for r in result["live"].values():
            errors.extend(r["errors"])
            warnings.extend(r["warnings"])
    result["errors"] = errors
    result["passed"] = not errors and bool(gen["commands_by_router"])
    result["commands_by_router"] = gen["commands_by_router"]
    return result


def discover_interfaces(router_names: list[str]) -> dict:
    inventory = config.router_inventory()
    out = {}
    for n in router_names:
        if n not in inventory:
            out[n] = {"error": f"{n} not in .env inventory"}
            continue
        r = _live_one(n, inventory[n], None)
        if not r["reachable"]:
            out[n] = {"error": "; ".join(r["errors"])}
            continue
        out[n] = {"host": r["host"], "hostname": r.get("hostname"), "ssh_interface": r.get("ssh_interface"),
                  "management_interface": inventory[n].get("management_interface"),
                  "interfaces": [dict(i, carries_ssh=(i["name"] == r.get("ssh_interface"))) for i in r["interfaces"]]}
    return out
