#!/usr/bin/env python3
"""Pre-demo check: SSH to every router in .env (legacy IOS algorithms).

  python lab/check_routers.py          verify host keys + login + privilege + interfaces
  python lab/check_routers.py --trust  first run / after a router IP or key change: store host keys
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app import config  # noqa: E402
from app.router_ssh import RouterError, connect_router  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--trust", action="store_true", help="accept and save unknown host keys")
args = ap.parse_args()
rc = 0
inv = config.router_inventory()
if not inv:
    print("no routers in .env (R1_HOST=...)")
    sys.exit(1)
for name, r in inv.items():
    try:
        with connect_router(name, r["host"], trust_new=args.trust) as s:
            print(f"== {name} {r['host']}: hostname={s.hostname} privilege={s.privilege()} "
                  f"(management {r['management_interface']}, transit {r['transit_interfaces']}, lan {r['lan_interfaces']})")
            print(s.send("show ip interface brief"))
            if s.hostname != name:
                print(f"!! hostname mismatch: expected {name}")
                rc = 1
    except RouterError as e:
        print(f"!! {name}: {e}")
        rc = 1
print(f"known_hosts file: {config.SSH_KNOWN_HOSTS}")
sys.exit(rc)
