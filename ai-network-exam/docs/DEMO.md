# Demo runbook
1. VMware: start GNS3 VM + Ubuntu VM. GNS3: open project **lab exam**, start all nodes.
2. Ubuntu: `cd ~/ai-network-exam && .venv/bin/python lab/check_routers.py && ./run.sh start`
3. Browser: `http://192.168.85.130:8000` → choose `lab/exam_topology.png` → **Generate** (screenshot: AI analysis)
4. **Discover router interfaces** → **Review commands** → **Validate** → tick confirmation → **Approve** → **Deploy**
5. `/jobs` → job PENDING → RUNNING → SUCCESS (screenshots: Kafka message, deployment status, OSPF checks)
6. Router consoles: `show ip ospf neighbor`, `show ip route ospf` (screenshots)
7. PC1 console: `ping 10.2.0.10` (screenshot)
8. Reset for another run: `.venv/bin/python worker.py --rollback latest`
