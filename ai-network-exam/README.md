# AI Network Automation — OSPF

Upload a topology diagram → AI (Groq, image model) extracts a structured topology → admin reviews and
resolves ambiguities → IOS/OSPF config is generated from a Jinja2 template → static + live (read-only SSH)
validation → explicit approval → Kafka job → Python worker deploys over Paramiko → automatic OSPF verification.

```
Browser (/ , /jobs) ─► FastAPI backend (app/main.py) ─► Kafka topic network-config-jobs ─► worker.py ─► R1/R2 (SSH)
                         plans/jobs as JSON in data/        (IDs + config hash only)        claims job via backend
```

| Path | Purpose |
|---|---|
| `app/main.py` | API, approval gate, Kafka producer, job claim/progress |
| `app/ai.py` | Diagram → JSON (AI reads only); deterministic mapping to lab interfaces |
| `app/ios.py`, `app/templates/router_ospf.j2` | Config generation (config template) |
| `app/validation.py` | Addressing, subnets, interface mapping, OSPF, management protection, live checks |
| `app/router_ssh.py` | Paramiko with IOS 15.2 legacy algorithms (paramiko 3.5.1) |
| `worker.py` | Kafka consumer, deploy, verify, `--rollback` recovery |
| `compose.yaml` | Kafka 4.1.2 (KRaft) on 127.0.0.1:39092 |
| `run.sh` | `start / stop / restart / status` |
| `lab/check_routers.py` | Pre-demo SSH check, `--trust` stores router host keys |

## Setup (Ubuntu VM)
```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env && chmod 600 .env    # fill GROQ_API_KEY, SSH_PASSWORD, router hosts/interfaces
.venv/bin/python lab/check_routers.py --trust
./run.sh start                            # http://<vm-ip>:8000  and  /jobs
```

## Lab inventory (.env)
Physical interface roles per router (`R<n>_HOST`, `_MANAGEMENT_INTERFACE`, `_TRANSIT_INTERFACE`, `_LAN_INTERFACE`).
Names only — all addressing comes from the diagram or the admin. The management interface is never configured;
validation rejects any plan that would touch it.

## Security
- Secrets only in `.env` (git-ignored, chmod 600); never in Kafka messages, logs or job records.
- AI never connects to routers; approval (typed `APPROVE` + re-validation) is mandatory before deploy.
- Worker re-checks approval and config hash with the backend (`/claim`); a job runs at most once.
- No static routes; verification fails if any `S` route exists.

## Recovery
`.venv/bin/python worker.py --rollback latest` removes OSPF and resets the data interfaces (management untouched).
Failed jobs can be revoked in `/jobs`, which un-approves the plan.

## Lab used for testing
GNS3 2.2 with two Cisco c7200 routers (IOS 15.2(4)S5, C7200-IO-FE + PA-2FE-TX) and two VPCS hosts:

| Router | LAN | R1–R2 link | Management (SSH, never configured) |
|---|---|---|---|
| R1 | FastEthernet0/0 | FastEthernet1/1 | FastEthernet1/0 → switch → GNS3 Cloud (VMware NAT) |
| R2 | FastEthernet0/0 | FastEthernet1/1 | FastEthernet1/0 → switch → GNS3 Cloud (VMware NAT) |

The backend, worker and Kafka run on an Ubuntu VM on the same VMware network as the management interfaces.
A different lab only needs a different `.env`.

## Test diagrams (`lab/`)
| File | Purpose |
|---|---|
| `exam_topology.png` | Exam topology (10.0.0.0/24, 10.1.0.0/24, 10.2.0.0/24, OSPF 1, IDs 1.1.1.1 / 2.2.2.2) |
| `alt_topology.png` | Alternative addressing: 192.168.10.0/24, 172.16.12.0/30, 192.168.20.0/24, OSPF 10, custom router IDs |
| `gns3_screenshot_no_ips.png` | Interface labels but no IP addresses: every missing IP is flagged and must be resolved in the editor |

## Verified results (exam topology)
- AI analysis: all addresses, links and PCs extracted, no ambiguities; generated commands match the template.
- Validation passed live (reachability, hostname, privilege 15, interfaces exist, management protected).
- Deploy without approval and with a wrong confirmation word were rejected.
- Job PENDING → RUNNING → SUCCESS in under a minute; OSPF neighbour FULL on both routers, remote LAN learned
  via OSPF, no static routes, router IDs correct.
- PC1 `ping 10.2.0.10`: 5/5 replies, TTL 62.
- Replaying the same Kafka message: "Job is SUCCESS; it will not be executed again".
- `worker.py --rollback latest`: data interfaces reset, management interface still up.
