"""FastAPI backend: analyze -> resolve -> review -> validate -> approve -> deploy (Kafka) -> monitor."""
from __future__ import annotations

import io
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse
from PIL import Image

from . import config, store
from .ai import AIError, analyze_image
from .config import expand_interface
from .ios import config_digest, generate
from .models import Approval, Claim, Progress, TopologyEdit
from .validation import discover_interfaces, open_ambiguities, static_checks, validate_plan

log = logging.getLogger("backend")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
app = FastAPI(title="AI Network Automation (OSPF)")
STATIC = Path(__file__).parent / "static"
MAX_BYTES, MAX_PIXELS = 5 * 1024 * 1024, 20_000_000
EDITABLE = ("DRAFT", "REVOKED")

_producer = None


def producer():
    global _producer
    if _producer is None:
        from kafka import KafkaProducer
        _producer = KafkaProducer(
            bootstrap_servers=config.KAFKA_BOOTSTRAP_SERVERS, acks="all", retries=3,
            value_serializer=lambda v: json.dumps(v).encode(), key_serializer=lambda k: k.encode(),
            request_timeout_ms=10000, max_block_ms=10000,
        )
    return _producer


def _plan(plan_id: str) -> dict:
    plan = store.load("plan", plan_id)
    if not plan:
        raise HTTPException(404, "plan not found")
    return plan


def _job(job_id: str) -> dict:
    job = store.load("job", job_id)
    if not job:
        raise HTTPException(404, "job not found")
    return job


def _history(job: dict, status: str, stage: str, device=None, message=None):
    job.setdefault("history", []).append(
        {"at": store.now(), "status": status, "stage": stage, "device": device, "message": message})


# ---------------------------------------------------------------- pages
@app.get("/", response_class=HTMLResponse)
def index():
    return (STATIC / "index.html").read_text(encoding="utf-8")


@app.get("/jobs", response_class=HTMLResponse)
def jobs_page():
    return (STATIC / "jobs.html").read_text(encoding="utf-8")


@app.get("/health")
def health():
    return {"status": "ok", "model": config.GROQ_MODEL, "topic": config.KAFKA_TOPIC,
            "routers": {k: {"host": v["host"], "management_interface": v["management_interface"]}
                        for k, v in config.router_inventory().items()},
            "groq_key_set": bool(config.groq_api_key()), "ssh_password_set": bool(config.ssh_password())}


# ---------------------------------------------------------------- AI analysis
@app.post("/api/analyze")
async def analyze(image: UploadFile = File(...)):
    data = await image.read()
    if len(data) > MAX_BYTES:
        raise HTTPException(413, "image larger than 5 MB")
    try:
        im = Image.open(io.BytesIO(data))
        fmt = im.format
        im.verify()
    except Exception:
        raise HTTPException(415, "not a valid image")
    if fmt not in ("PNG", "JPEG"):
        raise HTTPException(415, "only PNG or JPEG")
    w, h = Image.open(io.BytesIO(data)).size
    if w * h > MAX_PIXELS:
        raise HTTPException(413, "image larger than 20 megapixels")
    mime = "image/png" if fmt == "PNG" else "image/jpeg"
    inventory = config.router_inventory()
    try:
        ai_plan, mapped, raw = analyze_image(data, mime, inventory)
    except AIError as e:
        raise HTTPException(e.status, str(e))
    plan_id = uuid.uuid4().hex
    ext = "png" if fmt == "PNG" else "jpg"
    (config.UPLOADS_DIR / f"{plan_id}.{ext}").write_bytes(data)
    plan = {
        "id": plan_id, "created_at": store.now(), "status": "DRAFT", "image": f"{plan_id}.{ext}",
        "ai_model": config.GROQ_MODEL, "ai_raw": raw, "ai_topology": ai_plan.model_dump(),
        "topology": mapped.model_dump(), "resolved_ambiguities": [], "edit_count": 0,
        "validation": None, "approval": None, "approved_config": None, "config_sha256": None,
        "deployment_status": "NOT_DEPLOYED", "jobs": [], "current_job_id": None,
    }
    with store.LOCK:
        store.save("plan", plan)
    log.info("plan %s created, %d ambiguities", plan_id, len(mapped.ambiguities))
    return _plan_view(plan)


def _plan_view(plan: dict) -> dict:
    out = {k: v for k, v in plan.items() if k not in ("ai_raw",)}
    out["open_ambiguities"] = open_ambiguities(plan)
    out["inventory"] = config.router_inventory()
    return out


@app.get("/api/plans")
def list_plans():
    return [{"id": p["id"], "created_at": p["created_at"], "status": p["status"],
             "deployment_status": p.get("deployment_status")} for p in store.list_all("plan")]


@app.get("/api/plans/{plan_id}")
def get_plan(plan_id: str):
    return _plan_view(_plan(plan_id))


@app.get("/api/plans/{plan_id}/image")
def plan_image(plan_id: str):
    plan = _plan(plan_id)
    return FileResponse(config.UPLOADS_DIR / plan["image"])


# ---------------------------------------------------------------- admin resolve
@app.put("/api/plans/{plan_id}/topology")
def edit_topology(plan_id: str, body: TopologyEdit):
    with store.LOCK:
        plan = _plan(plan_id)
        if plan["status"] not in EDITABLE:
            raise HTTPException(409, f"plan is {plan['status']}; only DRAFT/REVOKED plans can be edited")
        topo = body.topology.model_dump()
        old = {r["name"] for r in plan["topology"]["routers"]}
        new = {r["name"] for r in topo["routers"]}
        if old != new:
            raise HTTPException(422, "routers cannot be renamed, added or removed in the editor")
        for r in topo["routers"]:
            for i in r["interfaces"]:
                i["name"] = expand_interface(i.get("name"))
                i["ipv4_cidr"] = (i.get("ipv4_cidr") or "").strip() or None
                if i["role"] == "management":
                    i["ipv4_cidr"] = None
            r["router_id"] = (r.get("router_id") or "").strip() or None
        for p in topo["pcs"]:
            p["ipv4_cidr"] = (p.get("ipv4_cidr") or "").strip() or None
            p["gateway"] = (p.get("gateway") or "").strip() or None
        pcs = {p["name"] for p in topo["pcs"]}
        for link in topo["links"]:
            for side in ("a", "b"):
                if link[f"device_{side}"] in pcs:
                    link[f"interface_{side}"] = "e0"
                elif link[f"device_{side}"] in new:
                    link[f"interface_{side}"] = expand_interface(link[f"interface_{side}"])
        known = set(topo["ambiguities"])
        resolved = list(plan.get("resolved_ambiguities", []))
        done = {r["ambiguity"] for r in resolved}
        for res in body.resolved:
            if res.ambiguity not in known:
                raise HTTPException(422, f"unknown ambiguity: {res.ambiguity[:80]}")
            if not res.note.strip():
                raise HTTPException(422, "a resolution note is required")
            if res.ambiguity not in done:
                resolved.append({"ambiguity": res.ambiguity, "note": res.note.strip(), "at": store.now()})
        plan["topology"] = topo
        plan["resolved_ambiguities"] = resolved
        plan["edit_count"] = plan.get("edit_count", 0) + 1
        plan["validation"] = None
        store.save("plan", plan)
    return _plan_view(plan)


@app.post("/api/plans/{plan_id}/discover")
def discover(plan_id: str):
    plan = _plan(plan_id)
    return discover_interfaces([r["name"] for r in plan["topology"]["routers"]])


# ---------------------------------------------------------------- review / validate / approve
@app.get("/api/plans/{plan_id}/review")
def review(plan_id: str):
    plan = _plan(plan_id)
    errors, warnings, gen = static_checks(plan, config.router_inventory())
    return {"plan_id": plan_id, "status": plan["status"], "commands_by_router": gen["commands_by_router"],
            "devices": gen["devices"], "generation_errors": gen["errors"], "static_errors": errors,
            "warnings": warnings, "open_ambiguities": open_ambiguities(plan),
            "resolved_ambiguities": plan.get("resolved_ambiguities", []),
            "config_sha256": config_digest(gen["commands_by_router"]) if gen["commands_by_router"] else None}


@app.post("/api/plans/{plan_id}/validate")
def validate(plan_id: str):
    plan = _plan(plan_id)
    result = validate_plan(plan, live=True)
    result["validated_at"] = store.now()
    result["config_sha256"] = config_digest(result["commands_by_router"]) if result["commands_by_router"] else None
    with store.LOCK:
        plan = _plan(plan_id)
        if plan["status"] in EDITABLE:
            plan["validation"] = result
            store.save("plan", plan)
    return result


@app.post("/api/plans/{plan_id}/approve")
def approve(plan_id: str, body: Approval):
    if body.confirmation != "APPROVE":
        raise HTTPException(422, 'confirmation must be exactly "APPROVE"')
    plan = _plan(plan_id)
    if plan["status"] not in EDITABLE:
        raise HTTPException(409, f"plan is {plan['status']}")
    result = validate_plan(plan, live=True)  # re-validate at approval time
    result["validated_at"] = store.now()
    if not result["passed"]:
        with store.LOCK:
            plan = _plan(plan_id)
            plan["validation"] = result
            store.save("plan", plan)
        raise HTTPException(409, {"message": "validation failed", "errors": result["errors"]})
    gen = generate(plan["topology"], config.router_inventory())
    digest = config_digest(gen["commands_by_router"])
    result["config_sha256"] = digest
    with store.LOCK:
        plan = _plan(plan_id)
        if plan["status"] not in EDITABLE:
            raise HTTPException(409, f"plan is {plan['status']}")
        pcs = []
        for pc in plan["topology"].get("pcs", []):
            if pc.get("ipv4_cidr"):
                pcs.append({"name": pc["name"], "ip": pc["ipv4_cidr"].split("/")[0]})
        plan["validation"] = result
        plan["approved_config"] = {
            "plan_id": plan_id, "commands_by_router": gen["commands_by_router"],
            "devices": gen["devices"], "ospf": gen["ospf"], "pcs": pcs,
        }
        plan["config_sha256"] = digest
        plan["approval"] = {"approved_at": store.now(), "approved_by": "admin (web UI)", "confirmation": "APPROVE"}
        plan["status"] = "APPROVED"
        if plan.get("deployment_status") not in ("NOT_DEPLOYED",):
            plan["deployment_status"] = "NOT_DEPLOYED"
        store.save("plan", plan)
    return _plan_view(plan)


@app.get("/api/plans/{plan_id}/approved-config")
def approved_config(plan_id: str):
    plan = _plan(plan_id)
    if plan["status"] != "APPROVED" or not plan.get("approved_config"):
        raise HTTPException(409, f"plan is {plan['status']}, no approved configuration")
    return {"plan_id": plan_id, "config_sha256": plan["config_sha256"], **plan["approved_config"]}


# ---------------------------------------------------------------- deploy (Kafka producer)
@app.post("/api/plans/{plan_id}/deploy")
def deploy(plan_id: str):
    with store.LOCK:
        plan = _plan(plan_id)
        if plan["status"] != "APPROVED":
            raise HTTPException(409, "plan is not APPROVED - approval is mandatory before deployment")
        if not (plan.get("validation") or {}).get("passed"):
            raise HTTPException(409, "validation has not passed")
        ac = plan["approved_config"]
        if config_digest(ac["commands_by_router"]) != plan["config_sha256"]:
            raise HTTPException(409, "approved configuration hash mismatch - re-approve")
        if plan["deployment_status"] in ("QUEUED", "RUNNING"):
            raise HTTPException(409, f"a deployment is already {plan['deployment_status']} ({plan['current_job_id']})")
        if plan["deployment_status"] == "SUCCESS":
            raise HTTPException(409, "this plan is already deployed successfully")
        job_id = str(uuid.uuid4())
        devices = list(ac["commands_by_router"].keys())
        job = {"id": job_id, "plan_id": plan_id, "status": "PENDING", "stage": "queued", "devices": devices,
               "config_sha256": plan["config_sha256"], "created_at": store.now(), "started_at": None,
               "finished_at": None, "worker_id": None, "router_results": {}, "verification": {},
               "error": None, "history": []}
        _history(job, "PENDING", "queued", message="job created, sending to Kafka")
        msg = {"job_id": job_id, "plan_id": plan_id, "device_ids": devices,
               "config_sha256": plan["config_sha256"],
               "approved_config_ref": f"/api/plans/{plan_id}/approved-config", "requested_at": job["created_at"]}
        job["kafka_message"] = msg
        store.save("job", job)
        try:
            meta = producer().send(config.KAFKA_TOPIC, key=job_id, value=msg).get(timeout=15)
            job["kafka"] = {"topic": meta.topic, "partition": meta.partition, "offset": meta.offset}
        except Exception as e:
            job["status"], job["error"], job["finished_at"] = "FAILED", f"Kafka produce failed: {e}", store.now()
            _history(job, "FAILED", "queued", message=job["error"])
            store.save("job", job)
            plan["jobs"].append(job_id)
            store.save("plan", plan)
            raise HTTPException(503, job["error"])
        store.save("job", job)
        plan["deployment_status"], plan["current_job_id"] = "QUEUED", job_id
        plan["jobs"].append(job_id)
        store.save("plan", plan)
    return {"job_id": job_id, "status": "PENDING", "kafka_message": msg, "monitor": f"/jobs?job={job_id}"}


# ---------------------------------------------------------------- worker callbacks
@app.post("/api/jobs/{job_id}/claim")
def claim(job_id: str, body: Claim):
    with store.LOCK:
        job = _job(job_id)
        if job["status"] != "PENDING":
            raise HTTPException(409, f"Job is {job['status']}; it will not be executed again")
        plan = store.load("plan", job["plan_id"])
        problem = None
        if not plan:
            problem = "plan no longer exists"
        elif plan["status"] != "APPROVED":
            problem = f"plan is {plan['status']} (not approved)"
        elif plan.get("current_job_id") != job_id or plan.get("deployment_status") != "QUEUED":
            problem = "job is not the current queued deployment of the plan"
        elif body.config_sha256 != plan["config_sha256"] or body.config_sha256 != job["config_sha256"] \
                or config_digest(plan["approved_config"]["commands_by_router"]) != plan["config_sha256"]:
            problem = "configuration hash does not match the approved configuration"
        if problem:
            job["status"], job["error"], job["finished_at"] = "FAILED", f"claim rejected: {problem}", store.now()
            _history(job, "FAILED", "claim", message=job["error"])
            store.save("job", job)
            if plan and plan.get("current_job_id") == job_id:
                plan["deployment_status"] = "FAILED"
                store.save("plan", plan)
            raise HTTPException(409, job["error"])
        job["status"], job["stage"], job["started_at"], job["worker_id"] = "RUNNING", "claimed", store.now(), body.worker_id
        _history(job, "RUNNING", "claimed", message=f"claimed by {body.worker_id}")
        store.save("job", job)
        plan["deployment_status"] = "RUNNING"
        store.save("plan", plan)
    return {"job_id": job_id, "status": "RUNNING"}


@app.post("/api/jobs/{job_id}/progress")
def progress(job_id: str, body: Progress):
    with store.LOCK:
        job = _job(job_id)
        if job["status"] != "RUNNING":
            raise HTTPException(409, f"Job is {job['status']}; progress not accepted")
        job["stage"] = body.stage
        if body.router_results:
            for dev, res in body.router_results.items():
                job["router_results"].setdefault(dev, {}).update(res)
        if body.verification:
            job["verification"].update(body.verification)
        if body.error:
            job["error"] = body.error
        job["status"] = body.status
        _history(job, body.status, body.stage, body.device, body.message or body.error)
        if body.status in ("SUCCESS", "FAILED"):
            job["finished_at"] = store.now()
            if body.status == "SUCCESS":
                job["error"] = None
            plan = store.load("plan", job["plan_id"])
            if plan and plan.get("current_job_id") == job_id:
                plan["deployment_status"] = body.status
                store.save("plan", plan)
        store.save("job", job)
    return {"ok": True}


def _expire_stale(job: dict) -> dict:
    if job["status"] == "RUNNING" and job.get("started_at"):
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(job["started_at"])).total_seconds()
        if age > config.JOB_STALE_SECONDS:
            with store.LOCK:
                job = _job(job["id"])
                if job["status"] == "RUNNING":
                    job["status"], job["finished_at"] = "FAILED", store.now()
                    job["error"] = f"worker did not report for {config.JOB_STALE_SECONDS}s (crashed?)"
                    _history(job, "FAILED", job["stage"], message=job["error"])
                    store.save("job", job)
                    plan = store.load("plan", job["plan_id"])
                    if plan and plan.get("current_job_id") == job["id"]:
                        plan["deployment_status"] = "FAILED"
                        store.save("plan", plan)
    return job


@app.get("/api/jobs")
def list_jobs():
    return [_expire_stale(j) for j in store.list_all("job")]


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str):
    return _expire_stale(_job(job_id))


@app.post("/api/jobs/{job_id}/revoke")
def revoke(job_id: str):
    with store.LOCK:
        job = _job(job_id)
        if job["status"] != "FAILED":
            raise HTTPException(409, "only FAILED jobs can be revoked")
        plan = _plan(job["plan_id"])
        if plan["status"] == "APPROVED":
            plan["status"] = "REVOKED"
            plan["revoked"] = {"at": store.now(), "job_id": job_id}
            plan["approval"] = None
            plan["approved_config"] = None
            plan["config_sha256"] = None
            plan["validation"] = None
            store.save("plan", plan)
        job["revoked"] = True
        _history(job, job["status"], "revoked", message="plan approval revoked by admin")
        store.save("job", job)
    return {"job_id": job_id, "plan_status": plan["status"]}
