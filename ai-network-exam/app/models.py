"""Structured topology schema produced by the AI and edited by the admin."""
from __future__ import annotations

from typing import Literal, Optional, Union

from pydantic import BaseModel, Field

Role = Literal["lan", "transit", "management", "unknown"]


class Interface(BaseModel):
    name: Optional[str] = None            # physical router interface (from lab inventory / admin)
    diagram_label: Optional[str] = None   # what the diagram says, for traceability
    role: Role = "unknown"
    ipv4_cidr: Optional[str] = None


class Router(BaseModel):
    name: str
    router_id: Optional[str] = None
    interfaces: list[Interface] = Field(default_factory=list)


class PC(BaseModel):
    name: str
    ipv4_cidr: Optional[str] = None
    gateway: Optional[str] = None


class Link(BaseModel):
    device_a: str
    interface_a: Optional[str] = None
    device_b: str
    interface_b: Optional[str] = None


class TopologyPlan(BaseModel):
    routers: list[Router] = Field(default_factory=list)
    pcs: list[PC] = Field(default_factory=list)
    other_devices: list[str] = Field(default_factory=list)
    links: list[Link] = Field(default_factory=list)
    ospf_process_id: Optional[int] = 1
    ospf_area: Optional[Union[int, str]] = 0
    ambiguities: list[str] = Field(default_factory=list)


class Resolution(BaseModel):
    ambiguity: str
    note: str


class TopologyEdit(BaseModel):
    topology: TopologyPlan
    resolved: list[Resolution] = Field(default_factory=list)


class Approval(BaseModel):
    confirmation: str


class Claim(BaseModel):
    config_sha256: str
    worker_id: str


class Progress(BaseModel):
    status: Literal["RUNNING", "SUCCESS", "FAILED"]
    stage: str
    device: Optional[str] = None
    message: Optional[str] = None
    router_results: Optional[dict] = None
    verification: Optional[dict] = None
    error: Optional[str] = None
