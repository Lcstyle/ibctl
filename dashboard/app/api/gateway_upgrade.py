"""Gateway upgrades: policy, the decision, CI's build report, the swap report.

GET  /api/v1/gateway/upgrade            policy, decision, candidate, last swap, swap plan
PUT  /api/v1/gateway/upgrade/policy     save the policy (422 when invalid)
POST /api/v1/gateway/upgrade/candidate  CI: the image built for a gateway/<version> branch
POST /api/v1/gateway/upgrade/swap       the Sunday maintenance job: what the swap did
"""

from __future__ import annotations

import logging
from datetime import date
from typing import Callable

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, StrictBool, StrictInt, StrictStr

from app.services.gateway_version.decision import Decision, decide, next_sunday, today_et
from app.services.gateway_version.policy import CADENCES, PolicyError, UpgradePolicy
from app.services.gateway_version.releases import CHANNELS
from app.services.gateway_version.upgrade import ReportError, UpgradeStore, swap_plan

logger = logging.getLogger("dashboard.api.gateway_upgrade")

router = APIRouter()


class PolicyBody(BaseModel):
    enabled: StrictBool
    channel: StrictStr
    cadence: StrictStr
    soak_days: StrictInt
    deadline_days: StrictInt


class BuildBody(BaseModel):
    version: StrictStr
    sha: StrictStr
    status: StrictStr
    detail: StrictStr = ""


class SwapBody(BaseModel):
    version: StrictStr
    sha: StrictStr
    result: StrictStr
    detail: StrictStr = ""


def _unavailable() -> JSONResponse:
    return JSONResponse(status_code=503, content={"error": "Gateway upgrades are not running"})


def _invalid(message: str) -> JSONResponse:
    return JSONResponse(status_code=422, content={"error": message})


def _store(request: Request) -> UpgradeStore | None:
    return getattr(request.app.state, "gateway_upgrade", None)


def _today(request: Request) -> date:
    today: Callable[[], date] = getattr(request.app.state, "gateway_upgrade_today", today_et)
    return today()


def upgrade_view(request: Request, store: UpgradeStore) -> dict:
    """Everything the Gateway tab, CI and the Sunday job read, in one shape."""
    today = _today(request)
    versions = getattr(request.app.state, "gateway_version", None)
    record = store.record()
    try:
        policy, policy_error = store.policy(), None
    except PolicyError as exc:
        policy, policy_error = None, str(exc)
    if policy is None:
        decision = Decision(False, next_sunday(today), None, None, f"the saved upgrade policy is unreadable: {policy_error}")
    elif versions is None:
        decision = Decision(False, next_sunday(today), None, None, "Gateway version tracking is not running")
    else:
        decision = decide(policy, versions.current(), today)
    return {
        "policy": policy.to_json() if policy else None,
        "policy_error": policy_error,
        "decision": decision.to_json(),
        "candidate": record.candidate.to_json() if record.candidate else None,
        "last_swap": record.last_swap.to_json() if record.last_swap else None,
        "swap": swap_plan(decision, record.candidate).to_json(),
        "channels": list(CHANNELS),
        "cadences": CADENCES,
    }


@router.get("/api/v1/gateway/upgrade")
async def get_upgrade(request: Request):
    store = _store(request)
    if store is None:
        return _unavailable()
    return upgrade_view(request, store)


@router.put("/api/v1/gateway/upgrade/policy")
async def put_policy(request: Request, body: PolicyBody):
    store = _store(request)
    if store is None:
        return _unavailable()
    try:
        policy = UpgradePolicy(**body.model_dump())
    except PolicyError as exc:
        return _invalid(str(exc))
    store.set_policy(policy)
    return upgrade_view(request, store)


@router.post("/api/v1/gateway/upgrade/candidate")
async def post_candidate(request: Request, body: BuildBody):
    store = _store(request)
    if store is None:
        return _unavailable()
    try:
        report = store.report_build(body.version, body.sha, body.status, body.detail)
    except ReportError as exc:
        return _invalid(str(exc))
    return {"candidate": report.to_json()}


@router.post("/api/v1/gateway/upgrade/swap")
async def post_swap(request: Request, body: SwapBody):
    store = _store(request)
    if store is None:
        return _unavailable()
    try:
        report = store.report_swap(body.version, body.sha, body.result, body.detail)
    except ReportError as exc:
        return _invalid(str(exc))
    return {"last_swap": report.to_json()}
