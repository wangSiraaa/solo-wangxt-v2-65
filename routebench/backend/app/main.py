"""
FastAPI 入口。

两类接口：
  /api/sim/*  无状态推演（策略随请求提交）：求值/命中链/前缀树/语义差异/遮蔽
  /api/...    有状态：邻居、持久化策略与规则顺序、快照、可回放编辑日志、FRR 实验室
"""
from __future__ import annotations

import ipaddress
from typing import Optional, Union

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import db as dbmod, frr_lab, repo
from .db import JournalEntry, Neighbor, Policy as PolicyRow, Run, Snapshot, new_id
from .engine import (
    Policy,
    PolicyError,
    diff_policies,
    find_shadowed,
    trie_view,
)
from .frr_config import render_applied_config
from .scenarios import SCENARIOS
from .schemas import (
    CrossCheckIn,
    DiffIn,
    EvaluateIn,
    NeighborIn,
    PolicyIn,
    ReplayIn,
    ShadowIn,
    TrieIn,
)

app = FastAPI(title="RouteBench 离线路由策略推演工作台", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _startup() -> None:
    dbmod.init_db()


def _policy(model: PolicyIn) -> Policy:
    try:
        return Policy.from_dict(model.model_dump())
    except PolicyError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


def _get_policy_or_404(db: Session, policy_id: str) -> PolicyRow:
    row = db.get(PolicyRow, policy_id)
    if row is None:
        raise HTTPException(404, f"策略不存在: {policy_id}")
    return row


# --------------------------------------------------------------------------- #
# 无状态推演
# --------------------------------------------------------------------------- #
@app.post("/api/sim/evaluate")
def sim_evaluate(body: EvaluateIn):
    policy = _policy(body.policy)
    if not body.prefixes:
        raise HTTPException(422, "请提供至少一个查询前缀")
    out = []
    for p in body.prefixes:
        try:
            res = policy.evaluate(p)
        except PolicyError as exc:
            raise HTTPException(422, f"前缀 {p}: {exc}")
        if body.family and res["family"] != body.family:
            raise HTTPException(422, f"{p} 是 {res['family']} 地址，与请求族 {body.family} 混算被拒绝")
        out.append(res)
    return {"results": out}


@app.post("/api/sim/diff")
def sim_diff(body: DiffIn):
    before, after = _policy(body.before), _policy(body.after)
    return diff_policies(before, after)


@app.post("/api/sim/shadow")
def sim_shadow(body: ShadowIn):
    return find_shadowed(_policy(body.policy))


@app.post("/api/sim/trie")
def sim_trie(body: TrieIn):
    version = 4 if body.family == "ipv4" else 6
    try:
        return trie_view(_policy(body.policy), version, body.query)
    except PolicyError as exc:
        raise HTTPException(422, str(exc))


@app.post("/api/sim/frr-text")
def sim_frr_text(body: PolicyIn):
    return {"config": render_applied_config(_policy(body))["lines"]}


@app.get("/api/scenarios")
def list_scenarios():
    return {"scenarios": [{"id": k, **{kk: vv for kk, vv in v.items()
                                       if kk not in ("before", "after")}} for k, v in SCENARIOS.items()]}


@app.get("/api/scenarios/{scenario_id}")
def get_scenario(scenario_id: str):
    if scenario_id not in SCENARIOS:
        raise HTTPException(404, f"未知案例: {scenario_id}")
    s = SCENARIOS[scenario_id]
    out = {"id": scenario_id, **s}
    out["analysis"] = {
        "diff": diff_policies(Policy.from_dict(s["before"]), Policy.from_dict(s["after"])),
        "shadow_before": find_shadowed(Policy.from_dict(s["before"])),
        "shadow_after": find_shadowed(Policy.from_dict(s["after"])),
    }
    return out


# --------------------------------------------------------------------------- #
# 持久化策略
# --------------------------------------------------------------------------- #
@app.get("/api/policies")
def list_policies(db: Session = Depends(dbmod.get_session)):
    rows = db.scalars(select(PolicyRow).order_by(PolicyRow.updated_at.desc())).all()
    return {"policies": [{"id": r.id, "name": r.name,
                          "default_v4": r.default_v4, "default_v6": r.default_v6,
                          "rule_count": len(r.rules),
                          "updated_at": r.updated_at.isoformat()} for r in rows]}


@app.post("/api/policies")
def create_policy(body: PolicyIn, db: Session = Depends(dbmod.get_session)):
    if db.scalar(select(PolicyRow).where(PolicyRow.name == body.name)):
        raise HTTPException(409, f"策略名已存在: {body.name}")
    try:
        row = repo.create_policy(db, body.model_dump())
    except PolicyError as exc:
        raise HTTPException(422, str(exc))
    return {"id": row.id, "policy": repo.policy_to_dict(row)}


@app.get("/api/policies/{policy_id}")
def get_policy(policy_id: str, db: Session = Depends(dbmod.get_session)):
    row = _get_policy_or_404(db, policy_id)
    pol = repo.policy_to_dict(row)
    return {"id": row.id, "policy": pol,
            "shadow": find_shadowed(Policy.from_dict(pol))}


@app.patch("/api/policies/{policy_id}")
def patch_policy(policy_id: str, body: dict, db: Session = Depends(dbmod.get_session)):
    """统一的可回放编辑入口。body 形如 {op, ...}。"""
    row = _get_policy_or_404(db, policy_id)
    op = body.pop("op", None)
    if not op:
        raise HTTPException(422, "缺少 op")
    try:
        state = repo.mutate(db, row, op, body, actor=body.get("actor", "local"))
    except PolicyError as exc:
        raise HTTPException(422, str(exc))
    return {"id": row.id, "policy": state}


@app.delete("/api/policies/{policy_id}")
def delete_policy(policy_id: str, db: Session = Depends(dbmod.get_session)):
    row = _get_policy_or_404(db, policy_id)
    db.delete(row)
    db.commit()
    return {"deleted": policy_id}


@app.get("/api/policies/{policy_id}/journal")
def get_journal(policy_id: str, db: Session = Depends(dbmod.get_session)):
    _get_policy_or_404(db, policy_id)
    entries = db.scalars(
        select(JournalEntry).where(JournalEntry.policy_id == policy_id).order_by(JournalEntry.seq)
    ).all()
    return {"journal": [{"seq": e.seq, "op": e.op, "args": e.args,
                         "actor": e.actor, "created_at": e.created_at.isoformat()} for e in entries]}


@app.post("/api/policies/{policy_id}/replay")
def post_replay(policy_id: str, body: ReplayIn, db: Session = Depends(dbmod.get_session)):
    if body.policy_id != policy_id:
        raise HTTPException(422, "路径与请求体 policy_id 不一致")
    try:
        return repo.replay(db, policy_id, body.from_seq, body.to_seq)
    except PolicyError as exc:
        raise HTTPException(422, str(exc))


@app.post("/api/policies/{policy_id}/snapshot")
def post_snapshot(policy_id: str, body: dict, db: Session = Depends(dbmod.get_session)):
    row = _get_policy_or_404(db, policy_id)
    name = body.get("name", "snapshot")
    sid = repo.save_snapshot(db, row, name, body.get("kind", "manual"), repo.policy_to_dict(row))
    return {"snapshot_id": sid}


@app.get("/api/snapshots")
def list_snapshots(db: Session = Depends(dbmod.get_session)):
    rows = db.scalars(select(Snapshot).order_by(Snapshot.created_at.desc())).all()
    return {"snapshots": [{"id": r.id, "name": r.name, "kind": r.kind,
                           "policy_id": r.policy_id, "created_at": r.created_at.isoformat()}
                          for r in rows]}


@app.get("/api/snapshots/{snapshot_id}")
def get_snapshot(snapshot_id: str, db: Session = Depends(dbmod.get_session)):
    row = db.get(Snapshot, snapshot_id)
    if row is None:
        raise HTTPException(404, "快照不存在")
    return {"id": row.id, "name": row.name, "kind": row.kind, "payload": row.payload,
            "created_at": row.created_at.isoformat()}


# --------------------------------------------------------------------------- #
# 邻居（离线元数据；不发起连接）
# --------------------------------------------------------------------------- #
@app.get("/api/neighbors")
def list_neighbors(db: Session = Depends(dbmod.get_session)):
    rows = db.scalars(select(Neighbor).order_by(Neighbor.created_at)).all()
    return {"neighbors": [{"id": r.id, "name": r.name, "ip": r.ip, "asn": r.asn,
                           "family": r.family, "description": r.description,
                           "policy_id": r.policy_id} for r in rows]}


@app.post("/api/neighbors")
def create_neighbor(body: NeighborIn, db: Session = Depends(dbmod.get_session)):
    try:
        addr = ipaddress.ip_address(body.ip)
    except ValueError:
        raise HTTPException(422, f"邻居地址非法: {body.ip}")
    fam = f"ipv{addr.version}"
    if fam != body.family:
        raise HTTPException(422, f"地址族与 IP 不匹配：{body.ip} 属于 {fam}")
    if body.policy_id and db.get(PolicyRow, body.policy_id) is None:
        raise HTTPException(422, "policy_id 不存在")
    row = Neighbor(id=new_id(), name=body.name, ip=body.ip, asn=body.asn,
                   family=body.family, description=body.description, policy_id=body.policy_id)
    db.add(row)
    db.commit()
    return {"id": row.id}


# --------------------------------------------------------------------------- #
# FRR 容器实验室
# --------------------------------------------------------------------------- #
@app.get("/api/frr/status")
def frr_status():
    return frr_lab.status()


@app.post("/api/frr/setup")
def frr_setup():
    try:
        return frr_lab.setup()
    except frr_lab.LabError as exc:
        raise HTTPException(503, str(exc))


@app.post("/api/frr/teardown")
def frr_teardown():
    try:
        return frr_lab.teardown()
    except frr_lab.LabError as exc:
        raise HTTPException(503, str(exc))


@app.post("/api/frr/check")
def frr_check(body: CrossCheckIn, db: Session = Depends(dbmod.get_session)):
    try:
        pol = Policy.from_dict(body.policy.model_dump())
        # 提前自校验所有测试前缀
        for p in body.test_prefixes:
            pol.evaluate(p)
        result = frr_lab.run_case(body.policy.model_dump(), list(body.test_prefixes))
    except PolicyError as exc:
        raise HTTPException(422, str(exc))
    except frr_lab.LabError as exc:
        raise HTTPException(503, str(exc))
    if body.save:
        run = Run(id=new_id(), scenario=body.scenario,
                  policy_payload=body.policy.model_dump(),
                  test_prefixes=list(body.test_prefixes),
                  result=result, consistent=result["consistent"])
        db.add(run)
        db.commit()
        result["run_id"] = run.id
    return result


@app.post("/api/frr/check-scenario/{scenario_id}")
def frr_check_scenario(scenario_id: str, db: Session = Depends(dbmod.get_session)):
    if scenario_id not in SCENARIOS:
        raise HTTPException(404, f"未知案例: {scenario_id}")
    s = SCENARIOS[scenario_id]
    body = CrossCheckIn(policy=PolicyIn(**s["after"]),
                        test_prefixes=s["test_prefixes"],
                        scenario=scenario_id, save=True)
    return frr_check(body, db)


@app.get("/api/frr/runs")
def frr_runs(db: Session = Depends(dbmod.get_session)):
    rows = db.scalars(select(Run).order_by(Run.created_at.desc()).limit(50)).all()
    return {"runs": [{"id": r.id, "scenario": r.scenario, "consistent": r.consistent,
                      "mismatches": r.result.get("mismatches", []),
                      "created_at": r.created_at.isoformat()} for r in rows]}


@app.get("/healthz")
def healthz():
    return {"ok": True}
