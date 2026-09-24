"""
策略仓储与“可回放编辑”。

规则数组在内存中的顺序即生效次序（DB 中体现为 rule.position）。
每次改动先通过引擎 Policy.from_dict 校验，再落库并追加 journal；
回放时从 seq=0 的 reset 基线出发逐条重放，末态必须与库内现状一致（漂移检测）。
"""
from __future__ import annotations

from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import db as dbmod
from .engine import Policy, PolicyError
from .db import JournalEntry, Policy as PolicyRow, Rule as RuleRow, Neighbor, new_id


# --------------------------------------------------------------------------- #
# 行 <-> dict
# --------------------------------------------------------------------------- #
def policy_to_dict(row: PolicyRow) -> dict:
    return {
        "name": row.name,
        "default_v4": row.default_v4,
        "default_v6": row.default_v6,
        "rules": [
            {
                "id": r.client_id,
                "action": r.action,
                "prefix": r.prefix,
                "ge": r.ge,
                "le": r.le,
                "label": r.label or "",
            }
            for r in sorted(row.rules, key=lambda r: r.position)
        ],
    }


def create_policy(db: Session, data: dict, actor: str = "local") -> PolicyRow:
    Policy.from_dict(data)  # 校验
    row = PolicyRow(
        id=new_id(),
        name=data["name"],
        default_v4=data.get("default_v4", "deny"),
        default_v6=data.get("default_v6", "deny"),
    )
    db.add(row)
    db.flush()
    _replace_rules(db, row, data["rules"])
    _append_journal(db, row, 0, "reset", {"policy": dict(data)}, policy_to_dict(row), actor)
    db.commit()
    db.refresh(row)
    return row


def _replace_rules(db: Session, row: PolicyRow, rules: list[dict]) -> None:
    for old in list(row.rules):
        db.delete(old)
    db.flush()
    for pos, r in enumerate(rules):
        db.add(
            RuleRow(
                id=new_id(),
                client_id=str(r["id"]),
                policy_id=row.id,
                position=pos,
                action=r["action"],
                prefix=r["prefix"],
                ge=r.get("ge"),
                le=r.get("le"),
                label=r.get("label", ""),
            )
        )
    db.flush()


# --------------------------------------------------------------------------- #
# 操作应用（纯函数，引擎校验；回放复用同一路径）
# --------------------------------------------------------------------------- #
def apply_op(state: dict, op: str, args: dict) -> dict:
    s = {
        "name": state.get("name", "draft"),
        "default_v4": state.get("default_v4", "deny"),
        "default_v6": state.get("default_v6", "deny"),
        "rules": [dict(r) for r in state.get("rules", [])],
    }
    rules = s["rules"]

    if op == "reset":
        s = dict(args["policy"])
        s.setdefault("rules", [])
    elif op == "add_rule":
        rule = dict(args["rule"])
        if any(r["id"] == rule["id"] for r in rules):
            raise PolicyError(f"规则 id 已存在: {rule['id']}")
        pos = args.get("position")
        pos = len(rules) if pos is None else min(int(pos), len(rules))
        rules.insert(pos, rule)
    elif op == "update_rule":
        rid = args["rule_id"]
        for r in rules:
            if r["id"] == rid:
                for key in ("action", "prefix", "ge", "le", "label"):
                    if key in args and args[key] is not None:
                        r[key] = args[key]
                break
        else:
            raise PolicyError(f"规则不存在: {rid}")
    elif op == "move_rule":
        rid, pos = args["rule_id"], int(args["position"])
        idx = next((i for i, r in enumerate(rules) if r["id"] == rid), None)
        if idx is None:
            raise PolicyError(f"规则不存在: {rid}")
        rules.insert(min(pos, len(rules) - 1), rules.pop(idx))
    elif op == "delete_rule":
        rid = args["rule_id"]
        n = len(rules)
        s["rules"] = [r for r in rules if r["id"] != rid]
        if len(s["rules"]) == n:
            raise PolicyError(f"规则不存在: {rid}")
    elif op == "set_default":
        s["default_v4" if args["family"] == "ipv4" else "default_v6"] = args["action"]
    elif op == "reorder":
        order = args["rule_ids"]
        if sorted(order) != sorted(r["id"] for r in rules):
            raise PolicyError("reorder 的 id 集合必须与当前规则完全一致")
        idx = {r["id"]: r for r in rules}
        s["rules"] = [idx[rid] for rid in order]
    else:
        raise PolicyError(f"未知操作: {op}")

    Policy.from_dict(s)  # 任何非法中间态都被拒绝
    return s


def mutate(db: Session, row: PolicyRow, op: str, args: dict, actor: str = "local") -> dict:
    state = policy_to_dict(row)
    new_state = apply_op(state, op, args)
    row.name = new_state["name"]
    row.default_v4 = new_state["default_v4"]
    row.default_v6 = new_state["default_v6"]
    _replace_rules(db, row, new_state["rules"])
    seq = db.scalar(
        select(JournalEntry)
        .where(JournalEntry.policy_id == row.id)
        .with_only_columns(JournalEntry.seq)
        .order_by(JournalEntry.seq.desc())
        .limit(1)
    )
    next_seq = 0 if seq is None else seq + 1
    _append_journal(db, row, next_seq, op, args, new_state, actor)
    db.commit()
    return new_state


def _append_journal(db, row, seq, op, args, state_after, actor) -> None:
    db.add(
        JournalEntry(
            id=new_id(),
            policy_id=row.id,
            seq=seq,
            op=op,
            args=args,
            actor=actor,
            state_after=state_after,
        )
    )
    db.flush()


# --------------------------------------------------------------------------- #
# 回放
# --------------------------------------------------------------------------- #
def replay(db: Session, policy_id: str, from_seq: Optional[int] = None,
           to_seq: Optional[int] = None) -> dict:
    row = db.get(PolicyRow, policy_id)
    if row is None:
        raise PolicyError(f"策略不存在: {policy_id}")
    entries = db.scalars(
        select(JournalEntry)
        .where(JournalEntry.policy_id == policy_id)
        .order_by(JournalEntry.seq)
    ).all()
    if not entries or entries[0].op != "reset":
        raise PolicyError("缺少 seq=0 reset 基线，无法回放")

    lo = 0 if from_seq is None else max(0, from_seq)
    hi = entries[-1].seq if to_seq is None else min(to_seq, entries[-1].seq)

    # 从 reset 基线（或 from_seq-1 的已记录态作为锚点）开始连续重放
    states: list[dict] = []
    if lo > 0:
        anchor = entries[lo - 1]
        state = anchor.state_after
        states.append(
            {"seq": anchor.seq, "op": anchor.op, "state": _safe_summary(state), "anchored": True}
        )
        start = lo
    else:
        state = entries[0].args["policy"]
        states.append({"seq": 0, "op": "reset", "state": _safe_summary(state)})
        start = 1

    for e in entries[start:]:
        if e.seq > hi:
            break
        state = apply_op(state, e.op, e.args)
        recorded = e.state_after
        same = _canonical(state) == _canonical(recorded)
        states.append(
            {
                "seq": e.seq,
                "op": e.op,
                "args": e.args,
                "state": _safe_summary(state),
                "matches_recorded": same,
            }
        )

    final = state
    current = policy_to_dict(row)
    drift = _canonical(final) != _canonical(current)
    return {
        "policy_id": policy_id,
        "steps": states,
        "final_state": final,
        "current_state": current,
        "drift": drift,
        "fully_replayable": not drift and all(s.get("matches_recorded", True) for s in states),
    }


def _safe_summary(state: dict) -> dict:
    return state


def _canonical(state: dict) -> list:
    return [
        (state.get("default_v4"), state.get("default_v6")),
        [(r["id"], r["action"], r["prefix"], r.get("ge"), r.get("le"), r.get("label", ""))
         for r in state.get("rules", [])],
    ]


# --------------------------------------------------------------------------- #
# 快照
# --------------------------------------------------------------------------- #
def save_snapshot(db: Session, row: Optional[PolicyRow], name: str, kind: str, payload: dict) -> str:
    snap = dbmod.Snapshot(
        id=new_id(),
        policy_id=row.id if row else None,
        name=name,
        kind=kind,
        payload=payload,
    )
    db.add(snap)
    db.commit()
    return snap.id
