"""初始化演示数据：邻居、案例策略（含完整操作日志）、配置快照。"""
from __future__ import annotations

from sqlalchemy import select

from app import db as dbmod, repo
from app.db import Neighbor, Policy as PolicyRow, new_id
from app.scenarios import SCENARIOS


def seed() -> None:
    dbmod.init_db()
    db = next(dbmod.get_session())

    if db.scalar(select(PolicyRow).where(PolicyRow.name == "demo-reorder")):
        print("演示数据已存在，跳过")
        return

    s = SCENARIOS["v4-reorder"]
    row = repo.create_policy(db, {**s["before"], "name": "demo-reorder"})
    # before 的顺序是 r1,r2（r2 被遮蔽），after 是 r2,r1 ->
    # 通过 move_rule 完成换序，journal 因而保留了可完整回放的变更链
    repo.mutate(db, row, "move_rule", {"rule_id": "r2", "position": 0})
    repo.save_snapshot(db, row, "发布前快照-换序修正", "pre-publish", repo.policy_to_dict(row))

    for sid in ("v4-over-permit", "v4-default-flip", "v6-over-permit"):
        sc = SCENARIOS[sid]
        repo.create_policy(db, {**sc["before"], "name": f"demo-{sid}"})

    db.add_all([
        Neighbor(id=new_id(), name="lab-frr-b", ip="172.30.0.3", asn=65002,
                 family="ipv4", description="本地 FRR 容器实验邻居（隔离）", policy_id=row.id),
        Neighbor(id=new_id(), name="lab-frr-b-v6", ip="172.30.0.3", asn=65002,
                 family="ipv6", description="同一会话承载 IPv6（multiprotocol BGP）"),
        Neighbor(id=new_id(), name="core-example", ip="198.51.100.9", asn=64512,
                 family="ipv4", description="仅登记元数据；工作台不发起任何真实连接"),
    ])
    db.commit()
    print("演示数据已创建：4 条策略、3 个邻居、1 份快照")


if __name__ == "__main__":
    seed()
