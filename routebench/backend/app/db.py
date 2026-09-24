"""
PostgreSQL 持久层（默认）/ SQLite（测试与无 PG 环境回退）。

保存对象：
  neighbors     BGP 邻居元数据（仅离线元数据，不发起任何真实连接）
  policies      策略头（含 v4/v6 默认动作）
  rules         规则行，position 即生效次序
  snapshots     配置快照（策略 JSON 全量，发布前留档/回放）
  journal       操作日志（按序记录改动，支撑“回放输入及生效次序”）
  runs          FRR 交叉验证结果存档
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

DEFAULT_DSN = os.environ.get(
    "ROUTEBENCH_DSN",
    "postgresql+psycopg://routebench:routebench@localhost:5432/routebench",
)
# 无 PG 的本地环境（含本仓库测试）自动落到文件型 SQLite
FALLBACK_SQLITE = os.environ.get("ROUTEBENCH_SQLITE", "/tmp/routebench.db")


class Base(DeclarativeBase):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Neighbor(Base):
    __tablename__ = "neighbors"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    ip: Mapped[str] = mapped_column(String(64))           # IPv4/IPv6 文本，引擎负责校验
    asn: Mapped[int] = mapped_column(Integer)
    family: Mapped[str] = mapped_column(String(8))        # ipv4 / ipv6
    description: Mapped[str] = mapped_column(Text, default="")
    policy_id: Mapped[str | None] = mapped_column(ForeignKey("policies.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Policy(Base):
    __tablename__ = "policies"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    default_v4: Mapped[str] = mapped_column(String(8), default="deny")
    default_v6: Mapped[str] = mapped_column(String(8), default="deny")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)

    rules: Mapped[list["Rule"]] = relationship(
        back_populates="policy", cascade="all, delete-orphan", order_by="Rule.position"
    )


class Rule(Base):
    __tablename__ = "rules"
    __table_args__ = (
        UniqueConstraint("policy_id", "position", name="uq_rule_position"),
        UniqueConstraint("policy_id", "client_id", name="uq_rule_client_id"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)   # 内部 UUID
    client_id: Mapped[str] = mapped_column(String(64))              # 用户规则 id（引擎中使用）
    policy_id: Mapped[str] = mapped_column(ForeignKey("policies.id", ondelete="CASCADE"))
    position: Mapped[int] = mapped_column(Integer)        # 生效次序
    action: Mapped[str] = mapped_column(String(8))
    prefix: Mapped[str] = mapped_column(String(64))
    ge: Mapped[int | None] = mapped_column(Integer, nullable=True)
    le: Mapped[int | None] = mapped_column(Integer, nullable=True)
    label: Mapped[str] = mapped_column(Text, default="")

    policy: Mapped[Policy] = relationship(back_populates="rules")


class Snapshot(Base):
    __tablename__ = "snapshots"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    policy_id: Mapped[str | None] = mapped_column(ForeignKey("policies.id", ondelete="SET NULL"))
    name: Mapped[str] = mapped_column(String(128))
    kind: Mapped[str] = mapped_column(String(16))         # manual / pre-publish / scenario
    payload: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class JournalEntry(Base):
    """
    操作日志：每次对策略的结构性改动一行。
    seq 单调递增；op/args 足以重放；before/after 快照便于审阅。
    """
    __tablename__ = "journal"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    policy_id: Mapped[str] = mapped_column(ForeignKey("policies.id", ondelete="CASCADE"))
    seq: Mapped[int] = mapped_column(Integer)
    op: Mapped[str] = mapped_column(String(32))           # add_rule/update_rule/move_rule/delete_rule/set_default/reorder/reset
    args: Mapped[dict] = mapped_column(JSON, default=dict)
    actor: Mapped[str] = mapped_column(String(64), default="local")
    state_after: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Run(Base):
    __tablename__ = "frr_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scenario: Mapped[str | None] = mapped_column(String(64), nullable=True)
    policy_payload: Mapped[dict] = mapped_column(JSON)
    test_prefixes: Mapped[list] = mapped_column(JSON)
    result: Mapped[dict] = mapped_column(JSON)
    consistent: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


def new_id() -> str:
    return str(uuid.uuid4())


_engine = None
_SessionLocal = None


def init_db(dsn: str | None = None, *, echo: bool = False):
    """初始化引擎；PostgreSQL 不可用时回退 SQLite（仅限离线/测试）。"""
    global _engine, _SessionLocal
    chosen = dsn or DEFAULT_DSN
    try:
        _engine = create_engine(chosen, echo=echo, pool_pre_ping=True)
        with _engine.connect() as conn:
            conn.exec_driver_sql("SELECT 1")
    except Exception as exc:  # 文档化回退：缺 PG 时工作台仍能离线运行
        print(f"[db] PostgreSQL 不可用（{exc.__class__.__name__}），回退 SQLite: {FALLBACK_SQLITE}")
        _engine = create_engine(f"sqlite:///{FALLBACK_SQLITE}", echo=echo)
    Base.metadata.create_all(_engine)
    _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False)
    return _engine


def get_session():
    if _SessionLocal is None:
        init_db()
    db = _SessionLocal()
    try:
        yield db
    finally:
        db.close()
