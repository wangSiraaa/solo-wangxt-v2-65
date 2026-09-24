"""Pydantic API 模式（与引擎解耦：非法输入返回 422/PolicyError）。"""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field

Action = Literal["permit", "deny"]


class RuleIn(BaseModel):
    id: str
    action: Action
    prefix: str
    ge: Optional[int] = Field(default=None, ge=0)
    le: Optional[int] = Field(default=None, ge=0)
    label: str = ""


class PolicyIn(BaseModel):
    name: str = "draft"
    default_v4: Action = "deny"
    default_v6: Action = "deny"
    rules: list[RuleIn] = []


class EvaluateIn(BaseModel):
    policy: PolicyIn
    prefixes: list[str] = []
    family: Optional[Literal["ipv4", "ipv6"]] = None


class DiffIn(BaseModel):
    before: PolicyIn
    after: PolicyIn


class ShadowIn(BaseModel):
    policy: PolicyIn


class TrieIn(BaseModel):
    policy: PolicyIn
    family: Literal["ipv4", "ipv6"]
    query: Optional[str] = None


class CrossCheckIn(BaseModel):
    policy: PolicyIn
    test_prefixes: list[str]
    scenario: Optional[str] = None
    save: bool = True


class NeighborIn(BaseModel):
    name: str
    ip: str
    asn: int = Field(ge=1, le=4294967295)
    family: Literal["ipv4", "ipv6"]
    description: str = ""
    policy_id: Optional[str] = None


# ---------------- 策略编辑操作（可回放） ---------------- #
class AddRuleOp(BaseModel):
    op: Literal["add_rule"]
    rule: RuleIn
    position: Optional[int] = None


class UpdateRuleOp(BaseModel):
    op: Literal["update_rule"]
    rule_id: str
    action: Optional[Action] = None
    prefix: Optional[str] = None
    ge: Optional[int] = None
    le: Optional[int] = None
    label: Optional[str] = None


class MoveRuleOp(BaseModel):
    op: Literal["move_rule"]
    rule_id: str
    position: int = Field(ge=0)


class DeleteRuleOp(BaseModel):
    op: Literal["delete_rule"]
    rule_id: str


class SetDefaultOp(BaseModel):
    op: Literal["set_default"]
    family: Literal["ipv4", "ipv6"]
    action: Action


class ReorderOp(BaseModel):
    op: Literal["reorder"]
    rule_ids: list[str]


class ResetOp(BaseModel):
    op: Literal["reset"]
    policy: PolicyIn


class ReplayIn(BaseModel):
    policy_id: str
    from_seq: Optional[int] = None
    to_seq: Optional[int] = None
