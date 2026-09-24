"""
路由策略推演引擎（离线，无任何设备交互）

语义对齐 FRRouting prefix-list + route-map 的首条匹配模型：
  * 精确前缀：        permit 10.0.0.0/8            (ge=le=8)
  * 掩码长度范围：    permit 10.0.0.0/8 ge 9 le 24
                     只给 ge 时 le=地址族上限；只给 le 时 ge=前缀长度
  * 首条匹配：        规则按 position 顺序求值，命中即终止
  * 默认动作：        无规则命中时按地址族默认动作（生产习惯默认 deny）
  * IPv4 / IPv6 严格不混算：地址族不同直接判定为不匹配，跨族求值报错

本模块只依赖标准库 ipaddress，保证模拟器结果可与容器内 FRR 观测逐一对照。
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Iterable, Literal, Optional, Union

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
Action = Literal["permit", "deny"]
FAMILIES = {4: "ipv4", 6: "ipv6"}
MAXLEN = {4: 32, 6: 128}
DEFAULT_WORLD = {4: "0.0.0.0/0", 6: "::/0"}


class PolicyError(ValueError):
    """策略输入非法（主机位非零、掩码越界、跨族等）。"""


# --------------------------------------------------------------------------- #
# 规则
# --------------------------------------------------------------------------- #
@dataclass
class Rule:
    id: str
    action: Action
    prefix: str
    ge: Optional[int] = None
    le: Optional[int] = None
    label: str = ""

    # 校验后填充
    network: IPNetwork = field(init=False, repr=False)
    ge_eff: int = field(init=False)
    le_eff: int = field(init=False)

    def __post_init__(self) -> None:
        if self.action not in ("permit", "deny"):
            raise PolicyError(f"规则 {self.id}: action 只能是 permit/deny，得到 {self.action!r}")
        # strict=True：拒绝 10.0.0.1/8 这类主机位非零写法（FRR 同样拒绝）
        try:
            net = ipaddress.ip_network(str(self.prefix), strict=True)
        except ValueError as exc:
            raise PolicyError(f"规则 {self.id}: 前缀非法 {self.prefix!r}（{exc}）")
        self.network = net
        maxlen = net.max_prefixlen
        pfxlen = net.prefixlen
        # FRR 语义：不带 ge/le 即精确匹配（ge=le=pfxlen）；
        # 只给 ge 时 le=maxlen；只给 le 时 ge=pfxlen。
        if self.ge is None and self.le is None:
            ge = le = pfxlen
        else:
            ge = pfxlen if self.ge is None else int(self.ge)
            le = maxlen if self.le is None else int(self.le)
        if not (pfxlen <= ge <= le <= maxlen):
            raise PolicyError(
                f"规则 {self.id}: 需要满足 prefixlen({pfxlen}) <= ge({ge}) <= le({le}) <= {maxlen}"
            )
        self.ge_eff, self.le_eff = ge, le
        # 规范化显示
        self.prefix = str(net)

    @property
    def version(self) -> int:
        return self.network.version

    @property
    def is_exact(self) -> bool:
        return self.ge_eff == self.le_eff == self.network.prefixlen

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "action": self.action,
            "prefix": self.prefix,
            "ge": self.ge_eff if self.ge_eff != self.network.prefixlen else None,
            "le": self.le_eff if self.le_eff != self.network.max_prefixlen else None,
            "label": self.label,
        }

    def matches_network(self, net: IPNetwork) -> bool:
        if net.version != self.version:
            return False  # v4/v6 不混算
        if net.prefixlen < self.ge_eff or net.prefixlen > self.le_eff:
            return False
        return net.subnet_of(self.network)


def make_rule(raw: dict) -> Rule:
    try:
        return Rule(
            id=str(raw["id"]),
            action=raw["action"],
            prefix=raw["prefix"],
            ge=raw.get("ge"),
            le=raw.get("le"),
            label=raw.get("label", "") or "",
        )
    except KeyError as exc:
        raise PolicyError(f"规则缺少字段: {exc}")


def parse_prefix(prefix: str) -> IPNetwork:
    try:
        return ipaddress.ip_network(str(prefix), strict=True)
    except ValueError as exc:
        raise PolicyError(f"查询前缀非法 {prefix!r}（{exc}）")


# --------------------------------------------------------------------------- #
# 策略
# --------------------------------------------------------------------------- #
@dataclass
class Policy:
    rules: list[Rule]
    default_v4: Action = "deny"
    default_v6: Action = "deny"
    name: str = ""

    def __post_init__(self) -> None:
        if self.default_v4 not in ("permit", "deny"):
            raise PolicyError("default_v4 必须为 permit/deny")
        if self.default_v6 not in ("permit", "deny"):
            raise PolicyError("default_v6 必须为 permit/deny")

    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        rules = [make_rule(r) for r in data.get("rules", [])]
        return cls(
            rules=rules,
            default_v4=data.get("default_v4", "deny"),
            default_v6=data.get("default_v6", "deny"),
            name=data.get("name", "") or "",
        )

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "default_v4": self.default_v4,
            "default_v6": self.default_v6,
            "rules": [r.to_dict() for r in self.rules],
        }

    def rules_of(self, version: int) -> list[Rule]:
        return [r for r in self.rules if r.version == version]

    def default_of(self, version: int) -> Action:
        return self.default_v4 if version == 4 else self.default_v6

    # ------------------------------------------------------------------ #
    # 求值
    # ------------------------------------------------------------------ #
    def evaluate(self, prefix: str) -> dict:
        net = parse_prefix(prefix)
        chain = []
        matched_rule: Optional[Rule] = None
        for rule in self.rules_of(net.version):
            # 命中链语义：只有“首条命中”标记 matched=True；
            # 范围上能匹配但排在首条之后的规则属于“被遮蔽的候选”，matched=False
            in_scope = rule.matches_network(net)
            hit = in_scope and matched_rule is None
            chain.append(
                {
                    "rule_id": rule.id,
                    "order": len(chain),
                    "action": rule.action,
                    "prefix": rule.prefix,
                    "ge": rule.ge_eff,
                    "le": rule.le_eff,
                    "matched": hit,
                    "in_scope": in_scope,
                    "terminal": False,
                }
            )
            if hit:
                matched_rule = rule
                chain[-1]["terminal"] = True
        if matched_rule is None:
            action = self.default_of(net.version)
            matched_id = None
        else:
            action = matched_rule.action
            matched_id = matched_rule.id
        default_action = self.default_of(net.version)
        chain.append(
            {
                "rule_id": None,
                "order": len(chain),
                "action": default_action,
                "prefix": DEFAULT_WORLD[net.version],
                "ge": 0,
                "le": MAXLEN[net.version],
                "matched": matched_rule is None,
                "terminal": True,
                "default": True,
            }
        )
        return {
            "prefix": str(net),
            "family": FAMILIES[net.version],
            "action": action,
            "matched_rule_id": matched_id,
            "chain": chain,
        }

    def evaluate_many(self, prefixes: Iterable[str]) -> list[dict]:
        return [self.evaluate(p) for p in prefixes]


# --------------------------------------------------------------------------- #
# 二进制前缀树 + 行为区域枚举
# --------------------------------------------------------------------------- #
# 为什么不能只做文本差异：
# 一条 ge/le 规则覆盖的是一个连续前缀集合（子树 × 长度区间），规则换序、
# 插入、默认动作翻转造成的影响面必须在“被放行/拒绝的实际前缀”上计算。
# 做法：把两版策略的锚点前缀放进同一棵二叉 Trie，切分出互不重叠的
# “行为单元”——锚点精确格 与 不含任何锚点的最大间隙子树；同一单元内
# 任一长度 L 的判定只取决于 (路径上的祖先规则集合, L)，因此每类只需一个
# 见证前缀即可代表，这在行为等价意义下是最小集合。

class _Node:
    __slots__ = ("net", "depth", "anchors", "left", "right")

    def __init__(self, net: IPNetwork, depth: int):
        self.net = net
        self.depth = depth
        self.anchors: list[Rule] = []
        self.left: Optional[_Node] = None
        self.right: Optional[_Node] = None


def _build_trie(version: int, rules: list[Rule]) -> _Node:
    root = _Node(ipaddress.ip_network(DEFAULT_WORLD[version]), 0)
    nodes: dict[IPNetwork, _Node] = {root.net: root}
    for rule in sorted(rules, key=lambda r: (r.network.prefixlen, int(r.network.network_address))):
        node = root
        net = rule.network
        for depth in range(1, net.prefixlen + 1):
            bit = (int(net.network_address) >> (net.max_prefixlen - depth)) & 1
            child = node.right if bit else node.left
            if child is None:
                child_net = ipaddress.ip_network(
                    f"{net.network_address}/{depth}", strict=False
                )
                child = _Node(child_net, depth)
                nodes[child_net] = child
                if bit:
                    node.right = child
                else:
                    node.left = child
            node = child
        node.anchors.append(rule)  # rules 已按 position 有序，同锚点保持插入序
    return root


def _relevant_lengths(version: int, list_of_rules: Iterable[list[Rule]]) -> list[int]:
    """
    判定可能发生变化的所有长度：
      0、每个规则的前缀长度（锚点深度）、每个范围的起点 ge 与终点 le+1。
    锚点深度与范围来源规则属于哪一版策略都要纳入（diff 时取两版并集）。
    """
    maxlen = MAXLEN[version]
    lengths = {0}
    for rules in list_of_rules:
        for r in rules:
            if r.version != version:
                continue
            lengths.add(r.network.prefixlen)
            lengths.add(r.ge_eff)
            if r.le_eff < maxlen:
                lengths.add(r.le_eff + 1)
    return sorted(lengths)


def _enumerate_cells(version: int, rules: list[Rule]) -> list[dict]:
    """
    返回行为单元列表：
      {"kind": "exact", "depth": L, "net": 锚点网络}
      {"kind": "gap",   "depth": L, "net": 最大无锚点子树网络}

    关键：间隙覆盖规则来自两类锚点——
      * 路径上的锥形祖先；
      * 间隙内部子树的“旁侧”锥形锚点（例如 /25 锥形覆盖同一 /24 另一 /25 的洞）。
    因此不能只按路径祖先归并；每个最大无锚点子树独立成单元，
    在见证层按实际判定签名去重，得到最小代表集合。
    """
    fam_rules = [r for r in rules if r.version == version]
    root = _build_trie(version, fam_rules)
    cells: list[dict] = []

    def walk(node: _Node) -> None:
        """
        后序归并：
          * 锚点节点 -> 精确单元；其内部未被更深锚点占据的子树输出最大间隙，
            保证锚点自身到后代锚点之间的锥形行为区域不丢失；
          * 非锚点内部节点 -> 只处理孩子（缺失的那个孩子就是一个最大间隙）；
          * 非锚点叶子 -> 以该节点为根的一个最大间隙。
        """
        if node.anchors:
            cells.append({"kind": "exact", "depth": node.depth, "net": node.net})
        elif node.left is None and node.right is None:
            cells.append({"kind": "gap", "depth": node.depth, "net": node.net})
            return

        subs = list(node.net.subnets(new_prefix=node.depth + 1))
        for bit, child in enumerate((node.left, node.right)):
            if child is None:
                cells.append({"kind": "gap", "depth": node.depth + 1, "net": subs[bit]})
            else:
                walk(child)

    if not fam_rules:
        cells.append({"kind": "gap", "depth": 0, "net": root.net})
    else:
        walk(root)
    return cells


def _witness(net: IPNetwork, length: int) -> IPNetwork:
    return ipaddress.ip_network(f"{net.network_address}/{length}", strict=False)


def _verdict_at(policy: Policy, version: int, net: IPNetwork) -> dict:
    res = policy.evaluate(str(net))
    return {
        "action": res["action"],
        "rule_id": res["matched_rule_id"],
        "label": next(
            (r.label for r in policy.rules_of(version) if r.id == res["matched_rule_id"]),
            "",
        ),
        "default": res["matched_rule_id"] is None,
    }


def _sig(v: dict) -> tuple:
    return (v["action"], v["rule_id"])


def witness_table(policy: Policy, version: int, extra_rules: Optional[list[Rule]] = None) -> list[dict]:
    """
    枚举某地址族全部行为单元 × 关键长度上的见证前缀及其判定。

    遮蔽分析必须看到每一个独立单元（两个单元即使判定相同也不能合并，
    否则会漏掉“仅被并集覆盖”的情形）；这里的去重只在同一单元内部发生。
    跨单元的最小化（按前后判定签名）在 diff_policies 中做。
    """
    other = extra_rules or []
    lengths = _relevant_lengths(version, [policy.rules, other])
    cells = _enumerate_cells(version, policy.rules + [r for r in other if r.version == version])
    rows: list[dict] = []
    for ci, cell in enumerate(cells):
        seen_len: set[int] = set()
        for length in lengths:
            if cell["kind"] == "exact":
                if length != cell["depth"]:
                    continue
                net = cell["net"]
            else:
                if length < cell["depth"]:
                    continue
                net = _witness(cell["net"], length)
            # 同一单元在同一长度上唯一
            mark = -1 if cell["kind"] == "exact" else length
            if mark in seen_len:
                continue
            seen_len.add(mark)
            rows.append(
                {
                    "witness": str(net),
                    "length": length,
                    "cell_kind": cell["kind"],
                    "cell_id": ci,
                    "verdict": _verdict_at(policy, version, net),
                }
            )
    rows.sort(key=lambda r: (int(ipaddress.ip_network(r["witness"]).network_address), r["length"]))
    return rows


# --------------------------------------------------------------------------- #
# 语义差异：最小变化前缀集合
# --------------------------------------------------------------------------- #
def diff_policies(before: Policy, after: Policy) -> dict:
    """对两个地址族分别求行为变化；同时给出文本层变化做辅助说明。"""
    out = {"families": {}}
    for version, fam in FAMILIES.items():
        lengths = _relevant_lengths(version, [before.rules, after.rules])
        # 用两版锚点的并集切分单元，保证任何一侧的变化都有代表
        union_rules = before.rules_of(version) + after.rules_of(version)
        cells = _enumerate_cells(version, union_rules)
        # 最小集合：判定在相邻“关键长度”之间恒定。
        # 同一长度上、前后判定签名相同的多个区域行为等价，只保留一个见证；
        # 不同长度即使签名相同也分别保留（/24 泄漏面与 /32 主机泄漏面各自独立）。
        change_buckets: dict[tuple, dict] = {}
        same_buckets: dict[tuple, dict] = {}
        for cell in cells:
            for length in lengths:
                if cell["kind"] == "exact":
                    if length != cell["depth"]:
                        continue
                    net = cell["net"]
                    length_mark = -1
                else:
                    if length < cell["depth"]:
                        continue
                    net = _witness(cell["net"], length)
                    length_mark = length
                b = _verdict_at(before, version, net)
                a = _verdict_at(after, version, net)
                changed = _sig(b) != _sig(a)
                action_flip = b["action"] != a["action"]
                key = (cell["kind"], length_mark, _sig(b), _sig(a))
                buckets = change_buckets if changed else same_buckets
                if key in buckets:
                    continue
                buckets[key] = {
                    "witness": str(net),
                    "length": length,
                    "cell_kind": cell["kind"],
                    "before": b,
                    "after": a,
                    "changed": changed,
                    "action_flipped": action_flip,
                    "reason": _explain_change(b, a, action_flip),
                }
        records = [*change_buckets.values(), *same_buckets.values()]
        records.sort(key=lambda r: (int(ipaddress.ip_network(r["witness"]).network_address), r["length"]))
        changed = [r for r in records if r["changed"]]
        flips = [r for r in records if r["action_flipped"]]
        out["families"][fam] = {
            "witnesses": records,
            "minimal_change_set": changed,
            "action_flips": flips,
            "summary": {
                "cells_checked": len(records),
                "changed_cells": len(changed),
                "action_flip_cells": len(flips),
                "default": {
                    "before": before.default_of(version),
                    "after": after.default_of(version),
                    "changed": before.default_of(version) != after.default_of(version),
                },
            },
        }

    out["text"] = _text_diff(before, after)
    return out


def _explain_change(b: dict, a: dict, flip: bool) -> str:
    def who(v: dict) -> str:
        return "默认动作" if v["default"] else f"规则 {v['rule_id']}"

    def act(v: dict) -> str:
        return "放行" if v["action"] == "permit" else "拒绝"

    if not flip and b["rule_id"] != a["rule_id"]:
        return f"动作仍为{act(a)}，但命中规则由{who(b)}变为{who(a)}（遮蔽/换序）"
    arrow = "误放行" if (b["action"] == "deny" and a["action"] == "permit") else (
        "误拒绝" if b["action"] == "permit" and a["action"] == "deny" else "动作变化"
    )
    return f"{arrow}：{act(b)}→{act(a)}，判定由{who(b)}变为{who(a)}"


def _text_diff(before: Policy, after: Policy) -> dict:
    added, removed, modified = [], [], []
    b_idx = {r.id: r for r in before.rules}
    a_idx = {r.id: r for r in after.rules}
    for rid, r in a_idx.items():
        if rid not in b_idx:
            added.append(r.to_dict())
        else:
            old = b_idx[rid]
            if (old.action, old.prefix, old.ge_eff, old.le_eff) != (
                r.action, r.prefix, r.ge_eff, r.le_eff
            ):
                modified.append({"id": rid, "before": old.to_dict(), "after": r.to_dict()})
    for rid, r in b_idx.items():
        if rid not in a_idx:
            removed.append(r.to_dict())
    reordered = []
    kept_b = [r.id for r in before.rules if r.id in a_idx]
    kept_a = [r.id for r in after.rules if r.id in b_idx]
    if kept_b != kept_a:
        reordered = [{"id": rid, "before": kept_b.index(rid), "after": kept_a.index(rid)}
                     for rid in kept_a if kept_b.index(rid) != kept_a.index(rid)]
    return {
        "added": added,
        "removed": removed,
        "modified": modified,
        "reordered": reordered,
        "default_changes": {
            "ipv4": before.default_v4 != after.default_v4,
            "ipv6": before.default_v6 != after.default_v6,
        },
    }


# --------------------------------------------------------------------------- #
# 遮蔽分析
# --------------------------------------------------------------------------- #
def _shadow_witnesses(policy: Policy, version: int) -> list[dict]:
    """
    遮蔽分析专用见证表：在每个无锚点间隙区域上，对“任一规则的范围端点”都取样。
    与 diff 的关键长度采样不同——遮蔽必须覆盖每条规则自己的 [ge,le] 全区间，
    否则像 deny /16 ge16 le23 这种在 16..23 上被遮蔽、24 以上却无关的规则会漏判。
    """
    maxlen = MAXLEN[version]
    fam = policy.rules_of(version)
    lengths = {0}
    for r in fam:
        # 规则自身锚点深度、范围起点/终点及其相邻长度都要取样：
        # 遮蔽要覆盖整条 [ge,le]，而“锚点+1”这类内部间隙不一定是任何规则的边界。
        lengths.add(r.network.prefixlen)
        lengths.add(r.ge_eff)
        if r.ge_eff < maxlen:
            lengths.add(r.ge_eff + 1)
        lengths.add(r.le_eff)
        if r.le_eff < maxlen:
            lengths.add(r.le_eff + 1)
    cells = _enumerate_cells(version, fam)
    uniq: dict[str, dict] = {}
    for cell in cells:
        for length in sorted(lengths):
            if cell["kind"] == "exact":
                if length != cell["depth"]:
                    continue
                net = cell["net"]
            else:
                if length < cell["depth"]:
                    continue
                net = _witness(cell["net"], length)
            uniq.setdefault(str(net), {"witness": str(net), "length": length, "net": net})
    for row in uniq.values():
        row["verdict"] = _verdict_at(policy, version, row["net"])
    return list(uniq.values())


def find_shadowed(policy: Policy) -> dict:
    """
    找出永远不可能成为首条命中的规则。
    判定在行为单元见证集上进行（对整个真实前缀空间可靠，不依赖随机抽样）：
      * 该规则能命中的每个见证，首条命中都是更靠前的规则 → 完全遮蔽
      * 存在单一覆盖规则             -> cover_type=single
      * 没有单一规则但被靠前规则的并集覆盖 -> cover_type=union
    """
    out = {"families": {}}
    for version, fam in FAMILIES.items():
        rules = policy.rules_of(version)
        table = _shadow_witnesses(policy, version)
        result = []
        for i, rule in enumerate(rules):
            earlier = rules[:i]
            mine = []
            for row in table:
                net = parse_prefix(row["witness"])
                if rule.matches_network(net):
                    mine.append(row)
            blocked = [row for row in mine if row["verdict"]["rule_id"] != rule.id]
            if mine and len(blocked) == len(mine):
                coverers: dict[str, int] = {}
                for row in blocked:
                    hit = row["verdict"]["rule_id"]
                    coverers[hit] = coverers.get(hit, 0) + 1
                single = None
                for e in earlier:
                    if all(e.matches_network(parse_prefix(row["witness"])) for row in mine):
                        single = e.id
                        break
                proof = [
                    {
                        "witness": row["witness"],
                        "hit_rule_id": row["verdict"]["rule_id"],
                        "hit_label": row["verdict"]["label"],
                    }
                    for row in blocked[:5]
                ]
                result.append(
                    {
                        "rule_id": rule.id,
                        "rule": rule.to_dict(),
                        "position": i,
                        "cover_type": "single" if single else "union",
                        "single_cover_rule_id": single,
                        "coverers": [
                            {"rule_id": rid, "regions": cnt} for rid, cnt in coverers.items()
                        ],
                        "proof": proof,
                    }
                )
        result.sort(key=lambda s: s["position"])
        out["families"][fam] = {"shadowed": result, "rule_count": len(rules)}
    return out


# --------------------------------------------------------------------------- #
# 前缀树视图（供 UI）
# --------------------------------------------------------------------------- #
def trie_view(policy: Policy, version: int, query: Optional[str] = None) -> dict:
    rules = policy.rules_of(version)
    root = _build_trie(version, rules)

    path_nets: set[str] = set()
    hit_id = None
    query_result = None
    if query:
        q = policy.evaluate(query)
        if q["family"] != FAMILIES[version]:
            raise PolicyError(f"查询前缀 {query} 不属于 {FAMILIES[version]}")
        hit_id = q["matched_rule_id"]
        query_result = q
        qnet = parse_prefix(query)
        cur = root
        path_nets.add(str(cur.net))
        for depth in range(1, qnet.prefixlen + 1):
            bit = (int(qnet.network_address) >> (qnet.max_prefixlen - depth)) & 1
            cur = cur.right if bit else cur.left
            if cur is None:
                break
            path_nets.add(str(cur.net))

    def node_dict(node: _Node) -> dict:
        return {
            "prefix": str(node.net),
            "depth": node.depth,
            "rules": [r.to_dict() | {"order": policy.rules.index(r)} for r in node.anchors],
            "matched_rule_id": hit_id if any(r.id == hit_id for r in node.anchors) else None,
            "on_query_path": str(node.net) in path_nets,
            "children": [
                node_dict(node.left) if node.left else None,
                node_dict(node.right) if node.right else None,
            ],
        }

    return {"family": FAMILIES[version], "root": node_dict(root), "query": query_result}
