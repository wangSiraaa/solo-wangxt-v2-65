"""引擎语义单测：精确/范围/首条匹配/默认拒绝/v4v6 隔离。"""
import ipaddress

import pytest

from app.engine import (
    Policy,
    PolicyError,
    Rule,
    diff_policies,
    find_shadowed,
    make_rule,
    trie_view,
)


def P(rows, dv4="deny", dv6="deny"):
    return Policy(
        rules=[make_rule({"id": f"r{i}", **r}) for i, r in enumerate(rows)],
        default_v4=dv4,
        default_v6=dv6,
    )


# deny 锥形封锁测试段在前，permit 业务锥形在后 —— 与真实例外顺序一致
BASE = [
    {"action": "deny", "prefix": "10.1.0.0/16", "ge": 16, "le": 32},
    {"action": "permit", "prefix": "10.0.0.0/8", "ge": 9, "le": 24},
]


def test_exact_vs_range_semantics():
    p = P(BASE)
    cases = {
        "10.0.0.0/8": ("deny", None),       # ge 9：聚合本身不匹配
        "10.0.1.0/24": ("permit", "r1"),
        "10.1.0.0/16": ("deny", "r0"),      # deny 锥形包含聚合自身
        "10.1.5.0/24": ("deny", "r0"),      # 明细也在封锁锥形内
        "10.0.0.0/25": ("deny", None),      # 超 permit 的 le
        "192.0.2.0/24": ("deny", None),     # 默认拒绝
        "10.1.0.1/32": ("deny", "r0"),
    }
    for prefix, (action, rid) in cases.items():
        r = p.evaluate(prefix)
        assert (r["action"], r["matched_rule_id"]) == (action, rid), prefix


def test_chain_is_first_match_and_default_terminal():
    p = P(BASE)
    chain = p.evaluate("10.1.0.0/16")["chain"]
    assert chain[0]["matched"] and chain[0]["terminal"]
    assert chain[1]["matched"] is False and chain[1]["terminal"] is False
    assert chain[1]["in_scope"] is True  # 业务锥形也覆盖 /16，只是封锁规则先生效
    default_node = chain[-1]
    assert default_node["default"] is True
    assert default_node["action"] == "deny"
    # 即使规则命中，默认节点也必须展示地址族自身的默认动作，而不是命中动作
    p_perm = P(BASE, dv4="permit")
    last = p_perm.evaluate("10.1.0.0/16")["chain"][-1]
    assert last["action"] == "permit" and last["matched"] is False

    # 范围上能匹配但排在首条之后的规则是“被遮蔽候选”，不应标记为 matched
    shadowed_p = P([
        {"action": "permit", "prefix": "10.0.0.0/8", "ge": 9, "le": 24},
        {"action": "deny", "prefix": "10.1.0.0/16"},
    ])
    c = shadowed_p.evaluate("10.1.0.0/16")["chain"]
    assert c[0]["matched"] is True and c[1]["matched"] is False
    assert c[1]["in_scope"] is True  # 范围确实覆盖，只是被首条遮蔽


def test_ipv4_ipv6_never_mix():
    p = P([{"action": "permit", "prefix": "10.0.0.0/8"}])
    assert p.evaluate("2001:db8::/32")["action"] == "deny"
    rule = make_rule({"id": "x", "action": "permit", "prefix": "10.0.0.0/8"})
    assert rule.matches_network(ipaddress.ip_network("2001:db8::/32")) is False
    # deny ::/0 是精确匹配（只匹配 ::/0 本身），128 位地址落到默认 permit
    p6 = P([{"action": "deny", "prefix": "::/0"}], dv6="permit")
    assert p6.evaluate("2001:db8::1/128")["action"] == "permit"
    assert p6.evaluate("::/0")["action"] == "deny"
    assert p6.evaluate("10.0.0.1/32")["action"] == "deny"  # v4 默认不受 v6 影响


def test_validation_rejects_host_bits_and_bad_ranges():
    with pytest.raises(PolicyError):
        make_rule({"id": "x", "action": "permit", "prefix": "10.0.0.1/8"})
    with pytest.raises(PolicyError):
        make_rule({"id": "x", "action": "permit", "prefix": "10.0.0.0/8", "ge": 30, "le": 24})
    with pytest.raises(PolicyError):
        make_rule({"id": "x", "action": "permit", "prefix": "10.0.0.0/8", "ge": 33})
    with pytest.raises(PolicyError):
        Policy.from_dict({"default_v4": "bogus", "rules": []})


def test_shadowed_single_and_union():
    # 单条覆盖：锥形 permit 在精确 deny 之前，/16 被锥形完全覆盖（9<=16<=24）
    p = P([
        {"action": "permit", "prefix": "10.0.0.0/8", "ge": 9, "le": 24},
        {"action": "deny", "prefix": "10.1.0.0/16"},
    ])
    sh = find_shadowed(p)["families"]["ipv4"]["shadowed"]
    assert [(s["rule_id"], s["cover_type"], s["single_cover_rule_id"]) for s in sh] == [
        ("r1", "single", "r0")
    ]

    # 精确规则互不遮蔽（精确匹配只覆盖自身）
    p_exact = P([
        {"action": "permit", "prefix": "10.0.0.0/8"},
        {"action": "deny", "prefix": "10.1.0.0/16"},
    ])
    assert find_shadowed(p_exact)["families"]["ipv4"]["shadowed"] == []

    # 并集遮蔽：两个 /25 锥形（ge25 le26）拼出 /24 的 /25-/26 空间，
    # 随后的 deny 10.0.0.0/24 ge25 le26 没有任何单条规则能单独覆盖另一半，
    # 但它永远不可能成为首条命中 —— 必须由并集分析抓出。
    p2 = P([
        {"action": "permit", "prefix": "10.0.0.0/25", "ge": 25, "le": 26},
        {"action": "permit", "prefix": "10.0.0.128/25", "ge": 25, "le": 26},
        {"action": "deny", "prefix": "10.0.0.0/24", "ge": 25, "le": 26},
    ])
    sh2 = find_shadowed(p2)["families"]["ipv4"]["shadowed"]
    assert len(sh2) == 1 and sh2[0]["rule_id"] == "r2"
    assert sh2[0]["cover_type"] == "union"
    assert {c["rule_id"] for c in sh2[0]["coverers"]} == {"r0", "r1"}
    assert sh2[0]["proof"], "必须给出可复现的遮蔽见证前缀"


def test_reorder_changes_action():
    before = P([
        {"action": "deny", "prefix": "10.1.0.0/16"},
        {"action": "permit", "prefix": "10.0.0.0/8", "ge": 9, "le": 24},
    ])
    after = P([
        {"action": "permit", "prefix": "10.0.0.0/8", "ge": 9, "le": 24},
        {"action": "deny", "prefix": "10.1.0.0/16"},
    ])
    d = diff_policies(before, after)["families"]["ipv4"]
    flips = {r["witness"]: r for r in d["action_flips"]}
    assert "10.1.0.0/16" in flips
    assert flips["10.1.0.0/16"]["before"]["action"] == "deny"
    assert flips["10.1.0.0/16"]["after"]["action"] == "permit"
    # 同动作但换命中规则的点也必须指出（不只是 permit/deny 翻转）
    same_action = {r["witness"]: r for r in d["minimal_change_set"] if not r["action_flipped"]}
    assert same_action, "换序后 10.0.1.0/24 等点命中规则身份发生变化，应被最小集合覆盖"
    sample = next(iter(same_action.values()))
    assert sample["before"]["rule_id"] != sample["after"]["rule_id"]
    assert sample["before"]["action"] == sample["after"]["action"]


def test_default_flip_touches_all_unmatched_space():
    before = P([{"action": "permit", "prefix": "10.0.0.0/8", "ge": 9, "le": 24}], dv4="deny")
    after = P([{"action": "permit", "prefix": "10.0.0.0/8", "ge": 9, "le": 24}], dv4="permit")
    d = diff_policies(before, after)["families"]["ipv4"]
    witnesses = {r["witness"] for r in d["action_flips"]}
    assert any(w.startswith("0.0.0.0/") for w in witnesses)
    # 显式命中的点不受影响
    assert "10.0.1.0/24" not in witnesses
    assert d["summary"]["default"]["changed"] is True


def test_witness_completeness_via_exhaustive_enumeration():
    """
    穷举 10.0.0.0/8 内 /8../12 共 31 个真实前缀：
      任一真实差异的（前判定,后判定）签名都必须在最小变化集合里出现（完备）；
      最小集合每条记录都必须对应真实差异（无虚报）。
    """
    before = P([
        {"action": "deny", "prefix": "10.1.0.0/16", "ge": 16, "le": 32},
        {"action": "permit", "prefix": "10.0.0.0/8", "ge": 9, "le": 24},
    ])
    after = P([
        {"action": "permit", "prefix": "10.1.0.0/16", "ge": 24, "le": 32},
        {"action": "deny", "prefix": "10.1.0.0/16", "ge": 16, "le": 32},
        {"action": "permit", "prefix": "10.0.0.0/8", "ge": 9, "le": 24},
    ])
    universe = []
    root = ipaddress.ip_network("10.0.0.0/8")
    for length in range(8, 13):
        universe.extend(root.subnets(new_prefix=length))

    def verdict(pol, net):
        r = pol.evaluate(str(net))
        return r["action"], r["matched_rule_id"]

    d = diff_policies(before, after)["families"]["ipv4"]
    real_diffs = [n for n in universe if verdict(before, n) != verdict(after, n)]
    assert real_diffs
    changed = d["minimal_change_set"]
    signatures = {(c["before"]["action"], c["before"]["rule_id"],
                   c["after"]["action"], c["after"]["rule_id"]) for c in changed}
    # 无虚报
    assert all(c["changed"] for c in changed)
    # 完备：每个真实差异签名均有见证
    for net in real_diffs:
        b = before.evaluate(str(net))
        a = after.evaluate(str(net))
        assert (b["action"], b["matched_rule_id"],
                a["action"], a["matched_rule_id"]) in signatures, str(net)
    # 最小：同一长度 × 同一（前后签名）的区域不会重复出现代表
    keyed = [(c["length"], c["before"]["action"], c["before"]["rule_id"],
              c["after"]["action"], c["after"]["rule_id"]) for c in changed]
    assert len(keyed) == len(set(keyed))
    # 真实泄漏点必须在见证里
    assert "10.1.0.0/24" in {c["witness"] for c in changed if c["action_flipped"]}


def test_ipv6_witness_set_is_small_not_enumerated():
    before = P([
        {"action": "deny", "prefix": "2001:db8:1::/48", "ge": 48, "le": 128},
        {"action": "permit", "prefix": "2001:db8::/32", "ge": 48, "le": 64},
    ])
    after = P([
        {"action": "permit", "prefix": "2001:db8:1::/48", "ge": 56, "le": 64},
        {"action": "deny", "prefix": "2001:db8:1::/48", "ge": 48, "le": 128},
        {"action": "permit", "prefix": "2001:db8::/32", "ge": 48, "le": 64},
        {"action": "deny", "prefix": "2001:db8:1::/48", "ge": 72, "le": 128},
    ])
    d = diff_policies(before, after)["families"]["ipv6"]
    flips = {r["witness"]: r for r in d["action_flips"]}
    assert "2001:db8:1::/56" in flips
    # /65 超出两个 permit 的 le 64，deny 锥形仍生效 -> 不在误放行集合
    assert "2001:db8:1::/65" not in flips
    assert d["summary"]["cells_checked"] < 120  # 有界，不随 2^128 膨胀
    # 末尾细化 deny 完全落在 r1(deny 锥形) 之内 -> 单条遮蔽
    sh = find_shadowed(after)["families"]["ipv6"]["shadowed"]
    assert [(s["rule_id"], s["cover_type"], s["single_cover_rule_id"]) for s in sh] == [
        ("r3", "single", "r1")
    ]
    # 且 /72 前缀两版都拒绝（r4 遮蔽与否对结果无影响，但遮蔽面板必须指出它）
    assert before.evaluate("2001:db8:1::/72")["action"] == "deny"
    assert after.evaluate("2001:db8:1::/72")["action"] == "deny"


def test_trie_view_marks_query_path():
    p = P(BASE)
    view = trie_view(p, 4, "10.1.0.0/16")
    path_prefixes = []

    def walk(node):
        if node is None:
            return
        if node["on_query_path"]:
            path_prefixes.append(node["prefix"])
        walk(node["children"][0])
        walk(node["children"][1])

    walk(view["root"])
    assert "10.0.0.0/8" in path_prefixes
    assert "10.1.0.0/16" in path_prefixes
    assert view["query"]["matched_rule_id"] == "r0"
