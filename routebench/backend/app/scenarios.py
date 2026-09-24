"""内置推演案例。

每个案例给出 before/after 两版 Policy、用于容器交叉验证的测试前缀集合和说明。
覆盖需求中明确要求的三类典型变化：
  1. over-permit   更具体路由误放行（明细 permit 被插到 deny 聚合之前）
  2. reorder       规则换序（deny 聚合被 permit 锥形推到后面而失效）
  3. default-flip  默认动作变化
另含 IPv6 案例，专门验证 v4/v6 不混算与长掩码空间下的见证枚举。

规则顺序按真实网络意图书写：需要例外拒绝的明细/聚合放在 permit 锥形之前，
这样“换序”和“遮蔽”才有业务意义。
"""
from __future__ import annotations

V4_OVERPERMIT_PREFIXES = [
    "10.0.0.0/8",      # 锥形 permit ge9 le24 不含 /8 自身
    "10.0.1.0/24",     # 命中 permit 范围
    "10.1.0.0/16",     # 聚合本身：变换后被业务锥形放行
    "10.1.0.0/17",     # /16-/23 中间长度段
    "10.1.0.0/24",     # 关键：明细泄漏
    "10.1.0.1/32",     # 主机路由也被带出
    "10.2.0.0/16",     # 正常 permit
    "10.0.0.0/25",     # 超过 le 24，默认拒绝
    "192.0.2.0/24",    # 默认拒绝
]

V4_REORDER_PREFIXES = [
    "10.0.0.0/8",
    "10.1.0.0/16",
    "10.2.0.0/16",
]

V4_DEFAULT_PREFIXES = [
    "10.0.0.0/8",
    "192.0.2.0/24",
    "8.8.8.8/32",
]

V6_PREFIXES = [
    "2001:db8::/32",       # ge 48 不含 /32 自身
    "2001:db8::/48",       # permit 范围
    "2001:db8:1::/48",     # 精确 deny（变换后仍 deny）
    "2001:db8:1::/56",     # 变换后 ge 56 明细泄漏
    "2001:db8:1::/72",     # 超出 r3 的 le64，仍走 r2 deny
    "2001:db8:9::/64",     # 正常 permit
    "2001:db9::/48",       # 默认拒绝
]

ALL_TEST_PREFIXES = V4_OVERPERMIT_PREFIXES + V4_REORDER_PREFIXES + V4_DEFAULT_PREFIXES + V6_PREFIXES


def _rule(rid, action, prefix, ge=None, le=None, label=""):
    d = {"id": rid, "action": action, "prefix": prefix, "label": label}
    if ge is not None:
        d["ge"] = ge
    if le is not None:
        d["le"] = le
    return d


SCENARIOS = {
    "v4-over-permit": {
        "title": "IPv4 更具体路由误放行",
        "family": "ipv4",
        "description": (
            "运维意图：放行 10/8 上 9..24 位业务前缀，但封锁测试段 10.1.0.0/16"
            "及其所有更具体路由，基线用 deny 10.1.0.0/16 ge 16 le 32 放在最前。"
            "改动时误把一条 permit 10.1.0.0/16 ge 24 le 32 的‘明细放行’插到最前，"
            "于是 /24、/32 明细（含主机路由）被整体带出。文本 diff 只看到新增一行，"
            "语义面板必须指出 10.1.0.0/24 等具体泄漏点，而不只是顺序变化。"
        ),
        "test_prefixes": V4_OVERPERMIT_PREFIXES,
        "before": {
            "name": "baseline-deny-cone",
            "default_v4": "deny",
            "default_v6": "deny",
            "rules": [
                _rule("r2", "deny", "10.1.0.0/16", ge=16, le=32, label="封锁测试段及全部明细"),
                _rule("r1", "permit", "10.0.0.0/8", ge=9, le=24, label="放行 /8 内常见业务掩码"),
            ],
        },
        "after": {
            "name": "leaked-morespecific",
            "default_v4": "deny",
            "default_v6": "deny",
            "rules": [
                _rule("r3", "permit", "10.1.0.0/16", ge=24, le=32, label="误加：更具体放行洞"),
                _rule("r2", "deny", "10.1.0.0/16", ge=16, le=32,
                      label="原全锥形拒绝：/16-/23 仍生效，/24+ 被 r3 遮蔽"),
                _rule("r1", "permit", "10.0.0.0/8", ge=9, le=24, label="放行 /8 内常见业务掩码"),
                _rule("r4", "deny", "10.1.0.0/16", ge=17, le=23,
                      label="清理时保留的细化拒绝：完全落在 r2 锥形内，单条遮蔽（应清理）"),
            ],
        },
    },
    "v4-reorder": {
        "title": "IPv4 规则换序",
        "family": "ipv4",
        "description": (
            "首条匹配模型下，把精确 deny 10.1.0.0/16 挪到 permit 锥形 ge9 le24 之后，"
            "/16 恰好落在锥形范围内（9<=16<=24），deny 立刻失效；语义差异面板必须指出"
            "10.1.0.0/16 由拒绝变放行，且同动作换命中规则的点（如 /8 聚合）也要可见。"
        ),
        "test_prefixes": V4_REORDER_PREFIXES,
        "before": {
            "name": "deny-first",
            "default_v4": "deny",
            "default_v6": "deny",
            "rules": [
                _rule("r2", "deny", "10.1.0.0/16"),
                _rule("r1", "permit", "10.0.0.0/8", ge=9, le=24),
            ],
        },
        "after": {
            "name": "permit-first",
            "default_v4": "deny",
            "default_v6": "deny",
            "rules": [
                _rule("r1", "permit", "10.0.0.0/8", ge=9, le=24),
                _rule("r2", "deny", "10.1.0.0/16"),
            ],
        },
    },
    "v4-default-flip": {
        "title": "IPv4 默认动作变化",
        "family": "ipv4",
        "description": (
            "规则一行未动，仅把默认拒绝改为默认放行；所有未显式命中的前缀"
            "（192.0.2.0/24、8.8.8.8/32，以及 10/8 内 /25 以上的掩码）整体反转。"
            "文本 diff 只有一个开关，行为差异面板给出每个受影响区域的最小见证。"
        ),
        "test_prefixes": V4_DEFAULT_PREFIXES,
        "before": {
            "name": "default-deny",
            "default_v4": "deny",
            "default_v6": "deny",
            "rules": [_rule("r1", "permit", "10.0.0.0/8", ge=9, le=24)],
        },
        "after": {
            "name": "default-permit",
            "default_v4": "permit",
            "default_v6": "deny",
            "rules": [_rule("r1", "permit", "10.0.0.0/8", ge=9, le=24)],
        },
    },
    "v6-over-permit": {
        "title": "IPv6 更具体路由误放行（v4/v6 不混算）",
        "family": "ipv6",
        "description": (
            "与 v4 案例同构的 IPv6 版本：保留块 2001:db8:1::/48 及其明细本被封锁，"
            "误插入的 permit 2001:db8:1::/48 ge 56 le 64 让 /56-/64 的 IPv6 明细泄漏。"
            "模拟器对 IPv6 不做地址枚举，只产出有界数量的行为见证。"
        ),
        "test_prefixes": V6_PREFIXES,
        "before": {
            "name": "v6-baseline",
            "default_v4": "deny",
            "default_v6": "deny",
            "rules": [
                _rule("r2", "deny", "2001:db8:1::/48", ge=48, le=128, label="封锁保留块及全部明细"),
                _rule("r1", "permit", "2001:db8::/32", ge=48, le=64, label="放行 /48-/64 业务块"),
            ],
        },
        "after": {
            "name": "v6-leaked",
            "default_v4": "deny",
            "default_v6": "deny",
            "rules": [
                _rule("r3", "permit", "2001:db8:1::/48", ge=56, le=64, label="误加：更细 IPv6 放行"),
                _rule("r2", "deny", "2001:db8:1::/48", ge=48, le=128, label="封锁保留块（/56-/64 被 r3 遮蔽）"),
                _rule("r1", "permit", "2001:db8::/32", ge=48, le=64, label="放行 /48-/64 业务块"),
                _rule("r4", "deny", "2001:db8:1::/48", ge=72, le=128,
                      label="冗余细化拒绝：完全落在 r2 锥形内，单条遮蔽（应清理）"),
            ],
        },
    },
}


def all_static_prefixes() -> list[str]:
    """FRR 容器 A 上预装 Null0 静态路由的并集（各案例共享）。"""
    seen = []
    for p in ALL_TEST_PREFIXES:
        if p not in seen:
            seen.append(p)
    return seen
