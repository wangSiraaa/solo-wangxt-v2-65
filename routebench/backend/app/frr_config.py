"""
FRRouting 配置生成（模拟器与容器共用同一份规则文本）。

映射模型：
  route-map SEQ <permit|deny>
    match ip/ipv6 address prefix-list NAME
  ip prefix-list NAME SEQ <permit|deny> NET/LEN [ge N] [le M]

策略默认 deny 用一条空的 deny 序列（或 route-map 无匹配）表达；
默认 permit 则在末尾显式补 permit 0.0.0.0/0 le 32 / ::/0 le 128，
使“默认动作变化”在容器侧同样可观测，而不是依赖隐式差异。
"""
from __future__ import annotations

from .engine import Policy, FAMILIES

SEQ_STEP = 10


def render_prefix_list(policy: Policy, version: int, name: str) -> list[str]:
    proto = "ipv6" if version == 6 else "ip"
    lines: list[str] = []
    fam_rules = policy.rules_of(version)
    for i, rule in enumerate(fam_rules):
        seq = (i + 1) * SEQ_STEP
        if rule.is_exact:
            rng = ""
        else:
            # FRR：ge 缺省=前缀长度、le 缺省=maxlen，但两者都省略会退化为“精确”；
            # 因此只要不是精确匹配，至少显式写出 ge 或 le 中的一个。
            parts = []
            if rule.ge_eff != rule.network.prefixlen:
                parts.append(f"ge {rule.ge_eff}")
            if rule.le_eff != rule.network.max_prefixlen:
                parts.append(f"le {rule.le_eff}")
            if not parts:
                # 全锥形（ge=pfxlen, le=maxlen）：显式写全
                parts = [f"ge {rule.ge_eff}", f"le {rule.le_eff}"]
            rng = " " + " ".join(parts)
        lines.append(f"{proto} prefix-list {name} seq {seq} {rule.action} {rule.network}{rng}")

    default = policy.default_of(version)
    tail_seq = (len(fam_rules) + 1) * SEQ_STEP
    if default == "permit":
        # 显式表达默认放行
        world = "::/0 le 128" if version == 6 else "0.0.0.0/0 le 32"
        lines.append(f"{proto} prefix-list {name} seq {tail_seq} permit {world}")
    # default == deny 时不加放行尾：FRR prefix-list 自身结尾即隐式 deny any，
    # route-map 无序列匹配时也走隐式 deny。
    return lines


def render_route_map(policy: Policy, version: int, name: str, plist_name: str) -> list[str]:
    """
    prefix-list 自身按 seq 首条匹配并自带 permit/deny 动作，因此 route-map 只需：
      序列 10 permit + match prefix-list —— prefix-list 放行则通过，
      prefix-list 拒绝则本序列不匹配、落到序列 20 的显式 deny；
    默认 permit 时 prefix-list 尾部有 any 放行，同样在序列 10 通过。
    """
    proto = "ipv6" if version == 6 else "ip"
    return [
        f"route-map {name} permit 10",
        f" match {proto} address prefix-list {plist_name}",
        f"route-map {name} deny 20",
    ]


def render_applied_config(policy: Policy) -> dict:
    """生成一次 cross-check 需要灌入 A 设备的配置段（先删后建）。"""
    blocks: list[str] = []
    names = {}
    for version, fam in FAMILIES.items():
        plist = f"RB_{fam.upper()}_PL"
        rmap = f"RB_{fam.upper()}_OUT"
        names[fam] = {"prefix_list": plist, "route_map": rmap}
        # 删除旧版本（no 命令对不存在的对象在 FRR 中安全）
        blocks.append(f"no {('ipv6' if version == 6 else 'ip')} prefix-list {plist}")
        blocks.append(f"no route-map {rmap}")
        blocks.extend(render_prefix_list(policy, version, plist))
        blocks.extend(render_route_map(policy, version, rmap, plist))
    return {"lines": blocks, "names": names}


# --------------------------------------------------------------------------- #
# 基座配置（两容器、多协议 eBGP over IPv4、预装 Null0 测试路由）
# --------------------------------------------------------------------------- #
A_IP = "172.30.0.2"
B_IP = "172.30.0.3"
A_ASN = 65001
B_ASN = 65002


def render_base_configs(static_prefixes: list[str]) -> dict:
    v4_static = [p for p in static_prefixes if ":" not in p]
    v6_static = [p for p in static_prefixes if ":" in p]

    a_lines = [
        "hostname frr-a",
        "ip route 10.0.0.0/8 Null0",  # 见下方全量逐条添加（占位，实际用真实明细）
    ]
    a_lines = ["hostname frr-a", "log syslog", "!", "frr defaults traditional"]
    for p in v4_static:
        a_lines.append(f"ip route {p} Null0")
    for p in v6_static:
        a_lines.append(f"ipv6 route {p} Null0")
    a_lines += [
        "!",
        "router bgp 65001",
        " bgp router-id 172.30.0.2",
        " no bgp ebgp-requires-policy",
        f" neighbor {B_IP} remote-as 65002",
        " address-family ipv4 unicast",
        f" neighbor {B_IP} activate",
        " redistribute static",
        " exit-address-family",
        " address-family ipv6 unicast",
        f" neighbor {B_IP} activate",
        " redistribute static",
        " exit-address-family",
        "!",
        "line vty",
    ]

    b_lines = [
        "hostname frr-b",
        "log syslog",
        "!",
        "frr defaults traditional",
        "router bgp 65002",
        " bgp router-id 172.30.0.3",
        " no bgp ebgp-requires-policy",
        f" neighbor {A_IP} remote-as 65001",
        " address-family ipv4 unicast",
        f" neighbor {A_IP} activate",
        " exit-address-family",
        " address-family ipv6 unicast",
        f" neighbor {A_IP} activate",
        " exit-address-family",
        "!",
        "line vty",
    ]
    return {"frr-a": "\n".join(a_lines) + "\n", "frr-b": "\n".join(b_lines) + "\n"}


DAEMONS = """zebra=yes
bgpd=yes
ospfd=no
ospf6d=no
ripd=no
ripngd=no
isisd=no
pimd=no
ldpd=no
nhrpd=no
eigrpd=no
babeld=no
sharpd=no
pbrd=no
bfdd=no
fabricd=no
vrrpd=no
pathd=no
"""
