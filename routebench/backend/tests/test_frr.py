"""
FRR 交叉验证测试。

* test_frr_config_*   离线：渲染出的 FRR 配置文本必须与引擎判定一一对应
                      （默认 deny 无尾放行；默认 permit 显式 any 尾）
* test_lab_*          需要本机 docker 与镜像 frrouting/frr:latest，
                      默认跳过；用 `pytest --run-frr` 开启真实容器对照。
"""
import os

import pytest

from app.engine import Policy
from app.frr_config import render_applied_config, render_base_configs
from app.scenarios import SCENARIOS, all_static_prefixes


def _pol(scenario_id, side):
    return Policy.from_dict(SCENARIOS[scenario_id][side])


def test_base_config_has_static_null_routes_and_bgp():
    cfg = render_base_configs(all_static_prefixes())
    assert "ip route 10.1.0.0/24 Null0" in cfg["frr-a"]
    assert "ipv6 route 2001:db8:1::/56 Null0" in cfg["frr-a"]
    assert "redistribute static" in cfg["frr-a"]
    assert "address-family ipv6 unicast" in cfg["frr-a"]
    assert cfg["frr-b"].count("neighbor 172.30.0.2 remote-as 65001") == 1


def test_route_map_semantics_match_engine_defaults():
    # 默认 permit：prefix-list 尾部 any 放行，route-map 仍只需一个引用序列
    pol_perm = Policy.from_dict(SCENARIOS["v4-default-flip"]["after"])
    text = "\n".join(render_applied_config(pol_perm)["lines"])
    assert "ip prefix-list RB_IPV4_PL seq 20 permit 0.0.0.0/0 le 32" in text
    assert text.count("route-map RB_IPV4_OUT permit") == 1
    assert "route-map RB_IPV4_OUT deny 20" in text


def test_rendered_prefix_list_matches_engine_permits():
    """每条 prefix-list 规则与引擎 Rule 语义同构；默认动作显式化。"""
    pol = _pol("v4-over-permit", "after")
    applied = render_applied_config(pol)
    text = "\n".join(applied["lines"])
    assert "ip prefix-list RB_IPV4_PL seq 10 permit 10.1.0.0/16 ge 24" in text
    assert "ip prefix-list RB_IPV4_PL seq 20 deny 10.1.0.0/16 ge 16 le 32" in text
    assert "ip prefix-list RB_IPV4_PL seq 30 permit 10.0.0.0/8 ge 9 le 24" in text
    assert "ip prefix-list RB_IPV4_PL seq 40 deny 10.1.0.0/16 ge 17 le 23" in text
    # 默认 deny：不应出现 0.0.0.0/0 尾放行；route-map 只有一个引用序列 + 显式 deny 兜底
    assert "permit 0.0.0.0/0 le 32" not in text
    assert "route-map RB_IPV4_OUT permit 10" in text
    assert " match ip address prefix-list RB_IPV4_PL" in text
    assert "route-map RB_IPV4_OUT deny 20" in text

    pol_perm = Policy.from_dict(SCENARIOS["v4-default-flip"]["after"])
    text2 = "\n".join(render_applied_config(pol_perm)["lines"])
    assert "ip prefix-list RB_IPV4_PL seq 20 permit 0.0.0.0/0 le 32" in text2


def test_rendered_ipv6_uses_ipv6_directive():
    pol = _pol("v6-over-permit", "after")
    text = "\n".join(render_applied_config(pol)["lines"])
    assert "ipv6 prefix-list RB_IPV6_PL seq 10 permit 2001:db8:1::/48 ge 56 le 64" in text
    assert "ipv6 prefix-list RB_IPV6_PL seq 40 deny 2001:db8:1::/48 ge 72" in text
    assert "match ipv6 address prefix-list RB_IPV6_PL" in text
    # v4 规则集为空时不得渲染 v4 放行尾
    assert "ip prefix-list RB_IPV4_PL seq" not in text


@pytest.fixture
def frr_enabled(request):
    from app import frr_lab
    if not frr_lab.docker_available():
        pytest.skip("docker 不可用")
    return frr_lab


@pytest.mark.parametrize("scenario_id", ["v4-over-permit", "v4-reorder", "v4-default-flip", "v6-over-permit"])
def test_lab_simulator_matches_container(frr_enabled, scenario_id):
    lab = frr_enabled
    lab.setup()
    s = SCENARIOS[scenario_id]
    # before/after 两版都与容器对照
    for side in ("before", "after"):
        report = lab.run_case(s[side], s["test_prefixes"])
        assert report["consistent"], (
            f"{scenario_id}/{side} 模拟器与 FRR 不一致: {report['mismatches']}\n"
            f"sim={report['simulator_permitted']}\nfrr={report['frr_received']}"
        )
