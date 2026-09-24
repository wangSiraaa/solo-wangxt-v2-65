"""
本地 FRRouting 容器实验室编排（docker CLI，子进程方式）。

拓扑（纯本地、隔离网络，绝不连接生产设备）：

    172.30.0.2/24                  172.30.0.3/24
    frr-a (AS 65001) ----------- frr-b (AS 65002)
      |  redistribute static
      |  Null0 预装全部测试前缀
      |  出向 route-map = 被推演策略
      └ 从 B 的 BGP RIB 观测“实际被放行集合”

每轮：把策略渲染成 prefix-list/route-map 灌入 A → soft clear →
轮询 B 的 BGP RIB(JSON) → 与模拟器逐个测试前缀比对。
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import dataclass

from .engine import Policy, parse_prefix
from .frr_config import (
    DAEMONS,
    A_IP,
    B_IP,
    render_applied_config,
    render_base_configs,
)
from .scenarios import all_static_prefixes

IMAGE = "frrouting/frr:latest"
NETWORK = "routebench-lab"
CTR_A = "routebench-frr-a"
CTR_B = "routebench-frr-b"
CONTAINER_LABEL = "routebench=lab"


class LabError(RuntimeError):
    pass


def docker_available() -> bool:
    return shutil.which("docker") is not None and _run(["docker", "info"], check=False).returncode == 0


def _run(cmd: list[str], check: bool = True, timeout: int = 60) -> subprocess.CompletedProcess:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise LabError(f"命令超时: {' '.join(cmd[:3])}...") from exc
    except FileNotFoundError as exc:
        raise LabError("找不到 docker CLI") from exc
    if check and proc.returncode != 0:
        raise LabError(f"命令失败: {' '.join(cmd)}\n{proc.stderr.strip() or proc.stdout.strip()}")
    return proc


def _container_exists(name: str) -> bool:
    proc = _run(["docker", "ps", "-a", "--filter", f"name=^/{name}$", "--format", "{{.Names}}"])
    return name in proc.stdout.split()


def _container_running(name: str) -> bool:
    proc = _run(["docker", "ps", "--filter", f"name=^/{name}$", "--format", "{{.Names}}"])
    return name in proc.stdout.split()


def status() -> dict:
    if not docker_available():
        return {"available": False, "running": False, "reason": "docker CLI 不可用或 daemon 未运行"}
    a, b = _container_running(CTR_A), _container_running(CTR_B)
    return {
        "available": True,
        "running": a and b,
        "containers": {CTR_A: a, CTR_B: b},
        "network": NETWORK,
        "image": IMAGE,
    }


def setup(timeout: int = 180) -> dict:
    """创建隔离网络与两台 FRR，等待 BGP 会话建立。"""
    if not docker_available():
        raise LabError("docker 不可用：无法启动本地容器实验室（模拟器仍可独立使用）")

    # 隔离网络（仅用于本实验；driver bridge，不映射端口到宿主）
    nets = _run(["docker", "network", "ls", "--filter", f"name=^/{NETWORK}$", "--format", "{{.Name}}"])
    if NETWORK not in nets.stdout.split():
        _run(["docker", "network", "create", "--internal", "--subnet=172.30.0.0/24", NETWORK])

    bases = render_base_configs(all_static_prefixes())
    for name, ip, cfg in ((CTR_A, A_IP, bases["frr-a"]), (CTR_B, B_IP, bases["frr-b"])):
        if _container_exists(name):
            _run(["docker", "rm", "-f", name])
        _run(
            [
                "docker", "run", "-d", "--name", name,
                "--network", NETWORK, "--ip", ip,
                "--cap-add=NET_ADMIN", "--cap-add=SYS_ADMIN",
                "--label", CONTAINER_LABEL,
                "-v", f"/tmp/routebench-{name}-daemons:/etc/frr/daemons",
                "-v", f"/tmp/routebench-{name}-frr.conf:/etc/frr/frr.conf",
                IMAGE,
            ],
            timeout=timeout,
        )
        # 通过 cp 写入配置（不依赖宿主 /tmp 挂载语义）
        _put_config(name, "daemons", DAEMONS)
        _put_config(name, "frr.conf", cfg)
        _run(["docker", "restart", name])

    if not _wait_bgp(timeout=90):
        logs = _run(["docker", "logs", "--tail", "30", CTR_A], check=False).stdout
        raise LabError(f"BGP 会话未在限定时间内建立。frr-a 日志:\n{logs}")
    return {"running": True, "network": NETWORK, "static_prefixes": all_static_prefixes()}


def _put_config(container: str, filename: str, content: str) -> None:
    proc = subprocess.run(
        ["docker", "exec", "-i", container, "tee", f"/etc/frr/{filename}"],
        input=content, capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise LabError(f"写入 {filename} 失败: {proc.stderr}")


def teardown() -> dict:
    for name in (CTR_A, CTR_B):
        if _container_exists(name):
            _run(["docker", "rm", "-f", name])
    nets = _run(["docker", "network", "ls", "--filter", f"name=^/{NETWORK}$", "--format", "{{.Name}}"])
    if NETWORK in nets.stdout.split():
        _run(["docker", "network", "rm", NETWORK])
    return {"removed": True}


def _vtysh(container: str, commands: list[str], timeout: int = 30) -> str:
    script = "configure terminal\n" + "\n".join(commands) + "\nend\nwrite memory\n"
    proc = subprocess.run(
        ["docker", "exec", "-i", container, "vtysh"],
        input=script, capture_output=True, text=True, timeout=timeout,
    )
    if proc.returncode != 0:
        raise LabError(f"vtysh 失败: {proc.stderr or proc.stdout}")
    return proc.stdout


def _bgp_table(version: int) -> dict:
    cmd = ["docker", "exec", CTR_B, "vtysh", "-c",
           f"show bgp ipv{version} unicast json"]
    proc = _run(cmd, timeout=30)
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise LabError(f"无法解析 BGP JSON: {exc}\n{proc.stdout[:500]}")
    # FRR 不同版本字段：routes（dict）或 table dump
    routes = data.get("routes", {})
    if isinstance(routes, dict):
        return set(routes.keys())
    if isinstance(routes, list):
        return {r.get("prefix") or f"{r['prefix']}/{r.get('prefixLen','')}" for r in routes}
    raise LabError(f"未知 BGP JSON 结构: {list(data)[:5]}")


def _wait_bgp(timeout: int) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        proc = _run(
            ["docker", "exec", CTR_B, "vtysh", "-c", "show bgp summary json"],
            check=False,
        )
        try:
            data = json.loads(proc.stdout)
            v4 = data.get("ipv4Unicast", {}).get("peers", {}).get(A_IP, {})
            if v4.get("state") == "Established":
                return True
        except (json.JSONDecodeError, KeyError):
            pass
        time.sleep(2)
    return False


@dataclass
class CaseResult:
    prefix: str
    sim_action: str
    sim_rule_id: str | None
    frr_received: bool
    consistent: bool

    def to_dict(self) -> dict:
        return {
            "prefix": self.prefix,
            "sim_action": self.sim_action,
            "sim_rule_id": self.sim_rule_id,
            "frr_received": self.frr_received,
            "consistent": self.consistent,
        }


def run_case(policy_dict: dict, test_prefixes: list[str], *, poll_timeout: int = 45) -> dict:
    """
    将一版策略应用到 frr-a 出向，从 frr-b 观测收敛后的 RIB，
    并与模拟器对每个测试前缀的判定逐项比对。
    """
    if not (docker_available() and _container_running(CTR_A) and _container_running(CTR_B)):
        raise LabError("FRR 实验室未运行，请先 POST /api/frr/setup")

    policy = Policy.from_dict(policy_dict)
    # 引擎先自校验（非法策略不会下发到容器）
    applied = render_applied_config(policy)
    commands = list(applied["lines"])
    fam4 = applied["names"]["ipv4"]
    fam6 = applied["names"]["ipv6"]
    commands += [
        "router bgp 65001",
        " address-family ipv4 unicast",
        f" neighbor {B_IP} route-map {fam4['route_map']} out",
        " exit-address-family",
        " address-family ipv6 unicast",
        f" neighbor {B_IP} route-map {fam6['route_map']} out",
        " exit-address-family",
    ]
    _vtysh(CTR_A, commands)
    _run(["docker", "exec", CTR_A, "vtysh", "-c",
          f"clear bgp ipv4 unicast {B_IP} soft out"], check=False)
    _run(["docker", "exec", CTR_A, "vtysh", "-c",
          f"clear bgp ipv6 unicast {B_IP} soft out"], check=False)

    # 模拟器判定
    sim = {p: policy.evaluate(p) for p in test_prefixes}

    expected_v4 = {p for p, r in sim.items() if ":" not in p and r["action"] == "permit"}
    expected_v6 = {p for p, r in sim.items() if ":" in p and r["action"] == "permit"}

    got_v4, got_v6 = _poll_convergence(expected_v4, expected_v6, poll_timeout)

    results, mismatches = [], []
    for prefix in test_prefixes:
        net = parse_prefix(prefix)
        got = got_v4 if net.version == 4 else got_v6
        # Null0 静态按测试前缀逐条重分发，BGP 收到的必须是精确前缀
        frr_received = str(net) in got
        sim_action = sim[prefix]["action"]
        consistent = (sim_action == "permit") == frr_received
        row = CaseResult(prefix, sim_action, sim[prefix]["matched_rule_id"], frr_received, consistent)
        results.append(row.to_dict())
        if not consistent:
            mismatches.append(prefix)

    return {
        "applied_frr_config": applied["lines"],
        "results": results,
        "mismatches": mismatches,
        "consistent": not mismatches,
        "simulator_permitted": {
            "ipv4": sorted(expected_v4),
            "ipv6": sorted(expected_v6),
        },
        "frr_received": {
            "ipv4": sorted(got_v4),
            "ipv6": sorted(got_v6),
        },
    }


def _normalize_table(entries: set[str], version: int) -> set[str]:
    out = set()
    for e in entries:
        try:
            out.add(str(parse_prefix(e)))
        except Exception:
            pass
    return out


def _poll_convergence(expected_v4, expected_v6, timeout: int):
    """轮询 B 的 RIB；连续两轮内容完全一致即视为收敛。"""
    deadline = time.time() + timeout
    prev_v4 = prev_v6 = None
    last_v4, last_v6 = set(), set()
    while time.time() < deadline:
        last_v4 = _bgp_table(4)
        last_v6 = _bgp_table(6)
        norm4, norm6 = _normalize_table(last_v4, 4), _normalize_table(last_v6, 6)
        if prev_v4 is not None and norm4 == prev_v4 and norm6 == prev_v6:
            return norm4, norm6
        prev_v4, prev_v6 = norm4, norm6
        time.sleep(2)
    return _normalize_table(last_v4, 4), _normalize_table(last_v6, 6)
