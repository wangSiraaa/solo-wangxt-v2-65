"""API 层测试（SQLite 回退，无需 PostgreSQL）。"""
import os
import tempfile

import pytest

# 必须在导入 app 之前指定 SQLite
_tmpdb = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmpdb.close()
os.environ["ROUTEBENCH_SQLITE"] = _tmpdb.name
os.environ["ROUTEBENCH_DSN"] = "postgresql+psycopg://u:p@127.0.0.1:1/none"

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.scenarios import SCENARIOS  # noqa: E402


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_evaluate_first_match(client):
    pol = {
        "name": "t", "default_v4": "deny", "default_v6": "deny",
        "rules": [
            {"id": "r2", "action": "deny", "prefix": "10.1.0.0/16"},
            {"id": "r1", "action": "permit", "prefix": "10.0.0.0/8", "ge": 9, "le": 24},
        ],
    }
    resp = client.post("/api/sim/evaluate",
                       json={"policy": pol, "prefixes": ["10.1.0.0/16", "8.8.8.8/32", "10.0.1.0/24"]})
    assert resp.status_code == 200
    results = resp.json()["results"]
    assert results[0]["action"] == "deny" and results[0]["matched_rule_id"] == "r2"
    assert results[1]["action"] == "deny" and results[1]["matched_rule_id"] is None
    assert results[2]["action"] == "permit" and results[2]["matched_rule_id"] == "r1"


def test_family_mixing_rejected(client):
    pol = {"name": "t", "rules": [{"id": "a", "action": "permit", "prefix": "10.0.0.0/8"}]}
    resp = client.post("/api/sim/evaluate",
                       json={"policy": pol, "prefixes": ["2001:db8::/32"], "family": "ipv4"})
    assert resp.status_code == 422


def test_invalid_prefix_422(client):
    pol = {"name": "t", "rules": [{"id": "a", "action": "permit", "prefix": "10.0.0.1/8"}]}
    resp = client.post("/api/sim/frr-text", json=pol)
    assert resp.status_code == 422


def test_scenario_analysis_endpoint(client):
    resp = client.get("/api/scenarios/v4-over-permit")
    data = resp.json()
    flips = [r["witness"] for r in data["analysis"]["diff"]["families"]["ipv4"]["action_flips"]]
    assert "10.1.0.0/24" in flips
    # before：无遮蔽；after：新增的细化 deny r4 被 r2 单条遮蔽
    assert data["analysis"]["shadow_before"]["families"]["ipv4"]["shadowed"] == []
    sh = data["analysis"]["shadow_after"]["families"]["ipv4"]["shadowed"]
    assert [(s["rule_id"], s["cover_type"], s["single_cover_rule_id"]) for s in sh] == [
        ("r4", "single", "r2")
    ]


def test_policy_crud_journal_and_replay(client):
    pol = {"name": "api-demo", "rules": [
        {"id": "r1", "action": "permit", "prefix": "10.0.0.0/8"}]}
    pid = client.post("/api/policies", json=pol).json()["id"]

    client.patch(f"/api/policies/{pid}",
                 json={"op": "add_rule",
                       "rule": {"id": "r2", "action": "deny", "prefix": "10.1.0.0/16"}})
    client.patch(f"/api/policies/{pid}", json={"op": "move_rule", "rule_id": "r2", "position": 0})
    client.patch(f"/api/policies/{pid}", json={"op": "set_default", "family": "ipv4", "action": "permit"})

    journal = client.get(f"/api/policies/{pid}/journal").json()["journal"]
    ops = [e["op"] for e in journal]
    assert ops == ["reset", "add_rule", "move_rule", "set_default"]

    replay = client.post(f"/api/policies/{pid}/replay", json={"policy_id": pid}).json()
    assert replay["drift"] is False
    assert replay["fully_replayable"] is True
    assert replay["final_state"]["default_v4"] == "permit"
    assert [r["id"] for r in replay["final_state"]["rules"]] == ["r2", "r1"]

    detail = client.get(f"/api/policies/{pid}").json()
    shadowed = detail["shadow"]["families"]["ipv4"]["shadowed"]
    # 末态：r2 deny /16 在前且能命中精确 /16，r1 permit /8 也能命中 /8 自身，互不遮蔽
    assert shadowed == []


def test_snapshot_and_neighbor_validation(client):
    n = client.post("/api/neighbors", json={
        "name": "n1", "ip": "2001:db8::1", "asn": 65002, "family": "ipv6"})
    assert n.status_code == 200
    bad = client.post("/api/neighbors", json={
        "name": "n2", "ip": "10.0.0.1", "asn": 65002, "family": "ipv6"})
    assert bad.status_code == 422  # 地址族不匹配


def test_diff_is_semantic_not_text(client):
    # 规则文本完全相同，仅默认动作变化
    body = {
        "before": {"name": "a", "default_v4": "deny", "rules": [
            {"id": "r1", "action": "permit", "prefix": "10.0.0.0/8"}]},
        "after": {"name": "a", "default_v4": "permit", "rules": [
            {"id": "r1", "action": "permit", "prefix": "10.0.0.0/8"}]},
    }
    d = client.post("/api/sim/diff", json=body).json()
    assert d["text"]["default_changes"]["ipv4"] is True
    assert len(d["text"]["added"]) == 0 and len(d["text"]["removed"]) == 0
    assert d["families"]["ipv4"]["summary"]["action_flip_cells"] > 0
