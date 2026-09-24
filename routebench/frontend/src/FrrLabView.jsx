import { useEffect, useState } from 'react';
import { api } from './api.js';

export default function FrrLabView({ scenarios, policy, testPrefixes, onError }) {
  const [status, setStatus] = useState(null);
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState(null);
  const [runs, setRuns] = useState([]);
  const [activeScenario, setActiveScenario] = useState('v4-over-permit');

  const refresh = async () => {
    setStatus(await api.frrStatus());
    setRuns((await api.frrRuns()).runs);
  };
  useEffect(() => { refresh(); }, []);

  const act = async (fn) => {
    setBusy(true); setReport(null);
    try { await fn(); } catch (e) { onError(e.message); }
    await refresh(); setBusy(false);
  };

  const runScenario = async (sid) => {
    setActiveScenario(sid);
    setBusy(true);
    try {
      setReport(await api.frrCheckScenario(sid));
      setRuns((await api.frrRuns()).runs);
    } catch (e) { onError(e.message); }
    setBusy(false);
  };

  const runCustom = async () => {
    setBusy(true);
    try {
      // 自定义策略走通用 check 接口（直接 fetch 以传入完整 payload）
      const resp = await fetch('/api/frr/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ policy, test_prefixes: testPrefixes, save: true }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.detail || '检查失败');
      setReport(data);
      setRuns((await api.frrRuns()).runs);
    } catch (e) { onError(e.message); }
    setBusy(false);
  };

  return (
    <div className="grid">
      <div className="panel">
        <h2>本地 FRRouting 容器实验室（隔离网络，不连接任何生产设备）</h2>
        <div className="toolbar">
          {status?.available ? (
            <span className={`badge ${status.running ? 'permit' : 'warn'}`}>
              Docker {status.running ? '就绪：frr-a / frr-b 运行中' : '可用，实验室未启动'}
            </span>
          ) : (
            <span className="badge deny">Docker 不可用（模拟器与所有离线分析仍可正常使用）</span>
          )}
          <button className="btn primary" disabled={busy || !status?.available}
                  onClick={() => act(api.frrSetup)}>启动实验室</button>
          <button className="btn danger" disabled={busy || !status?.available}
                  onClick={() => act(api.frrTeardown)}>拆除</button>
          <span className="muted small">
            拓扑：frr-a(AS65001) ↔ frr-b(AS65002)，172.30.0.0/24 内部网络；
            A 预装 Null0 测试路由，出向 route-map = 被推演策略；从 B 的 BGP RIB 观测实际放行集合。
          </span>
        </div>

        <h3>内置案例交叉验证（before/after 两套策略的每个测试前缀逐项比对）</h3>
        <div className="toolbar">
          {scenarios.map((s) => (
            <button key={s.id} className={`btn ${activeScenario === s.id ? 'primary' : ''}`}
                    disabled={busy || !status?.running} onClick={() => runScenario(s.id)}>
              跑案例：{s.title}
            </button>
          ))}
        </div>
        <div className="toolbar">
          <button className="btn" disabled={busy || !status?.running || testPrefixes.length === 0}
                  onClick={runCustom}>
            用当前编辑器策略 + 批量查询前缀做一次对照（{testPrefixes.length} 条）
          </button>
        </div>
      </div>

      {report && (
        <div className="panel">
          <h2>
            对照结果{' '}
            <span className={`badge ${report.consistent ? 'permit' : 'deny'}`}>
              {report.consistent ? '✓ 模拟器与 FRR 容器观测完全一致' : `不一致：${report.mismatches.join(', ')}`}
            </span>
          </h2>
          <table>
            <thead><tr><th>测试前缀</th><th>模拟器</th><th>命中</th><th>FRR 是否收到</th><th>一致</th></tr></thead>
            <tbody>
              {report.results.map((r) => (
                <tr key={r.prefix} style={!r.consistent ? { background: 'rgba(255,93,108,.08)' } : undefined}>
                  <td className="code">{r.prefix}</td>
                  <td><span className={`badge ${r.sim_action}`}>{r.sim_action}</span></td>
                  <td className="muted small">{r.sim_rule_id ?? '默认'}</td>
                  <td>{r.frr_received ? '✓ 收到（放行）' : '× 未收到（拒绝）'}</td>
                  <td>{r.consistent ? '✓' : <b className="flip-block">✗</b>}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <h3>下发到 frr-a 的配置（可审计/可回放）</h3>
          <pre className="config">{report.applied_frr_config.join('\n')}</pre>
        </div>
      )}

      <div className="panel">
        <h2>历史对照记录</h2>
        {runs.length === 0 && <div className="muted small">暂无记录</div>}
        <table>
          <thead><tr><th>时间</th><th>案例</th><th>一致</th><th>不一致前缀</th></tr></thead>
          <tbody>
            {runs.map((r) => (
              <tr key={r.id}>
                <td className="small">{new Date(r.created_at).toLocaleString()}</td>
                <td className="code small">{r.scenario ?? '自定义'}</td>
                <td><span className={`badge ${r.consistent ? 'permit' : 'deny'}`}>{r.consistent ? '一致' : '不一致'}</span></td>
                <td className="code small">{r.mismatches.join(', ') || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
