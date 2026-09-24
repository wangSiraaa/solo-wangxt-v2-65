import { useEffect, useMemo, useState } from 'react';
import { api, emptyPolicy, familyOf } from './api.js';
import PolicyEditor from './PolicyEditor.jsx';
import TrieView from './TrieView.jsx';
import { EvaluatePanel } from './HitChain.jsx';
import DiffView from './DiffView.jsx';
import ShadowView from './ShadowView.jsx';
import ReplayView from './ReplayView.jsx';
import FrrLabView from './FrrLabView.jsx';
import { NeighborsView, LibraryView } from './NeighborsView.jsx';
import { ruleText } from './DiffView.jsx';

const TABS = [
  ['bench', '推演台'],
  ['compare', '语义对比'],
  ['frr', 'FRR 容器验证'],
  ['library', '策略库'],
  ['replay', '回放'],
  ['neighbors', '邻居'],
];

export default function App() {
  const [tab, setTab] = useState('bench');
  const [scenarios, setScenarios] = useState([]);
  const [scenarioId, setScenarioId] = useState('v4-over-permit');
  const [before, setBefore] = useState(emptyPolicy('before'));
  const [after, setAfter] = useState(emptyPolicy('after'));
  const [editTarget, setEditTarget] = useState('after');
  const [family, setFamily] = useState('ipv4');
  const [queryText, setQueryText] = useState('10.1.0.0/24');
  const [evalResults, setEvalResults] = useState(null);
  const [trie, setTrie] = useState(null);
  const [shadow, setShadow] = useState(null);
  const [diff, setDiff] = useState(null);
  const [frrText, setFrrText] = useState(null);
  const [error, setError] = useState('');
  const [savedId, setSavedId] = useState(null);
  const [libKey, setLibKey] = useState(0);

  const policy = editTarget === 'after' ? after : before;
  const setPolicy = editTarget === 'after' ? setAfter : setBefore;
  const testPrefixes = useMemo(
    () => queryText.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean),
    [queryText],
  );

  useEffect(() => { api.scenarios().then((d) => setScenarios(d.scenarios)); }, []);

  const loadScenario = async (id, side) => {
    const s = await api.scenario(id);
    setScenarioId(id);
    setBefore(s.before);
    setAfter(s.after);
    setFamily(s.family);
    setDiff(s.analysis.diff);
    setShadow(s.analysis.shadow_after);
    setQueryText(s.test_prefixes.join('\n'));
    setError('');
    setEditTarget(side || 'after');
    runAll(side === 'before' ? s.before : s.after, s.family, s.test_prefixes);
  };

  const runAll = async (pol = policy, fam = family, prefixes = testPrefixes) => {
    setError('');
    try {
      const q0 = prefixes[0];
      if (q0) {
        const ev = await api.evaluate(pol, prefixes, null);
        setEvalResults(ev.results);
        setTrie(await api.trie(pol, fam, q0));
      } else {
        setEvalResults(null);
        setTrie(await api.trie(pol, fam, null));
      }
      setShadow(await api.shadow(pol));
      setFrrText(await api.frrText(pol));
    } catch (e) {
      setError(e.message);
      setShadow(null); setEvalResults(null); setTrie(null);
    }
  };

  const runDiff = async () => {
    setError('');
    try {
      setDiff(await api.diff(before, after));
    } catch (e) { setError(e.message); setDiff(null); }
  };

  const pickWitness = (w) => {
    setQueryText(w);
    setTab('bench');
    runAll(policy, familyOf(w), [w]);
  };

  const openSaved = async (id) => {
    setSavedId(id);
    const d = await api.getPolicy(id);
    setAfter(d.policy);
    setBefore(emptyPolicy('before'));
    setDiff(null);
    setEditTarget('after');
    setTab('bench');
    runAll(d.policy);
  };

  const persistOp = async (opBody) => {
    if (!savedId) {
      try {
        const r = await api.createPolicy(policy);
        setSavedId(r.id);
        setLibKey((k) => k + 1);
      } catch (e) { setError(e.message); return; }
    }
    try {
      const d = await api.patchPolicy(savedId, opBody);
      setPolicy(d.policy);
      runAll(d.policy);
    } catch (e) { setError(e.message); }
  };

  return (
    <>
      <header>
        <div>
          <h1>RouteBench · 离线路由策略推演工作台</h1>
          <div className="sub">发布前看清每个前缀的放行/拒绝 · 首条匹配 · 默认拒绝 · IPv4/IPv6 隔离 · 仅本地容器交叉验证</div>
        </div>
        <nav>
          {TABS.map(([id, label]) => (
            <button key={id} className={tab === id ? 'active' : ''} onClick={() => setTab(id)}>{label}</button>
          ))}
        </nav>
      </header>

      <main>
        {error && <div className="error">{error}</div>}

        {(tab === 'bench' || tab === 'compare') && (
          <div className="toolbar">
            <span className="muted small">加载示例：</span>
            {scenarios.map((s) => (
              <button key={s.id} className={`btn small ${scenarioId === s.id ? 'primary' : ''}`}
                      onClick={() => loadScenario(s.id, 'after')}>{s.title}</button>
            ))}
            <div className="pill-tabs" style={{ marginLeft: 'auto' }}>
              <button className={family === 'ipv4' ? 'active' : ''} onClick={() => { setFamily('ipv4'); runAll(policy, 'ipv4'); }}>IPv4</button>
              <button className={family === 'ipv6' ? 'active' : ''} onClick={() => { setFamily('ipv6'); runAll(policy, 'ipv6'); }}>IPv6</button>
            </div>
          </div>
        )}

        {scenarioId && scenarios.find((s) => s.id === scenarioId) && (tab === 'bench' || tab === 'compare') && (
          <div className="lead">{scenarios.find((s) => s.id === scenarioId).description}</div>
        )}

        {tab === 'bench' && (
          <div className="grid cols-2">
            <div className="grid">
              <div className="panel">
                <div className="toolbar">
                  <div className="pill-tabs">
                    <button className={editTarget === 'after' ? 'active' : ''} onClick={() => setEditTarget('after')}>当前/改动后</button>
                    <button className={editTarget === 'before' ? 'active' : ''} onClick={() => setEditTarget('before')}>基线</button>
                  </div>
                  <button className="btn primary" onClick={() => runAll()}>重新推演</button>
                  <button className="btn" onClick={runDiff}>生成语义对比</button>
                  {editTarget === 'after' && (
                    savedId ? (
                      <button className="btn" title="以 reset 操作把当前编辑态写入日志（可回放）"
                              onClick={() => persistOp({ op: 'reset', policy })}>
                        保存到操作日志
                      </button>
                    ) : (
                      <button className="btn" title="在库内创建该策略（首条日志为 reset 基线）"
                              onClick={() => persistOp({ op: 'reset', policy })}>
                        存入策略库
                      </button>
                    )
                  )}
                  {savedId && <span className="muted small">已绑定：<b className="code">{savedId.slice(0, 8)}</b></span>}
                </div>
                <PolicyEditor policy={policy}
                              onChange={(p) => setPolicy(p)}
                              error={error} />
              </div>
              <div className="panel">
                <h2>批量查询前缀（空格/逗号/换行分隔，v4 与 v6 会被分别求值）</h2>
                <textarea rows={3} className="mono" value={queryText}
                          onChange={(e) => setQueryText(e.target.value)} />
                <h3>下发 FRR 配置预览</h3>
                <pre className="config">{(frrText?.config ?? ['（推演后生成）']).join('\n')}</pre>
              </div>
            </div>
            <div className="grid">
              <EvaluatePanel results={evalResults} />
              <TrieView data={trie} />
              <ShadowView shadow={shadow} family={family} onPickWitness={pickWitness} />
            </div>
          </div>
        )}

        {tab === 'compare' && (
          <div className="grid">
            <div className="panel">
              <div className="toolbar">
                <h2 style={{ margin: 0 }}>对比基线 → 改动后</h2>
                <button className="btn primary" onClick={runDiff}>计算语义差异</button>
                <span className="muted small">
                  当前：基线 {before.rules.length} 条 / 改动后 {after.rules.length} 条（{family}）
                </span>
              </div>
              <div className="grid cols-2">
                <MiniPolicy title="基线" policy={before} />
                <MiniPolicy title="改动后" policy={after} />
              </div>
            </div>
            {diff && <DiffView diff={diff} family={family} onPickWitness={pickWitness} />}
          </div>
        )}

        {tab === 'frr' && (
          <FrrLabView scenarios={scenarios} policy={policy}
                      testPrefixes={testPrefixes} onError={setError} />
        )}

        {tab === 'library' && (
          <LibraryView onOpen={openSaved} refreshKey={libKey} />
        )}

        {tab === 'replay' && <ReplayView policyId={savedId} />}

        {tab === 'neighbors' && <NeighborsView />}
      </main>
    </>
  );
}

function MiniPolicy({ title, policy: pol }) {
  return (
    <div>
      <h3>{title} · {pol.name} · 默认 <span className={`badge ${pol.default_v4}`}>v4:{pol.default_v4}</span>{' '}
        <span className={`badge ${pol.default_v6}`}>v6:{pol.default_v6}</span></h3>
      <table>
        <tbody>
          {pol.rules.map((r, i) => (
            <tr key={r.id}>
              <td className="muted small mono">{i}</td>
              <td><span className={`badge ${r.action}`}>{r.action}</span></td>
              <td className="code">{ruleText(r)}</td>
              <td className="muted small">{r.label}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
