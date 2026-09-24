import { useEffect, useState } from 'react';
import { api } from './api.js';
import { ruleText } from './DiffView.jsx';

function MiniRules({ rules }) {
  return (
    <div className="small mono" style={{ marginTop: 4 }}>
      {rules.map((r, i) => (
        <div key={r.id}>
          <span className="muted">{i}:</span> <span className={`badge ${r.action}`}>{r.action}</span>{' '}
          {r.id} {ruleText(r)}
        </div>
      ))}
      <div className="muted">默认 v4/v6: {rules.length ? '' : ''}见默认徽标</div>
    </div>
  );
}

export default function ReplayView({ policyId }) {
  const [journal, setJournal] = useState(null);
  const [replay, setReplay] = useState(null);
  const [snapshots, setSnapshots] = useState([]);
  const [error, setError] = useState('');

  const load = async () => {
    if (!policyId) {
      setJournal(null); setReplay(null);
      return;
    }
    setError('');
    try {
      const [j, s] = await Promise.all([api.journal(policyId), api.snapshots()]);
      setJournal(j.journal);
      setSnapshots(s.snapshots.filter((x) => x.policy_id === policyId));
      setReplay(await api.replay(policyId));
    } catch (e) { setError(e.message); }
  };

  useEffect(() => { load(); /* eslint-disable-next-line */ }, [policyId]);

  if (!policyId) return <div className="panel muted">先在“策略库”中打开/创建一条持久化策略。</div>;

  return (
    <div className="grid cols-2">
      <div className="panel">
        <h2>操作日志（seq 即生效次序）</h2>
        {error && <div className="error">{error}</div>}
        {journal?.map((e) => (
          <div className="step" key={e.seq}>
            <div>
              <span className="badge neutral">#{e.seq}</span>{' '}
              <b>{e.op}</b> <span className="muted small">— {e.actor} · {new Date(e.created_at).toLocaleString()}</span>
            </div>
            <div className="small mono muted" style={{ marginTop: 2 }}>{JSON.stringify(e.args)}</div>
          </div>
        ))}
        <h3>配置快照</h3>
        {snapshots.length === 0 && <div className="muted small">暂无快照</div>}
        {snapshots.map((s) => (
          <div key={s.id} className="small">
            <span className="badge neutral">{s.kind}</span> {s.name}{' '}
            <span className="muted">{new Date(s.created_at).toLocaleString()}</span>{' '}
            <button className="btn small" onClick={async () => {
              const full = await api.getSnapshot(s.id);
              setReplay({ final_state: full.payload, current_state: full.payload,
                          drift: false, fully_replayable: true, steps: [], snapshot: full });
            }}>载入查看</button>
          </div>
        ))}
      </div>

      <div className="panel">
        <h2>回放结果</h2>
        {replay && (
          <>
            <div className="toolbar">
              <span className={`badge ${replay.fully_replayable ? 'permit' : 'deny'}`}>
                {replay.fully_replayable ? '✓ 可完整回放' : '回放与记录不一致'}
              </span>
              <span className={`badge ${replay.drift ? 'deny' : 'permit'}`}>
                {replay.drift ? '末态与库内现状漂移' : '末态与库内现状一致'}
              </span>
              <button className="btn" onClick={load}>重新回放</button>
            </div>
            {replay.steps.map((s) => (
              <div className={`step ${s.matches_recorded === false ? 'bad' : 'good'}`} key={s.seq}>
                <div>
                  <span className="badge neutral">#{s.seq}</span> <b>{s.op}</b>
                  {s.anchored && <span className="muted small">（从已记录态锚点开始）</span>}
                  {s.matches_recorded === true && <span className="ok-note"> ✓ 重放态=记录态</span>}
                  {s.matches_recorded === false && <span className="flip-block"> ✗ 与记录态不符</span>}
                </div>
                <MiniRules rules={s.state.rules || []} />
                <div className="small muted">
                  默认 v4={s.state.default_v4} · v6={s.state.default_v6}
                </div>
              </div>
            ))}
            {replay.snapshot && (
              <div className="step good">
                <b>快照：{replay.snapshot.name}</b>
                <MiniRules rules={replay.final_state.rules} />
              </div>
            )}
            {replay.steps.length > 0 && (
              <>
                <h3>回放末态</h3>
                <MiniRules rules={replay.final_state.rules} />
                <div className="small muted">默认 v4={replay.final_state.default_v4} · v6={replay.final_state.default_v6}</div>
              </>
            )}
          </>
        )}
      </div>
    </div>
  );
}
