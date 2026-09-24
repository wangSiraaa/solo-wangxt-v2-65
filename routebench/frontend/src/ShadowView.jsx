import { ruleText } from './DiffView.jsx';

export default function ShadowView({ shadow, family, onPickWitness }) {
  if (!shadow) return null;
  const fam = shadow.families[family];
  return (
    <div className="panel">
      <h2>被遮蔽条目（{family}，共 {fam.rule_count} 条规则，{fam.shadowed.length} 条永不可达）</h2>
      {fam.shadowed.length === 0 && (
        <div className="ok-note">✓ 没有规则被完全遮蔽（每条规则都至少在一个前缀上成为首条命中）</div>
      )}
      {fam.shadowed.map((s) => (
        <div className="shadow-card" key={s.rule_id}>
          <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
            <span className="muted mono small">位置 #{s.position}</span>
            <span className={`badge ${s.rule.action}`}>{s.rule.action}</span>
            <span className="code">{s.rule.prefix}
              {(s.rule.ge !== null) && ` ge ${s.rule.ge}`}
              {(s.rule.le !== null) && ` le ${s.rule.le}`}
            </span>
            <span className={`badge ${s.cover_type === 'single' ? 'warn' : 'deny'}`}>
              {s.cover_type === 'single'
                ? `被规则 ${s.single_cover_rule_id} 单条遮蔽`
                : '被多条靠前规则并集遮蔽'}
            </span>
            {s.rule.label && <span className="muted small">{s.rule.label}</span>}
          </div>
          <div className="muted small" style={{ marginTop: 6 }}>
            实际命中分布：
            {s.coverers.map((c) => (
              <span key={c.rule_id} className="code" style={{ marginLeft: 8 }}>
                规则 {c.rule_id} × {c.regions} 个区域
              </span>
            ))}
          </div>
          <div className="small" style={{ marginTop: 4 }}>
            可复现见证：
            {s.proof.map((p) => (
              <span key={p.witness} style={{ marginLeft: 8 }}>
                <span className="code">{p.witness}</span>
                <span className="muted"> → 命中 {p.hit_rule_id}</span>
                {onPickWitness && (
                  <button className="btn small" style={{ marginLeft: 4 }}
                          onClick={() => onPickWitness(p.witness)}>求值</button>
                )}
              </span>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
