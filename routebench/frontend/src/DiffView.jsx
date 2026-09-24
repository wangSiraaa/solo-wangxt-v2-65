export function ruleText(r) {
  let s = `${r.action} ${r.prefix}`;
  if (r.ge !== null && r.ge !== undefined) s += ` ge ${r.ge}`;
  if (r.le !== null && r.le !== undefined) s += ` le ${r.le}`;
  return s;
}

export function verdictCell(v) {
  return (
    <span>
      <span className={`badge ${v.action}`}>{v.action}</span>{' '}
      <span className="muted small">{v.default ? '默认动作' : `规则 ${v.rule_id}`}</span>
    </span>
  );
}

export default function DiffView({ diff, family, onPickWitness }) {
  if (!diff) return null;
  const fam = diff.families[family];
  const flips = fam.action_flips;
  const sameAction = fam.minimal_change_set.filter((r) => !r.action_flipped);

  return (
    <div className="grid">
      <div className="panel">
        <h2>
          行为变化 · 最小前缀集合（{family}）
          <span className="muted small"> — 不是文本 diff：每个见证代表一个行为区域</span>
        </h2>
        <div className="muted small" style={{ marginBottom: 8 }}>
          检查单元 {fam.summary.cells_checked} 个 · 判定变化 {fam.summary.changed_cells} 个 ·
          动作翻转 {fam.summary.action_flip_cells} 个 ·
          默认动作：{fam.summary.default.before} → {fam.summary.default.after}
          {fam.summary.default.changed && <span className="badge warn" style={{ marginLeft: 6 }}>默认动作已变</span>}
        </div>

        <h3 className="flip-leak">动作翻转（{flips.length}）</h3>
        {flips.length === 0 && <div className="muted small">无放行/拒绝翻转</div>}
        <table>
          <thead><tr><th>见证前缀</th><th>变化前</th><th></th><th>变化后</th><th>解释</th><th></th></tr></thead>
          <tbody>
            {flips.map((r) => (
              <tr key={r.witness}>
                <td className="code">{r.witness}</td>
                <td>{verdictCell(r.before)}</td>
                <td>→</td>
                <td>{verdictCell(r.after)}</td>
                <td className="small">{r.reason}</td>
                <td>
                  {onPickWitness && (
                    <button className="btn small" onClick={() => onPickWitness(r.witness)}>求值</button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        <h3>动作不变但命中规则变化 · 遮蔽/换序（{sameAction.length}）</h3>
        {sameAction.length === 0 && <div className="muted small">无</div>}
        <table>
          <thead><tr><th>见证前缀</th><th>变化前</th><th></th><th>变化后</th></tr></thead>
          <tbody>
            {sameAction.map((r) => (
              <tr key={r.witness}>
                <td className="code">{r.witness}</td>
                <td>{verdictCell(r.before)}</td>
                <td>→</td>
                <td>{verdictCell(r.after)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="panel">
        <h2>文本层变化（辅助参考，不能替代左侧行为分析）</h2>
        <TextDiff diff={diff} family={family} />
      </div>
    </div>
  );
}

function TextDiff({ diff, family }) {
  const t = diff.text;
  return (
    <div>
      {t.added.length > 0 && (
        <>
          <h3>新增行</h3>
          {t.added.filter((r) => (family === 'ipv6') === r.prefix.includes(':')).map((r) => (
            <div key={r.id} className="code" style={{ color: 'var(--permit)' }}>+ #{r.id} {ruleText(r)}</div>
          ))}
        </>
      )}
      {t.removed.length > 0 && (
        <>
          <h3>删除行</h3>
          {t.removed.filter((r) => (family === 'ipv6') === r.prefix.includes(':')).map((r) => (
            <div key={r.id} className="code" style={{ color: 'var(--deny)' }}>- #{r.id} {ruleText(r)}</div>
          ))}
        </>
      )}
      {t.modified.length > 0 && (
        <>
          <h3>修改行</h3>
          {t.modified.filter((m) => (family === 'ipv6') === m.before.prefix.includes(':')).map((m) => (
            <div key={m.id} className="code small">
              <div style={{ color: 'var(--deny)' }}>- #{m.id} {ruleText(m.before)}</div>
              <div style={{ color: 'var(--permit)' }}>+ #{m.id} {ruleText(m.after)}</div>
            </div>
          ))}
        </>
      )}
      {t.reordered.length > 0 && (
        <>
          <h3>换序</h3>
          {t.reordered.map((r) => (
            <div key={r.id} className="code small">规则 {r.id}：位置 {r.before} → {r.after}</div>
          ))}
        </>
      )}
      {t.default_changes[family] && (
        <div className="badge warn">默认动作开关变化</div>
      )}
      {t.added.length + t.removed.length + t.modified.length + t.reordered.length === 0
        && !t.default_changes[family] && <div className="muted small">{family} 文本无变化</div>}
    </div>
  );
}
