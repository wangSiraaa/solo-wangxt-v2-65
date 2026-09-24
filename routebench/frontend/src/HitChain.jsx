export function HitChain({ result }) {
  if (!result) return null;
  return (
    <div>
      <div style={{ margin: '4px 0 8px' }}>
        <span className="code">{result.prefix}</span> →{' '}
        <span className={`badge ${result.action}`}>{result.action.toUpperCase()}</span>{' '}
        {result.matched_rule_id ? (
          <span className="muted small">首条命中：规则 {result.matched_rule_id}</span>
        ) : (
          <span className="muted small">无规则命中，走默认动作</span>
        )}
      </div>
      {result.chain.map((c) => {
        const cls = c.terminal
          ? c.action === 'permit' ? 'terminal-permit' : 'terminal-deny'
          : c.in_scope === false ? 'missed' : '';
        return (
          <div key={c.order} className={`chain-line ${cls}`}>
            <span className="muted mono small" style={{ width: 34 }}>{c.order}</span>
            <span className={`badge ${c.action}`}>{c.action}</span>
            <span className="code">
              {c.default ? `默认 ${result.family === 'ipv4' ? '0.0.0.0/0' : '::/0'}` : c.prefix}
              {c.ge !== null || c.le !== null ? ` [${c.ge}..${c.le}]` : ''}
            </span>
            <span className="muted small">
              {c.default ? '(默认终端)' : c.terminal ? '★ 首条命中，终止'
                : c.in_scope ? '范围覆盖但已被遮蔽' : '不在范围'}
            </span>
          </div>
        );
      })}
    </div>
  );
}

export function EvaluatePanel({ results }) {
  if (!results?.length) return null;
  const [first, ...rest] = results;
  return (
    <div className="panel">
      <h2>命中链（按生效次序逐条求值）</h2>
      <HitChain result={first} />
      {rest.length > 0 && (
        <>
          <h3>其余查询前缀</h3>
          <table>
            <thead><tr><th>前缀</th><th>判定</th><th>命中规则</th></tr></thead>
            <tbody>
              {rest.map((r) => (
                <tr key={r.prefix}>
                  <td className="code">{r.prefix}</td>
                  <td><span className={`badge ${r.action}`}>{r.action}</span></td>
                  <td className="muted small">{r.matched_rule_id ?? '默认动作'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}
