import { useState } from 'react';
import { familyOf } from './api.js';

function RuleRow({ rule, index, total, onChange, onMove, onRemove }) {
  const set = (patch) => onChange({ ...rule, ...patch });
  const fam = familyOf(rule.prefix || '0.0.0.0/0');
  return (
    <div className="rule-row">
      <span className="muted mono small">#{index}</span>
      <select value={rule.action} onChange={(e) => set({ action: e.target.value })}>
        <option value="permit">permit</option>
        <option value="deny">deny</option>
      </select>
      <input
        className="mono"
        value={rule.prefix}
        placeholder={fam === 'ipv6' ? '2001:db8::/32' : '10.0.0.0/8'}
        onChange={(e) => set({ prefix: e.target.value.trim() })}
      />
      <input className="mono" type="number" min="0" placeholder="ge" value={rule.ge ?? ''}
             onChange={(e) => set({ ge: e.target.value === '' ? null : Number(e.target.value) })} />
      <input className="mono" type="number" min="0" placeholder="le" value={rule.le ?? ''}
             onChange={(e) => set({ le: e.target.value === '' ? null : Number(e.target.value) })} />
      <input className="mono" placeholder="备注" value={rule.label ?? ''}
             onChange={(e) => set({ label: e.target.value })} />
      <span style={{ display: 'flex', gap: 2 }}>
        <button className="btn small" title="上移" disabled={index === 0}
                onClick={() => onMove(index, index - 1)}>↑</button>
        <button className="btn small" title="下移" disabled={index === total - 1}
                onClick={() => onMove(index, index + 1)}>↓</button>
        <button className="btn small danger" title="删除" onClick={() => onRemove(index)}>×</button>
      </span>
    </div>
  );
}

export default function PolicyEditor({ policy, onChange, error }) {
  const [family, setFamily] = useState('ipv4');
  const [draft, setDraft] = useState({ id: '', action: 'permit', prefix: '', ge: '', le: '', label: '' });

  const famRules = policy.rules
    .map((r, i) => ({ r, i }))
    .filter(({ r }) => familyOf(r.prefix || '0.0.0.0/0') === family);

  const setRules = (next) => onChange({ ...policy, rules: next });

  const updateRule = (globalIndex, next) => {
    const rules = policy.rules.slice();
    rules[globalIndex] = next;
    setRules(rules);
  };
  const moveRule = (globalIndex, to) => {
    const rules = policy.rules.slice();
    const [item] = rules.splice(globalIndex, 1);
    rules.splice(to, 0, item);
    setRules(rules);
  };
  const removeRule = (globalIndex) => setRules(policy.rules.filter((_, i) => i !== globalIndex));

  const addRule = () => {
    if (!draft.prefix.trim()) return;
    const id = draft.id.trim() || `r${policy.rules.length + 1}-${Date.now().toString(36)}`;
    const rule = {
      id,
      action: draft.action,
      prefix: draft.prefix.trim(),
      ge: draft.ge === '' ? null : Number(draft.ge),
      le: draft.le === '' ? null : Number(draft.le),
      label: draft.label,
    };
    // 同地址族追加到该族规则段末尾
    const lastOfFam = policy.rules.reduce(
      (acc, r, i) => (familyOf(r.prefix || '0.0.0.0/0') === family ? i : acc),
      -1,
    );
    const rules = policy.rules.slice();
    rules.splice(lastOfFam + 1, 0, rule);
    setRules(rules);
    setDraft({ ...draft, prefix: '', ge: '', le: '', label: '' });
  };

  return (
    <div className="panel">
      <h2>策略编辑 · {policy.name}</h2>
      <div className="pill-tabs">
        <button className={family === 'ipv4' ? 'active' : ''} onClick={() => setFamily('ipv4')}>IPv4</button>
        <button className={family === 'ipv6' ? 'active' : ''} onClick={() => setFamily('ipv6')}>IPv6</button>
        <span className="muted small" style={{ alignSelf: 'center', marginLeft: 8 }}>
          两族规则独立求值，顺序即为生效次序（首条匹配）
        </span>
      </div>

      <div className="rule-row" style={{ color: 'var(--muted)', fontSize: 12 }}>
        <span>#</span><span>动作</span><span>前缀（精确）</span><span>ge</span><span>le</span><span>备注</span><span />
      </div>

      {famRules.length === 0 && <div className="muted small" style={{ padding: '8px 0' }}>（暂无 {family} 规则）</div>}
      {famRules.map(({ r, i }) => (
        <RuleRow key={r.id} rule={r} index={i} total={famRules.length}
                 onChange={(next) => updateRule(i, next)} onMove={moveRule} onRemove={removeRule} />
      ))}

      <h3>新增规则</h3>
      <div className="rule-row">
        <input className="mono" placeholder="id" value={draft.id}
               onChange={(e) => setDraft({ ...draft, id: e.target.value })} />
        <select value={draft.action} onChange={(e) => setDraft({ ...draft, action: e.target.value })}>
          <option value="permit">permit</option>
          <option value="deny">deny</option>
        </select>
        <input className="mono" placeholder={family === 'ipv6' ? '2001:db8::/32' : '10.0.0.0/8'}
               value={draft.prefix} onChange={(e) => setDraft({ ...draft, prefix: e.target.value })} />
        <input className="mono" type="number" placeholder="ge" value={draft.ge}
               onChange={(e) => setDraft({ ...draft, ge: e.target.value })} />
        <input className="mono" type="number" placeholder="le" value={draft.le}
               onChange={(e) => setDraft({ ...draft, le: e.target.value })} />
        <input className="mono" placeholder="备注" value={draft.label}
               onChange={(e) => setDraft({ ...draft, label: e.target.value })} />
        <button className="btn primary" onClick={addRule}>+</button>
      </div>
      <div className="muted small">
        不带 ge/le = 精确匹配；只给 ge 则 le={family === 'ipv6' ? 128 : 32}；只给 le 则 ge=前缀长度。
        主机位非零（如 10.0.0.1/8）会被拒绝。
      </div>

      <h3>{family === 'ipv4' ? 'IPv4' : 'IPv6'} 默认动作（无规则命中时）</h3>
      <select
        value={family === 'ipv4' ? policy.default_v4 : policy.default_v6}
        onChange={(e) =>
          onChange(family === 'ipv4' ? { ...policy, default_v4: e.target.value }
                                      : { ...policy, default_v6: e.target.value })
        }
      >
        <option value="deny">deny（默认拒绝，生产习惯）</option>
        <option value="permit">permit（默认放行）</option>
      </select>

      {error && <div className="error">{error}</div>}
    </div>
  );
}
