import { useEffect, useState } from 'react';
import { api } from './api.js';

export function NeighborsView() {
  const [items, setItems] = useState([]);
  const [policies, setPolicies] = useState([]);
  const [form, setForm] = useState({ name: '', ip: '', asn: 65000, family: 'ipv4', description: '' });
  const [error, setError] = useState('');

  const load = async () => {
    setItems((await api.neighbors()).neighbors);
    setPolicies((await api.policies()).policies);
  };
  useEffect(() => { load(); }, []);

  const submit = async () => {
    setError('');
    try {
      await api.createNeighbor({ ...form, policy_id: form.policy_id || null });
      setForm({ name: '', ip: '', asn: 65000, family: 'ipv4', description: '' });
      await load();
    } catch (e) { setError(e.message); }
  };

  return (
    <div className="grid cols-2">
      <div className="panel">
        <h2>BGP 邻居（仅离线元数据，工作台不发起真实连接）</h2>
        <table>
          <thead><tr><th>名称</th><th>地址</th><th>ASN</th><th>族</th><th>绑定策略</th><th>说明</th></tr></thead>
          <tbody>
            {items.map((n) => (
              <tr key={n.id}>
                <td>{n.name}</td>
                <td className="code">{n.ip}</td>
                <td>{n.asn}</td>
                <td><span className="badge neutral">{n.family}</span></td>
                <td className="small muted">{policies.find((p) => p.id === n.policy_id)?.name ?? '—'}</td>
                <td className="small muted">{n.description}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="panel">
        <h2>登记邻居</h2>
        {error && <div className="error">{error}</div>}
        <div className="grid" style={{ gap: 8 }}>
          <label className="field">名称
            <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
          <label className="field">IP（IPv4/IPv6，族不一致会被拒绝）
            <input className="mono" value={form.ip} onChange={(e) => setForm({ ...form, ip: e.target.value.trim() })}
                   placeholder="192.0.2.1 或 2001:db8::1" /></label>
          <div style={{ display: 'flex', gap: 8 }}>
            <label className="field" style={{ flex: 1 }}>ASN
              <input type="number" value={form.asn} onChange={(e) => setForm({ ...form, asn: Number(e.target.value) })} /></label>
            <label className="field" style={{ flex: 1 }}>地址族
              <select value={form.family} onChange={(e) => setForm({ ...form, family: e.target.value })}>
                <option value="ipv4">ipv4</option><option value="ipv6">ipv6</option>
              </select></label>
          </div>
          <label className="field">说明
            <input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></label>
          <label className="field">绑定已存策略
            <select value={form.policy_id ?? ''} onChange={(e) => setForm({ ...form, policy_id: e.target.value })}>
              <option value="">（不绑定）</option>
              {policies.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select></label>
          <button className="btn primary" onClick={submit}>登记</button>
        </div>
      </div>
    </div>
  );
}

export function LibraryView({ onOpen, refreshKey }) {
  const [items, setItems] = useState([]);
  const [error, setError] = useState('');
  const load = async () => setItems((await api.policies()).policies);
  useEffect(() => { load(); }, [refreshKey]);

  const create = async () => {
    setError('');
    const name = `policy-${items.length + 1}`;
    try {
      const r = await api.createPolicy({ name, default_v4: 'deny', default_v6: 'deny', rules: [] });
      onOpen(r.id);
    } catch (e) { setError(e.message); }
  };

  return (
    <div className="panel">
      <h2>策略库（规则顺序与快照持久化于 PostgreSQL；无 PG 时回退本地 SQLite）</h2>
      {error && <div className="error">{error}</div>}
      <div className="toolbar"><button className="btn primary" onClick={create}>新建空策略</button></div>
      <table>
        <thead><tr><th>名称</th><th>规则数</th><th>默认 v4/v6</th><th>更新时间</th><th></th></tr></thead>
        <tbody>
          {items.map((p) => (
            <tr key={p.id}>
              <td className="code">{p.name}</td>
              <td>{p.rule_count}</td>
              <td><span className={`badge ${p.default_v4}`}>{p.default_v4}</span>{' '}
                  <span className={`badge ${p.default_v6}`}>{p.default_v6}</span></td>
              <td className="small muted">{new Date(p.updated_at).toLocaleString()}</td>
              <td><button className="btn small" onClick={() => onOpen(p.id)}>打开编辑/回放</button></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
