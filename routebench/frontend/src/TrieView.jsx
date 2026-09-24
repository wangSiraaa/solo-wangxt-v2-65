import { useState } from 'react';

function TrieNode({ node, queryRuleId, depth = 0 }) {
  const [open, setOpen] = useState(depth < 3 || node.on_query_path);
  const hasChildren = node.children[0] || node.children[1];

  return (
    <li>
      <span className={`node ${node.on_query_path ? 'on-path' : ''}`}>
        {hasChildren ? (
          <span className="caret" onClick={() => setOpen(!open)}>{open ? '▾' : '▸'}</span>
        ) : (
          <span className="caret">·</span>
        )}
        <span>{node.prefix}</span>
        {node.rules.map((r) => {
          const isHit = r.id === queryRuleId;
          return (
            <span key={r.id} className={`badge ${r.action} ${isHit ? '' : 'neutral'}`}
                  title={`规则 ${r.id}（第 ${r.order} 条）${r.label ? ' — ' + r.label : ''}`}>
              #{r.order} {r.action}
              {r.ge !== null || r.le !== null
                ? ` [${r.ge}..${r.le}]`
                : ''}
              {isHit ? ' ★命中' : ''}
            </span>
          );
        })}
      </span>
      {open && hasChildren && (
        <ul>
          {node.children[0] ? (
            <TrieNode node={node.children[0]} queryRuleId={queryRuleId} depth={depth + 1} />
          ) : (
            <li><span className="missing">0 子树（无锚点）</span></li>
          )}
          {node.children[1] ? (
            <TrieNode node={node.children[1]} queryRuleId={queryRuleId} depth={depth + 1} />
          ) : (
            <li><span className="missing">1 子树（无锚点）</span></li>
          )}
        </ul>
      )}
    </li>
  );
}

export default function TrieView({ data }) {
  if (!data) return <div className="muted">选择族并输入查询前缀后展示。</div>;
  const hitId = data.query?.matched_rule_id ?? null;
  return (
    <div className="panel trie">
      <h2>前缀树（{data.family}）— 锚点节点挂规则徽标，★为当前查询的首条命中</h2>
      <ul>
        <TrieNode node={data.root} queryRuleId={hitId} />
      </ul>
    </div>
  );
}
