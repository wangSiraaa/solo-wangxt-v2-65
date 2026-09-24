const BASE = '/api';

async function request(path, options = {}) {
  const resp = await fetch(BASE + path, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    const detail = typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail || data);
    throw new Error(`${resp.status}: ${detail}`);
  }
  return data;
}

export const api = {
  scenarios: () => request('/scenarios'),
  scenario: (id) => request(`/scenarios/${id}`),
  evaluate: (policy, prefixes, family) =>
    request('/sim/evaluate', { method: 'POST', body: JSON.stringify({ policy, prefixes, family }) }),
  diff: (before, after) => request('/sim/diff', { method: 'POST', body: JSON.stringify({ before, after }) }),
  shadow: (policy) => request('/sim/shadow', { method: 'POST', body: JSON.stringify({ policy }) }),
  trie: (policy, family, query) =>
    request('/sim/trie', { method: 'POST', body: JSON.stringify({ policy, family, query }) }),
  frrText: (policy) => request('/sim/frr-text', { method: 'POST', body: JSON.stringify(policy) }),
  policies: () => request('/policies'),
  createPolicy: (policy) => request('/policies', { method: 'POST', body: JSON.stringify(policy) }),
  getPolicy: (id) => request(`/policies/${id}`),
  patchPolicy: (id, op) => request(`/policies/${id}`, { method: 'PATCH', body: JSON.stringify(op) }),
  deletePolicy: (id) => request(`/policies/${id}`, { method: 'DELETE' }),
  journal: (id) => request(`/policies/${id}/journal`),
  replay: (id, fromSeq = null) =>
    request(`/policies/${id}/replay`, {
      method: 'POST',
      body: JSON.stringify({ policy_id: id, from_seq: fromSeq }),
    }),
  snapshot: (id, name) =>
    request(`/policies/${id}/snapshot`, { method: 'POST', body: JSON.stringify({ name }) }),
  snapshots: () => request('/snapshots'),
  getSnapshot: (id) => request(`/snapshots/${id}`),
  neighbors: () => request('/neighbors'),
  createNeighbor: (n) => request('/neighbors', { method: 'POST', body: JSON.stringify(n) }),
  frrStatus: () => request('/frr/status'),
  frrSetup: () => request('/frr/setup', { method: 'POST' }),
  frrTeardown: () => request('/frr/teardown', { method: 'POST' }),
  frrCheckScenario: (id) => request(`/frr/check-scenario/${id}`, { method: 'POST' }),
  frrRuns: () => request('/frr/runs'),
};

export function familyOf(prefix) {
  return prefix.includes(':') ? 'ipv6' : 'ipv4';
}

export function emptyPolicy(name = 'draft') {
  return { name, default_v4: 'deny', default_v6: 'deny', rules: [] };
}
