import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ScopedHeaders,
  validateExpandedHeaders,
  HEADER_RULE_START as START,
  HEADER_RULE_END as END,
} from '../extension_assets/scoped-headers.mjs';
const defer = () => {
  let resolve, reject;
  const promise = new Promise((a, b) => {
    resolve = a;
    reject = b;
  });
  return { promise, resolve, reject };
};
const tick = () => new Promise((resolve) => setImmediate(resolve));
const headers = (value) => [{ name: 'x-browser-agent', value }];
function fixture(options = {}) {
  const claims = new Map([
    ['a', { token: 'a', generation: 'gen-1', owner: 'owner-a', tabId: 8 }],
    ['b', { token: 'b', generation: 'gen-1', owner: 'owner-a', tabId: 2 }],
    ['c', { token: 'c', generation: 'gen-1', owner: 'owner-b', tabId: 7 }],
  ]);
  const rules = new Map();
  const updates = [];
  const hooks = {};
  const live = new Set([8, 2, 7]);
  const chrome = {
    runtime: { id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' },
    tabs: {
      async query(arg) {
        assert.deepEqual(arg, {});
        if (hooks.query) await hooks.query();
        return [...live].map((id) => ({ id }));
      },
    },
    declarativeNetRequest: {
      async getSessionRules() {
        if (hooks.get) await hooks.get();
        return structuredClone([...rules.values()]);
      },
      async updateSessionRules(update) {
        updates.push(structuredClone(update));
        if (hooks.beforeUpdate) await hooks.beforeUpdate(update);
        for (const id of update.removeRuleIds) rules.delete(id);
        for (const rule of update.addRules) rules.set(rule.id, structuredClone(rule));
        if (hooks.afterUpdate) await hooks.afterUpdate(update);
      },
    },
  };
  const leaf = new ScopedHeaders(chrome, {
    resolveClaim: (token) => {
      const claim = claims.get(token);
      if (!claim) throw new Error('claim revoked');
      return claim;
    },
    ...options,
  });
  return { claims, rules, updates, hooks, live, chrome, leaf };
}
async function ready(options) {
  const f = fixture(options);
  await f.leaf.initialize();
  return f;
}
test('startup removes only dedicated orphan rule interval and adopts no claims', async () => {
  const f = fixture();
  for (const id of [START - 1, START, END, END + 1]) f.rules.set(id, { id });
  assert.equal(f.leaf.statusForOwner('owner-a').cleanupConfirmed, false);
  await assert.rejects(
    f.leaf.setScopedHeaders('a', 'session-a', headers('Maka/session-a')),
    /startup/,
  );
  await f.leaf.initialize();
  assert.deepEqual([...f.rules.keys()], [START - 1, END + 1]);
  assert.equal(f.leaf.entries.size, 0);
  assert.equal(f.leaf.statusForOwner('owner-a').cleanupConfirmed, true);
});
test('exact two-rule scope uses only actual owned IDs and own initiator exclusion', async () => {
  const f = await ready();
  const a = await f.leaf.setScopedHeaders('a', 'session-a', headers('Host supplied'));
  assert.equal(a.applied, true);
  assert.equal(a.cleanupConfirmed, false);
  assert.equal(a.stateConfirmed, true);
  await f.leaf.setScopedHeaders('b', 'session-a', headers('Host supplied'));
  const rules = [...f.rules.values()];
  assert.equal(rules.length, 2);
  assert.deepEqual(rules[0], {
    id: START,
    priority: 1,
    action: {
      type: 'modifyHeaders',
      requestHeaders: [{ header: 'x-browser-agent', operation: 'set', value: 'Host supplied' }],
    },
    condition: { tabIds: [2, 8], resourceTypes: ['main_frame', 'sub_frame', 'object'] },
  });
  assert.deepEqual(rules[1].condition, {
    tabIds: [2, 8],
    excludedResourceTypes: ['main_frame', 'sub_frame', 'object'],
    excludedInitiatorDomains: [f.chrome.runtime.id],
  });
  for (const rule of rules)
    assert.equal(
      Object.keys(rule.condition).some((k) => /url|method|requestDomains/i.test(k)),
      false,
    );
});
test('session and expanded-header differences form different groups, no default label is invented', async () => {
  const f = await ready();
  await f.leaf.setScopedHeaders('a', 'session-a', []);
  assert.equal(f.rules.size, 0);
  await f.leaf.setScopedHeaders('b', 'session-b', headers('explicit-b'));
  await f.leaf.setScopedHeaders('c', 'session-c', headers('explicit-c'));
  assert.equal(f.rules.size, 4);
  assert.equal(JSON.stringify([...f.rules.values()]).includes('ChatGPT'), false);
  assert.equal(
    f.leaf.statusForClaim({ claim: 'a', generation: 'gen-1', owner: 'owner-a', tabId: 8 })
      .cleanupConfirmed,
    true,
  );
});
test('expanded headers normalize names and reject sensitive, duplicate, braces and value violations', () => {
  assert.deepEqual(validateExpandedHeaders([{ name: 'X-Example', value: ' !~' }]), [
    { name: 'x-example', value: ' !~' },
  ]);
  const bad = [
    ...[
      'authorization',
      'cookie',
      'cookie2',
      'host',
      'connection',
      'content-length',
      'transfer-encoding',
      'upgrade',
      'te',
      'trailer',
      'origin',
      'referer',
      'accept-encoding',
      'sec-test',
      'proxy-test',
    ].map((name) => [{ name, value: 'x' }]),
    [
      { name: 'x', value: 'ok' },
      { name: 'X', value: 'two' },
    ],
    [{ name: 'x', value: '\n' }],
    [{ name: 'x', value: '汉' }],
    [{ name: 'x', value: '{{session_id}}' }],
    [{ name: 'x', value: 'ok', extra: 1 }],
    Array.from({ length: 17 }, (_, i) => ({ name: 'x' + i, value: 'ok' })),
    [{ name: 'x'.repeat(257), value: 'ok' }],
    [{ name: 'x', value: 'x'.repeat(8193) }],
    Array.from({ length: 4 }, (_, i) => ({ name: 'x' + i, value: 'x'.repeat(8192) })),
  ];
  for (const input of bad)
    assert.throws(() => validateExpandedHeaders(input), { kind: 'invalid_request' });
});
test('claim revocation while queued prevents any new rule dispatch', async () => {
  const f = await ready();
  const gate = defer();
  f.hooks.get = () => gate.promise;
  const first = f.leaf.setScopedHeaders('b', 'session-a', headers('b'));
  await tick();
  const second = f.leaf.setScopedHeaders('a', 'session-a', headers('a'));
  f.claims.delete('a');
  gate.resolve();
  await first;
  await assert.rejects(second, /revoked/);
  assert.equal(
    [...f.rules.values()].some((rule) => rule.condition.tabIds.includes(8)),
    false,
  );
});
test('unknown update acknowledgement retains desired scope and old rule custody', async () => {
  const f = await ready();
  await f.leaf.setScopedHeaders('a', 'session-a', headers('one'));
  f.hooks.afterUpdate = () => {
    throw new Error('ACK lost after applying');
  };
  await assert.rejects(f.leaf.setScopedHeaders('a', 'session-a', headers('two')), {
    kind: 'outcome_unknown',
  });
  assert.equal(f.leaf.entries.size, 1);
  assert.equal(f.leaf.statusForOwner('owner-a').stateConfirmed, false);
  assert.equal(f.rules.get(START).action.requestHeaders[0].value, 'two');
  f.hooks.afterUpdate = null;
  assert.equal((await f.leaf.clearOwner('owner-a')).cleanupConfirmed, true);
  assert.equal(f.rules.size, 0);
});
test('failed cleanup retains removal tombstone even when Chrome already removed rules', async () => {
  const f = await ready();
  const { scope } = await f.leaf.setScopedHeaders('a', 'session-a', headers('one'));
  f.hooks.afterUpdate = () => {
    throw new Error('cleanup ACK lost');
  };
  await assert.rejects(f.leaf.clearClaim(scope), { kind: 'outcome_unknown' });
  assert.equal(f.rules.size, 0);
  assert.equal(f.leaf.statusForClaim(scope).pendingRemoval, true);
  assert.equal(f.leaf.statusForClaim(scope).cleanupConfirmed, false);
  f.hooks.afterUpdate = null;
  await f.leaf.clearClaim(scope);
  assert.equal(f.leaf.entries.size, 0);
  assert.equal(f.leaf.statusForClaim(scope).cleanupConfirmed, true);
});
test('cleanup accepts prior exact scope after physical revoke without re-adopting claim', async () => {
  const f = await ready();
  const { scope } = await f.leaf.setScopedHeaders('a', 'session-a', headers('one'));
  f.claims.delete('a');
  await f.leaf.clearClaim(scope);
  assert.equal(f.rules.size, 0);
  assert.equal(f.claims.has('a'), false);
});
test('other owner rules survive exact claim or owner cleanup', async () => {
  const f = await ready();
  const { scope } = await f.leaf.setScopedHeaders('a', 'session-a', headers('a'));
  await f.leaf.setScopedHeaders('c', 'session-b', headers('c'));
  await f.leaf.clearClaim(scope);
  assert.deepEqual(
    [...f.rules.values()].map((rule) => rule.condition.tabIds),
    [[7], [7]],
  );
  assert.equal(f.leaf.statusForOwner('owner-b').cleanupConfirmed, false);
  await f.leaf.clearOwner('owner-a');
  assert.equal(f.rules.size, 2);
});
test('another same-tab scope cannot replace uncertain cleanup', async () => {
  const f = await ready();
  const { scope } = await f.leaf.setScopedHeaders('a', 'session-a', headers('one'));
  f.hooks.beforeUpdate = () => {
    throw new Error('failed before mutation');
  };
  await assert.rejects(f.leaf.clearClaim(scope), { kind: 'outcome_unknown' });
  f.claims.set('replacement', {
    token: 'replacement',
    generation: 'gen-2',
    owner: 'owner-b',
    tabId: 8,
  });
  await assert.rejects(f.leaf.setScopedHeaders('replacement', 'session-b', headers('two')), {
    kind: 'header_tab_busy',
  });
  assert.equal(f.rules.get(START).action.requestHeaders[0].value, 'one');
});
test('forced live-tab reconciliation removes nonexistent tab scopes only', async () => {
  const f = await ready();
  await f.leaf.setScopedHeaders('a', 'session-a', headers('a'));
  await f.leaf.setScopedHeaders('c', 'session-b', headers('c'));
  f.live.delete(8);
  const r = await f.leaf.reconcile({ forceLive: true });
  assert.equal(r.physicallyMissingScopes[0].claim, 'a');
  assert.deepEqual(
    [...f.rules.values()].map((rule) => rule.condition.tabIds),
    [[7], [7]],
  );
});
test('capacity failure keeps committed desired policy unknown instead of claiming rollback', async () => {
  const f = await ready({ idStart: 10, idEnd: 11 });
  await f.leaf.setScopedHeaders('a', 'session-a', headers('a'));
  await assert.rejects(f.leaf.setScopedHeaders('c', 'session-c', headers('c')), {
    kind: 'outcome_unknown',
  });
  assert.equal(f.leaf.entries.size, 2);
  assert.equal(f.leaf.statusForOwner('owner-b').stateConfirmed, false);
  assert.equal(f.rules.size, 2);
  assert.equal(f.rules.get(10).condition.tabIds[0], 8);
});
test('owner cleanup fences queued policy writes and leaves no hidden default', async () => {
  const f = await ready();
  const gate = defer();
  f.hooks.get = () => gate.promise;
  const first = f.leaf.setScopedHeaders('b', 'session-a', headers('b'));
  await tick();
  const queued = f.leaf.setScopedHeaders('a', 'session-a', headers('a'));
  const clear = f.leaf.clearOwner('owner-a');
  gate.resolve();
  await assert.rejects(first, { kind: 'outcome_unknown' });
  await assert.rejects(queued, { kind: 'owner_closed' });
  assert.equal((await clear).cleanupConfirmed, true);
  assert.equal(f.rules.size, 0);
});
test('initialize and reconcile never confuse active-header state ACK with cleanup absence', async () => {
  const f = await ready();
  await f.leaf.setScopedHeaders('a', 'session-a', headers('active'));
  for (const result of [
    await f.leaf.initialize(),
    await f.leaf.reconcile(),
    await f.leaf.reconcile({ forceLive: true }),
  ]) {
    assert.equal(result.stateConfirmed, true);
    assert.equal(result.cleanupConfirmed, false);
  }
});
test('revocation during the rule read fences an unsent active-header write', async () => {
  const f = await ready();
  const gate = defer();
  f.hooks.get = () => gate.promise;
  const set = f.leaf.setScopedHeaders('a', 'session-a', headers('must not dispatch'));
  await tick();
  const scope = { claim: 'a', generation: 'gen-1', owner: 'owner-a', tabId: 8 };
  f.claims.delete('a');
  const clear = f.leaf.clearClaim(scope);
  gate.resolve();
  await assert.rejects(set, { kind: 'outcome_unknown' });
  await clear;
  assert.equal(f.updates.length, 0);
  assert.equal(f.rules.size, 0);
});
