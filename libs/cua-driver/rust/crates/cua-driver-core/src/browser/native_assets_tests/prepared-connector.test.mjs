import test from 'node:test';
import assert from 'node:assert/strict';
import { PreparedBrowserConnector } from '../native_assets/prepared-connector.mjs';
import { HEADER_RULE_START as START } from '../native_assets/scoped-headers.mjs';
const tick = () => new Promise((resolve) => setImmediate(resolve));
const defer = () => {
  let resolve;
  const promise = new Promise((r) => (resolve = r));
  return { promise, resolve };
};
function event() {
  const listeners = [];
  return {
    addListener(fn) {
      listeners.push(fn);
    },
    fire(...args) {
      for (const fn of listeners) fn(...args);
    },
  };
}
function fixture(options = {}) {
  const tabs = new Map([
    [1, { id: 1, windowId: 3, index: 0, title: 'one', url: 'https://example.test/', groupId: -1 }],
    [2, { id: 2, windowId: 3, index: 1, title: 'two', url: 'about:blank', groupId: -1 }],
  ]);
  const rules = new Map(),
    attached = new Set(),
    calls = [],
    events = [],
    hooks = {};
  const chrome = {
    runtime: { id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' },
    tabs: {
      async query() {
        return [...tabs.values()];
      },
      async get(id) {
        if (!tabs.has(id)) throw new Error('not found');
        return tabs.get(id);
      },
      async create(options) {
        calls.push(['create', options]);
        const tab = {
          id: 200,
          windowId: options.windowId,
          index: 2,
          title: '',
          url: 'about:blank',
          groupId: -1,
        };
        tabs.set(tab.id, tab);
        return tab;
      },
      async remove(id) {
        calls.push(['remove', id]);
        if (hooks.remove) await hooks.remove(id);
        tabs.delete(id);
        attached.delete(id);
        chrome.tabs.onRemoved.fire(id);
      },
      onRemoved: event(),
    },
    windows: {
      async getAll() {
        return [{ id: 3, type: 'normal', focused: true }];
      },
    },
    debugger: {
      onEvent: event(),
      onDetach: event(),
      async getTargets() {
        return [...tabs.keys()].map((id) => ({
          id: 'target-' + id,
          tabId: id,
          type: 'page',
          attached: attached.has(id),
        }));
      },
      async attach({ tabId }) {
        calls.push(['attach', tabId]);
        attached.add(tabId);
      },
      async detach({ tabId }) {
        calls.push(['detach', tabId]);
        attached.delete(tabId);
        chrome.debugger.onDetach.fire({ tabId }, 'canceled_by_user');
      },
      async sendCommand() {
        return {};
      },
    },
    declarativeNetRequest: {
      async getSessionRules() {
        if (hooks.get) await hooks.get();
        return structuredClone([...rules.values()]);
      },
      async updateSessionRules(update) {
        calls.push(['dnr', structuredClone(update)]);
        if (hooks.beforeUpdate) await hooks.beforeUpdate(update);
        for (const id of update.removeRuleIds) rules.delete(id);
        for (const rule of update.addRules) rules.set(rule.id, structuredClone(rule));
        if (hooks.afterUpdate) await hooks.afterUpdate(update);
      },
    },
  };
  let nonce = 0,
    id = 0;
  const connector = new PreparedBrowserConnector(chrome, {
    emit: (evt) => events.push(evt),
    randomUUID: () => `token-${++nonce}`,
    ...options,
  });
  const request = (method, params = {}, owner = 'owner-a') =>
    connector.request({
      kind: 'request',
      protocol: 1,
      generation: 'generation-1',
      id: String(++id),
      owner,
      method,
      params,
    });
  return { chrome, connector, request, tabs, rules, attached, calls, events, hooks };
}
async function ready(options) {
  const f = fixture(options);
  await f.connector.initialize();
  f.connector.bind('generation-1');
  return f;
}
async function attach(f, id = 1, owner = 'owner-a') {
  const r = await f.request('attach', { tabId: id }, owner);
  assert.ok(r.result, JSON.stringify(r));
  return r.result.claim;
}
async function label(f, claim, owner = 'owner-a') {
  const r = await f.request(
    'setScopedHeaders',
    {
      claim,
      sessionId: 'Host-session',
      headers: [{ name: 'x-browser-agent', value: 'Host label' }],
    },
    owner,
  );
  assert.ok(r.result, JSON.stringify(r));
  return r.result.scope;
}
test('startup DNR cleanup gates bind and capability and never adopts prior claims', async () => {
  const f = fixture();
  f.rules.set(START, { id: START });
  assert.equal(f.connector.hello().capabilities.scopedHeaders, false);
  assert.throws(() => f.connector.bind('generation-1'), { kind: 'headers_not_ready' });
  await f.connector.initialize();
  assert.equal(f.rules.size, 0);
  assert.equal(f.connector.hello().capabilities.scopedHeaders, true);
  assert.equal(f.connector.records.size, 0);
  f.connector.bind('generation-1');
});
test('foreign owner cannot label a token, and invalid headers are known before DNR side effects', async () => {
  const f = await ready();
  const claim = await attach(f);
  assert.equal(
    (await f.request('setScopedHeaders', { claim, sessionId: 'x', headers: [] }, 'owner-b')).error
      .kind,
    'claim_unavailable',
  );
  assert.equal(
    (
      await f.request('setScopedHeaders', {
        claim,
        sessionId: 'x',
        headers: [{ name: 'authorization', value: 'x' }],
      })
    ).error.kind,
    'invalid_request',
  );
  assert.equal(f.rules.size, 0);
  assert.equal(f.calls.filter((c) => c[0] === 'dnr').length, 0);
});
test('normal owned detach awaits separate DNR cleanup acknowledgement before releasing custody', async () => {
  const f = await ready();
  const claim = await attach(f);
  await label(f, claim);
  const gate = defer();
  f.hooks.beforeUpdate = (update) => (update.addRules.length === 0 ? gate.promise : undefined);
  let settled = false;
  const detach = f.request('detach', { claim }).then((r) => {
    settled = true;
    return r;
  });
  await tick();
  assert.equal(settled, false);
  assert.equal(f.attached.has(1), false);
  assert.equal(f.connector.records.has(1), true);
  gate.resolve();
  const r = await detach;
  assert.equal(r.result.scopedHeadersCleanupConfirmed, true);
  assert.equal(f.rules.size, 0);
  assert.equal(f.connector.records.has(1), false);
});
test('header ACK loss after physical detach keeps custody and blocks same-tab reclaim', async () => {
  const f = await ready();
  const claim = await attach(f);
  await label(f, claim);
  f.hooks.afterUpdate = () => {
    throw new Error('header cleanup ACK lost');
  };
  const r = await f.request('detach', { claim });
  assert.equal(r.error.kind, 'outcome_unknown');
  assert.equal(f.attached.has(1), false);
  assert.equal(f.connector.records.has(1), true);
  assert.equal((await f.request('attach', { tabId: 1 }, 'owner-b')).error.kind, 'tab_busy');
  assert.equal(f.calls.filter((c) => c[0] === 'detach').length, 1);
  f.hooks.afterUpdate = null;
  await f.connector.reconcileHeaders();
  assert.equal(f.connector.records.has(1), false);
  assert.ok((await f.request('attach', { tabId: 1 }, 'owner-b')).result);
});
test('Chrome revocation immediately revokes CDP and asynchronously clears scoped headers', async () => {
  const f = await ready();
  const claim = await attach(f);
  await label(f, claim);
  const gate = defer();
  f.hooks.beforeUpdate = () => gate.promise;
  f.attached.delete(1);
  f.chrome.debugger.onDetach.fire({ tabId: 1 }, 'canceled_by_user');
  assert.equal(
    (await f.request('cdp', { claim, method: 'Page.enable' })).error.kind,
    'claim_revoked',
  );
  assert.equal(f.connector.records.has(1), true);
  gate.resolve();
  await tick();
  await tick();
  assert.equal(f.rules.size, 0);
  assert.equal(f.connector.records.has(1), false);
  assert.equal(
    f.events.some((e) => e.kind === 'effects_cleanup' && e.cleanupConfirmed),
    true,
  );
  assert.equal(f.calls.filter((c) => c[0] === 'attach').length, 1);
});
test('closeOwner cannot confirm cleanup from detach alone when DNR cleanup fails', async () => {
  const f = await ready();
  const claim = await attach(f);
  await label(f, claim);
  f.hooks.beforeUpdate = () => {
    throw new Error('DNR unavailable');
  };
  const r = await f.request('closeOwner');
  assert.equal(r.error.kind, 'outcome_unknown');
  assert.equal(f.connector.records.has(1), true);
  assert.equal(f.rules.size, 2);
  f.hooks.beforeUpdate = null;
  const recovered = await f.connector.closeOwner('owner-a');
  assert.equal(recovered.cleanupConfirmed, true);
  assert.equal(f.rules.size, 0);
  assert.equal(f.connector.records.has(1), false);
  assert.equal(f.calls.filter((c) => c[0] === 'detach').length, 1);
});
test('explicit close proves physical tab gone but retains header custody on missing cleanup ACK', async () => {
  const f = await ready();
  const claim = await attach(f);
  await label(f, claim);
  f.hooks.afterUpdate = () => {
    throw new Error('cleanup ack lost');
  };
  const r = await f.request('closeTab', { claim });
  assert.equal(r.error.kind, 'outcome_unknown');
  assert.equal(f.tabs.has(1), false);
  assert.equal(f.connector.records.has(1), true);
  assert.equal(f.calls.filter((c) => c[0] === 'remove').length, 1);
  f.hooks.afterUpdate = null;
  await f.connector.reconcileHeaders();
  assert.equal(f.connector.records.has(1), false);
});
test('same-owner different token cannot label a physically revoked claim', async () => {
  const f = await ready();
  const a = await attach(f);
  const b = await attach(f, 2);
  await label(f, a);
  f.attached.delete(1);
  f.chrome.debugger.onDetach.fire({ tabId: 1 }, 'canceled_by_user');
  const response = await f.request('setScopedHeaders', { claim: a, sessionId: 'x', headers: [] });
  assert.ok(['claim_unavailable', 'claim_revoked'].includes(response.error.kind));
  assert.ok(
    (await f.request('setScopedHeaders', { claim: b, sessionId: 'x', headers: [] })).result,
  );
});
test('optional preparation callback receives admitted context without extra browser implementation', async () => {
  const calls = [];
  const f = await ready({
    prepareUserTab: async (owner, params, context) => {
      calls.push({ owner, params, context });
      return { tab: { id: params.tabId } };
    },
  });
  assert.equal((await f.request('prepareUserTab', { tabId: 1 })).result.tab.id, 1);
  assert.deepEqual(calls, [
    { owner: 'owner-a', params: { tabId: 1 }, context: { generation: 'generation-1' } },
  ]);
});
test('preparation preserves only actual optional pending URL and active facts internally', async () => {
  const f = await ready({
    prepareUserTab: async () => ({
      tab: {
        id: 1,
        url: 'about:blank',
        pendingUrl: 'https://actual.test/',
        active: false,
        arbitrary: 'ignored',
      },
      normalized: true,
    }),
  });
  const r = await f.request('prepareUserTab', { tabId: 1 });
  assert.deepEqual(r.result, {
    tab: { id: 1, url: 'about:blank', pendingUrl: 'https://actual.test/', active: false },
    normalized: true,
  });
});
test('throwing event observer cannot interrupt natural-revoke header cleanup or silently reuse transport', async () => {
  const f = await ready({
    emit: () => {
      throw new Error('wire observer failed');
    },
  });
  const claim = await attach(f);
  await label(f, claim);
  f.attached.delete(1);
  f.chrome.debugger.onDetach.fire({ tabId: 1 }, 'canceled_by_user');
  await tick();
  await tick();
  assert.equal(f.rules.size, 0);
  assert.equal(f.connector.records.has(1), false);
  assert.equal(f.connector.observer.failed, true);
  assert.equal(f.connector.accepting, false);
  assert.equal(f.calls.filter((c) => c[0] === 'detach').length, 0);
  assert.throws(() => f.connector.bind('new-generation'), { kind: 'observer_unavailable' });
});
test('throwing observer during explicit detach keeps DNR and custody bookkeeping and never replays', async () => {
  const f = await ready({
    emit: () => {
      throw new Error('wire observer failed');
    },
  });
  const claim = await attach(f);
  await label(f, claim);
  const r = await f.request('detach', { claim });
  assert.equal(r.error.kind, 'outcome_unknown');
  await tick();
  assert.equal(f.rules.size, 0);
  assert.equal(f.connector.records.has(1), false);
  assert.equal(f.calls.filter((c) => c[0] === 'detach').length, 1);
});
test('fresh reconciled cleanup proof overrides cached earlier header failure before physical detach', async () => {
  const f = await ready();
  const claim = await attach(f);
  await label(f, claim);
  f.hooks.afterUpdate = () => {
    throw new Error('old header ACK lost');
  };
  assert.equal((await f.request('clearScopedHeaders', { claim })).error.kind, 'outcome_unknown');
  assert.equal(f.attached.has(1), true);
  f.hooks.afterUpdate = null;
  await f.connector.reconcileHeaders();
  const r = await f.request('detach', { claim });
  assert.equal(r.result.scopedHeadersCleanupConfirmed, true);
  assert.equal(f.connector.records.has(1), false);
  assert.equal(f.calls.filter((c) => c[0] === 'detach').length, 1);
});
test('created explicit close in flight then Stop performs one close and awaits physical plus header ACK', async () => {
  const f = await ready();
  const created = await f.request('createTab');
  assert.equal(created.result.tab.id, 200);
  const claim = await attach(f, 200);
  await label(f, claim);
  const physical = defer(),
    header = defer();
  f.hooks.remove = () => physical.promise;
  f.hooks.beforeUpdate = (update) => (update.addRules.length === 0 ? header.promise : undefined);
  let explicitSettled = false,
    stopSettled = false;
  const close = f.request('closeTab', { claim }).then((r) => {
    explicitSettled = true;
    return r;
  });
  await tick();
  const stop = f.request('closeOwner').then((r) => {
    stopSettled = true;
    return r;
  });
  await tick();
  assert.equal(f.calls.filter((c) => c[0] === 'remove').length, 1);
  assert.equal(explicitSettled, false);
  assert.equal(stopSettled, false);
  physical.resolve();
  await tick();
  assert.equal(f.tabs.has(200), false);
  assert.equal(f.connector.records.has(200), true);
  assert.equal(stopSettled, false);
  header.resolve();
  const explicit = await close;
  const stopped = await stop;
  assert.equal(explicit.error.kind, 'outcome_unknown');
  assert.equal(stopped.result.cleanupConfirmed, true);
  assert.equal(stopped.result.scopedHeadersCleanupConfirmed, true);
  assert.equal(f.rules.size, 0);
  assert.equal(f.connector.records.has(200), false);
  assert.equal(f.calls.filter((c) => c[0] === 'remove').length, 1);
  assert.equal(f.calls.filter((c) => c[0] === 'detach').length, 0);
});
test('Stop of a user claim with active headers only detaches and clears rules', async () => {
  const f = await ready();
  const claim = await attach(f);
  await label(f, claim);
  const r = await f.request('closeOwner');
  assert.equal(r.result.cleanupConfirmed, true);
  assert.equal(f.tabs.has(1), true);
  assert.equal(f.rules.size, 0);
  assert.equal(f.calls.filter((c) => c[0] === 'remove').length, 0);
  assert.equal(f.calls.filter((c) => c[0] === 'detach').length, 1);
});
