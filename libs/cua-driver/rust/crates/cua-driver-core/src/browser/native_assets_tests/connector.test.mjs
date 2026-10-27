import test from 'node:test';
import assert from 'node:assert/strict';
import { BrowserConnector } from '../native_assets/connector.mjs';
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((a, b) => {
    resolve = a;
    reject = b;
  });
  return { promise, resolve, reject };
};
const tick = () => new Promise((resolve) => setImmediate(resolve));
function event() {
  const handlers = [];
  return {
    addListener(fn) {
      handlers.push(fn);
    },
    fire(...args) {
      for (const fn of handlers) fn(...args);
    },
  };
}
function fixture() {
  const tabs = new Map([
    [1, { id: 1, windowId: 3, index: 0, title: 'one', url: 'https://example.test/', groupId: -1 }],
    [
      2,
      {
        id: 2,
        windowId: 3,
        index: 1,
        title: 'two',
        url: 'about:blank',
        lastAccessed: 123,
        groupId: 9,
      },
    ],
    [
      100,
      { id: 100, windowId: 4, index: 0, title: 'hundred', url: 'https://other.test/', groupId: -1 },
    ],
  ]);
  const attached = new Set();
  const calls = [];
  const events = [];
  const hooks = {};
  const windows = [
    { id: 3, type: 'normal', focused: true },
    { id: 4, type: 'normal', focused: false },
  ];
  let nextTab = 200;
  const chrome = {
    runtime: { id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' },
    tabs: {
      async query(query) {
        calls.push(['query', query]);
        return [...tabs.values()];
      },
      async get(id) {
        calls.push(['get', id]);
        if (!tabs.has(id)) throw new Error('No tab');
        return tabs.get(id);
      },
      async create(options) {
        calls.push(['create', options]);
        if (hooks.create) await hooks.create(options);
        const tab = {
          id: nextTab++,
          windowId: options.windowId,
          index: tabs.size,
          title: '',
          url: options.url,
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
        chrome.tabs.onRemoved.fire(id, {});
      },
      onRemoved: event(),
    },
    windows: {
      async getAll(options) {
        calls.push(['windows', options]);
        return windows;
      },
      async create(options) {
        calls.push(['createWindow', options]);
        const window = { id: 10, type: 'normal', focused: false };
        windows.push(window);
        const tab = { id: nextTab++, windowId: 10, index: 0, title: '', url: 'about:blank' };
        tabs.set(tab.id, tab);
        return { ...window, tabs: [tab] };
      },
    },
    tabGroups: {
      async get(id) {
        if (hooks.groupError) throw new Error('No group');
        return { id, title: '  actual group  ' };
      },
    },
    debugger: {
      onEvent: event(),
      onDetach: event(),
      async getTargets() {
        if (hooks.targets) return hooks.targets();
        return [...tabs.values()].map((tab) => ({
          id: 'target-' + tab.id,
          tabId: tab.id,
          type: 'page',
          attached: attached.has(tab.id),
        }));
      },
      async attach(source, version) {
        calls.push(['attach', source, version]);
        if (hooks.attach) await hooks.attach(source);
        attached.add(source.tabId);
      },
      async detach(source) {
        calls.push(['detach', source]);
        if (hooks.detach) await hooks.detach(source);
        attached.delete(source.tabId);
        if (!hooks.noDetachEvent) chrome.debugger.onDetach.fire(source, 'canceled_by_user');
      },
      async sendCommand(source, method, params) {
        calls.push(['cdp', source, method, params]);
        return hooks.cdp ? hooks.cdp(source, method, params) : { ok: true };
      },
    },
  };
  let seq = 0;
  const connector = new BrowserConnector(chrome, {
    emit: (value) => events.push(value),
    randomUUID: () => `token-${++seq}`,
  });
  connector.bind('gen-1');
  let id = 0;
  const request = (method, params = {}, owner = 'owner-a', generation = 'gen-1') =>
    connector.request({
      kind: 'request',
      protocol: 1,
      generation,
      id: String(++id),
      owner,
      method,
      params,
    });
  return { tabs, windows, attached, calls, events, hooks, chrome, connector, request };
}
const claim = async (f) => {
  const response = await f.request('attach', { tabId: 1 });
  assert.ok(response.result, JSON.stringify(response));
  return response.result.claim;
};
test('metadata is real, optional, and has no attach/focus effect', async () => {
  const f = fixture();
  const r = await f.request('inventory');
  assert.equal(r.result.tabs.length, 3);
  assert.equal('lastAccessed' in r.result.tabs[0], false);
  assert.equal(r.result.tabs[1].lastAccessed, 123);
  assert.equal(r.result.tabs[1].groupTitle, 'actual group');
  assert.deepEqual(f.calls, [['query', {}]]);
  f.hooks.groupError = true;
  assert.equal('groupTitle' in (await f.request('inventory')).result.tabs[1], false);
});
test('native raw-ID resolution preserves Number grammar without mutating browser', async () => {
  const f = fixture();
  for (const rawId of ['1e2', '0x64', ' 100 '])
    assert.equal((await f.request('resolve', { rawId })).result.tab.id, 100);
  for (const rawId of ['0', '-1', '1.5', 'Infinity', 'abc', ''])
    assert.equal((await f.request('resolve', { rawId })).error.kind, 'invalid_request');
  assert.equal(
    f.calls.some((c) => c[0] === 'attach'),
    false,
  );
});
test('inventory includes raw id0 but invalid raw native claim IDs are not normalized globally', async () => {
  const f = fixture();
  f.tabs.set(0, { id: 0, windowId: 3, index: 3 });
  assert.ok((await f.request('inventory')).result.tabs.some((t) => t.id === 0));
  for (const tabId of [-1, 1.2, Number.MAX_SAFE_INTEGER + 1, '1'])
    assert.equal((await f.request('attach', { tabId })).error.kind, 'invalid_request');
});
test('foreign debugger is never adopted or detached', async () => {
  const f = fixture();
  f.attached.add(1);
  assert.equal((await f.request('attach', { tabId: 1 })).error.kind, 'foreign_debugger');
  await f.connector.disconnect();
  assert.deepEqual(f.calls, []);
});
test('same owner reuses exact physical token, competing owner cannot attach or detach', async () => {
  const f = fixture();
  const token = await claim(f);
  assert.equal((await f.request('attach', { tabId: 1 })).result.claim, token);
  assert.equal((await f.request('attach', { tabId: 1 }, 'owner-b')).error.kind, 'tab_busy');
  assert.equal(
    (await f.request('detach', { claim: token }, 'owner-b')).error.kind,
    'claim_unavailable',
  );
  assert.equal(f.calls.filter((c) => c[0] === 'attach').length, 1);
  assert.equal(f.calls.filter((c) => c[0] === 'detach').length, 0);
});
test('Chrome attach rejection stays rejection, including already-attached messages', async () => {
  const f = fixture();
  f.hooks.attach = () => {
    throw new Error('Another debugger is already attached');
  };
  const r = await f.request('attach', { tabId: 1 });
  assert.equal(r.error.kind, 'chrome_rejected');
  assert.match(r.error.message, /Another debugger/);
  assert.equal(f.calls.filter((c) => c[0] === 'detach').length, 0);
  assert.equal(f.connector.records.size, 0);
});
test('owned detach happens once and exact acknowledged cleanup permits fresh claim', async () => {
  const f = fixture();
  const token = await claim(f);
  assert.equal((await f.request('detach', { claim: token })).result.proof, 'detach_ack');
  assert.equal(f.calls.filter((c) => c[0] === 'detach').length, 1);
  assert.equal(f.connector.records.size, 0);
  const fresh = await claim(f);
  assert.notEqual(fresh, token);
  assert.equal(
    (await f.request('cdp', { claim: token, method: 'Page.enable' })).error.kind,
    'claim_unavailable',
  );
});
test('detach acknowledgement without event quarantines tab against late-event epoch confusion', async () => {
  const f = fixture();
  const token = await claim(f);
  f.hooks.noDetachEvent = true;
  assert.equal((await f.request('detach', { claim: token })).result.proof, 'detach_ack');
  assert.equal((await f.request('attach', { tabId: 1 })).error.kind, 'tab_busy');
  f.chrome.debugger.onDetach.fire({ tabId: 1 }, 'canceled_by_user');
  const fresh = await claim(f);
  assert.notEqual(fresh, token);
});
test('user/DevTools revocation invalidates token and never triggers automatic attach', async () => {
  const f = fixture();
  const token = await claim(f);
  f.attached.delete(1);
  f.chrome.debugger.onDetach.fire({ tabId: 1 }, 'canceled_by_user');
  assert.equal(
    (await f.request('cdp', { claim: token, method: 'Page.enable' })).error.kind,
    'claim_unavailable',
  );
  assert.equal(f.events.at(-1).kind, 'revoked');
  assert.equal(f.calls.filter((c) => c[0] === 'attach').length, 1);
});
test('Browser domain support and errors come from the actual Chrome command', async () => {
  const f = fixture();
  const token = await claim(f);
  f.hooks.cdp = () => {
    throw new Error('actual Chrome Browser domain error');
  };
  const result = await f.request('cdp', { claim: token, method: 'Browser.getWindowForTarget' });
  assert.equal(result.error.kind, 'chrome_rejected');
  assert.equal(result.error.message, 'actual Chrome Browser domain error');
  assert.deepEqual(
    f.calls.filter((call) => call[0] === 'cdp'),
    [['cdp', { tabId: 1 }, 'Browser.getWindowForTarget', {}]],
  );
});
test('Target.getTargets returns actual debugger metadata and its exact native identity mapping', async () => {
  const f = fixture();
  const token = await claim(f);
  const targets = [
    { id: 'target-1', tabId: 1, type: 'page', title: 'current', attached: true },
    { id: 'foreign-target', tabId: 100, type: 'page', url: 'https://other.test/' },
  ];
  let reads = 0;
  f.hooks.targets = () => {
    reads++;
    return targets;
  };
  const result = await f.request('cdp', {
    claim: token,
    method: 'Target.getTargets',
    params: { filter: [{ type: 'iframe' }] },
  });
  assert.deepEqual(result.result.result, {
    targetInfos: targets.map((target) => ({ ...target, targetId: target.id })),
  });
  assert.equal(reads, 1);
  assert.equal(f.calls.filter((call) => call[0] === 'cdp').length, 0);
});
test('Target.getTargetInfo reaches Chrome for the actual root and observed child only', async () => {
  const f = fixture();
  const token = await claim(f);
  f.hooks.cdp = (source, method, params) => ({
    targetInfo: { targetId: params.targetId ?? 'target-1', title: 'live' },
  });
  assert.equal(
    (await f.request('cdp', { claim: token, method: 'Target.getTargetInfo' })).result.result
      .targetInfo.title,
    'live',
  );
  assert.equal(
    (
      await f.request('cdp', {
        claim: token,
        method: 'Target.getTargetInfo',
        params: { targetId: 'target-1' },
      })
    ).result.result.targetInfo.title,
    'live',
  );
  f.chrome.debugger.onEvent.fire({ tabId: 1 }, 'Target.attachedToTarget', {
    sessionId: 'child',
    targetInfo: { targetId: 'frame-a' },
  });
  assert.equal(
    (
      await f.request('cdp', {
        claim: token,
        method: 'Target.getTargetInfo',
        params: { targetId: 'frame-a' },
      })
    ).result.result.targetInfo.targetId,
    'frame-a',
  );
  const before = f.calls.length;
  const result = await f.request('cdp', {
    claim: token,
    method: 'Target.getTargetInfo',
    params: { targetId: 'foreign-target' },
  });
  assert.equal(result.error.kind, 'target_unavailable');
  assert.equal(f.calls.length, before);
});
test('Target.attachToTarget uses the actual matched Chrome session acknowledgement without inventing an ID', async () => {
  const f = fixture();
  const token = await claim(f);
  const pending = deferred();
  f.hooks.cdp = (source, method) =>
    method === 'Target.attachToTarget' ? pending.promise : { source };
  const result = f.request('cdp', {
    claim: token,
    method: 'Target.attachToTarget',
    params: { targetId: 'target-1', flatten: true },
  });
  await tick();
  assert.equal(
    (
      await f.request('cdp', {
        claim: token,
        sessionId: 'actual-session',
        method: 'Runtime.enable',
      })
    ).error.kind,
    'child_session_unavailable',
  );
  pending.resolve({ sessionId: 'actual-session' });
  assert.deepEqual((await result).result.result, { sessionId: 'actual-session' });
  assert.deepEqual(
    (
      await f.request('cdp', {
        claim: token,
        sessionId: 'actual-session',
        method: 'Runtime.enable',
      })
    ).result.result.source,
    { tabId: 1, sessionId: 'actual-session' },
  );
  assert.equal(
    f.calls.filter((call) => call[0] === 'cdp' && call[2] === 'Target.attachToTarget').length,
    1,
  );
});
test('target attach preserves actual child events before the acknowledgement and refuses foreign target mutation', async () => {
  const f = fixture();
  const token = await claim(f);
  f.hooks.cdp = (source, method) => {
    if (method === 'Target.attachToTarget') {
      f.chrome.debugger.onEvent.fire(source, 'Target.attachedToTarget', {
        sessionId: 'actual-session',
        targetInfo: { targetId: 'target-1' },
      });
      return { sessionId: 'actual-session' };
    }
    return {};
  };
  const result = await f.request('cdp', {
    claim: token,
    method: 'Target.attachToTarget',
    params: { targetId: 'target-1', flatten: true },
  });
  assert.deepEqual(result.result.result, { sessionId: 'actual-session' });
  assert.equal(f.events.at(-1).method, 'Target.attachedToTarget');
  const before = f.calls.length;
  assert.equal(
    (
      await f.request('cdp', {
        claim: token,
        method: 'Target.attachToTarget',
        params: { targetId: 'foreign', flatten: true },
      })
    ).error.kind,
    'target_unavailable',
  );
  assert.equal(f.calls.length, before);
});
test('a target attach result without a real session identity is unknown and is never replayed', async () => {
  const f = fixture();
  const token = await claim(f);
  f.hooks.cdp = () => ({});
  const result = await f.request('cdp', {
    claim: token,
    method: 'Target.attachToTarget',
    params: { targetId: 'target-1', flatten: true },
  });
  assert.equal(result.error.kind, 'outcome_unknown');
  assert.deepEqual(result.error.details.acknowledgedResult, {});
  assert.equal(f.calls.filter((call) => call[0] === 'cdp').length, 1);
});
test('an actual detach before a target attach ACK cannot resurrect that child session', async () => {
  const f = fixture();
  const token = await claim(f);
  const pending = deferred();
  f.hooks.cdp = (source, method) => {
    if (method === 'Target.attachToTarget') {
      f.chrome.debugger.onEvent.fire(source, 'Target.attachedToTarget', {
        sessionId: 'actual-session',
        targetInfo: { targetId: 'target-1' },
      });
      return pending.promise;
    }
    return {};
  };
  const result = f.request('cdp', {
    claim: token,
    method: 'Target.attachToTarget',
    params: { targetId: 'target-1', flatten: true },
  });
  await tick();
  f.chrome.debugger.onEvent.fire({ tabId: 1 }, 'Target.detachedFromTarget', {
    sessionId: 'actual-session',
  });
  assert.equal(
    (
      await f.request('cdp', {
        claim: token,
        sessionId: 'actual-session',
        method: 'Runtime.enable',
      })
    ).error.kind,
    'child_session_unavailable',
  );
  pending.resolve({ sessionId: 'actual-session' });
  assert.equal((await result).error.kind, 'outcome_unknown');
  assert.equal(
    (
      await f.request('cdp', {
        claim: token,
        sessionId: 'actual-session',
        method: 'Runtime.enable',
      })
    ).error.kind,
    'child_session_unavailable',
  );
  assert.ok((await f.request('cdp', { claim: token, method: 'Runtime.enable' })).result);
  assert.equal(
    f.calls.filter((call) => call[0] === 'cdp' && call[2] === 'Target.attachToTarget').length,
    1,
  );
});
test('an actual pre-ACK detach stays final even if its attached event was not observed', async () => {
  const f = fixture();
  const token = await claim(f);
  const pending = deferred();
  f.hooks.cdp = () => pending.promise;
  const result = f.request('cdp', {
    claim: token,
    method: 'Target.attachToTarget',
    params: { targetId: 'target-1', flatten: true },
  });
  await tick();
  f.chrome.debugger.onEvent.fire({ tabId: 1 }, 'Target.detachedFromTarget', {
    sessionId: 'actual-session',
  });
  pending.resolve({ sessionId: 'actual-session' });
  assert.equal((await result).error.kind, 'outcome_unknown');
  assert.equal(
    (
      await f.request('cdp', {
        claim: token,
        sessionId: 'actual-session',
        method: 'Runtime.enable',
      })
    ).error.kind,
    'child_session_unavailable',
  );
  assert.equal(f.calls.filter((call) => call[0] === 'cdp').length, 1);
});
test('concurrent target attaches retain only their actual live child across another child detach', async () => {
  const f = fixture();
  const token = await claim(f);
  const first = deferred();
  const second = deferred();
  let calls = 0;
  f.hooks.cdp = (source, method) =>
    method === 'Target.attachToTarget' ? (++calls === 1 ? first.promise : second.promise) : {};
  const a = f.request('cdp', {
    claim: token,
    method: 'Target.attachToTarget',
    params: { targetId: 'target-1', flatten: true },
  });
  const b = f.request('cdp', {
    claim: token,
    method: 'Target.attachToTarget',
    params: { targetId: 'target-1', flatten: true },
  });
  await tick();
  f.chrome.debugger.onEvent.fire({ tabId: 1 }, 'Target.attachedToTarget', {
    sessionId: 'session-a',
    targetInfo: { targetId: 'target-1' },
  });
  f.chrome.debugger.onEvent.fire({ tabId: 1 }, 'Target.attachedToTarget', {
    sessionId: 'session-b',
    targetInfo: { targetId: 'target-1' },
  });
  f.chrome.debugger.onEvent.fire({ tabId: 1 }, 'Target.detachedFromTarget', {
    sessionId: 'session-a',
  });
  first.resolve({ sessionId: 'session-a' });
  assert.equal((await a).error.kind, 'outcome_unknown');
  second.resolve({ sessionId: 'session-b' });
  assert.deepEqual((await b).result.result, { sessionId: 'session-b' });
  assert.equal(
    (await f.request('cdp', { claim: token, sessionId: 'session-a', method: 'Runtime.enable' }))
      .error.kind,
    'child_session_unavailable',
  );
  assert.ok(
    (await f.request('cdp', { claim: token, sessionId: 'session-b', method: 'Runtime.enable' }))
      .result,
  );
  assert.equal(calls, 2);
});
for (const earlyChildEvent of [false, true])
  test(`a nested target attach cannot outlive its parent with early child event ${earlyChildEvent}`, async () => {
    const f = fixture();
    const token = await claim(f);
    f.chrome.debugger.onEvent.fire({ tabId: 1 }, 'Target.attachedToTarget', {
      sessionId: 'parent-session',
      targetInfo: { targetId: 'frame-a' },
    });
    const pending = deferred();
    f.hooks.cdp = (source, method) => {
      if (method === 'Target.attachToTarget') {
        if (earlyChildEvent)
          f.chrome.debugger.onEvent.fire(source, 'Target.attachedToTarget', {
            sessionId: 'new-child',
            targetInfo: { targetId: 'frame-a' },
          });
        return pending.promise;
      }
      return {};
    };
    const result = f.request('cdp', {
      claim: token,
      sessionId: 'parent-session',
      method: 'Target.attachToTarget',
      params: { targetId: 'frame-a', flatten: true },
    });
    await tick();
    f.chrome.debugger.onEvent.fire({ tabId: 1 }, 'Target.detachedFromTarget', {
      sessionId: 'parent-session',
    });
    pending.resolve({ sessionId: 'new-child' });
    const response = await result;
    assert.equal(response.error.kind, 'outcome_unknown');
    assert.deepEqual(response.error.details.acknowledgedResult, { sessionId: 'new-child' });
    for (const sessionId of ['parent-session', 'new-child'])
      assert.equal(
        (await f.request('cdp', { claim: token, sessionId, method: 'Runtime.enable' })).error.kind,
        'child_session_unavailable',
      );
    assert.ok((await f.request('cdp', { claim: token, method: 'Runtime.enable' })).result);
    assert.equal(
      f.calls.filter((call) => call[0] === 'cdp' && call[2] === 'Target.attachToTarget').length,
      1,
    );
  });
test('Target.detachFromTarget sends only an observed child and retires its descendants after the actual acknowledgement', async () => {
  const f = fixture();
  const token = await claim(f);
  f.chrome.debugger.onEvent.fire({ tabId: 1 }, 'Target.attachedToTarget', {
    sessionId: 'child',
    targetInfo: { targetId: 'frame-a' },
  });
  f.chrome.debugger.onEvent.fire({ tabId: 1, sessionId: 'child' }, 'Target.attachedToTarget', {
    sessionId: 'grandchild',
    targetInfo: { targetId: 'frame-b' },
  });
  const pending = deferred();
  f.hooks.cdp = (source, method) => (method === 'Target.detachFromTarget' ? pending.promise : {});
  const result = f.request('cdp', {
    claim: token,
    method: 'Target.detachFromTarget',
    params: { sessionId: 'child' },
  });
  await tick();
  assert.ok(
    (await f.request('cdp', { claim: token, sessionId: 'grandchild', method: 'Runtime.enable' }))
      .result,
  );
  pending.resolve({});
  assert.deepEqual((await result).result.result, {});
  assert.equal(
    (await f.request('cdp', { claim: token, sessionId: 'grandchild', method: 'Runtime.enable' }))
      .error.kind,
    'child_session_unavailable',
  );
  const before = f.calls.length;
  assert.equal(
    (
      await f.request('cdp', {
        claim: token,
        method: 'Target.detachFromTarget',
        params: { sessionId: 'foreign' },
      })
    ).error.kind,
    'child_session_unavailable',
  );
  assert.equal(f.calls.length, before);
});
test('untracked global target creation is an explicit pending Host custody adaptation, not an Original capability classification', async () => {
  const f = fixture();
  const token = await claim(f);
  for (const method of [
    'Target.createTarget',
    'Target.createBrowserContext',
    'Target.disposeBrowserContext',
    'Target.attachToBrowserTarget',
  ]) {
    const result = await f.request('cdp', { claim: token, method, params: { url: 'about:blank' } });
    assert.equal(result.error.kind, 'host_scope_required');
  }
  assert.equal(
    (
      await f.request('cdp', {
        claim: token,
        method: 'Target.setAutoAttach',
        params: { flatten: false, waitForDebuggerOnStart: false },
      })
    ).error.kind,
    'invalid_request',
  );
  assert.equal(f.calls.filter((call) => call[0] === 'cdp').length, 0);
});
test('child sessions are admitted only through exact observed parent and recursively retired', async () => {
  const f = fixture();
  const token = await claim(f);
  assert.equal(
    (await f.request('cdp', { claim: token, sessionId: 'foreign', method: 'Runtime.enable' })).error
      .kind,
    'child_session_unavailable',
  );
  f.chrome.debugger.onEvent.fire({ tabId: 1 }, 'Target.attachedToTarget', {
    sessionId: 'child',
    targetInfo: { targetId: 'frame-a' },
  });
  f.chrome.debugger.onEvent.fire({ tabId: 1, sessionId: 'child' }, 'Target.attachedToTarget', {
    sessionId: 'grandchild',
    targetInfo: { targetId: 'frame-b' },
  });
  assert.deepEqual(
    (await f.request('cdp', { claim: token, sessionId: 'grandchild', method: 'Runtime.enable' }))
      .result.result,
    { ok: true },
  );
  f.chrome.debugger.onEvent.fire({ tabId: 1 }, 'Target.detachedFromTarget', { sessionId: 'child' });
  assert.equal(
    (await f.request('cdp', { claim: token, sessionId: 'grandchild', method: 'Runtime.enable' }))
      .error.kind,
    'child_session_unavailable',
  );
});
test('CDP event emitted before actual command response remains before it', async () => {
  const f = fixture();
  const token = await claim(f);
  f.hooks.cdp = () => {
    f.chrome.debugger.onEvent.fire({ tabId: 1 }, 'Page.loadEventFired', { timestamp: 1 });
    return { done: true };
  };
  const r = await f.request('cdp', { claim: token, method: 'Page.enable' });
  assert.equal(f.events.at(-1).method, 'Page.loadEventFired');
  assert.equal(r.result.result.done, true);
});
test('in-flight input on revocation is unknown and is never replayed', async () => {
  const f = fixture();
  const token = await claim(f);
  const gate = deferred();
  f.hooks.cdp = () => gate.promise;
  const pending = f.request('cdp', {
    claim: token,
    method: 'Input.insertText',
    params: { text: 'one' },
  });
  await tick();
  f.chrome.debugger.onDetach.fire({ tabId: 1 }, 'canceled_by_user');
  gate.resolve({});
  assert.equal((await pending).error.kind, 'outcome_unknown');
  assert.equal(f.calls.filter((c) => c[0] === 'cdp').length, 1);
});
test('disconnect during attach waits for actual acknowledgement and cleans only that epoch', async () => {
  const f = fixture();
  const gate = deferred();
  f.hooks.attach = () => gate.promise;
  const pending = f.request('attach', { tabId: 1 });
  await tick();
  const cleanup = f.connector.disconnect();
  await tick();
  assert.equal(f.calls.filter((c) => c[0] === 'detach').length, 0);
  gate.resolve();
  assert.equal((await pending).error.kind, 'outcome_unknown');
  assert.equal(f.calls.filter((c) => c[0] === 'attach').length, 1);
  assert.equal(f.calls.filter((c) => c[0] === 'detach').length, 1);
  await cleanup;
});
test('revocation while attach Promise is pending cannot return a live claim', async () => {
  const f = fixture();
  const gate = deferred();
  f.hooks.attach = () => gate.promise;
  const pending = f.request('attach', { tabId: 1 });
  await tick();
  f.chrome.debugger.onDetach.fire({ tabId: 1 }, 'canceled_by_user');
  gate.resolve();
  assert.equal((await pending).error.kind, 'outcome_unknown');
  assert.equal(f.calls.filter((c) => c[0] === 'detach').length, 1);
});
test('unconfirmed cleanup retains orphan custody across reconnect and rejects new owner', async () => {
  const f = fixture();
  await claim(f);
  f.hooks.detach = () => {
    throw new Error('transport failed while detaching');
  };
  await f.connector.disconnect();
  f.connector.bind('gen-2');
  const r = await f.request('attach', { tabId: 1 }, 'owner-b', 'gen-2');
  assert.equal(r.error.kind, 'tab_busy');
  assert.equal(f.calls.filter((c) => c[0] === 'attach').length, 1);
  assert.equal(f.calls.filter((c) => c[0] === 'detach').length, 1);
});
test('request replay does not replay attach and stale generation is fenced', async () => {
  const f = fixture();
  const msg = {
    kind: 'request',
    protocol: 1,
    generation: 'gen-1',
    owner: 'owner-a',
    id: '1',
    method: 'attach',
    params: { tabId: 1 },
  };
  assert.ok((await f.connector.request(msg)).result);
  assert.equal((await f.connector.request(msg)).error.kind, 'duplicate_request');
  assert.equal((await f.request('inventory', {}, 'owner-a', 'old')).error.kind, 'generation_lost');
  assert.equal(f.calls.filter((c) => c[0] === 'attach').length, 1);
});
test('closeOwner only detaches owned claims, reports pending attachment separately', async () => {
  const f = fixture();
  const token = await claim(f);
  const r = await f.request('closeOwner');
  assert.equal(r.result.cleanupConfirmed, true);
  assert.equal(r.result.pendingAttachments, 0);
  assert.equal(f.calls.filter((c) => c[0] === 'detach').length, 1);
  assert.equal(
    (await f.request('cdp', { claim: token, method: 'Page.enable' })).error.kind,
    'owner_closed',
  );
});
test('post-attach observation failure plus failed cleanup is unknown with retained custody', async () => {
  const f = fixture();
  let targets = 0;
  f.hooks.targets = () => {
    if (++targets === 1) return [{ id: 't', tabId: 1, type: 'page', attached: false }];
    throw new Error('lost observation');
  };
  f.hooks.detach = () => {
    throw new Error('lost cleanup');
  };
  const r = await f.request('attach', { tabId: 1 });
  assert.equal(r.error.kind, 'outcome_unknown');
  assert.equal(r.error.details.custody.tabId, 1);
  assert.equal(f.connector.records.size, 1);
});
test('closeOwner with a pending attach never claims cleanup confirmation', async () => {
  const f = fixture();
  const gate = deferred();
  f.hooks.attach = () => gate.promise;
  const pending = f.request('attach', { tabId: 1 });
  await tick();
  let settled = false;
  const close = f.request('closeOwner').then((r) => {
    settled = true;
    return r;
  });
  await tick();
  assert.equal(settled, false);
  gate.resolve();
  await pending;
  const r = await close;
  assert.equal(r.result.cleanupConfirmed, true);
  assert.equal(r.result.pendingAttachments, 0);
});
test('completed request count does not consume bounded in-flight capacity', async () => {
  const f = fixture();
  for (let i = 0; i < 8200; i++) assert.ok((await f.request('inventory')).result);
  assert.equal(f.connector.pending, 0);
});
test('create uses actual blank inactive tab in selected normal window, never arbitrary URL/active', async () => {
  const f = fixture();
  const r = await f.request('createTab', { windowId: 4 });
  assert.equal(r.result.tab.windowId, 4);
  assert.deepEqual(f.calls.find((c) => c[0] === 'create')[1], {
    active: false,
    url: 'about:blank',
    windowId: 4,
  });
  assert.equal(
    f.calls.some((c) => c[0] === 'attach'),
    false,
  );
  for (const params of [{ url: 'https://example.test/' }, { active: true }, { windowId: -1 }])
    assert.equal((await f.request('createTab', params)).error.kind, 'invalid_request');
});
test('create fallback opens a background normal blank window when no normal window exists', async () => {
  const f = fixture();
  f.windows.length = 0;
  const r = await f.request('createTab');
  assert.equal(r.result.tab.windowId, 10);
  assert.deepEqual(f.calls.find((c) => c[0] === 'createWindow')[1], {
    focused: false,
    type: 'normal',
    url: 'about:blank',
  });
});
test('lazy created tab has generation+owner receipt and closes on Stop without debugger attach', async () => {
  const f = fixture();
  const r = await f.request('createTab');
  const token = r.result.creation;
  const id = r.result.tab.id;
  assert.equal(
    (await f.request('stopCreatedTab', { creation: token }, 'owner-b')).error.kind,
    'creation_unavailable',
  );
  assert.equal((await f.request('closeOwner')).result.cleanupConfirmed, true);
  assert.equal(f.tabs.has(id), false);
  assert.equal(f.calls.filter((c) => c[0] === 'attach').length, 0);
  assert.equal(f.calls.filter((c) => c[0] === 'remove').length, 1);
});
test('explicit close may close an owned user tab, while automatic Stop only detaches it', async () => {
  const f = fixture();
  const token = await claim(f);
  assert.equal(
    (await f.request('closeTab', { claim: token }, 'owner-b')).error.kind,
    'claim_unavailable',
  );
  assert.equal((await f.request('closeTab', { claim: token })).result.proof, 'close_ack');
  assert.equal(f.tabs.has(1), false);
  assert.equal(f.calls.filter((c) => c[0] === 'detach').length, 0);
  const g = fixture();
  await claim(g);
  await g.request('closeOwner');
  assert.equal(g.tabs.has(1), true);
  assert.equal(g.calls.filter((c) => c[0] === 'remove').length, 0);
});
test('agent-created origin is not downgraded by same-owner user attachment', async () => {
  const f = fixture();
  const created = await f.request('createTab');
  const id = created.result.tab.id;
  assert.ok((await f.request('attach', { tabId: id })).result);
  await f.request('closeOwner');
  assert.equal(f.tabs.has(id), false);
  const detach = f.calls.findIndex((c) => c[0] === 'detach');
  const close = f.calls.findIndex((c) => c[0] === 'remove');
  assert.ok(detach >= 0 && close > detach);
});
test('another owner cannot claim a lazy created tab before its creator attaches', async () => {
  const f = fixture();
  const created = await f.request('createTab');
  assert.equal(
    (await f.request('attach', { tabId: created.result.tab.id }, 'owner-b')).error.kind,
    'tab_busy',
  );
  assert.equal(f.calls.filter((c) => c[0] === 'attach').length, 0);
});
test('disconnect during create waits acknowledgement and cleans exact created receipt once', async () => {
  const f = fixture();
  const gate = deferred();
  f.hooks.create = () => gate.promise;
  const create = f.request('createTab');
  await tick();
  const cleanup = f.connector.disconnect();
  await tick();
  assert.equal(f.calls.filter((c) => c[0] === 'remove').length, 0);
  gate.resolve();
  const r = await create;
  await cleanup;
  assert.equal(r.error.kind, 'outcome_unknown');
  assert.equal(r.error.details.acknowledgedResult.tab.id, 200);
  assert.equal(f.tabs.has(200), false);
  assert.equal(f.calls.filter((c) => c[0] === 'create').length, 1);
  assert.equal(f.calls.filter((c) => c[0] === 'remove').length, 1);
});
test('failed close is retained once, never automatically replayed or reported cleaned', async () => {
  const f = fixture();
  const created = await f.request('createTab');
  f.hooks.remove = () => {
    throw new Error('close rejected');
  };
  const a = await f.request('stopCreatedTab', { creation: created.result.creation });
  assert.equal(a.error.kind, 'chrome_rejected');
  const b = await f.request('stopCreatedTab', { creation: created.result.creation });
  assert.equal(b.error.kind, 'chrome_rejected');
  assert.equal((await f.request('closeOwner')).result.cleanupConfirmed, false);
  assert.equal(f.calls.filter((c) => c[0] === 'remove').length, 1);
});
test('explicit close in flight followed by Stop shares one physical close operation', async () => {
  const f = fixture();
  const created = await f.request('createTab');
  const attached = await f.request('attach', { tabId: created.result.tab.id });
  const gate = deferred();
  f.hooks.remove = () => gate.promise;
  const close = f.request('closeTab', { claim: attached.result.claim });
  await tick();
  const stop = f.request('closeOwner');
  await tick();
  assert.equal(f.calls.filter((c) => c[0] === 'remove').length, 1);
  gate.resolve();
  await close;
  assert.equal((await stop).result.cleanupConfirmed, true);
  assert.equal(f.calls.filter((c) => c[0] === 'remove').length, 1);
});
test('exact created-tab removal overrides an earlier detach rejection as final physical proof', async () => {
  const f = fixture();
  const created = await f.request('createTab');
  await f.request('attach', { tabId: created.result.tab.id });
  f.hooks.detach = () => {
    throw new Error('detach rejected');
  };
  const r = await f.request('closeOwner');
  assert.equal(r.result.cleanupConfirmed, true);
  assert.ok(r.result.diagnostics.length > 0);
  assert.equal(f.tabs.has(created.result.tab.id), false);
});
test('failed explicit user-tab close still detaches own debugger on Stop without replaying close', async () => {
  const f = fixture();
  const token = await claim(f);
  f.hooks.remove = () => {
    throw new Error('close rejected');
  };
  assert.equal((await f.request('closeTab', { claim: token })).error.kind, 'chrome_rejected');
  const stop = await f.request('closeOwner');
  assert.equal(stop.result.cleanupConfirmed, true);
  assert.equal(f.tabs.has(1), true);
  assert.equal(f.calls.filter((c) => c[0] === 'remove').length, 1);
  assert.equal(f.calls.filter((c) => c[0] === 'detach').length, 1);
});
test('created-tab gone proof during detach prevents redundant physical close', async () => {
  const f = fixture();
  const created = await f.request('createTab');
  await f.request('attach', { tabId: created.result.tab.id });
  const gate = deferred();
  f.hooks.detach = () => gate.promise;
  const stop = f.request('stopCreatedTab', { creation: created.result.creation });
  await tick();
  f.tabs.delete(created.result.tab.id);
  f.chrome.tabs.onRemoved.fire(created.result.tab.id, {});
  gate.resolve();
  assert.equal((await stop).result.proof, 'tab_removed');
  assert.equal(f.calls.filter((c) => c[0] === 'remove').length, 0);
});
test('exact detach retains reserved cleanup admission while all regular request slots are occupied', async () => {
  const f = fixture();
  const token = await claim(f);
  f.connector.maxPending = 1;
  const gate = deferred();
  f.hooks.cdp = () => gate.promise;
  const input = f.request('cdp', {
    claim: token,
    method: 'Input.insertText',
    params: { text: 'one' },
  });
  await tick();
  assert.equal((await f.request('inventory')).error.kind, 'request_budget');
  assert.equal((await f.request('detach', { claim: token })).result.proof, 'detach_ack');
  gate.resolve({});
  assert.equal((await input).error.kind, 'outcome_unknown');
  assert.equal(f.calls.filter((c) => c[0] === 'detach').length, 1);
  assert.equal(f.calls.filter((c) => c[0] === 'cdp').length, 1);
});
test('reserved cleanup capacity rejects duplicate waiting requests rather than growing awaiters', async () => {
  const f = fixture();
  const token = await claim(f);
  f.connector.maxPending = 1;
  const gate = deferred();
  f.hooks.detach = () => gate.promise;
  const detach = f.request('detach', { claim: token });
  await tick();
  assert.equal(f.connector.pendingCleanup.size, 1);
  for (let i = 0; i < 20; i++)
    assert.equal((await f.request('detach', { claim: token })).error.kind, 'cleanup_pending');
  assert.equal(f.connector.pending, 1);
  assert.equal(f.calls.filter((c) => c[0] === 'detach').length, 1);
  gate.resolve();
  await detach;
  assert.equal(f.connector.pendingCleanup.size, 0);
});
