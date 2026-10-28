// SPDX-License-Identifier: MIT

import assert from 'node:assert/strict';
import test from 'node:test';
import { ClaimPreparation } from '../extension_assets/claim-preparation.mjs';

function event() {
  const listeners = new Set();
  return {
    addListener: (callback) => listeners.add(callback),
    fire: (...args) => [...listeners].forEach((callback) => callback(...args)),
  };
}
const tick = () => new Promise((resolve) => setImmediate(resolve));

function fixture() {
  const calls = [],
    emitted = [],
    cleaned = [];
  const record = { token: 'claim-a', owner: 'owner-a', generation: 'generation-a', tabId: 11 };
  const current = new Map([[record.tabId, record]]);
  const tabs = new Map([[11, { id: 11, url: 'https://fixture.test/' }]]);
  let frames = [{ frameId: 0, documentId: 'doc-main-a', documentLifecycle: 'active' }];
  const installed = new Set();
  let interception = null;
  const chrome = {
    runtime: { id: 'own-extension', onMessage: event() },
    tabs: {
      onUpdated: event(),
      onReplaced: event(),
      get: async (id) => ({ ...tabs.get(id) }),
    },
    webNavigation: {
      onCommitted: event(),
      getAllFrames: async (target) => {
        calls.push({ api: 'frames', target });
        return frames.map((frame) => ({ ...frame }));
      },
    },
    scripting: {
      async executeScript(request) {
        calls.push({ api: 'script', ...request });
        if (interception) {
          const result = await interception(request);
          if (result !== undefined) return result;
        }
        const docs = request.target.documentIds ?? frames.map((frame) => frame.documentId);
        return docs.map((documentId) => {
          const key = [documentId, request.world, request.args[0], request.args[1]].join(':');
          const name = request.func.name;
          if (name.startsWith('install')) installed.add(key);
          if (name.startsWith('remove')) installed.delete(key);
          return {
            documentId,
            frameId: frames.find((frame) => frame.documentId === documentId)?.frameId ?? 0,
            result: name.endsWith('Status') ? installed.has(key) : true,
          };
        });
      },
    },
  };
  const preparation = new ClaimPreparation(chrome, {
    resolveClaim: (candidate) => current.get(candidate.tabId) === candidate,
    emit: (message) => emitted.push(message),
    onCleanup: (candidate) => cleaned.push(candidate),
  });
  return {
    chrome,
    preparation,
    record,
    current,
    tabs,
    calls,
    emitted,
    cleaned,
    setFrames: (value) => {
      frames = value;
    },
    intercept: (callback) => {
      interception = callback;
    },
  };
}

test('preparation installs document-scoped foreign monitor and isolated-before-main popup hooks', async () => {
  const f = fixture();
  assert.deepEqual(await f.preparation.prepare(f.record, { headerEnabled: true }), {
    foreignInstalled: true,
    popupInstalled: true,
  });
  const scripts = f.calls.filter((call) => call.api === 'script');
  const bridge = scripts.findIndex((call) => call.func.name === 'installPopupBridge');
  const main = scripts.findIndex((call) => call.func.name === 'installPopupHook');
  assert.ok(bridge >= 0 && main > bridge, 'bridge must be installed before MAIN interception');
  assert.deepEqual(scripts.find((call) => call.func.name === 'installForeignFrameMonitor').target, {
    tabId: 11,
    documentIds: ['doc-main-a'],
  });
  assert.equal(scripts[main].world, 'MAIN');
  assert.equal(scripts[bridge].world, 'ISOLATED');
  const before = scripts.length;
  assert.equal(
    (await f.preparation.prepare(f.record, { headerEnabled: true })).popupInstalled,
    true,
  );
  const additional = f.calls.filter((call) => call.api === 'script').slice(before);
  assert.deepEqual(
    additional.map((call) => call.func.name),
    ['popupHookStatus'],
  );
});

test('simultaneous preparation shares pending installation without replaying injected effects', async () => {
  const f = fixture();
  const [first, second] = await Promise.all([
    f.preparation.prepare(f.record, { popupEnabled: true }),
    f.preparation.prepare(f.record, { popupEnabled: true }),
  ]);
  assert.equal(first.popupInstalled && second.popupInstalled, true);
  for (const name of ['installPopupBridge', 'installPopupHook', 'installForeignFrameMonitor'])
    assert.equal(f.calls.filter((call) => call.func?.name === name).length, 1, name);
});

test('current extension sender intent is scoped to its live lease and never creates a tab itself', async () => {
  const f = fixture();
  await f.preparation.prepare(f.record, { popupEnabled: true });
  const sender = {
    id: 'own-extension',
    tab: { id: 11 },
    frameId: 2,
    documentId: 'doc-child',
    url: 'https://fixture.test/frame',
  };
  const fire = (url, actual = sender) =>
    f.chrome.runtime.onMessage.fire({ type: 'MAKA_OPEN_BACKGROUND_POPUP', url }, actual);
  fire('https://popup.test/next');
  assert.deepEqual(f.emitted, [
    {
      kind: 'popup_requested',
      protocol: 1,
      generation: 'generation-a',
      owner: 'owner-a',
      claim: 'claim-a',
      tabId: 11,
      url: 'https://popup.test/next',
      frameId: 2,
      documentId: 'doc-child',
      sourceUrl: 'https://fixture.test/frame',
    },
  ]);
  fire('data:text/plain,own');
  fire('https://popup.test/foreign', { ...sender, id: 'foreign-extension' });
  f.current.delete(11);
  fire('https://popup.test/stopped');
  assert.equal(f.emitted.length, 1);
  assert.equal(
    f.calls.some((call) => call.api === 'create'),
    false,
  );
});

test('popup preparation failure rejects enabled headers except on exact about:blank', async () => {
  const f = fixture();
  f.intercept(async (request) => {
    if (request.func.name === 'installPopupBridge') return [{ result: false }];
  });
  await assert.rejects(f.preparation.prepare(f.record, { headerEnabled: true }), {
    kind: 'preparation_failed',
    message: 'Unable to prepare popup request headers. Retry the browser command.',
  });
  f.tabs.get(11).url = 'about:blank';
  assert.deepEqual(await f.preparation.prepare(f.record, { headerEnabled: true }), {
    foreignInstalled: true,
    popupInstalled: false,
  });
});

test('navigation re-prepares only the new active document under the same current lease', async () => {
  const f = fixture();
  await f.preparation.prepare(f.record);
  f.setFrames([
    { frameId: 0, documentId: 'doc-main-a', documentLifecycle: 'active' },
    { frameId: 2, documentId: 'doc-child-b', documentLifecycle: 'active' },
  ]);
  f.chrome.webNavigation.onCommitted.fire({ tabId: 11, frameId: 2 });
  await tick();
  const installs = f.calls.filter((call) => call.func?.name === 'installForeignFrameMonitor');
  assert.deepEqual(
    installs.map((call) => call.target.documentIds),
    [['doc-main-a'], ['doc-child-b']],
  );
  f.current.delete(11);
  const count = f.calls.length;
  f.chrome.webNavigation.onCommitted.fire({ tabId: 11, frameId: 0 });
  await tick();
  assert.equal(f.calls.length, count);
});

test('incomplete frame inventory uses the same fixed all-frame observer fallback', async () => {
  const f = fixture();
  f.setFrames([{ frameId: 0, documentId: 'doc-main-a', documentLifecycle: 'cached' }]);
  assert.equal((await f.preparation.prepare(f.record)).foreignInstalled, true);
  const installed = f.calls.find((call) => call.func?.name === 'installForeignFrameMonitor');
  assert.deepEqual(installed.target, { tabId: 11, allFrames: true });
  assert.equal(installed.world, 'ISOLATED');
});

test('a late old-document reply cannot suppress installation in a newly committed document', async () => {
  const f = fixture();
  let release, reached;
  const entered = new Promise((resolve) => {
    reached = resolve;
  });
  f.intercept((request) => {
    if (
      request.func.name === 'installForeignFrameMonitor' &&
      request.target.documentIds?.[0] === 'doc-main-a'
    ) {
      reached();
      return new Promise((resolve) => {
        release = resolve;
      });
    }
  });
  const old = f.preparation.prepare(f.record);
  await entered;
  f.setFrames([{ frameId: 0, documentId: 'doc-main-b', documentLifecycle: 'active' }]);
  f.chrome.webNavigation.onCommitted.fire({ tabId: 11, frameId: 0 });
  await tick();
  assert.deepEqual([...f.record.preparation.documents], ['doc-main-b']);
  release([{ documentId: 'doc-main-a', result: true }]);
  assert.equal((await old).foreignInstalled, false);
  assert.deepEqual([...f.record.preparation.documents], ['doc-main-b']);
});

test('Stop fences intent synchronously and waits for a late bridge before exact cleanup', async () => {
  const f = fixture();
  let release, reached;
  const entered = new Promise((resolve) => {
    reached = resolve;
  });
  f.intercept((request) => {
    if (request.func.name === 'installPopupBridge') {
      reached();
      return new Promise((resolve) => {
        release = resolve;
      });
    }
    return undefined;
  });
  const prepare = f.preparation.prepare(f.record, { popupEnabled: true });
  await entered;
  const stop = f.preparation.stop(f.record);
  assert.equal(f.preparation.cleanupConfirmed(f.record), false);
  f.chrome.runtime.onMessage.fire(
    { type: 'MAKA_OPEN_BACKGROUND_POPUP', url: 'https://popup.test/' },
    { id: 'own-extension', tab: { id: 11 } },
  );
  assert.equal(f.emitted.length, 0);
  release([{ result: true }]);
  await prepare;
  assert.equal((await stop).cleanupConfirmed, true);
  assert.equal(f.preparation.cleanupConfirmed(f.record), true);
  assert.equal(
    f.calls.some((call) => call.func?.name === 'installPopupHook'),
    false,
  );
  const cleanup = f.calls.filter((call) => call.func?.name.startsWith('remove'));
  assert.deepEqual(cleanup.map((call) => call.func.name).sort(), [
    'removeForeignFrameMonitor',
    'removePopupBridge',
  ]);
  assert.ok(cleanup.every((call) => call.args[1] === 'claim-a'));
});

test('unknown script cleanup remains unconfirmed while actual tab removal settles document effects', async () => {
  const f = fixture();
  await f.preparation.prepare(f.record, { popupEnabled: true });
  f.intercept((request) => {
    if (request.func.name === 'removePopupHook') throw Error('lost cleanup reply');
  });
  await assert.rejects(f.preparation.stop(f.record), { kind: 'outcome_unknown' });
  assert.equal(f.preparation.cleanupConfirmed(f.record), false);
  assert.equal((await f.preparation.stop(f.record, { gone: true })).proof, 'tab_removed');
  assert.equal(
    f.preparation.cleanupConfirmed(f.record),
    true,
    'actual removal destroys the prepared documents',
  );
});

test('no mutating script dispatched means no invented cleanup obligation', async () => {
  const f = fixture();
  delete f.chrome.scripting;
  const outcome = await f.preparation.prepare(f.record);
  assert.equal(outcome.foreignInstalled, false);
  assert.equal(f.preparation.available(), false);
  assert.equal((await f.preparation.stop(f.record)).cleanupConfirmed, true);
  assert.equal(f.calls.filter((call) => call.api === 'script').length, 0);
});

test('a preparation API lost after injection preserves unknown cleanup custody', async () => {
  const f = fixture();
  await f.preparation.prepare(f.record);
  delete f.chrome.scripting;
  await assert.rejects(f.preparation.stop(f.record), { kind: 'outcome_unknown' });
  assert.equal(f.preparation.cleanupConfirmed(f.record), false);
});
