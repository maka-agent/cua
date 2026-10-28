// SPDX-License-Identifier: MIT

import assert from 'node:assert/strict';
import test from 'node:test';
import { ExtensionBrowserConnector } from '../extension_assets/provider-connector.mjs';

const TAB = 41;
const OWNER = 'fixed-session-owner';
const GENERATION = 'fixed-session-generation';
const SCOPE_A = '11111111-1111-4111-8111-111111111111';
const SCOPE_B = '22222222-2222-4222-8222-222222222222';
const WIRE = Object.freeze({
  hostSessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  hostTurnId: 'fixed-preparation-turn',
});
const POLICY = Object.freeze({
  popupEnabled: true,
  headerEnabled: true,
  headers: [{ name: 'x-fixed-session', value: 'captured-policy' }],
});
const UI = Object.freeze({
  cursor: {
    id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
    label: 'Fixed session',
    color: 'mint',
    enabled: true,
    reducedMotion: true,
  },
  ownerEpoch: '9',
  point: null,
  action: 'idle',
  operation: 'control',
});
const INITIAL_UI_ACK = Object.freeze({
  status: 'attempted',
  acknowledged: true,
  state: { status: 'ready', visible: false, requestedPosition: null },
});

function signal() {
  const callbacks = new Set();
  return {
    addListener(callback) { callbacks.add(callback); },
    removeListener(callback) { callbacks.delete(callback); },
    fire(...args) { for (const callback of callbacks) callback(...args); },
  };
}

function pause() {
  let arrive;
  let release;
  const reached = new Promise((resolve) => { arrive = resolve; });
  const pending = new Promise((resolve) => { release = resolve; });
  return { reached, release, enter() { arrive(); return pending; } };
}

async function fixture({ missingScripting = false, initialUiOutcome = 'ready' } = {}) {
  const calls = [];
  const emitted = [];
  const eventWaiters = new Set();
  const paused = new Map();
  const installed = new Set();
  const attached = new Set();
  let foreignAttachment = false;
  let ruleState = [];
  let uuidSequence = 0;
  let initialUiPending = true;
  const tab = { id: TAB, windowId: 7, index: 0, groupId: -1,
    title: 'Fixed fixture', url: 'https://fixed.test/current', active: false };
  const document = { frameId: 0,
    documentId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
    documentLifecycle: 'active', url: tab.url };

  async function entered(tag) {
    const blocked = paused.get(tag);
    if (blocked) {
      paused.delete(tag);
      await blocked.enter();
    }
  }

  const chrome = {
    runtime: { id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', onMessage: signal() },
    downloads: { onCreated: signal(), onChanged: signal() },
    tabs: {
      onRemoved: signal(), onActivated: signal(), onUpdated: signal(), onReplaced: signal(),
      async get(id) {
        calls.push({ api: 'tabs.get', id });
        assert.equal(id, TAB);
        return { ...tab };
      },
      async query() { calls.push({ api: 'tabs.query' }); return [{ ...tab }]; },
      async create(properties) {
        calls.push({ api: 'tabs.create', properties: structuredClone(properties) });
        assert.deepEqual(properties, { active: false, url: 'about:blank', windowId: 7 });
        tab.url = properties.url;
        document.url = properties.url;
        return { ...tab };
      },
      async update(id, change) {
        calls.push({ api: 'tabs.update', id, change });
        assert.fail('session preparation must not navigate, focus, or mute');
      },
      async highlight(change) {
        calls.push({ api: 'tabs.highlight', change });
        assert.fail('session preparation must not focus a tab');
      },
      async remove(id) {
        calls.push({ api: 'tabs.remove', id });
        assert.equal(id, TAB);
        attached.delete(id);
        chrome.tabs.onRemoved.fire(id, {});
      },
    },
    windows: {
      async getAll(properties) {
        calls.push({ api: 'windows.getAll', properties: structuredClone(properties) });
        assert.deepEqual(properties, { windowTypes: ['normal'] });
        return [{ id: 7, type: 'normal', focused: false }];
      },
      async update(id, change) {
        calls.push({ api: 'windows.update', id, change });
        assert.fail('session preparation must not focus a window');
      },
    },
    webNavigation: {
      onCommitted: signal(),
      async getAllFrames(target) {
        calls.push({ api: 'webNavigation.getAllFrames', target });
        assert.equal(target.tabId, TAB);
        return [{ ...document }];
      },
      async getFrame(target) {
        calls.push({ api: 'webNavigation.getFrame', target });
        assert.equal(target.tabId, TAB);
        assert.equal(target.frameId, 0);
        return { ...document };
      },
    },
    debugger: {
      onEvent: signal(), onDetach: signal(),
      async getTargets() {
        calls.push({ api: 'debugger.getTargets' });
        return [{ type: 'page', id: 'fixed-target-41', tabId: TAB,
          attached: foreignAttachment || attached.has(TAB) }];
      },
      async attach(source, version) {
        calls.push({ api: 'debugger.attach', source, version });
        assert.deepEqual(source, { tabId: TAB });
        assert.equal(version, '1.3');
        assert.equal(foreignAttachment, false);
        attached.add(TAB);
      },
      async detach(source) {
        calls.push({ api: 'debugger.detach', source });
        assert.deepEqual(source, { tabId: TAB });
        attached.delete(TAB);
        chrome.debugger.onDetach.fire(source, 'canceled_by_user');
      },
      async sendCommand(source, method, params) {
        calls.push({ api: 'debugger.sendCommand', source, method, params });
        assert.deepEqual(source, { tabId: TAB });
        assert.equal(attached.has(TAB), true);
        assert.equal(['Page.enable', 'Target.attachToTarget'].includes(method), true);
        await entered(`debugger.${method}`);
        return method === 'Page.enable'
          ? { acknowledged: 'Page.enable' }
          : { sessionId: 'old-child-session' };
      },
    },
    declarativeNetRequest: {
      async getSessionRules() { return structuredClone(ruleState); },
      async updateSessionRules(change) {
        calls.push({ api: 'dnr.updateSessionRules', change: structuredClone(change) });
        await entered(change.addRules.length ? 'dnr.install' : 'dnr.clear');
        ruleState = ruleState.filter((rule) => !change.removeRuleIds.includes(rule.id))
          .concat(structuredClone(change.addRules));
      },
    },
    scripting: {
      async executeScript(request) {
        const name = request.files ? 'loadFixedCursorAsset' : request.func.name;
        calls.push({ api: 'scripting.executeScript', name,
          target: structuredClone(request.target), world: request.world,
          files: structuredClone(request.files), args: structuredClone(request.args) });
        assert.equal(request.target.tabId, TAB);
        if (request.files) {
          assert.deepEqual(request.files, ['maka-ui-cursor.js']);
          assert.equal(request.world, 'ISOLATED');
          assert.deepEqual(request.target.documentIds, [document.documentId]);
          await entered('ui.load');
          return [{ frameId: 0, documentId: document.documentId, result: null }];
        }
        if (name === 'invokeRenderer') {
          assert.equal(request.world, 'ISOLATED');
          assert.deepEqual(request.target.documentIds, [document.documentId]);
          assert.equal(request.args.length, 1);
          const input = request.args[0];
          await entered(`ui.${input.operation}`);
          if (initialUiPending && input.operation === 'control') {
            initialUiPending = false;
            if (initialUiOutcome === 'non-ready') {
              calls.push({ api: 'ui.result', operation: input.operation, result: null });
              return [{ frameId: 0, documentId: document.documentId, result: null }];
            }
            if (initialUiOutcome === 'rejected') {
              calls.push({ api: 'ui.rejected', operation: input.operation });
              throw new Error('fixture initial renderer RPC rejection');
            }
          }
          const visible = input.operation === 'update' && input.point !== null
            && input.cursor.enabled;
          const result = { status: 'ready', visible,
            requestedPosition: visible ? [...input.point] : null };
          calls.push({ api: 'ui.result', operation: input.operation, result });
          await entered(`ui.reply.${input.operation}`);
          return [{ frameId: 0, documentId: document.documentId, result }];
        }
        await entered(`script.${name}`);
        const fixed = new Set([
          'popupHookStatus', 'foreignMonitorStatus', 'installPopupBridge',
          'installPopupHook', 'installForeignFrameMonitor', 'removePopupHook',
          'removePopupBridge', 'removeForeignFrameMonitor',
        ]);
        assert.equal(fixed.has(name), true, `unrecognized fixed script ${name}`);
        const ids = request.target.documentIds ?? [document.documentId];
        return ids.map((documentId) => {
          const key = JSON.stringify([documentId, request.world ?? 'ISOLATED',
            request.args[0], request.args[1]]);
          const wasInstalled = installed.has(key);
          if (name.startsWith('install')) installed.add(key);
          if (name.startsWith('remove')) installed.delete(key);
          return { frameId: 0, documentId,
            result: name.endsWith('Status') ? wasInstalled : true };
        });
      },
    },
  };
  if (missingScripting) delete chrome.scripting;
  const connector = new ExtensionBrowserConnector(chrome, {
    emit: (message) => {
      emitted.push(message);
      for (const waiter of [...eventWaiters]) {
        if (waiter.predicate(message)) {
          eventWaiters.delete(waiter);
          waiter.resolve(message);
        }
      }
    },
    randomUUID: () => `00000000-0000-4000-8000-${String(++uuidSequence).padStart(12, '0')}`,
  });
  await connector.initialize();
  connector.bind(GENERATION);
  calls.length = 0;
  let sequence = 0;
  const request = (method, params, wireContext = WIRE, owner = OWNER) => connector.request({
    kind: 'request', protocol: 1, generation: GENERATION, owner,
    id: String(++sequence), method, params, wireContext,
  });
  return {
    chrome, connector, calls, emitted, attached, installed, request,
    requestAs: (owner, method, params, wireContext = WIRE) =>
      request(method, params, wireContext, owner),
    prepare: (scopeId = SCOPE_A) => request('prepareSessionTab', {
      tabId: TAB, scopeId, policy: structuredClone(POLICY), ui: structuredClone(UI),
    }),
    clear: (scopeId = SCOPE_A, wire = WIRE) =>
      request('clearSessionPreparation', { tabId: TAB, scopeId }, wire),
    block(tag) { const blocked = pause(); paused.set(tag, blocked); return blocked; },
    waitEvent(predicate) {
      return new Promise((resolve) => eventWaiters.add({ predicate, resolve }));
    },
    setForeignAttachment(value) { foreignAttachment = value; },
    rules: () => structuredClone(ruleState),
  };
}

function assertNoPhysicalOrContentEffects(calls) {
  assert.deepEqual(calls.filter((call) => call.api.startsWith('debugger.')
    || ['tabs.update', 'tabs.highlight', 'tabs.remove', 'windows.update'].includes(call.api)), []);
}

function prepared(reply, scopeId = SCOPE_A) {
  assert.equal(reply.error, undefined, JSON.stringify(reply));
  assert.equal(reply.result.tab.id, TAB);
  assert.equal(reply.result.sessionOnly, true);
  assert.equal(reply.result.preparation.scopeId, scopeId);
  assert.equal(reply.result.preparation.foreignInstalled, true);
  assert.equal(reply.result.preparation.popupInstalled, true);
  assert.equal(reply.result.preparation.headers.stateConfirmed, true);
  assert.deepEqual(reply.result.preparation.ui, INITIAL_UI_ACK);
  return reply.result.preparation;
}

test('fixed session preparation remains logical until a real physical attach', { timeout: 5000 }, async () => {
  const f = await fixture();
  prepared(await f.prepare());
  assertNoPhysicalOrContentEffects(f.calls);
  assert.equal(f.attached.size, 0);
  const headers = f.calls.findIndex((call) => call.api === 'dnr.updateSessionRules');
  const ui = f.calls.findIndex((call) => call.name === 'invokeRenderer'
    && call.args[0].operation === 'control');
  const fixed = f.calls.findIndex((call) => call.name?.startsWith('install'));
  for (const index of [headers, ui, fixed]) assert.notEqual(index, -1);
  assert.equal(headers < ui && ui < fixed, true,
    'captured DNR policy must precede actual UI control and fixed script installation');
  assert.deepEqual(f.calls[ui].args[0].nativeControl, {
    running: true, observed: false,
    sessionId: WIRE.hostSessionId, turnId: WIRE.hostTurnId,
  });
  assert.deepEqual(f.calls.filter((call) => call.name?.startsWith('install'))
    .map((call) => call.name).sort(),
  ['installForeignFrameMonitor', 'installPopupBridge', 'installPopupHook']);
  const acquired = await f.request('attach', { tabId: TAB });
  assert.equal(acquired.error, undefined, JSON.stringify(acquired));
  assert.equal(acquired.result.targetId, 'fixed-target-41');
  assert.deepEqual(f.calls.filter((call) => call.api === 'debugger.attach'),
    [{ api: 'debugger.attach', source: { tabId: TAB }, version: '1.3' }]);
  const cdp = await f.request('cdp', { claim: acquired.result.claim,
    method: 'Page.enable', params: {} });
  assert.deepEqual(cdp.result, { result: { acknowledged: 'Page.enable' } });
});

async function assertNonfatalInitialUi(f, expectedAck, attemptApi) {
  const reply = await f.prepare();
  assert.equal(reply.error, undefined, JSON.stringify(reply));
  assert.equal(reply.result.tab.id, TAB);
  assert.equal(reply.result.sessionOnly, true);
  assert.equal(reply.result.preparation.scopeId, SCOPE_A);
  assert.equal(reply.result.preparation.foreignInstalled, true);
  assert.equal(reply.result.preparation.popupInstalled, true);
  assert.equal(reply.result.preparation.headers.scope.claim, SCOPE_A);
  assert.equal(reply.result.preparation.headers.stateConfirmed, true);
  assert.deepEqual(reply.result.preparation.ui, expectedAck);
  assert.deepEqual(f.calls.filter((call) => call.name?.startsWith('install'))
    .map((call) => call.name).sort(),
  ['installForeignFrameMonitor', 'installPopupBridge', 'installPopupHook']);
  const header = f.calls.findIndex((call) => call.api === 'dnr.updateSessionRules');
  const attempt = f.calls.findIndex((call) => call.api === attemptApi
    && call.operation === 'control');
  const installations = f.calls.flatMap((call, index) =>
    call.name?.startsWith('install') ? [index] : []);
  assert.notEqual(header, -1);
  assert.notEqual(attempt, -1);
  assert.equal(header < attempt && installations.every((index) => index > attempt), true,
    'fixed foreign and popup hooks must run after the actual nonfatal initial UI attempt');
  assertNoPhysicalOrContentEffects(f.calls);
  const record = f.connector.records.get(TAB);
  const logical = record.logicalPreparation;
  assert.equal(logical.phase, 'ready');
  assert.equal(logical.cleanupConfirmed, false);
  assert.deepEqual(logical.uiState.lastAck, expectedAck);
  assert.equal(logical.uiState.documents.size, 1);
  assert.equal([...logical.uiState.documents.values()][0].attempted, true);
  assert.equal(logical.uiState.cleanupConfirmed, false);
  const blocked = f.block('ui.finalize');
  let acknowledged = false;
  const clearing = f.clear().then((result) => { acknowledged = true; return result; });
  try {
    await blocked.reached;
    await Promise.resolve();
    assert.equal(acknowledged, false);
    assert.equal(f.connector.records.get(TAB), record);
    assert.equal(record.logicalPreparation, logical);
    assert.equal(logical.cleanupConfirmed, false,
      'a tolerated initial UI outcome must retain the actual UI cleanup obligation');
  } finally {
    blocked.release();
  }
  assert.deepEqual((await clearing).result,
    { tabId: TAB, scopeId: SCOPE_A, cleanupConfirmed: true });
  assert.equal(logical.cleanupConfirmed, true);
  assert.equal(logical.uiState.cleanupConfirmed, true);
  assert.equal(f.installed.size, 0);
  assert.deepEqual(f.rules(), []);
  assertNoPhysicalOrContentEffects(f.calls);
}

test('a non-ready initial UI result preserves its false acknowledgement and fixed hooks',
  { timeout: 5000 }, async () => {
    const f = await fixture({ initialUiOutcome: 'non-ready' });
    await assertNonfatalInitialUi(f,
      { status: 'attempted', acknowledged: false }, 'ui.result');
  });

test('an initial renderer RPC rejection preserves unknown UI outcome and fixed hooks',
  { timeout: 5000 }, async () => {
    const f = await fixture({ initialUiOutcome: 'rejected' });
    await assertNonfatalInitialUi(f, { status: 'unknown' }, 'ui.rejected');
  });

// A scheduler barrier drains the already runnable Promise chain; it does not
// advance time. Only the explicit mock-clock ticks advance the UI public wait.
const schedulerTurn = () => new Promise((resolve) => setImmediate(resolve));

function preparedAfterUiPublicWait(reply) {
  assert.equal(reply.error, undefined, JSON.stringify(reply));
  assert.equal(reply.result.tab.id, TAB);
  assert.equal(reply.result.sessionOnly, true);
  assert.equal(reply.result.preparation.scopeId, SCOPE_A);
  assert.equal(reply.result.preparation.foreignInstalled, true);
  assert.equal(reply.result.preparation.popupInstalled, true);
  assert.equal(reply.result.preparation.headers.stateConfirmed, true);
  assert.deepEqual(reply.result.preparation.ui, { status: 'unknown' });
}

test('a one-second renderer public wait retains its same pending reply for cleanup',
  { timeout: 5000 }, async (t) => {
    const f = await fixture();
    const blocked = f.block('ui.reply.control');
    t.mock.timers.enable({ apis: ['setTimeout'] });
    let preparedSettled = false;
    let clearSettled = false;
    const preparing = f.prepare().then((reply) => { preparedSettled = true; return reply; });
    let clearing;
    try {
      await blocked.reached;
      const record = f.connector.records.get(TAB);
      const logical = record.logicalPreparation;
      assert.equal(logical.uiState.pending.size > 0, true);
      assert.equal(f.calls.filter((call) => call.api === 'ui.result'
        && call.operation === 'control').length, 1,
      'the actual renderer effect happened before its same RPC reply was delayed');
      t.mock.timers.tick(999);
      await schedulerTurn();
      assert.equal(preparedSettled, false);
      t.mock.timers.tick(1);
      await schedulerTurn();
      assert.equal(preparedSettled, true,
        'one second ends only the UI public wait, so fixed session preparation can continue');
      preparedAfterUiPublicWait(await preparing);
      assert.equal(logical.uiState.pending.size > 0, true,
        'the original unsettled Chrome RPC must remain in this scope pending set');
      assert.equal(logical.cleanupConfirmed, false);
      clearing = f.clear().then((reply) => { clearSettled = true; return reply; });
      await schedulerTurn();
      await f.connector.headers.queue;
      assert.equal(clearSettled, false);
      assert.equal(record.logicalPreparation, logical);
      assert.deepEqual(f.calls.filter((call) => call.name === 'invokeRenderer'
        && call.args[0].operation === 'finalize'), [],
      'cleanup must not overtake the original renderer reply');
      blocked.release();
      assert.deepEqual((await clearing).result,
        { tabId: TAB, scopeId: SCOPE_A, cleanupConfirmed: true });
      assert.equal(logical.uiState.pending.size, 0);
      assert.equal(f.calls.filter((call) => call.name === 'invokeRenderer'
        && call.args[0].operation === 'control').length, 1,
      'the timed-out UI call must never be replayed');
      assert.equal(f.calls.filter((call) => call.name === 'invokeRenderer'
        && call.args[0].operation === 'finalize').length, 1);
      assertNoPhysicalOrContentEffects(f.calls);
    } finally {
      blocked.release();
      await Promise.allSettled([preparing, clearing].filter(Boolean));
      if (!clearing) await Promise.allSettled([f.clear()]);
      t.mock.timers.reset();
    }
  });

test('a one-second asset public wait cannot append a fresh renderer RPC after timeout',
  { timeout: 5000 }, async (t) => {
    const f = await fixture();
    const blocked = f.block('ui.load');
    t.mock.timers.enable({ apis: ['setTimeout'] });
    let preparedSettled = false;
    let clearSettled = false;
    const preparing = f.prepare().then((reply) => { preparedSettled = true; return reply; });
    let clearing;
    try {
      await blocked.reached;
      const record = f.connector.records.get(TAB);
      const logical = record.logicalPreparation;
      t.mock.timers.tick(1000);
      await schedulerTurn();
      assert.equal(preparedSettled, true,
        'one second ends the asset public wait while its original Chrome RPC remains pending');
      preparedAfterUiPublicWait(await preparing);
      assert.equal(logical.uiState.pending.size > 0, true);
      assert.deepEqual(f.calls.filter((call) => call.name === 'invokeRenderer'), []);
      clearing = f.clear().then((reply) => { clearSettled = true; return reply; });
      await schedulerTurn();
      assert.equal(clearSettled, false);
      assert.equal(record.logicalPreparation, logical);
      blocked.release();
      assert.deepEqual((await clearing).result,
        { tabId: TAB, scopeId: SCOPE_A, cleanupConfirmed: true });
      assert.equal(logical.uiState.pending.size, 0);
      assert.deepEqual(f.calls.filter((call) => call.name === 'invokeRenderer'), [],
        'settling the original timed-out load must not start a new renderer or cleanup RPC');
      assertNoPhysicalOrContentEffects(f.calls);
    } finally {
      blocked.release();
      await Promise.allSettled([preparing, clearing].filter(Boolean));
      if (!clearing) await Promise.allSettled([f.clear()]);
      t.mock.timers.reset();
    }
  });

test('a refused competing fixed preparation cannot reserve another owner created tab',
  { timeout: 5000 }, async () => {
    const f = await fixture();
    const creator = 'fixed-session-creator';
    const created = await f.requestAs(creator, 'createTab', {});
    assert.equal(created.error, undefined, JSON.stringify(created));
    assert.equal(created.result.tab.id, TAB);
    const creation = f.connector.creations.get(created.result.creation);
    assert.equal(creation.owner, creator);
    assert.equal(creation.creationAck, true);
    assert.equal(creation.settled, true);
    assert.equal(f.connector.records.size, 0);
    const creationState = { owner: creation.owner, generation: creation.generation,
      tabId: creation.tabId, closed: creation.closed, closeStarted: creation.closeStarted,
      settled: creation.settled };
    const before = f.calls.length;
    const refused = await f.prepare();
    assert.equal(refused.error.kind, 'tab_busy');
    assert.deepEqual(f.calls.slice(before), [],
      'a competing created-tab owner must be rejected before every Chrome effect');
    assert.equal(f.connector.records.size, 0,
      'a known-refused preparation must not allocate competing resource custody');
    assert.equal(f.connector.creations.get(created.result.creation), creation);
    assert.deepEqual({ owner: creation.owner, generation: creation.generation,
      tabId: creation.tabId, closed: creation.closed, closeStarted: creation.closeStarted,
      settled: creation.settled }, creationState);
    prepared(await f.requestAs(creator, 'prepareSessionTab', {
      tabId: TAB, scopeId: SCOPE_A, policy: structuredClone(POLICY), ui: structuredClone(UI),
    }));
    assert.equal(f.connector.records.get(TAB).owner, creator);
    assert.equal(f.connector.records.get(TAB).logicalPreparation.owner, creator);
    assertNoPhysicalOrContentEffects(f.calls);
    const acquired = await f.requestAs(creator, 'attach', { tabId: TAB });
    assert.equal(acquired.error, undefined, JSON.stringify(acquired));
    assert.equal(acquired.result.targetId, 'fixed-target-41');
    assert.equal(f.connector.claims.get(acquired.result.claim).owner, creator);
    assert.deepEqual(f.calls.filter((call) => call.api === 'debugger.attach'),
      [{ api: 'debugger.attach', source: { tabId: TAB }, version: '1.3' }]);
  });

test('logical preparation token grants neither CDP nor close authority', { timeout: 5000 }, async () => {
  const f = await fixture();
  prepared(await f.prepare());
  const token = f.connector.records.get(TAB).token;
  for (const [method, params] of [
    ['cdp', { claim: token, method: 'Page.enable', params: {} }],
    ['closeTab', { claim: token }],
  ]) {
    const refused = await f.request(method, params);
    assert.equal(refused.error.kind, 'claim_unavailable');
  }
  assertNoPhysicalOrContentEffects(f.calls);
});

test('foreign debugger refusal preserves the fixed session without detaching', { timeout: 5000 }, async () => {
  const f = await fixture();
  prepared(await f.prepare());
  const logical = f.connector.records.get(TAB).logicalPreparation;
  const rules = f.rules();
  f.setForeignAttachment(true);
  const refused = await f.request('attach', { tabId: TAB });
  assert.equal(refused.error.kind, 'foreign_debugger');
  assert.equal(f.connector.records.get(TAB).logicalPreparation, logical);
  assert.deepEqual(f.rules(), rules);
  assert.deepEqual(f.calls.filter((call) => call.api === 'debugger.detach'), []);
  assert.deepEqual(f.calls.filter((call) => call.name?.startsWith('remove')), []);
  f.setForeignAttachment(false);
  assert.deepEqual((await f.clear()).result,
    { tabId: TAB, scopeId: SCOPE_A, cleanupConfirmed: true });
});

test('physical detach preserves the fixed scope and reattach retires the old claim token', { timeout: 5000 }, async () => {
  const f = await fixture();
  prepared(await f.prepare());
  const logical = f.connector.records.get(TAB).logicalPreparation;
  const rules = f.rules();
  const first = await f.request('attach', { tabId: TAB });
  assert.equal(first.error, undefined, JSON.stringify(first));
  const removed = await f.request('detach', { claim: first.result.claim });
  assert.equal(removed.result.detached, true);
  assert.equal(f.connector.records.get(TAB).logicalPreparation, logical);
  assert.deepEqual(f.rules(), rules);
  assert.deepEqual(f.calls.filter((call) => call.name?.startsWith('remove')), []);
  const second = await f.request('attach', { tabId: TAB });
  assert.equal(second.error, undefined, JSON.stringify(second));
  assert.notEqual(second.result.claim, first.result.claim);
  const stale = await f.request('cdp', { claim: first.result.claim,
    method: 'Page.enable', params: {} });
  assert.equal(stale.error.kind, 'claim_unavailable');
  assert.equal(f.calls.filter((call) => call.api === 'debugger.attach').length, 2);
});

test('a late CDP reply stays unknown and cannot mutate a reattached physical facet',
  { timeout: 5000 }, async () => {
    const f = await fixture();
    prepared(await f.prepare());
    const first = await f.request('attach', { tabId: TAB });
    assert.equal(first.error, undefined, JSON.stringify(first));
    const oldFacet = f.connector.records.get(TAB).physical;
    const blocked = f.block('debugger.Target.attachToTarget');
    const oldCall = f.request('cdp', { claim: first.result.claim,
      method: 'Target.attachToTarget', params: { targetId: 'fixed-target-41', flatten: true } });
    await blocked.reached;
    assert.equal(oldFacet.inFlight.size, 1);
    assert.equal(oldFacet.pendingTargetAttaches, 1);
    assert.equal((await f.request('detach', { claim: first.result.claim })).result.detached, true);
    const second = await f.request('attach', { tabId: TAB });
    assert.equal(second.error, undefined, JSON.stringify(second));
    assert.notEqual(second.result.claim, first.result.claim);
    const replacement = f.connector.records.get(TAB).physical;
    const before = { children: [...replacement.children], inFlight: replacement.inFlight.size,
      pendingTargetAttaches: replacement.pendingTargetAttaches };
    blocked.release();
    const late = await oldCall;
    assert.equal(late.error.kind, 'outcome_unknown');
    assert.equal(f.connector.records.get(TAB).physical, replacement);
    assert.deepEqual({ children: [...replacement.children], inFlight: replacement.inFlight.size,
      pendingTargetAttaches: replacement.pendingTargetAttaches }, before);
    assert.equal(oldFacet.inFlight.size, 0);
    assert.equal(oldFacet.pendingTargetAttaches, 0);
  });

test('a stale clear cannot remove a replacement fixed session scope', { timeout: 5000 }, async () => {
  const f = await fixture();
  prepared(await f.prepare());
  assert.deepEqual((await f.clear(SCOPE_A, { ...WIRE, hostTurnId: 'cleanup-turn' })).result,
    { tabId: TAB, scopeId: SCOPE_A, cleanupConfirmed: true });
  prepared(await f.prepare(SCOPE_B), SCOPE_B);
  const logical = f.connector.records.get(TAB).logicalPreparation;
  const rules = f.rules();
  const before = f.calls.length;
  const stale = await f.clear(SCOPE_A);
  assert.equal(stale.error.kind, 'preparation_unavailable');
  assert.equal(f.connector.records.get(TAB).logicalPreparation, logical);
  assert.deepEqual(f.rules(), rules);
  assert.deepEqual(f.calls.slice(before).filter((call) =>
    call.api === 'scripting.executeScript' || call.api === 'dnr.updateSessionRules'), []);
});

test('a replacement scope requires the prior explicit clear acknowledgement', { timeout: 5000 }, async () => {
  const f = await fixture();
  prepared(await f.prepare());
  const before = f.calls.length;
  const conflict = await f.prepare(SCOPE_B);
  assert.equal(conflict.error.kind, 'preparation_pending');
  assert.deepEqual(f.calls.slice(before).filter((call) =>
    call.api === 'scripting.executeScript' || call.api === 'dnr.updateSessionRules'), []);
  assert.deepEqual((await f.clear()).result,
    { tabId: TAB, scopeId: SCOPE_A, cleanupConfirmed: true });
  prepared(await f.prepare(SCOPE_B), SCOPE_B);
});

test('closing a logical-only owner has no fictitious attachment settlement to await', { timeout: 5000 }, async () => {
  const f = await fixture();
  prepared(await f.prepare());
  const closed = await f.request('closeOwner', {});
  assert.equal(closed.error, undefined, JSON.stringify(closed));
  assert.equal(closed.result.cleanupConfirmed, true);
  assert.equal(closed.result.pendingAttachments, 0);
  assert.equal(closed.result.unconfirmedClaims, 0);
  assertNoPhysicalOrContentEffects(f.calls);
  assert.deepEqual(f.rules(), []);
  assert.equal(f.installed.size, 0);
});

test('failed DNR cleanup retains the exact fixed scope and reports unknown', { timeout: 5000 }, async () => {
  const f = await fixture();
  prepared(await f.prepare());
  const logical = f.connector.records.get(TAB).logicalPreparation;
  const installedRules = f.rules();
  const update = f.chrome.declarativeNetRequest.updateSessionRules;
  f.chrome.declarativeNetRequest.updateSessionRules = async (change) => {
    if (change.addRules.length === 0) throw new Error('fixture DNR cleanup rejection');
    return update(change);
  };
  const uncertain = await f.clear();
  assert.equal(uncertain.error.kind, 'outcome_unknown');
  assert.equal(f.connector.records.get(TAB).logicalPreparation, logical);
  assert.deepEqual(f.rules(), installedRules);
  assert.equal(logical.cleanupConfirmed, false);
  const repeated = await f.clear();
  assert.equal(repeated.error.kind, 'outcome_unknown');
  assert.equal(f.connector.records.get(TAB).logicalPreparation, logical);
});

for (const [effect, tag] of [
  ['fixed-script', 'script.removeForeignFrameMonitor'],
  ['UI', 'ui.finalize'],
  ['DNR', 'dnr.clear'],
]) {
  test(`clearSessionPreparation waits for ${effect} cleanup acknowledgement`,
    { timeout: 5000 }, async () => {
      const f = await fixture();
      prepared(await f.prepare());
      const blocked = f.block(tag);
      let acknowledged = false;
      const clearing = f.clear().then((reply) => { acknowledged = true; return reply; });
      try {
        await blocked.reached;
        await Promise.resolve();
        assert.equal(acknowledged, false,
          `${effect} cleanup is still physically awaiting its fake Chrome acknowledgement`);
      } finally {
        blocked.release();
      }
      assert.deepEqual((await clearing).result,
        { tabId: TAB, scopeId: SCOPE_A, cleanupConfirmed: true });
      assert.equal(f.installed.size, 0);
      assert.deepEqual(f.rules(), []);
    });
}

test('clearSessionPreparation drains an in-flight UI update before finalization',
  { timeout: 5000 }, async () => {
    const f = await fixture();
    prepared(await f.prepare());
    const blocked = f.block('ui.update');
    const updating = f.request('sessionUi', { tabId: TAB, scopeId: SCOPE_A,
      ui: { ...structuredClone(UI), operation: 'update', point: [23, 37] } });
    await blocked.reached;
    const headerCleanup = f.block('dnr.clear');
    let acknowledged = false;
    const clearing = f.clear().then((reply) => { acknowledged = true; return reply; });
    try {
      await headerCleanup.reached;
      await Promise.resolve();
      assert.equal(acknowledged, false);
      assert.deepEqual(f.calls.filter((call) => call.name === 'invokeRenderer'
        && call.args[0].operation === 'finalize'), []);
    } finally {
      blocked.release();
      headerCleanup.release();
    }
    await updating;
    assert.deepEqual((await clearing).result,
      { tabId: TAB, scopeId: SCOPE_A, cleanupConfirmed: true });
    const completed = f.calls.findIndex((call) => call.api === 'ui.result'
      && call.operation === 'update');
    const finalized = f.calls.findIndex((call) => call.name === 'invokeRenderer'
      && call.args[0].operation === 'finalize');
    assert.equal(completed < finalized, true);
  });

test('owner cleanup reports final proof counts after a blocked UI finalization',
  { timeout: 5000 }, async () => {
    const f = await fixture();
    prepared(await f.prepare());
    const blocked = f.block('ui.finalize');
    let acknowledged = false;
    const closing = f.request('closeOwner', {}).then((reply) => {
      acknowledged = true;
      return reply;
    });
    try {
      await blocked.reached;
      await f.connector.headers.queue;
      await new Promise((resolve) => setImmediate(resolve));
      assert.equal(f.connector.headers.statusForOwner(OWNER).cleanupConfirmed, true);
      assert.equal(acknowledged, false);
    } finally {
      blocked.release();
    }
    const closed = await closing;
    assert.equal(closed.error, undefined, JSON.stringify(closed));
    assert.equal(closed.result.cleanupConfirmed, true);
    assert.equal(closed.result.pendingAttachments, 0);
    assert.equal(closed.result.unconfirmedClaims, 0);
    assertNoPhysicalOrContentEffects(f.calls);
    assert.deepEqual(f.rules(), []);
    assert.equal(f.installed.size, 0);
  });

test('an unconfirmed UI finalization retains the fixed scope instead of acknowledging clear',
  { timeout: 5000 }, async () => {
    const f = await fixture();
    prepared(await f.prepare());
    const logical = f.connector.records.get(TAB).logicalPreparation;
    const execute = f.chrome.scripting.executeScript;
    f.chrome.scripting.executeScript = async (request) => {
      if (request.func?.name === 'invokeRenderer' && request.args[0].operation === 'finalize') {
        return [{ frameId: 0, documentId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
          result: { status: 'ready', visible: true, requestedPosition: null } }];
      }
      return execute(request);
    };
    const uncertain = await f.clear();
    assert.equal(uncertain.error.kind, 'outcome_unknown');
    assert.equal(f.connector.records.get(TAB).logicalPreparation, logical);
    assert.equal(logical.cleanupConfirmed, false);
    assert.equal(logical.uiState.cleanupConfirmed, false);
    const replacement = await f.prepare(SCOPE_B);
    assert.equal(replacement.error.kind, 'preparation_pending');
  });

test('actual tab removal recovers an unknown UI clear without replaying fixed effects',
  { timeout: 5000 }, async () => {
    const f = await fixture();
    prepared(await f.prepare());
    const record = f.connector.records.get(TAB);
    const logical = record.logicalPreparation;
    const execute = f.chrome.scripting.executeScript;
    f.chrome.scripting.executeScript = async (request) => {
      if (request.func?.name === 'invokeRenderer' && request.args[0].operation === 'finalize') {
        return [{ frameId: 0, documentId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
          result: { status: 'ready', visible: true, requestedPosition: null } }];
      }
      return execute(request);
    };
    const uncertain = await f.clear();
    assert.equal(uncertain.error.kind, 'outcome_unknown');
    assert.equal(f.connector.records.get(TAB), record);
    assert.equal(record.logicalPreparation, logical);
    assert.equal(logical.cleanupConfirmed, false);
    assert.equal(logical.uiState.cleanupConfirmed, false);
    assert.deepEqual(f.rules(), []);

    const recovered = f.waitEvent((event) => event.kind === 'session_preparation_cleanup'
      && event.scopeId === SCOPE_A && event.cleanupConfirmed === true);
    const before = f.calls.length;
    f.chrome.tabs.onRemoved.fire(TAB, { windowId: 7, isWindowClosing: false });
    assert.deepEqual(await recovered, {
      kind: 'session_preparation_cleanup', protocol: 1,
      generation: GENERATION, owner: OWNER, tabId: TAB,
      scopeId: SCOPE_A, cleanupConfirmed: true, wireContext: WIRE,
    });
    assert.equal(f.connector.records.has(TAB), false);
    assert.equal(logical.cleanupConfirmed, true);
    assert.deepEqual(f.calls.slice(before).filter((call) =>
      call.api === 'scripting.executeScript' || call.api === 'dnr.updateSessionRules'), []);
  });

test('tab removal retains DNR uncertainty until an authorized reconciliation acknowledgement',
  { timeout: 5000 }, async () => {
    const f = await fixture();
    prepared(await f.prepare());
    const record = f.connector.records.get(TAB);
    const logical = record.logicalPreparation;
    const installedRules = f.rules();
    const update = f.chrome.declarativeNetRequest.updateSessionRules;
    let rejectCleanup = true;
    f.chrome.declarativeNetRequest.updateSessionRules = async (change) => {
      if (rejectCleanup && change.addRules.length === 0) {
        f.calls.push({ api: 'dnr.updateSessionRules', change: structuredClone(change),
          rejected: true });
        throw new Error('fixture DNR cleanup rejection');
      }
      return update(change);
    };
    const uncertain = await f.clear();
    assert.equal(uncertain.error.kind, 'outcome_unknown');
    assert.equal(record.logicalPreparation, logical);
    assert.equal(logical.cleanupConfirmed, false);
    assert.deepEqual(f.rules(), installedRules);

    const stillUnknown = f.waitEvent((event) => event.kind === 'session_preparation_cleanup'
      && event.scopeId === SCOPE_A && event.cleanupConfirmed === false);
    const beforeRemoval = f.calls.length;
    f.chrome.tabs.onRemoved.fire(TAB, { windowId: 7, isWindowClosing: false });
    assert.deepEqual(await stillUnknown, {
      kind: 'session_preparation_cleanup', protocol: 1,
      generation: GENERATION, owner: OWNER, tabId: TAB,
      scopeId: SCOPE_A, cleanupConfirmed: false, wireContext: WIRE,
    });
    assert.equal(f.connector.records.get(TAB), record);
    assert.equal(record.logicalPreparation, logical);
    assert.equal(logical.cleanupConfirmed, false);
    assert.deepEqual(f.rules(), installedRules);
    assert.deepEqual(f.calls.slice(beforeRemoval).filter((call) =>
      call.api === 'scripting.executeScript' || call.api === 'dnr.updateSessionRules'), []);

    const recovered = f.waitEvent((event) => event.kind === 'session_preparation_cleanup'
      && event.scopeId === SCOPE_A && event.cleanupConfirmed === true);
    rejectCleanup = false;
    const beforeReconciliation = f.calls.length;
    await f.connector.reconcileHeaders();
    assert.deepEqual(await recovered, {
      kind: 'session_preparation_cleanup', protocol: 1,
      generation: GENERATION, owner: OWNER, tabId: TAB,
      scopeId: SCOPE_A, cleanupConfirmed: true, wireContext: WIRE,
    });
    const writes = f.calls.slice(beforeReconciliation).filter((call) =>
      call.api === 'scripting.executeScript' || call.api === 'dnr.updateSessionRules');
    assert.deepEqual(writes.map((call) => call.api), ['dnr.updateSessionRules']);
    assert.deepEqual(writes[0].change.addRules, []);
    assert.equal(installedRules.every((rule) => writes[0].change.removeRuleIds.includes(rule.id)), true);
    assert.deepEqual(f.rules(), []);
    assert.equal(f.connector.records.has(TAB), false);
    assert.equal(logical.cleanupConfirmed, true);
  });

test('missing fixed UI transport refuses preparation before any effect', { timeout: 5000 }, async () => {
  const f = await fixture({ missingScripting: true });
  const refused = await f.prepare();
  assert.equal(refused.error.kind, 'unsupported');
  assertNoPhysicalOrContentEffects(f.calls);
  assert.deepEqual(f.calls.filter((call) =>
    call.api === 'scripting.executeScript' || call.api === 'dnr.updateSessionRules'), []);
});
