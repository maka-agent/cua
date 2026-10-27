import test from 'node:test';
import assert from 'node:assert/strict';
import { NativeBrowserConnector } from '../native_assets/provider-connector.mjs';
const tick = () => new Promise((resolve) => setImmediate(resolve));
const event = () => {
  const listeners = [];
  return {
    addListener(fn) {
      listeners.push(fn);
    },
    fire(...args) {
      for (const fn of listeners) fn(...args);
    },
  };
};
async function fixture() {
  const calls = [];
  const tabs = new Map([
    [
      1,
      {
        id: 1,
        windowId: 3,
        index: 0,
        url: 'chrome://newtab/',
        active: true,
        groupId: -1,
        mutedInfo: { muted: false },
      },
    ],
  ]);
  const groups = new Map();
  let rules = [];
  let id = 200;
  let groupId = 20;
  let token = 0;
  const attached = new Set();
  const events = [];
  const chrome = {
    runtime: { id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' },
    downloads: { onCreated: event(), onChanged: event() },
    tabs: {
      onRemoved: event(),
      onActivated: event(),
      async query(query) {
        return [...tabs.values()]
          .filter((t) => query?.active !== true || t.active)
          .map((t) => ({ ...t }));
      },
      async get(id) {
        if (!tabs.has(id)) throw Error('No tab');
        return { ...tabs.get(id) };
      },
      async create(options) {
        calls.push(['create', options]);
        const tab = {
          id: id++,
          windowId: options.windowId,
          index: 1,
          url: options.url,
          active: options.active,
          groupId: -1,
          mutedInfo: { muted: false },
        };
        tabs.set(tab.id, tab);
        return { ...tab };
      },
      async update(id, options) {
        calls.push(['update', id, options]);
        const tab = tabs.get(id);
        if ('url' in options) tab.url = options.url;
        if ('muted' in options)
          tab.mutedInfo = {
            muted: options.muted,
            reason: 'extension',
            extensionId: chrome.runtime.id,
          };
        return { ...tab };
      },
      async remove(id) {
        calls.push(['remove', id]);
        tabs.delete(id);
        attached.delete(id);
        chrome.tabs.onRemoved.fire(id, {});
      },
      async group(options) {
        calls.push(['group', options]);
        const result = options.groupId ?? groupId++;
        if (!groups.has(result)) groups.set(result, { id: result, windowId: 3 });
        for (const id of options.tabIds) tabs.get(id).groupId = result;
        return result;
      },
      async ungroup(id) {
        tabs.get(id).groupId = -1;
      },
    },
    windows: {
      async getAll() {
        return [{ id: 3, type: 'normal', focused: true }];
      },
    },
    tabGroups: {
      onRemoved: event(),
      async get(id) {
        if (!groups.has(id)) throw Error('No group');
        return { ...groups.get(id) };
      },
      async update(id, options) {
        calls.push(['updateGroup', id, options]);
        Object.assign(groups.get(id), options);
        return { ...groups.get(id) };
      },
    },
    debugger: {
      onEvent: event(),
      onDetach: event(),
      async getTargets() {
        return [...tabs.values()].map((t) => ({
          id: 'target-' + t.id,
          type: 'page',
          tabId: t.id,
          attached: attached.has(t.id),
        }));
      },
      async attach(source) {
        calls.push(['attach', source.tabId]);
        attached.add(source.tabId);
      },
      async detach(source) {
        calls.push(['detach', source.tabId]);
        attached.delete(source.tabId);
        chrome.debugger.onDetach.fire(source, 'canceled_by_user');
      },
      async sendCommand() {
        return {};
      },
    },
    declarativeNetRequest: {
      async getSessionRules() {
        return rules;
      },
      async updateSessionRules({ removeRuleIds, addRules }) {
        calls.push(['dnr', removeRuleIds, addRules]);
        rules = rules.filter((r) => !removeRuleIds.includes(r.id)).concat(addRules);
      },
    },
  };
  const connector = new NativeBrowserConnector(chrome, {
    emit: (e) => events.push(e),
    randomUUID: () => `token-${++token}`,
  });
  await connector.initialize();
  connector.bind('gen-1');
  let seq = 0;
  const request = (method, params = {}, owner = 'owner-a', wireContext) =>
    connector.request({
      kind: 'request',
      protocol: 1,
      generation: 'gen-1',
      id: String(++seq),
      owner,
      method,
      params,
      ...(wireContext === undefined ? {} : { wireContext }),
    });
  return { chrome, connector, tabs, groups, calls, events, request, rules: () => rules };
}
test('composed provider reports actual metadata and source preparation without attaching or focus', async () => {
  const f = await fixture();
  const r = await f.request('prepareUserTab', { tabId: 1 });
  assert.equal(r.result.normalized, true);
  assert.equal(r.result.tab.url, 'about:blank');
  assert.equal(r.result.tab.active, true);
  assert.equal(
    f.calls.some((c) => c[0] === 'attach'),
    false,
  );
  assert.deepEqual(
    f.calls.find((c) => c[0] === 'update'),
    ['update', 1, { url: 'about:blank' }],
  );
  assert.equal(f.connector.hello().capabilities.scopedHeaders, true);
  assert.equal(f.connector.hello().capabilities.createdPresentation, true);
});
test('Host-controlled created presentation uses causal creation receipts and no physical activation', async () => {
  const f = await fixture();
  const created = (await f.request('createTab')).result;
  const c = created.creation;
  assert.equal(
    (await f.request('muteCreatedTab', { creation: c })).result.mutationAcknowledged,
    true,
  );
  assert.equal(f.tabs.get(created.tab.id).active, false);
  const group = (
    await f.request('ensureCreatedTabGroup', {
      creation: c,
      presentation: { title: 'Maka', color: 'blue' },
    })
  ).result.group;
  assert.equal(group.owner, 'owner-a');
  assert.equal(f.groups.get(group.groupId).title, 'Maka');
  const before = f.calls.length;
  assert.equal(
    (
      await f.request(
        'updateCreatedTabGroup',
        { creation: c, group, presentation: { title: 'bad' } },
        'owner-b',
      )
    ).error.kind,
    'creation_unavailable',
  );
  assert.equal(f.calls.length, before);
});
test('actual own-created activation unmutes own-extension mute and does not create focus', async () => {
  const f = await fixture();
  const created = (await f.request('createTab')).result;
  await f.request('muteCreatedTab', { creation: created.creation });
  f.tabs.get(created.tab.id).active = true;
  f.chrome.tabs.onActivated.fire({ tabId: created.tab.id, windowId: 3 });
  await tick();
  assert.equal(f.tabs.get(created.tab.id).mutedInfo.muted, false);
  assert.equal(
    f.calls
      .filter((c) => c[0] === 'update')
      .every((c) => Object.keys(c[2]).every((k) => k === 'muted')),
    true,
  );
});
test('owned user header effects clear on Stop while physical tab stays open', async () => {
  const f = await fixture();
  await f.request('prepareUserTab', { tabId: 1 });
  const claim = (await f.request('attach', { tabId: 1 })).result.claim;
  const applied = await f.request('setScopedHeaders', {
    claim,
    sessionId: 'session-one',
    headers: [{ name: 'x-browser-agent', value: 'Maka/session-one' }],
  });
  assert.equal(applied.result.stateConfirmed, true);
  assert.equal(f.rules().length, 2);
  const stop = await f.request('closeOwner');
  assert.equal(stop.result.cleanupConfirmed, true);
  assert.equal(f.rules().length, 0);
  assert.equal(f.tabs.has(1), true);
  assert.equal(f.calls.filter((c) => c[0] === 'remove').length, 0);
});
test('another authenticated owner cannot normalize a lazy created tab or mutate its headers/group', async () => {
  const f = await fixture();
  const created = (await f.request('createTab')).result;
  f.tabs.get(created.tab.id).url = 'chrome://newtab/';
  const before = f.calls.length;
  assert.equal(
    (await f.request('prepareUserTab', { tabId: created.tab.id }, 'owner-b')).error.kind,
    'tab_busy',
  );
  assert.equal(
    (
      await f.request(
        'ensureCreatedTabGroup',
        { creation: created.creation, presentation: { title: 'Maka' } },
        'owner-b',
      )
    ).error.kind,
    'creation_unavailable',
  );
  assert.equal(f.calls.length, before);
});
test('prepared provider refuses raw ambient managed-group IDs instead of inventing ownership', async () => {
  const f = await fixture();
  const created = (await f.request('createTab')).result;
  const r = await f.request('ensureCreatedTabGroup', {
    creation: created.creation,
    presentation: { groupId: 99, title: 'Maka' },
  });
  assert.equal(r.error.kind, 'invalid_request');
  assert.equal(
    f.calls.some((c) => c[0] === 'group'),
    false,
  );
});
test('old-generation deferred preparation cannot navigate after reconnect revives a new owner', async () => {
  const f = await fixture();
  let release;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  f.chrome.tabs.get = () => gate;
  const pending = f.request('prepareUserTab', { tabId: 1 });
  await tick();
  await f.connector.disconnect();
  f.connector.bind('gen-2');
  release({ id: 1, url: 'chrome://newtab/', windowId: 3, index: 0 });
  assert.ok((await pending).error);
  assert.equal(
    f.calls.some((c) => c[0] === 'update'),
    false,
  );
});
test('presentation queued read cannot mutate after its causal created tab starts closing', async () => {
  const f = await fixture();
  const created = (await f.request('createTab')).result;
  let releaseGet, releaseRemove;
  const readGate = new Promise((resolve) => {
    releaseGet = resolve;
  });
  const removeGate = new Promise((resolve) => {
    releaseRemove = resolve;
  });
  const originalGet = f.chrome.tabs.get;
  f.chrome.tabs.get = async (id) => (id === created.tab.id ? readGate : originalGet(id));
  f.chrome.tabs.remove = async (id) => {
    f.calls.push(['remove', id]);
    await removeGate;
    f.tabs.delete(id);
    f.chrome.tabs.onRemoved.fire(id, {});
  };
  const presentation = f.request('ensureCreatedTabGroup', {
    creation: created.creation,
    presentation: { title: 'Maka' },
  });
  await tick();
  const stop = f.request('stopCreatedTab', { creation: created.creation });
  await tick();
  releaseGet({ ...f.tabs.get(created.tab.id) });
  assert.equal((await presentation).error.kind, 'creation_unavailable');
  assert.equal(
    f.calls.some((c) => c[0] === 'group'),
    false,
  );
  releaseRemove();
  await stop;
});
test('natural activation while created tab close is pending cannot dispatch unmute', async () => {
  const f = await fixture();
  const created = (await f.request('createTab')).result;
  await f.request('muteCreatedTab', { creation: created.creation });
  let releaseRemove;
  const gate = new Promise((resolve) => {
    releaseRemove = resolve;
  });
  f.chrome.tabs.remove = async (id) => {
    await gate;
    f.tabs.delete(id);
    f.chrome.tabs.onRemoved.fire(id, {});
  };
  const stop = f.request('stopCreatedTab', { creation: created.creation });
  await tick();
  f.tabs.get(created.tab.id).active = true;
  f.chrome.tabs.onActivated.fire({ tabId: created.tab.id, windowId: 3 });
  await tick();
  assert.equal(
    f.calls.some((c) => c[0] === 'update' && c[2].muted === false),
    false,
  );
  releaseRemove();
  await stop;
});
test('switching owned tab to unclaimed tab emits actual inactive visibility for owned claim only', async () => {
  const f = await fixture();
  await f.request('prepareUserTab', { tabId: 1 });
  const claim = (await f.request('attach', { tabId: 1 })).result.claim;
  f.tabs.set(2, { id: 2, windowId: 3, index: 1, active: true, url: 'https://unclaimed.test/' });
  f.tabs.get(1).active = false;
  f.chrome.tabs.onActivated.fire({ tabId: 2, windowId: 3 });
  await tick();
  const states = f.events.filter((e) => e.kind === 'tab_state_changed');
  assert.equal(states.at(-1).claim, claim);
  assert.equal(states.at(-1).active, false);
  assert.equal(
    states.some((e) => e.tabId === 2),
    false,
  );
});
test('stale activation query cannot overwrite a newer actual active-tab observation', async () => {
  const f = await fixture();
  await f.request('prepareUserTab', { tabId: 1 });
  await f.request('attach', { tabId: 1 });
  let release;
  let count = 0;
  f.chrome.tabs.query = async () =>
    ++count === 1
      ? new Promise((resolve) => {
          release = resolve;
        })
      : [{ id: 1, windowId: 3, active: true }];
  f.chrome.tabs.onActivated.fire({ tabId: 2, windowId: 3 });
  await tick();
  f.chrome.tabs.onActivated.fire({ tabId: 1, windowId: 3 });
  await tick();
  release([]);
  await tick();
  const states = f.events.filter((e) => e.kind === 'tab_state_changed');
  assert.equal(states.length, 1);
  assert.equal(states[0].active, true);
});
test('failed active-tab observation reports unknown without inventing active=false', async () => {
  const f = await fixture();
  await f.request('prepareUserTab', { tabId: 1 });
  await f.request('attach', { tabId: 1 });
  f.chrome.tabs.query = async () => {
    throw Error('metadata unavailable');
  };
  f.chrome.tabs.onActivated.fire({ tabId: 2, windowId: 3 });
  await tick();
  assert.equal(
    f.events.some((e) => e.kind === 'tab_state_changed'),
    false,
  );
  assert.equal(f.events.at(-1).kind, 'tab_state_unknown');
});
test('Own metadata supplies lastOpened only from actual positive lastAccessed with built-in ISO semantics', async () => {
  const f = await fixture();
  f.tabs.get(1).lastAccessed = 1;
  const tab = (await f.request('inventory')).result.tabs.find((tab) => tab.id === 1);
  assert.equal(tab.lastAccessed, 1);
  assert.equal(tab.lastOpened, '1970-01-01T00:00:00.001Z');
  assert.equal(tab.providerTabId, '1');
  const capabilities = f.connector.hello().capabilities;
  assert.equal(capabilities.userTabsOrder, 'host');
  assert.equal(capabilities.headerScope, 'claim');
  assert.equal(capabilities.createdPresentationOwner, 'host');
  assert.equal(capabilities.cursorPresentationOwner, 'host');
  assert.equal(capabilities.cursorHideOwner, 'host');
  assert.equal(capabilities.turnLifecycleOwner, 'host');
  assert.equal(capabilities.attachmentPreparation, 'metadata_only');
});
test('Own metadata does not synthesize lastOpened for missing, zero, negative or nonfinite activity time', async () => {
  const f = await fixture();
  for (const value of [undefined, 0, -1, NaN, Infinity]) {
    f.tabs.get(1).lastAccessed = value;
    const tab = (await f.request('inventory')).result.tabs.find((tab) => tab.id === 1);
    assert.equal('lastOpened' in tab, false);
  }
});
test('out-of-Date-range positive finite activity time retains Original built-in conversion failure', async () => {
  const f = await fixture();
  f.tabs.get(1).lastAccessed = 1e20;
  const response = await f.request('inventory');
  assert.equal(response.error.kind, 'connector_failure');
  assert.match(response.error.message, /time value/i);
});
test('download observer emits actual metadata only during an existing active control scope', async () => {
  const f = await fixture();
  f.chrome.downloads.onCreated.fire({
    id: 7,
    filename: 'unobserved',
    finalUrl: 'https://file.test/',
  });
  assert.equal(
    f.events.some((event) => event.kind === 'download_changed'),
    false,
  );
  await f.request('prepareUserTab', { tabId: 1 });
  await f.request('attach', { tabId: 1 });
  f.chrome.downloads.onCreated.fire({ id: 8, filename: '', finalUrl: 'https://actual.test/file' });
  const event = f.events.find((event) => event.kind === 'download_changed');
  assert.deepEqual(event.download, {
    id: '8',
    filename: '',
    url: 'https://actual.test/file',
    status: 'started',
  });
  assert.equal(event.generation, 'gen-1');
  assert.equal('owner' in event, false);
  assert.equal('claim' in event, false);
  assert.equal(f.connector.hello().capabilities.downloadNotifications, true);
});
test('late known download completion after owner Stop is metadata, never a physical cancellation claim', async () => {
  const f = await fixture();
  await f.request('prepareUserTab', { tabId: 1 });
  await f.request('attach', { tabId: 1 });
  f.chrome.downloads.onCreated.fire({ id: 9, filename: '', finalUrl: 'https://actual.test/file' });
  await f.request('closeOwner');
  f.chrome.downloads.onChanged.fire({
    id: 9,
    filename: { current: '/actual/Downloads/file' },
    state: { current: 'complete' },
  });
  const event = f.events.filter((event) => event.kind === 'download_changed').at(-1);
  assert.equal(event.download.status, 'complete');
  assert.equal(event.download.filename, '/actual/Downloads/file');
  assert.equal('cleanupConfirmed' in event, false);
  assert.equal(f.tabs.has(1), true);
});
test('native disconnect drops download delivery without replay or browser download mutation', async () => {
  const f = await fixture();
  await f.request('prepareUserTab', { tabId: 1 });
  await f.request('attach', { tabId: 1 });
  f.chrome.downloads.onCreated.fire({
    id: 10,
    filename: 'actual',
    finalUrl: 'https://actual.test/file',
  });
  const count = f.events.filter((event) => event.kind === 'download_changed').length;
  await f.connector.disconnect();
  f.chrome.downloads.onChanged.fire({ id: 10, state: { current: 'complete' } });
  assert.equal(f.events.filter((event) => event.kind === 'download_changed').length, count);
  f.connector.bind('gen-2');
  assert.equal(f.events.filter((event) => event.kind === 'download_changed').length, count);
  assert.deepEqual(Object.keys(f.chrome.downloads).sort(), ['onChanged', 'onCreated']);
});
test('metadata-only scope does not begin tracking unrelated downloads', async () => {
  const f = await fixture();
  await f.request('inventory');
  f.chrome.downloads.onCreated.fire({
    id: 11,
    filename: 'unrelated',
    finalUrl: 'https://actual.test/file',
  });
  f.chrome.downloads.onChanged.fire({ id: 11, state: { current: 'complete' } });
  assert.equal(
    f.events.some((event) => event.kind === 'download_changed'),
    false,
  );
});
test('metadata conversion failure after creation preserves the acknowledged exact creation receipt', async () => {
  const f = await fixture();
  const create = f.chrome.tabs.create;
  f.chrome.tabs.create = async (options) => ({ ...(await create(options)), lastAccessed: 1e20 });
  const response = await f.request('createTab');
  assert.equal(response.error.kind, 'outcome_unknown');
  const acknowledged = response.error.details.acknowledgedResult;
  assert.equal(acknowledged.tab.id, 200);
  assert.equal(f.tabs.has(200), true);
  assert.equal(
    (await f.request('stopCreatedTab', { creation: acknowledged.creation })).result.closed,
    true,
  );
  assert.equal(f.calls.filter((call) => call[0] === 'create').length, 1);
});

const sessionContext = Object.freeze({
  hostSessionId: 'actual-session',
  hostTurnId: 'actual-turn',
});
const resolutionMethods = [
  ['resolve', { rawId: '1' }],
  ['prepareUserTab', { tabId: 1 }],
];
test('session purpose traverses the composed dispatch layers and returns only actual Chrome metadata', async () => {
  const f = await fixture();
  f.tabs.set(1, {
    id: 1,
    windowId: 7,
    url: 'https://actual.test/current',
    title: 'Actual Chrome title',
    groupId: -1,
  });
  const reads = [];
  const get = f.chrome.tabs.get;
  f.chrome.tabs.get = async (id) => {
    reads.push(id);
    return get(id);
  };
  const before = f.calls.length;
  assert.deepEqual(
    (await f.request('resolve', { rawId: '1', sessionOnly: true }, 'owner-a', sessionContext))
      .result,
    {
      tab: {
        id: 1,
        windowId: 7,
        groupId: -1,
        title: 'Actual Chrome title',
        url: 'https://actual.test/current',
        providerTabId: '1',
      },
      sessionOnly: true,
    },
  );
  assert.deepEqual(reads, [1]);
  assert.equal(f.calls.length, before);
  assert.equal(f.connector.claims.size, 0);
  assert.equal(f.connector.records.size, 0);
  assert.equal(f.connector.creations.size, 0);
  assert.equal(f.connector.hello().capabilities.sessionTabResolution, true);
});
test('session selector must be a literal boolean before either semantic method reads Chrome', async () => {
  const f = await fixture();
  let reads = 0;
  f.chrome.tabs.get = async () => {
    reads++;
    throw Error('invalid selector reached Chrome');
  };
  const before = f.calls.length;
  for (const [method, params] of resolutionMethods)
    for (const sessionOnly of [undefined, null, 'true', 1, 0, {}, []]) {
      const response = await f.request(
        method,
        { ...params, sessionOnly },
        'owner-a',
        sessionContext,
      );
      assert.equal(response.error.kind, 'invalid_request', `${method}: ${String(sessionOnly)}`);
      assert.equal('result' in response, false);
    }
  assert.equal(reads, 0);
  assert.equal(f.calls.length, before);
});
test('session purpose requires actual captured envelope context and ignores params context', async () => {
  const f = await fixture();
  let reads = 0;
  f.chrome.tabs.get = async () => {
    reads++;
    throw Error('missing captured context reached Chrome');
  };
  for (const [method, params] of resolutionMethods)
    for (const wireContext of [
      undefined,
      null,
      {},
      { hostSessionId: 'actual-session' },
      { hostTurnId: 'actual-turn' },
      { hostSessionId: ' ', hostTurnId: 'actual-turn' },
      { hostSessionId: 'actual-session', hostTurnId: '\t' },
      { hostSessionId: 5, hostTurnId: 'actual-turn' },
      { hostSessionId: 'actual-session', hostTurnId: 'x'.repeat(4097) },
    ]) {
      const response = await f.request(
        method,
        { ...params, sessionOnly: true, wireContext: sessionContext },
        'owner-a',
        wireContext,
      );
      assert.equal(response.error.kind, 'invalid_request', method);
      assert.equal('result' in response, false);
    }
  assert.equal(reads, 0);
});
test('ordinary absent and false selectors preserve both existing result shapes without context', async () => {
  for (const selector of [{}, { sessionOnly: false }]) {
    const f = await fixture();
    const resolved = await f.request('resolve', { rawId: '1', ...selector });
    assert.deepEqual(resolved.result, {
      tab: {
        id: 1,
        windowId: 3,
        index: 0,
        groupId: -1,
        url: 'chrome://newtab/',
        providerTabId: '1',
        active: true,
      },
    });
    const prepared = await f.request('prepareUserTab', { tabId: 1, ...selector });
    assert.deepEqual(prepared.result, {
      tab: {
        id: 1,
        windowId: 3,
        index: 0,
        groupId: -1,
        url: 'about:blank',
        providerTabId: '1',
        active: true,
      },
      normalized: true,
    });
    assert.deepEqual(
      f.calls.filter((call) => call[0] === 'update'),
      [['update', 1, { url: 'about:blank' }]],
    );
  }
});
test('session tab preparation uses the same exact new-tab normalizer without a new claim', async () => {
  const f = await fixture();
  const response = await f.request(
    'prepareUserTab',
    { tabId: 1, sessionOnly: true },
    'owner-a',
    sessionContext,
  );
  assert.deepEqual(response.result, {
    tab: {
      id: 1,
      windowId: 3,
      index: 0,
      groupId: -1,
      url: 'about:blank',
      providerTabId: '1',
      active: true,
    },
    normalized: true,
    sessionOnly: true,
  });
  assert.deepEqual(
    f.calls.filter((call) => call[0] !== 'dnr'),
    [['update', 1, { url: 'about:blank' }]],
  );
  assert.equal(f.connector.claims.size, 0);
  assert.equal(f.connector.records.size, 0);
  assert.equal(f.connector.creations.size, 0);
});
test('failed actual session reads never return purpose success or invoke the normalizer', async () => {
  const f = await fixture();
  const reads = [];
  f.chrome.tabs.get = async (id) => {
    reads.push(id);
    throw Error('actual Chrome tab was removed');
  };
  const before = f.calls.length;
  for (const [method, params] of resolutionMethods) {
    const response = await f.request(
      method,
      { ...params, sessionOnly: true },
      'owner-a',
      sessionContext,
    );
    assert.equal(response.error.kind, 'chrome_rejected');
    assert.equal('result' in response, false);
  }
  assert.deepEqual(reads, [1, 1]);
  assert.equal(f.calls.length, before);
});
test('session resolution refuses missing or contradictory actual Chrome identity without changing ordinary resolution', async () => {
  const f = await fixture();
  for (const tab of [null, { id: 2, url: 'https://foreign.test/' }]) {
    f.chrome.tabs.get = async () => tab;
    const response = await f.request(
      'resolve',
      { rawId: '1', sessionOnly: true },
      'owner-a',
      sessionContext,
    );
    assert.equal(response.error.kind, 'target_unavailable');
    assert.equal('result' in response, false);
  }
  f.chrome.tabs.get = async () => null;
  assert.deepEqual((await f.request('resolve', { rawId: '1' })).result, { tab: null });
});
test('failed read after acknowledged session normalization retains Unknown without a purpose success echo', async () => {
  const f = await fixture();
  const get = f.chrome.tabs.get;
  let reads = 0;
  f.chrome.tabs.get = async (id) => {
    if (++reads > 1) throw Error('actual metadata ACK lost after update');
    return get(id);
  };
  f.chrome.tabs.update = async (id, options) => {
    f.calls.push(['update', id, options]);
    f.tabs.get(id).url = options.url;
    return { id, url: 'chrome://newtab/' };
  };
  const response = await f.request(
    'prepareUserTab',
    { tabId: 1, sessionOnly: true },
    'owner-a',
    sessionContext,
  );
  assert.equal(response.error.kind, 'outcome_unknown');
  assert.equal(response.error.details.tabId, 1);
  assert.equal('result' in response, false);
  assert.equal(f.tabs.get(1).url, 'about:blank');
  assert.deepEqual(
    f.calls.filter((call) => call[0] === 'update'),
    [['update', 1, { url: 'about:blank' }]],
  );
});

const committedParams = Object.freeze({
  rawId: '1',
  sessionOnly: true,
  committedUrlOnly: true,
});
test('committed session URL returns the exact actual string without reading pending URL or full metadata', async () => {
  const f = await fixture();
  const reads = [];
  const url = 'https://ACTUAL.test/path?raw=%2f#fragment';
  f.chrome.tabs.get = async (id) => {
    reads.push(id);
    return {
      id,
      url,
      get pendingUrl() {
        throw Error('pending navigation is not committed URL data');
      },
      get title() {
        throw Error('committed URL must not expand full tab metadata');
      },
      lastAccessed: 1e20,
    };
  };
  const before = f.calls.length;
  assert.deepEqual(
    (await f.request('resolve', committedParams, 'owner-a', sessionContext)).result,
    { url, sessionOnly: true, committedUrlOnly: true },
  );
  assert.deepEqual(reads, [1]);
  assert.equal(f.calls.length, before);
  assert.equal(f.connector.claims.size, 0);
  assert.equal(f.connector.records.size, 0);
  assert.equal(f.connector.creations.size, 0);
  assert.equal(f.connector.hello().capabilities.sessionCommittedUrl, true);
});
test('committed URL data preserves empty and non-site strings without claiming Origin or liveness', async () => {
  const f = await fixture();
  for (const url of ['', 'about:blank', 'chrome://newtab/', 'data:text/plain,observed']) {
    f.chrome.tabs.get = async () => ({ id: 1, url, pendingUrl: 'https://pending.test/' });
    assert.deepEqual(
      (await f.request('resolve', committedParams, 'owner-a', sessionContext)).result,
      { url, sessionOnly: true, committedUrlOnly: true },
    );
  }
  assert.equal(f.connector.claims.size, 0);
  assert.equal(f.connector.records.size, 0);
});
test('missing or malformed committed URL cannot be substituted by an actual pending URL', async () => {
  const f = await fixture();
  for (const tab of [
    { id: 1, pendingUrl: 'https://pending.test/' },
    { id: 1, url: null, pendingUrl: 'https://pending.test/' },
    { id: 1, url: 7, pendingUrl: 'https://pending.test/' },
    { id: 1, url: {}, pendingUrl: 'https://pending.test/' },
  ]) {
    f.chrome.tabs.get = async () => tab;
    const response = await f.request('resolve', committedParams, 'owner-a', sessionContext);
    assert.equal(response.error.kind, 'target_unavailable');
    assert.equal('result' in response, false);
  }
});
test('committed URL requires the exact actual Chrome tab identity without metadata conversion', async () => {
  const f = await fixture();
  for (const tab of [
    null,
    { url: 'https://actual.test/' },
    { id: 2, url: 'https://actual.test/' },
    { id: Number.MAX_SAFE_INTEGER + 1, url: 'https://actual.test/' },
  ]) {
    f.chrome.tabs.get = async () => tab;
    const response = await f.request('resolve', committedParams, 'owner-a', sessionContext);
    assert.equal(response.error.kind, 'target_unavailable');
    assert.equal('result' in response, false);
  }
});
test('committed session selectors reject malformed or contradictory purposes before Chrome', async () => {
  const f = await fixture();
  let reads = 0;
  f.chrome.tabs.get = async () => {
    reads++;
    throw Error('invalid purpose reached Chrome');
  };
  for (const invalid of [undefined, null, 'true', 1, 0, {}, []])
    for (const field of ['sessionOnly', 'committedUrlOnly']) {
      const response = await f.request(
        'resolve',
        { ...committedParams, [field]: invalid },
        'owner-a',
        sessionContext,
      );
      assert.equal(response.error.kind, 'invalid_request', field);
      assert.equal('result' in response, false);
    }
  for (const params of [
    { rawId: '1', committedUrlOnly: true },
    { rawId: '1', sessionOnly: false, committedUrlOnly: true },
  ]) {
    const response = await f.request('resolve', params);
    assert.equal(response.error.kind, 'invalid_request');
    assert.equal('result' in response, false);
  }
  assert.equal(reads, 0);
});
test('committed session URL requires captured envelope context and cannot use params context', async () => {
  const f = await fixture();
  let reads = 0;
  f.chrome.tabs.get = async () => {
    reads++;
    throw Error('uncaptured scope reached Chrome');
  };
  for (const wireContext of [
    undefined,
    null,
    {},
    { hostSessionId: 'actual-session' },
    { hostSessionId: ' ', hostTurnId: 'actual-turn' },
    { hostSessionId: 'actual-session', hostTurnId: '' },
    { hostSessionId: 'actual-session', hostTurnId: 'x'.repeat(4097) },
  ]) {
    const response = await f.request(
      'resolve',
      { ...committedParams, wireContext: sessionContext },
      'owner-a',
      wireContext,
    );
    assert.equal(response.error.kind, 'invalid_request');
    assert.equal('result' in response, false);
  }
  assert.equal(reads, 0);
});
test('false or absent committed selector preserves ordinary and session tab result shapes', async () => {
  const f = await fixture();
  const ordinary = (await f.request('resolve', { rawId: '1' })).result;
  assert.deepEqual(
    (await f.request('resolve', { rawId: '1', committedUrlOnly: false })).result,
    ordinary,
  );
  assert.deepEqual(
    (await f.request('resolve', { rawId: '1', sessionOnly: false, committedUrlOnly: false }))
      .result,
    ordinary,
  );
  const session = (
    await f.request('resolve', { rawId: '1', sessionOnly: true }, 'owner-a', sessionContext)
  ).result;
  assert.deepEqual(
    (
      await f.request(
        'resolve',
        { rawId: '1', sessionOnly: true, committedUrlOnly: false },
        'owner-a',
        sessionContext,
      )
    ).result,
    session,
  );
  assert.ok(ordinary.tab);
  assert.ok(session.tab);
  assert.equal('url' in ordinary, false);
  assert.equal('committedUrlOnly' in ordinary, false);
  assert.equal('committedUrlOnly' in session, false);
});
test('committed URL observation never normalizes a new-tab page or creates physical custody', async () => {
  const f = await fixture();
  f.tabs.get(1).pendingUrl = 'chrome://new-tab-page/';
  const before = f.calls.length;
  const response = await f.request('resolve', committedParams, 'owner-a', sessionContext);
  assert.deepEqual(response.result, {
    url: 'chrome://newtab/',
    sessionOnly: true,
    committedUrlOnly: true,
  });
  assert.equal(f.tabs.get(1).url, 'chrome://newtab/');
  assert.equal(f.calls.length, before);
  assert.equal(f.connector.claims.size, 0);
  assert.equal(f.connector.records.size, 0);
  assert.equal(f.connector.creations.size, 0);
});
test('closed native owners and malformed envelope owners cannot read committed URL', async () => {
  const f = await fixture();
  await f.request('closeOwner');
  let reads = 0;
  f.chrome.tabs.get = async () => {
    reads++;
    throw Error('ended or invalid owner reached Chrome');
  };
  const ended = await f.request('resolve', committedParams, 'owner-a', sessionContext);
  assert.equal(ended.error.kind, 'owner_closed');
  assert.equal('result' in ended, false);
  const invalid = await f.request('resolve', committedParams, '', sessionContext);
  assert.equal(invalid.error.kind, 'invalid_request');
  assert.equal('result' in invalid, false);
  assert.equal(reads, 0);
});
test('actual Chrome read rejection cannot produce committed URL or purpose acknowledgement', async () => {
  const f = await fixture();
  const reads = [];
  f.chrome.tabs.get = async (id) => {
    reads.push(id);
    throw Error('actual Chrome tab no longer exists');
  };
  const response = await f.request('resolve', committedParams, 'owner-a', sessionContext);
  assert.equal(response.error.kind, 'chrome_rejected');
  assert.equal('result' in response, false);
  assert.deepEqual(reads, [1]);
  assert.equal(f.connector.claims.size, 0);
});
test('owner closure during actual committed URL read retains data as Unknown without a live success', async () => {
  const f = await fixture();
  let release;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  let reads = 0;
  f.chrome.tabs.get = async (id) => {
    reads++;
    await gate;
    return { id, url: 'https://observed-before-reply.test/' };
  };
  const pending = f.request('resolve', committedParams, 'owner-a', sessionContext);
  await tick();
  await f.request('closeOwner');
  release();
  const response = await pending;
  assert.equal(response.error.kind, 'outcome_unknown');
  assert.equal('result' in response, false);
  assert.deepEqual(response.error.details.acknowledgedResult, {
    url: 'https://observed-before-reply.test/',
    sessionOnly: true,
    committedUrlOnly: true,
  });
  assert.equal(reads, 1);
  assert.equal(f.connector.claims.size, 0);
  assert.equal(f.connector.records.size, 0);
});
