import assert from 'node:assert/strict';
import test from 'node:test';
import { NativeBrowserConnector } from '../native_assets/provider-connector.mjs';
import { ConnectorError } from '../native_assets/connector.mjs';

const event = () => {
  const listeners = new Set();
  return {
    addListener: (fn) => listeners.add(fn),
    fire: (...args) => [...listeners].forEach((fn) => fn(...args)),
  };
};
const tick = () => new Promise((resolve) => setImmediate(resolve));
const deferred = () => {
  let resolve;
  const promise = new Promise((done) => {
    resolve = done;
  });
  return { promise, resolve };
};

async function fixture(url = 'https://admitted.test/document') {
  const calls = [],
    emitted = [],
    tabs = new Map([[11, { id: 11, windowId: 9, url, active: false }]]);
  let rules = [],
    sequence = 0,
    nextTab = 20,
    scriptInterceptor,
    getInterceptor;
  const attached = new Set(),
    installed = new Set();
  const hash = url.indexOf('#');
  let frame = {
    id: 'frame-main',
    loaderId: 'loader-main',
    url: hash === -1 ? url : url.slice(0, hash),
    ...(hash === -1 ? {} : { urlFragment: url.slice(hash) }),
  };
  const chrome = {
    runtime: { id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', onMessage: event() },
    downloads: { onCreated: event(), onChanged: event() },
    tabs: {
      onRemoved: event(),
      onActivated: event(),
      onUpdated: event(),
      onReplaced: event(),
      async get(id) {
        calls.push(['get', id]);
        if (getInterceptor) await getInterceptor(id);
        if (!tabs.has(id)) throw new Error('No tab');
        return { ...tabs.get(id) };
      },
      async query() {
        return [...tabs.values()].map((tab) => ({ ...tab }));
      },
      async create(options) {
        calls.push(['create', options]);
        const tab = { id: nextTab++, ...options };
        tabs.set(tab.id, tab);
        return { ...tab };
      },
      async update(id, options) {
        calls.push(['update', id, options]);
        Object.assign(tabs.get(id), options);
        return { ...tabs.get(id) };
      },
      async remove(id) {
        calls.push(['remove', id]);
        tabs.delete(id);
        attached.delete(id);
        chrome.tabs.onRemoved.fire(id);
      },
    },
    windows: {
      async getAll() {
        calls.push(['windows']);
        return [{ id: 1, type: 'normal', focused: true }];
      },
    },
    debugger: {
      onEvent: event(),
      onDetach: event(),
      async getTargets() {
        return [...tabs.values()].map((tab) => ({
          id: `target-${tab.id}`,
          tabId: tab.id,
          type: 'page',
          attached: attached.has(tab.id),
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
      async sendCommand(source, method) {
        calls.push(['cdp', source.tabId, method]);
        return method === 'Page.getFrameTree' ? { frameTree: { frame: { ...frame } } } : {};
      },
    },
    webNavigation: {
      onCommitted: event(),
      async getAllFrames() {
        calls.push(['frames']);
        return [{ frameId: 0, documentId: 'document-main', documentLifecycle: 'active' }];
      },
    },
    scripting: {
      async executeScript(request) {
        calls.push(['script', request.func.name, request.args[1], request.world]);
        if (scriptInterceptor) {
          const result = await scriptInterceptor(request);
          if (result !== undefined) return result;
        }
        const key = [request.world, request.args[0], request.args[1]].join(':');
        if (request.func.name.startsWith('install')) installed.add(key);
        if (request.func.name.startsWith('remove')) installed.delete(key);
        return [
          {
            documentId: 'document-main',
            frameId: 0,
            result: request.func.name.endsWith('Status') ? installed.has(key) : true,
          },
        ];
      },
    },
    declarativeNetRequest: {
      async getSessionRules() {
        return rules;
      },
      async updateSessionRules({ removeRuleIds, addRules }) {
        calls.push(['dnr']);
        rules = rules.filter((rule) => !removeRuleIds.includes(rule.id)).concat(addRules);
      },
    },
  };
  let token = 0;
  const connector = new NativeBrowserConnector(chrome, {
    emit: (message) => emitted.push(message),
    randomUUID: () => `token-${++token}`,
  });
  await connector.initialize();
  connector.bind('generation-main');
  const request = (method, params = {}, owner = 'owner-main', wireContext) =>
    connector.request({
      kind: 'request',
      protocol: 1,
      id: String(++sequence),
      generation: 'generation-main',
      owner,
      method,
      params,
      ...(wireContext === undefined ? {} : { wireContext }),
    });
  const attachedClaim = await request('attach', { tabId: 11 });
  assert.ok(attachedClaim.result);
  const claim = attachedClaim.result.claim,
    record = connector.claims.get(claim);
  calls.length = 0;
  const policy = (turn = 'turn-main') => ({
    wireContext: { hostSessionId: 'existing-host-session', hostTurnId: turn },
    document: {
      frameId: frame.id,
      loaderId: frame.loaderId,
      url: frame.url + (frame.urlFragment ?? ''),
    },
    popupEnabled: true,
    headerEnabled: true,
    headers: [{ name: 'x-browser-agent', value: 'Maka/existing-host-session' }],
  });
  return {
    connector,
    chrome,
    calls,
    emitted,
    tabs,
    claim,
    record,
    request,
    policy,
    interceptScript: (fn) => {
      scriptInterceptor = fn;
    },
    interceptGet: (fn) => {
      getInterceptor = fn;
    },
    setFrame: (value) => {
      frame = value;
    },
    prepare: (value = policy()) => connector.prepareLogicalClaim('owner-main', claim, value),
  };
}

test('metadata attachment and metadata normalizer do not install full preparation', async () => {
  const f = await fixture();
  await f.request('prepareUserTab', { tabId: 11 });
  assert.equal(
    f.calls.some((call) => call[0] === 'script' || call[0] === 'dnr'),
    false,
  );
  assert.equal(f.record.logicalPreparation, undefined);
  assert.equal(f.connector.hello().capabilities.attachmentPreparation, 'metadata_only');
});

test('explicit admitted logical upgrade reuses the physical record and prepares headers before fixed scripts', async () => {
  const f = await fixture();
  const result = await f.prepare();
  assert.equal(result.claim, f.claim);
  assert.equal(result.popupInstalled && result.foreignInstalled, true);
  assert.equal(f.connector.claims.get(f.claim), f.record);
  assert.equal(
    f.calls.some((call) => call[0] === 'attach'),
    false,
  );
  const firstScript = f.calls.findIndex((call) => call[0] === 'script');
  assert.ok(f.calls.findIndex((call) => call[0] === 'dnr') < firstScript);
  assert.equal(f.calls.filter((call) => call[0] === 'cdp').length, 2);
  assert.ok(
    result.preparationKey.includes('existing-host-session') &&
      result.preparationKey.includes('turn-main'),
  );
});

test('missing Host scope or changed actual loader refuses before DNR and page effects', async () => {
  const f = await fixture();
  await assert.rejects(f.prepare({ ...f.policy(), wireContext: undefined }), {
    kind: 'invalid_request',
  });
  const captured = f.policy();
  f.setFrame({ id: 'frame-main', loaderId: 'different-loader', url: captured.document.url });
  await assert.rejects(f.prepare(captured), { kind: 'document_changed' });
  assert.equal(
    f.calls.some((call) => call[0] === 'script' || call[0] === 'dnr'),
    false,
  );
  assert.equal(f.record.logicalPreparation, undefined);
});

test('concurrent same logical scope shares actual installation and competing scope does not replay it', async () => {
  const f = await fixture(),
    waiting = deferred();
  f.interceptScript(async (request) => {
    if (request.func.name === 'installPopupBridge') await waiting.promise;
  });
  const first = f.prepare(),
    second = f.prepare();
  await tick();
  await assert.rejects(f.prepare(f.policy('turn-other')), { kind: 'preparation_pending' });
  waiting.resolve();
  await Promise.all([first, second]);
  assert.equal(f.calls.filter((call) => call[1] === 'installPopupBridge').length, 1);
  const before = f.calls.filter((call) => call[0] === 'script').length;
  await f.prepare();
  assert.deepEqual(
    f.calls
      .filter((call) => call[0] === 'script')
      .slice(before)
      .map((call) => call[1]),
    ['popupHookStatus'],
  );
});

test('page popup only emits actual sender metadata with captured Host context and never creates', async () => {
  const f = await fixture();
  await f.prepare();
  f.chrome.runtime.onMessage.fire(
    {
      type: 'MAKA_OPEN_BACKGROUND_POPUP',
      url: 'https://popup.test/next',
      wireContext: { hostSessionId: 'forged', hostTurnId: 'forged' },
    },
    {
      id: f.chrome.runtime.id,
      tab: { id: 11 },
      frameId: 2,
      documentId: 'child-document',
      url: 'https://admitted.test/frame',
    },
  );
  const intent = f.emitted.find((message) => message.kind === 'popup_requested');
  assert.deepEqual(intent.wireContext, f.policy().wireContext);
  assert.equal(intent.claim, f.claim);
  assert.equal(intent.tabId, 11);
  assert.equal(intent.frameId, 2);
  assert.equal(
    f.calls.some((call) => call[0] === 'create'),
    false,
  );
});

test('Host popup creator reserves existing receipt before its first query and uses exact opener window without fallback or navigation', async () => {
  const f = await fixture();
  await f.prepare();
  f.calls.length = 0;
  const waiting = deferred();
  f.interceptGet(async (id) => {
    if (id === 11) await waiting.promise;
  });
  const creation = f.connector.createPopupTab('owner-main', f.claim, f.policy().wireContext);
  assert.equal(
    f.connector.creations.size,
    1,
    'same existing creation custody must precede its first asynchronous query',
  );
  assert.equal(
    f.calls.some((call) => call[0] === 'create'),
    false,
  );
  waiting.resolve();
  const created = await creation;
  assert.deepEqual(f.calls.find((call) => call[0] === 'create')[1], {
    active: false,
    openerTabId: 11,
    url: 'about:blank',
    windowId: 9,
  });
  assert.equal(f.connector.creations.get(created.creation).tabId, created.tab.id);
  assert.equal(
    f.calls.some((call) => call[0] === 'windows' || call[0] === 'update'),
    false,
  );
});

test('old captured popup scope or owner cancellation while resolving opener cannot create or adopt a tab', async () => {
  const f = await fixture();
  await f.prepare();
  assert.throws(
    () => f.connector.createPopupTab('owner-main', f.claim, f.policy('different-turn').wireContext),
    { kind: 'claim_revoked' },
  );
  const waiting = deferred();
  f.interceptGet(async () => waiting.promise);
  const pending = f.connector.createPopupTab('owner-main', f.claim, f.policy().wireContext);
  const stop = f.request('closeOwner');
  waiting.resolve();
  await assert.rejects(pending, { kind: 'claim_revoked' });
  await stop;
  assert.equal(
    f.calls.some((call) => call[0] === 'create'),
    false,
  );
  assert.equal(f.connector.creations.size, 0);
});

test('detach with a late installation waits for exact fixed cleanup and preserves physical proof separately', async () => {
  const f = await fixture(),
    waiting = deferred();
  f.interceptScript(async (request) => {
    if (request.func.name === 'installPopupBridge') await waiting.promise;
  });
  const preparing = f.prepare();
  await tick();
  let done = false;
  const detach = f.request('detach', { claim: f.claim }).then((value) => {
    done = true;
    return value;
  });
  await tick();
  assert.equal(done, false);
  assert.equal(f.connector.claims.get(f.claim), f.record);
  waiting.resolve();
  await assert.rejects(preparing, { kind: 'outcome_unknown' });
  const result = await detach;
  assert.equal(result.result.detached, true);
  assert.equal(result.result.preparationCleanupConfirmed, true);
  assert.ok(f.calls.some((call) => call[1] === 'removePopupBridge'));
  assert.ok(
    f.emitted.some((message) => message.effect === 'fixed_preparation' && message.cleanupConfirmed),
  );
  assert.equal(f.connector.claims.has(f.claim), false);
});

test('failed fixed cleanup retains same custody after known physical detach until real tab removal', async () => {
  const f = await fixture();
  await f.prepare();
  f.interceptScript(async (request) => {
    if (request.func.name.startsWith('remove')) throw new Error('script ACK lost');
  });
  const detached = await f.request('detach', { claim: f.claim });
  assert.equal(detached.error.kind, 'outcome_unknown');
  assert.equal(detached.error.details.physicalProof.detached, true);
  assert.equal(f.connector.claims.get(f.claim), f.record);
  assert.equal(f.connector.cleanupProven(f.record), false);
  assert.ok(
    f.emitted.some(
      (message) => message.effect === 'fixed_preparation' && !message.cleanupConfirmed,
    ),
  );
  f.chrome.tabs.onRemoved.fire(11);
  await tick();
  assert.equal(f.connector.claims.has(f.claim), false);
  assert.equal(f.calls.filter((call) => call[0] === 'detach').length, 1);
});

test('new logical turn waits for old exact hooks cleanup before installing its own scope', async () => {
  const f = await fixture();
  await f.prepare();
  const oldKey = f.record.preparationKey;
  const waiting = deferred();
  f.interceptScript(async (request) => {
    if (request.func.name === 'removePopupHook') await waiting.promise;
  });
  const transition = f.prepare(f.policy('turn-next'));
  await tick();
  assert.equal(f.record.logicalPreparation.wireContext.hostTurnId, 'turn-main');
  assert.throws(() => f.connector.createPopupTab('owner-main', f.claim, f.policy().wireContext), {
    kind: 'claim_revoked',
  });
  assert.equal(
    f.calls.some((call) => call[1] === 'installPopupHook' && call[2] !== oldKey),
    false,
  );
  waiting.resolve();
  await transition;
  assert.equal(f.record.logicalPreparation.wireContext.hostTurnId, 'turn-next');
  assert.notEqual(f.record.preparationKey, oldKey);
  assert.ok(f.calls.some((call) => call[1] === 'removePopupHook' && call[2] === oldKey));
  assert.ok(
    f.calls.some((call) => call[1] === 'installPopupHook' && call[2] === f.record.preparationKey),
  );
});

test('prepareClaim native dispatcher uses only its top-level captured context and reports actual preparation', async () => {
  const f = await fixture(),
    captured = f.policy();
  const params = {
    claim: f.claim,
    document: {
      frameId: captured.document.frameId,
      loaderId: captured.document.loaderId,
      url: captured.document.url,
    },
    policy: {
      popupEnabled: captured.popupEnabled,
      headerEnabled: captured.headerEnabled,
      headers: captured.headers,
    },
  };
  assert.equal(f.connector.hello().capabilities.explicitClaimPreparation, true);
  const missing = await f.request('prepareClaim', params);
  assert.equal(missing.error.kind, 'invalid_request');
  assert.equal(
    f.calls.some((call) => call[0] === 'dnr' || call[0] === 'script'),
    false,
  );
  const forged = await f.request('prepareClaim', { ...params, wireContext: captured.wireContext });
  assert.equal(forged.error.kind, 'invalid_request');
  const prepared = await f.request('prepareClaim', params, 'owner-main', captured.wireContext);
  assert.equal(prepared.result.claim, f.claim);
  assert.equal(prepared.result.foreignInstalled && prepared.result.popupInstalled, true);
  assert.deepEqual(f.record.logicalPreparation.wireContext, captured.wireContext);
});

test('native createPopupTab dispatcher requires exact source claim and captured top-level context', async () => {
  const f = await fixture();
  await f.prepare();
  f.calls.length = 0;
  const missing = await f.request('createPopupTab', { claim: f.claim });
  assert.equal(missing.error.kind, 'claim_revoked');
  const forged = await f.request('createPopupTab', {
    claim: f.claim,
    wireContext: f.policy().wireContext,
  });
  assert.equal(forged.error.kind, 'invalid_request');
  assert.equal(
    f.calls.some((call) => call[0] === 'create'),
    false,
  );
  const created = await f.request(
    'createPopupTab',
    { claim: f.claim },
    'owner-main',
    f.policy().wireContext,
  );
  assert.ok(created.result.creation);
  assert.equal(f.connector.creations.get(created.result.creation).tabId, created.result.tab.id);
  assert.deepEqual(f.calls.find((call) => call[0] === 'create')[1], {
    active: false,
    openerTabId: 11,
    url: 'about:blank',
    windowId: 9,
  });
});

test('disabled popup and header policy still acknowledges only actual foreign preparation', async () => {
  const f = await fixture(),
    captured = f.policy();
  const prepared = await f.request(
    'prepareClaim',
    {
      claim: f.claim,
      document: {
        frameId: captured.document.frameId,
        loaderId: captured.document.loaderId,
        url: captured.document.url,
      },
      policy: { popupEnabled: false, headerEnabled: false, headers: [] },
    },
    'owner-main',
    captured.wireContext,
  );
  assert.equal(prepared.result.foreignInstalled, true);
  assert.equal(prepared.result.popupInstalled, false);
  assert.equal(
    f.calls.some((call) => call[1] === 'installPopupHook'),
    false,
  );
});

test('failed preparation after DNR or script effects keeps same claim custody without fabricating a prep ACK', async () => {
  const f = await fixture(),
    captured = f.policy();
  f.interceptScript(async (request) =>
    request.func.name === 'installPopupBridge' ? [{ result: false }] : undefined,
  );
  const failed = await f.request(
    'prepareClaim',
    {
      claim: f.claim,
      document: {
        frameId: captured.document.frameId,
        loaderId: captured.document.loaderId,
        url: captured.document.url,
      },
      policy: { popupEnabled: true, headerEnabled: true, headers: captured.headers },
    },
    'owner-main',
    captured.wireContext,
  );
  assert.equal(failed.error.kind, 'outcome_unknown');
  assert.equal(failed.error.details.causeKind, 'preparation_failed');
  assert.equal(failed.error.details.custody.claim, f.claim);
  assert.equal('acknowledgedResult' in failed.error.details, false);
  assert.equal(f.connector.claims.get(f.claim), f.record);
  assert.equal(
    f.record.logicalPreparation.headers,
    undefined,
    'policy is held by existing ScopedHeaders, not duplicated in lifetime identity',
  );
  assert.equal(f.connector.attachmentCleanupConfirmed(f.record), false);
  const detached = await f.request('detach', { claim: f.claim });
  assert.equal(detached.result.preparationCleanupConfirmed, true);
  assert.equal(f.connector.claims.has(f.claim), false);
});

test('actual tab destruction remains confirmed when an already pending script-removal ACK fails late', async () => {
  const f = await fixture();
  await f.prepare();
  const waiting = deferred();
  f.interceptScript(async (request) => {
    if (request.func.name === 'removePopupBridge') {
      await waiting.promise;
      throw new Error('late removal ACK lost');
    }
  });
  const stopping = f.request('detach', { claim: f.claim });
  await tick();
  assert.ok(f.calls.some((call) => call[1] === 'removePopupBridge'));
  f.chrome.tabs.onRemoved.fire(11);
  await tick();
  assert.equal(f.record.preparation.cleanupConfirmed, true);
  waiting.resolve();
  const result = await stopping;
  await tick();
  assert.equal(result.result.preparationCleanupConfirmed, true);
  assert.equal(f.record.preparation.cleanupConfirmed, true);
  assert.equal(
    f.emitted.some(
      (message) => message.effect === 'fixed_preparation' && !message.cleanupConfirmed,
    ),
    false,
  );
  assert.equal(f.connector.claims.has(f.claim), false);
});

test('same-turn disabling new popup policy preserves Original enabled-set lifetime until logical cleanup', async () => {
  const f = await fixture();
  await f.prepare();
  f.calls.length = 0;
  const captured = f.policy();
  const prepared = await f.request(
    'prepareClaim',
    {
      claim: f.claim,
      document: {
        frameId: captured.document.frameId,
        loaderId: captured.document.loaderId,
        url: captured.document.url,
      },
      policy: { popupEnabled: false, headerEnabled: false, headers: [] },
    },
    'owner-main',
    captured.wireContext,
  );
  assert.equal(
    prepared.result.popupInstalled,
    true,
    'already enabled same-turn hooks remain until that logical lease is cleaned',
  );
  assert.equal(
    f.calls.some((call) => call[1] === 'removePopupHook'),
    false,
  );
  assert.equal(f.connector.headers.statusForClaim(f.record.headerScope).active, false);
  f.chrome.runtime.onMessage.fire(
    { type: 'MAKA_OPEN_BACKGROUND_POPUP', url: 'https://popup.test/still-enabled' },
    { id: f.chrome.runtime.id, tab: { id: 11 } },
  );
  assert.ok(
    f.emitted.some(
      (message) =>
        message.kind === 'popup_requested' && message.url === 'https://popup.test/still-enabled',
    ),
  );
  await f.request('detach', { claim: f.claim });
  assert.ok(f.calls.some((call) => call[1] === 'removePopupHook'));
});

test('pending opener lookup cannot create after a new turn begins cleaning the captured old scope', async () => {
  const f = await fixture();
  await f.prepare();
  f.calls.length = 0;
  const opener = deferred(),
    cleanup = deferred();
  f.interceptGet(async (id) => {
    if (id === 11) await opener.promise;
  });
  f.interceptScript(async (request) => {
    if (request.func.name === 'removePopupHook') await cleanup.promise;
  });
  const popup = f.connector.createPopupTab('owner-main', f.claim, f.policy().wireContext);
  const nextTurn = f.prepare(f.policy('turn-next'));
  await tick();
  assert.equal(f.record.preparation.ending, true);
  assert.equal(f.record.logicalPreparation.wireContext.hostTurnId, 'turn-main');
  opener.resolve();
  await assert.rejects(popup, { kind: 'claim_revoked' });
  assert.equal(
    f.calls.some((call) => call[0] === 'create'),
    false,
  );
  assert.equal(f.connector.creations.size, 0);
  cleanup.resolve();
  await nextTurn;
});

test('popup intent captures the live approved lease at receipt without rewriting an earlier captured turn', async () => {
  const f = await fixture();
  await f.prepare();
  const message = { type: 'MAKA_OPEN_BACKGROUND_POPUP', url: 'https://popup.test/delayed' };
  const sender = { id: f.chrome.runtime.id, tab: { id: 11 }, documentId: 'document-main' };
  f.chrome.runtime.onMessage.fire(message, sender);
  const before = f.emitted.find((event) => event.kind === 'popup_requested');
  assert.equal(before.wireContext.hostTurnId, 'turn-main');
  await f.prepare(f.policy('turn-next'));
  assert.throws(() => f.connector.createPopupTab('owner-main', f.claim, before.wireContext), {
    kind: 'claim_revoked',
  });
  // Original's type/URL-only runtime message is matched to the actual current
  // source lease when received. It is not evidence of an earlier Host input.
  f.chrome.runtime.onMessage.fire(message, sender);
  const intents = f.emitted.filter((event) => event.kind === 'popup_requested');
  assert.equal(intents.length, 2);
  assert.equal(intents[0].wireContext.hostTurnId, 'turn-main');
  assert.equal(intents[1].wireContext.hostTurnId, 'turn-next');
  assert.equal(
    f.calls.some((call) => call[0] === 'create'),
    false,
  );
});

test('actual detach ACK survives simultaneous header and fixed cleanup ACK loss with its issued immutable identity', async () => {
  const f = await fixture();
  await f.prepare();
  f.calls.length = 0;
  const dnr = deferred(),
    scripts = deferred();
  const update = f.chrome.declarativeNetRequest.updateSessionRules;
  f.chrome.declarativeNetRequest.updateSessionRules = async (value) => {
    await update(value);
    await dnr.promise;
    throw new Error('DNR cleanup ACK lost');
  };
  f.interceptScript(async (request) => {
    if (request.func.name === 'removePopupBridge') {
      await scripts.promise;
      throw new Error('fixed script cleanup ACK lost');
    }
  });
  const expectedTarget = f.record.targetId;
  const pending = f.request('detach', { claim: f.claim });
  await tick();
  assert.equal(
    f.record.detachedAck,
    true,
    'the physical call was actually acknowledged before the effect cleanup failures',
  );
  assert.equal(f.connector.claims.get(f.claim), f.record);
  f.record.targetId = 'changed-observation-after-issued-cleanup';
  dnr.resolve();
  scripts.resolve();
  const result = await pending;
  assert.equal(result.error.kind, 'outcome_unknown');
  assert.deepEqual(result.error.details.physicalProof, {
    detached: true,
    proof: 'detach_ack',
    claim: f.claim,
    tabId: 11,
    targetId: expectedTarget,
  });
  assert.match(result.error.details.headerError, /scoped header.*not acknowledged/);
  assert.equal(typeof result.error.details.preparationError, 'string');
  assert.ok(
    f.emitted.some(
      (event) => event.effect === 'scoped_headers' && event.cleanupConfirmed === false,
    ),
  );
  assert.ok(
    f.emitted.some(
      (event) => event.effect === 'fixed_preparation' && event.cleanupConfirmed === false,
    ),
  );
  assert.equal(f.connector.claims.get(f.claim), f.record);
  assert.equal(f.connector.cleanupProven(f.record), false);
  assert.equal(f.record.preparation.cleanupConfirmed, false);
  assert.equal(f.connector.headers.statusForClaim(f.record.headerScope).cleanupConfirmed, false);
  assert.equal(f.calls.filter((call) => call[0] === 'detach').length, 1);
  assert.equal(
    f.calls.some((call) => call[0] === 'attach' || call[0] === 'create'),
    false,
  );
});

test('joint-cleanup recovery refuses foreign, nested, malformed and differently typed physical facts', async () => {
  const f = await fixture();
  const issued = f.connector.cleanupIdentity(f.record, 'detach');
  const error = (proof) =>
    new ConnectorError('outcome_unknown', 'header cleanup failed', {
      physicalProof: proof,
      headerError: 'ACK lost',
    });
  const proof = { detached: true, proof: 'detach_ack' };
  const foreign = [
    error({ ...proof, claim: 'foreign-claim' }),
    error({ ...proof, tabId: 12 }),
    error({ ...proof, targetId: 'foreign-target' }),
    error({ closed: true, proof: 'close_ack' }),
    error({ ...proof, proof: 'tab_absent' }),
    error({ ...proof, detached: false }),
    error({ ...proof, closed: false }),
    new ConnectorError('outcome_unknown', 'nested', {
      headerError: 'ACK lost',
      custody: { physicalProof: proof },
    }),
    new ConnectorError('chrome_rejected', 'no ACK', {
      physicalProof: proof,
      headerError: 'ACK lost',
    }),
    Object.assign(new Error('unbranded peer object'), {
      kind: 'outcome_unknown',
      details: { physicalProof: proof, headerError: 'ACK lost' },
    }),
  ];
  for (const candidate of foreign)
    assert.equal(f.connector.canonicalPhysicalFailureProof(candidate, issued), undefined);
  const extra = error({
    ...proof,
    claim: f.claim,
    tabId: 11,
    targetId: issued.targetId,
    preparationCleanupConfirmed: true,
    scopedHeadersCleanupConfirmed: true,
  });
  const recovered = f.connector.canonicalPhysicalFailureProof(extra, issued);
  assert.deepEqual(recovered, { ...proof, claim: f.claim, tabId: 11, targetId: issued.targetId });
  assert.equal('preparationCleanupConfirmed' in recovered, false);
  assert.equal('scopedHeadersCleanupConfirmed' in recovered, false);
});

test('preparation matches actual CDP base URL plus route or trailing hash fragment', async () => {
  for (const url of [
    'https://admitted.test/document#route',
    'https://admitted.test/document#',
    'https://admitted.test/document',
  ]) {
    const f = await fixture(url);
    const captured = f.policy();
    assert.equal(captured.document.url, url);
    const result = await f.prepare(captured);
    assert.equal(result.claim, f.claim);
    assert.equal(result.foreignInstalled, true);
    assert.equal(result.popupInstalled, true);
    assert.equal(f.calls.filter((call) => call[0] === 'cdp').length, 2);
    assert.equal(f.connector.claims.get(f.claim), f.record);
    assert.equal(
      f.calls.some((call) => call[0] === 'attach'),
      false,
    );
  }
});

test('missing actual CDP fragment cannot confirm a captured route or trailing hash', async () => {
  for (const suffix of ['#route', '#']) {
    const f = await fixture('https://admitted.test/document' + suffix);
    const captured = f.policy();
    f.setFrame({
      id: 'frame-main',
      loaderId: 'loader-main',
      url: 'https://admitted.test/document',
    });
    await assert.rejects(f.prepare(captured), { kind: 'document_changed' });
    assert.equal(
      f.calls.some((call) => call[0] === 'script' || call[0] === 'dnr'),
      false,
    );
    assert.equal(f.record.logicalPreparation, undefined);
  }
});

test('changed frame loader base URL or fragment refuses preparation before effects', async () => {
  for (const changed of [
    { id: 'different-frame' },
    { loaderId: 'different-loader' },
    { url: 'https://admitted.test/other-document' },
    { urlFragment: '#other-route' },
    { urlFragment: '' },
  ]) {
    const f = await fixture('https://admitted.test/document#route');
    const captured = f.policy();
    f.setFrame({
      id: 'frame-main',
      loaderId: 'loader-main',
      url: 'https://admitted.test/document',
      urlFragment: '#route',
      ...changed,
    });
    await assert.rejects(f.prepare(captured), { kind: 'document_changed' });
    assert.equal(
      f.calls.some((call) => call[0] === 'script' || call[0] === 'dnr'),
      false,
    );
    assert.equal(f.record.logicalPreparation, undefined);
  }
});

test('malformed CDP URL or explicitly supplied fragment types cannot be coerced or treated as absent', async () => {
  for (const changed of [
    { url: undefined },
    { url: null },
    { url: 7 },
    { url: {} },
    { urlFragment: undefined },
    { urlFragment: null },
    { urlFragment: 7 },
    { urlFragment: [] },
  ]) {
    const f = await fixture();
    const captured = f.policy();
    f.setFrame({
      id: 'frame-main',
      loaderId: 'loader-main',
      url: 'https://admitted.test/document',
      ...changed,
    });
    await assert.rejects(f.prepare(captured), { kind: 'document_changed' });
    assert.equal(
      f.calls.some((call) => call[0] === 'script' || call[0] === 'dnr'),
      false,
    );
  }
});

test('full document URL comparison does not decode canonicalize or trim captured fragments', async () => {
  for (const changed of [
    'https://admitted.test/document#/',
    'https://admitted.test/document#%2F',
    'https://admitted.test/document#%2f ',
  ]) {
    const f = await fixture('https://admitted.test/document#%2f');
    const captured = f.policy();
    captured.document.url = changed;
    await assert.rejects(f.prepare(captured), { kind: 'document_changed' });
    assert.equal(
      f.calls.some((call) => call[0] === 'script' || call[0] === 'dnr'),
      false,
    );
  }
});

test('fragment change while header ACK is pending is fenced before fixed scripts and retains same claim', async () => {
  const f = await fixture('https://admitted.test/document#route');
  const captured = f.policy();
  const gate = deferred();
  const update = f.chrome.declarativeNetRequest.updateSessionRules;
  f.chrome.declarativeNetRequest.updateSessionRules = async (change) => {
    await update(change);
    await gate.promise;
  };
  const pending = f.prepare(captured);
  await tick();
  assert.equal(
    f.calls.some((call) => call[0] === 'dnr'),
    true,
  );
  f.setFrame({
    id: 'frame-main',
    loaderId: 'loader-main',
    url: 'https://admitted.test/document',
    urlFragment: '#new-route',
  });
  gate.resolve();
  await assert.rejects(pending, (error) => {
    assert.equal(error.kind, 'outcome_unknown');
    assert.equal(error.details.causeKind, 'document_changed');
    assert.equal(error.details.custody.claim, f.claim);
    return true;
  });
  assert.equal(
    f.calls.some((call) => call[0] === 'script'),
    false,
  );
  assert.equal(f.connector.claims.get(f.claim), f.record);
  assert.equal(f.connector.records.get(11), f.record);
  assert.equal(f.record.headerScope.claim, f.claim);
});

test('nonempty CDP fragments without a leading hash cannot confirm an accidental concatenation', async () => {
  for (const fragment of ['route', '%23route', ' #route', '?route', '/route']) {
    const f = await fixture();
    const captured = f.policy();
    captured.document.url += fragment;
    f.setFrame({
      id: 'frame-main',
      loaderId: 'loader-main',
      url: 'https://admitted.test/document',
      urlFragment: fragment,
    });
    await assert.rejects(f.prepare(captured), { kind: 'document_changed' });
    assert.equal(
      f.calls.some((call) => call[0] === 'script' || call[0] === 'dnr'),
      false,
    );
    assert.equal(f.record.logicalPreparation, undefined);
  }
});

test('an explicitly empty CDP fragment preserves the exact captured base URL', async () => {
  const f = await fixture();
  const captured = f.policy();
  f.setFrame({
    id: 'frame-main',
    loaderId: 'loader-main',
    url: 'https://admitted.test/document',
    urlFragment: '',
  });
  const result = await f.prepare(captured);
  assert.equal(result.claim, f.claim);
  assert.equal(result.foreignInstalled, true);
  assert.equal(result.popupInstalled, true);
  assert.equal(f.connector.claims.get(f.claim), f.record);
  assert.equal(f.calls.filter((call) => call[0] === 'cdp').length, 2);
});
