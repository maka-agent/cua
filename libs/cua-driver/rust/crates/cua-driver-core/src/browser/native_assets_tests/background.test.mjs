import test from 'node:test';
import assert from 'node:assert/strict';
const tick = () => new Promise((resolve) => setImmediate(resolve));
const deferred = () => {
  let resolve;
  const promise = new Promise((r) => {
    resolve = r;
  });
  return { promise, resolve };
};
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
let caseId = 0;
async function fixture(initialHooks = {}) {
  const calls = [];
  const ports = [];
  const hooks = { ...initialHooks };
  let rules = [];
  const attached = new Set();
  const chrome = {
    action: { onClicked: event() },
    downloads: { onCreated: event(), onChanged: event() },
    runtime: {
      id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      onStartup: event(),
      connectNative(host) {
        calls.push(['connect', host]);
        const port = {
          messages: [],
          onMessage: event(),
          onDisconnect: event(),
          closed: 0,
          postMessage(value) {
            if (hooks.failPost) throw new Error('port gone');
            this.messages.push(value);
          },
          disconnect() {
            this.closed++;
            this.onDisconnect.fire();
          },
        };
        ports.push(port);
        return port;
      },
    },
    tabs: {
      async query() {
        return hooks.query
          ? hooks.query()
          : [{ id: 1, windowId: 3, index: 0, title: 'actual', url: 'about:blank' }];
      },
      onRemoved: event(),
      onActivated: event(),
    },
    tabGroups: { onRemoved: event() },
    declarativeNetRequest: {
      async getSessionRules() {
        return rules;
      },
      async updateSessionRules({ removeRuleIds, addRules }) {
        if (hooks.failDnr) throw Error('DNR update unavailable');
        rules = rules.filter((rule) => !removeRuleIds.includes(rule.id)).concat(addRules);
      },
    },
    debugger: {
      onEvent: event(),
      onDetach: event(),
      async getTargets() {
        return [{ id: 'target-1', tabId: 1, type: 'page', attached: attached.has(1) }];
      },
      async attach() {
        calls.push(['attach']);
        attached.add(1);
      },
      async detach(source) {
        calls.push(['detach']);
        attached.delete(1);
        chrome.debugger.onDetach.fire(source, 'canceled_by_user');
      },
      async sendCommand(source, method) {
        calls.push(['cdp', method]);
        chrome.debugger.onEvent.fire(source, 'Page.loadEventFired', { timestamp: 1 });
        return {};
      },
    },
  };
  globalThis.chrome = chrome;
  await import(`../native_assets/background.mjs?fixture=${++caseId}`);
  await tick();
  const bind = (port, generation) =>
    port.onMessage.fire({ kind: 'bound', protocol: 1, generation });
  const request = (port, id, method, params = {}, generation = 'gen-1') =>
    port.onMessage.fire({
      kind: 'request',
      protocol: 1,
      generation,
      owner: 'owner-a',
      id: String(id),
      method,
      params,
    });
  return { chrome, calls, hooks, ports, bind, request, rules: () => rules };
}
test('background connects only own native host and sends real metadata through bound generation', async () => {
  const f = await fixture();
  const p = f.ports[0];
  assert.equal(f.calls[0][1], 'org.apache.maka.browser_connector');
  assert.equal(p.messages[0].kind, 'hello');
  f.bind(p, 'gen-1');
  f.request(p, 1, 'inventory');
  await tick();
  assert.equal(p.messages.at(-1).result.tabs[0].title, 'actual');
  assert.equal(
    f.calls.some((c) => c[0] === 'attach'),
    false,
  );
  p.disconnect();
});
test('response/event send loss retires port and own claim without throwing or replaying input', async () => {
  const f = await fixture();
  const p = f.ports[0];
  f.bind(p, 'gen-1');
  f.request(p, 1, 'attach', { tabId: 1 });
  await tick();
  const token = p.messages.at(-1).result.claim;
  f.hooks.failPost = true;
  assert.doesNotThrow(() =>
    f.request(p, 2, 'cdp', { claim: token, method: 'Input.insertText', params: { text: 'one' } }),
  );
  await tick();
  assert.equal(p.closed, 1);
  assert.equal(f.calls.filter((c) => c[0] === 'detach').length, 1);
  assert.equal(f.calls.filter((c) => c[0] === 'cdp').length, 1);
});
test('late old-port response cannot enter a newly bound native generation', async () => {
  const f = await fixture();
  const p = f.ports[0];
  f.bind(p, 'gen-1');
  const gate = deferred();
  f.hooks.query = () => gate.promise;
  f.request(p, 1, 'inventory');
  p.disconnect();
  f.chrome.action.onClicked.fire();
  await tick();
  const next = f.ports[1];
  f.bind(next, 'gen-2');
  gate.resolve([{ id: 1, title: 'old reply' }]);
  await tick();
  assert.equal(next.messages.length, 1);
  assert.equal(next.messages[0].kind, 'hello');
  f.hooks.query = null;
  f.request(next, 1, 'inventory', {}, 'gen-2');
  await tick();
  assert.equal(next.messages.at(-1).result.tabs[0].title, 'actual');
  next.disconnect();
});
test('reconnect cannot advertise ready transport while scoped-rule cleanup remains unacknowledged', async () => {
  const f = await fixture();
  const p = f.ports[0];
  f.bind(p, 'gen-1');
  f.request(p, 1, 'attach', { tabId: 1 });
  await tick();
  const claim = p.messages.at(-1).result.claim;
  f.request(p, 2, 'setScopedHeaders', {
    claim,
    sessionId: 'session-one',
    headers: [{ name: 'x-browser-agent', value: 'Maka/session-one' }],
  });
  await tick();
  assert.equal(f.rules().length, 2);
  f.hooks.failDnr = true;
  p.disconnect();
  await tick();
  f.chrome.action.onClicked.fire();
  await tick();
  assert.equal(f.ports.length, 1);
  f.hooks.failDnr = false;
  f.chrome.action.onClicked.fire();
  await tick();
  assert.equal(f.ports.length, 2);
  assert.equal(f.rules().length, 0);
  assert.equal(f.ports[1].messages[0].capabilities.scopedHeaders, true);
  f.ports[1].disconnect();
});
