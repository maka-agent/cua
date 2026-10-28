// SPDX-License-Identifier: MIT

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';
import { FixedUi } from '../extension_assets/fixed-ui.mjs';

const asset = readFileSync(new URL('../extension_assets/maka-ui/cursor.js', import.meta.url), 'utf8');
const deferred = () => {
  let resolve;
  const promise = new Promise((value) => { resolve = value; });
  return { promise, resolve };
};
function world() {
  const artwork = [];
  class Element {
    constructor(tagName) {
      this.tagName = tagName; this.children = []; this.parentNode = null;
      this.style = { setProperty(name, value) { this[name] = value; } };
      this.attributes = {}; this.textContent = ''; this.open = false;
    }
    get isConnected() { return this === root || this.parentNode?.isConnected === true; }
    setAttribute(name, value) { this.attributes[name] = value; }
    append(...children) { for (const child of children) { child.remove(); child.parentNode = this; this.children.push(child); } }
    replaceChildren(...children) { for (const child of [...this.children]) child.remove(); this.append(...children); }
    remove() { if (this.parentNode) this.parentNode.children = this.parentNode.children.filter((child) => child !== this); this.parentNode = null; }
    attachShadow() { this.shadow = new Element('shadow'); this.shadow.parentNode = this; return this.shadow; }
    matches(selector) { return selector === ':popover-open' && this.open; }
    showPopover() { this.open = true; }
    hidePopover() { this.open = false; }
    getAnimations() { return []; }
    animate() { return { finished: Promise.resolve(), cancel() {} }; }
  }
  const root = new Element('html');
  const sandbox = {
    document: { documentElement: root, createElement: (tag) => new Element(tag), importNode: (node) => node },
    DOMParser: class { parseFromString(markup) { assert.match(markup, /^<svg /); assert.equal(markup.includes('<script'), false); artwork.push(markup); return { documentElement: new Element('svg') }; } },
    innerWidth: 1024, innerHeight: 768,
    matchMedia: () => ({ matches: false }), getComputedStyle: () => ({ transform: 'none' }),
    requestAnimationFrame: (callback) => { queueMicrotask(() => callback(0)); return 1; },
  };
  const context = vm.createContext(sandbox);
  return { context, root, artwork };
}
function texts(node) {
  return [node.textContent, ...node.children.flatMap(texts), ...(node.shadow ? texts(node.shadow) : [])].filter(Boolean);
}
function fixture() {
  const record = { tabId: 17, owner: 'owner', generation: 'generation', tabRemoved: false };
  const scope = { scopeId: 'scope-a', ending: false };
  record.scope = scope;
  const worlds = new Map([['doc-a', world()]]);
  const calls = [];
  const hooks = {};
  let documentId = 'doc-a';
  const chrome = {
    webNavigation: { async getAllFrames() { if (hooks.frames) return hooks.frames(); return [{ frameId: 0, documentId }]; } },
    tabs: { async get(id) { assert.equal(id, 17); return { id, active: true, windowId: 8 }; } },
    windows: { async get(id) { return { id, focused: true, state: 'normal' }; }, onFocusChanged: { addListener() {} } },
    scripting: { async executeScript(request) {
      calls.push(request);
      assert.equal(request.world, 'ISOLATED');
      assert.equal(request.target.tabId, 17);
      const id = request.target.documentIds?.[0] ?? documentId;
      const selected = worlds.get(id);
      if (!selected) throw new Error('actual fixture document unavailable');
      if (request.files) {
        assert.deepEqual(request.files, ['maka-ui-cursor.js']);
        if (hooks.beforeLoad) await hooks.beforeLoad(id);
        vm.runInContext(asset, selected.context);
        return [{ frameId: 0, documentId: id }];
      }
      const operation = request.args[0].operation;
      if (hooks.beforeRender) await hooks.beforeRender(operation);
      selected.context.fixtureArgs = request.args;
      const result = await vm.runInContext(`(${request.func.toString()})(...fixtureArgs)`, selected.context);
      if (hooks.afterRender) await hooks.afterRender(operation);
      return [{ frameId: 0, documentId: id, result }];
    } },
  };
  Object.defineProperty(chrome, 'debugger', { get() { throw new Error('fixed UI must never acquire or use a debugger'); } });
  const service = new FixedUi(chrome, {
    resolveCurrent: (candidate, current, mode) => candidate === record && record.scope === current
      && (mode === 'cleanup' || !current.ending),
    isGone: () => record.tabRemoved,
    currentScopes: function* () { if (record.scope && !record.scope.ending) yield [record, record.scope]; },
  });
  return {
    service, record, scope, worlds, calls, hooks,
    navigate(id) { documentId = id; if (!worlds.has(id)) worlds.set(id, world()); },
  };
}
const wire = { hostSessionId: 'host-session', hostTurnId: 'turn-a' };
const input = (values = {}) => ({
  operation: 'control', cursor: { id: 'stable-cursor', label: 'Before', color: 'blue', enabled: true, reducedMotion: false },
  ownerEpoch: '1', point: null, action: 'idle', ...values,
});
const plain = (value) => JSON.parse(JSON.stringify(value));

test('one actual canonical renderer and extension realm survives later physical attachment and guards old epochs', async () => {
  const f = fixture();
  const prepared = await f.service.prepare(f.record, f.scope, input(), wire);
  assert.equal(prepared.status, 'attempted'); assert.equal(prepared.acknowledged, true);
  assert.equal(f.worlds.get('doc-a').root.children.length, 2);
  f.record.physical = { state: 'owned', token: 'actual-later-attachment' };
  const moved = await f.service.invoke(f.record, f.scope, input({ operation: 'update', point: [40, 50] }), wire);
  assert.deepEqual(plain(moved.state.requestedPosition), [40, 50]);
  await f.service.invoke(f.record, f.scope, input({ operation: 'configure', ownerEpoch: '2', cursor: { ...input().cursor, label: 'New epoch', enabled: false } }), wire);
  const old = await f.service.invoke(f.record, f.scope, input({ operation: 'update', point: [99, 99] }), wire);
  assert.deepEqual(plain(old.state.requestedPosition), [40, 50]);
  assert.equal(f.calls.filter((call) => call.files).length, 1, 'later Read/attach must not load a second UI world');
  assert.equal(f.worlds.get('doc-a').root.children.length, 2);
  assert.ok(texts(f.worlds.get('doc-a').root).includes('New epoch'));
});

test('passive publication rereads same-epoch latest configuration after actual metadata awaits', async () => {
  const f = fixture();
  await f.service.prepare(f.record, f.scope, input(), wire);
  const entered = deferred(); const release = deferred(); let block = true;
  f.hooks.frames = () => {
    if (block) { block = false; entered.resolve(); return release.promise; }
    return [{ frameId: 0, documentId: 'doc-a' }];
  };
  const refresh = f.service.refresh(f.record, f.scope);
  await entered.promise;
  await f.service.invoke(f.record, f.scope, input({ operation: 'configure', cursor: { ...input().cursor, label: 'Latest', enabled: false } }), wire);
  release.resolve([{ frameId: 0, documentId: 'doc-a' }]);
  await refresh;
  const actual = texts(f.worlds.get('doc-a').root);
  assert.ok(actual.includes('Latest'), 'old passive publication must not undo the current label');
  assert.equal(actual.includes('Before'), false);
});

test('scope seal drains the same actual UI reply before finalization and permits a new scope in the same epoch', async () => {
  const f = fixture();
  const started = deferred(); const release = deferred();
  f.hooks.afterRender = (operation) => {
    if (operation === 'control') { started.resolve(); return release.promise; }
  };
  const preparation = f.service.prepare(f.record, f.scope, input(), wire);
  await started.promise;
  f.scope.ending = true;
  const stop = f.service.stop(f.record, f.scope);
  await Promise.resolve();
  assert.equal(f.calls.some((call) => call.args?.[0].operation === 'finalize'), false);
  assert.throws(() => f.service.invoke(f.record, f.scope, input(), wire), /no longer current/);
  release.resolve();
  await Promise.allSettled([preparation]);
  assert.deepEqual(await stop, { cleanupConfirmed: true });
  assert.equal(f.worlds.get('doc-a').root.children.length, 0);
  f.hooks.afterRender = null;
  const next = { scopeId: 'scope-b', ending: false }; f.record.scope = next;
  const fresh = await f.service.prepare(f.record, next, input({ cursor: { ...input().cursor, label: 'Next turn' } }), wire);
  assert.equal(fresh.acknowledged, true);
  assert.ok(texts(f.worlds.get('doc-a').root).includes('Next turn'));
});

test('later actual tab removal closes retained UI cleanup Unknown without replay', async () => {
  const f = fixture();
  await f.service.prepare(f.record, f.scope, input(), wire);
  f.scope.ending = true;
  f.hooks.beforeRender = (operation) => { if (operation === 'finalize') throw new Error('lost actual cleanup reply'); };
  assert.deepEqual(await f.service.stop(f.record, f.scope), { cleanupConfirmed: false });
  const calls = f.calls.length;
  f.record.tabRemoved = true; f.worlds.clear();
  assert.deepEqual(await f.service.stop(f.record, f.scope), { cleanupConfirmed: true });
  assert.equal(f.calls.length, calls, 'positive absence observation must not replay a cleanup RPC');
});

test('a missing older document or debugger detach is not invented UI cleanup proof', async () => {
  const f = fixture();
  await f.service.prepare(f.record, f.scope, input(), wire);
  f.navigate('doc-b');
  await f.service.refresh(f.record, f.scope);
  f.worlds.delete('doc-a');
  f.record.physical = { detached: true };
  f.scope.ending = true;
  assert.deepEqual(await f.service.stop(f.record, f.scope), { cleanupConfirmed: false });
  assert.equal(f.scope.uiState.cleanupConfirmed, false);
});

test('concurrent top-frame fallback loads retain each actual document cleanup address', async () => {
  const f = fixture();
  const firstLoad = deferred(); const release = deferred();
  f.hooks.frames = () => [];
  f.hooks.beforeLoad = (id) => {
    if (id === 'doc-a') { firstLoad.resolve(); return release.promise; }
  };
  const first = f.service.prepare(f.record, f.scope, input(), wire);
  await firstLoad.promise;
  f.navigate('doc-b');
  const second = await f.service.invoke(f.record, f.scope,
    input({ operation: 'update', point: [40, 50] }), wire);
  assert.equal(second.acknowledged, true);
  release.resolve();
  assert.equal((await first).acknowledged, true);
  assert.ok(f.worlds.get('doc-a').root.children.length > 0);
  assert.ok(f.worlds.get('doc-b').root.children.length > 0);
  f.scope.ending = true;
  assert.deepEqual(await f.service.stop(f.record, f.scope), { cleanupConfirmed: true });
  const finalized = f.calls.filter((call) => call.args?.[0].operation === 'finalize')
    .map((call) => call.target.documentIds?.[0]).sort();
  assert.deepEqual(finalized, ['doc-a', 'doc-b'], 'each actual renderer effect must retain its immutable address');
  assert.equal(f.worlds.get('doc-a').root.children.length, 0);
  assert.equal(f.worlds.get('doc-b').root.children.length, 0);
});

test('canonical SVG preserves the existing Rust theme stroke joins for every color and layer', async () => {
  // Source theme MARK uses joins [2, 1, 1, 2], with 1=miter and 2=round.
  // Inspect the markup actually passed to DOMParser, rather than parsing the
  // asset's literals or restating its implementation in a second renderer.
  for (const color of ['blue', 'mint', 'violet', 'amber', 'rose', 'cyan']) {
    const f = fixture();
    await f.service.prepare(f.record, f.scope,
      input({ cursor: { ...input().cursor, color } }), wire);
    const [markup] = f.worlds.get('doc-a').artwork;
    assert.equal(typeof markup, 'string');
    const joins = [...markup.matchAll(/stroke-linejoin="([^"]+)"/g)].map((match) => match[1]);
    assert.deepEqual(joins, Array(3).fill(['round', 'miter', 'miter', 'round']).flat(), color);
  }
});
