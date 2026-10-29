// SPDX-License-Identifier: MIT
// Pure metadata/transport fixtures. These do not prove a real browser favicon.
import test from 'node:test';
import assert from 'node:assert/strict';
import { RetainedTabPresentation } from './fixed-ui.mjs';

const session = '00000000-0000-0000-0000-000000000001';
const event = () => { const callbacks = []; return { addListener: (fn) => callbacks.push(fn), emit: (...args) => callbacks.forEach((fn) => fn(...args)) }; };
function fixture({ active = false, focused = true, stored = undefined } = {}) {
  const records = new Map([[7, { tabId: 7, owner: null, physical: null, tabRemoved: false,
    faviconSource: { pageUrl: 'https://fixture.invalid/', data: 'data:image/png;base64,AA==' } }]]);
  const requests = [], values = stored ? structuredClone(stored) : {};
  const chrome = {
    storage: { session: { get: async () => structuredClone(values), set: async (next) => Object.assign(values, structuredClone(next)) } },
    tabs: { get: async (id) => ({ id, active, windowId: 11, url: 'https://fixture.invalid/', favIconUrl: 'https://fixture.invalid/icon.png' }),
      query: async () => [{ id: 7 }], onActivated: event(), onUpdated: event(), onRemoved: event(), onReplaced: event() },
    windows: { get: async (id) => ({ id, focused }), WINDOW_ID_NONE: -1, onFocusChanged: event() },
    runtime: { getURL: (path) => `chrome-extension://fixture${path}` },
    webNavigation: { getAllFrames: async () => [{ frameId: 0, documentId: 'fixture-document' }] },
    scripting: { executeScript: async (request) => { requests.push(request); return [{ frameId: 0,
      documentId: 'fixture-document', result: { acknowledged: true, applied: request.args[0].status !== null } }]; } },
  };
  const service = new RetainedTabPresentation(chrome, { records: () => records, chromeSessionId: () => session });
  return { service, chrome, records, requests, values };
}

test('seen persists its actual restore intent before renderer ACK and a restart completes it', async () => {
  const f = fixture(); await f.service.initialize();
  await f.service.finalized(f.records.get(7), 'deliverable');
  await f.service.publish(f.records.get(7));
  assert.equal(f.requests.at(-1).args[0].status, 'deliverable');
  let announce;
  const entered = new Promise((resolve) => { announce = resolve; });
  f.chrome.scripting.executeScript = async (request) => {
    f.requests.push(request); announce();
    // A lost worker cannot ACK the queued restore. No timer, socket or browser is used.
    return new Promise(() => {});
  };
  await f.service.seen(7); await entered;
  assert.equal(f.records.get(7).pendingRestore, true);
  const stored = structuredClone(f.values);
  assert.deepEqual(stored['org.apache.maka.retained-presentation.v1'].entries,
    [{ tabId: 7, status: null }]);
  const restarted = fixture({ stored });
  await restarted.service.initialize(); await restarted.service.publications;
  assert.equal(restarted.requests.at(-1).args[0].status, null);
  assert.equal(restarted.records.has(7), false);
  assert.deepEqual(restarted.values['org.apache.maka.retained-presentation.v1'].entries, []);
});
