import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {
  readUserTab, readPage, readWorkspaceExport, formatYoutubeTranscript,
} from '../extension_assets/user-tab-context.mjs';
const URL_VALUE = 'https://example.test/document';
function chromeFixture({ before = {}, after = {}, result = { text: 'body' }, onExecute } = {}) {
  const calls = []; let reads = 0;
  return { calls, chrome: {
    tabs: { async get(id) { calls.push(['get', id]); return { id, url: URL_VALUE, incognito: false, ...(reads++ ? after : before) }; } },
    scripting: { async executeScript(options) { calls.push(['execute', options]); onExecute?.(); return [{ result }]; } },
    debugger: { attach() { assert.fail('user-tab context must not attach debugger'); } },
    windows: { update() { assert.fail('user-tab context must not focus a window'); } },
  } };
}
test('actual fixed read checks admission and current tab twice without claiming', async () => {
  const { chrome, calls } = chromeFixture(); let checks = 0;
  const value = await readUserTab(chrome, { tabId: 7, expectedUrl: URL_VALUE, read: { kind: 'page' } }, () => checks++);
  assert.deepEqual(value, { text: 'body' }); assert.equal(checks, 2);
  assert.deepEqual(calls.map(([kind]) => kind), ['get', 'execute', 'get']);
  assert.equal(calls[1][1].world, 'ISOLATED'); assert.deepEqual(calls[1][1].args, [URL_VALUE]);
  assert.deepEqual(calls[1][1].target, { tabId: 7 });
});
for (const [label, options, executions] of [
  ['incognito before read', { before: { incognito: true } }, 0],
  ['URL changed before read', { before: { url: URL_VALUE + '#other' } }, 0],
  ['incognito after read', { after: { incognito: true } }, 1],
  ['URL changed after read', { after: { url: 'https://other.test/' } }, 1],
]) test(label, async () => {
  const { chrome, calls } = chromeFixture(options);
  await assert.rejects(readUserTab(chrome, { tabId: 7, expectedUrl: URL_VALUE, read: { kind: 'page' } }, () => {}),
    { message: 'The selected tab changed while being read' });
  assert.equal(calls.filter(([kind]) => kind === 'execute').length, executions);
});
test('non HTTP pages fail before metadata or script dispatch', async () => {
  const { chrome, calls } = chromeFixture();
  await assert.rejects(readUserTab(chrome, { tabId: 7, expectedUrl: 'file:///private', read: { kind: 'page' } }, () => {}),
    { message: 'Tab reads require an HTTP or HTTPS URL' }); assert.deepEqual(calls, []);
});
test('loss of current Host admission after script does not release result', async () => {
  const { chrome } = chromeFixture(); let checks = 0;
  await assert.rejects(readUserTab(chrome, { tabId: 7, expectedUrl: URL_VALUE, read: { kind: 'page' } }, () => {
    if (++checks > 1) throw new Error('host turn retired');
  }), { message: 'host turn retired' });
});
test('page extraction escapes markup, omits password/numeric values and traverses shadow DOM', () => {
  function element(tag, attrs = {}, children = [], extra = {}) {
    return { nodeType: 1, tagName: tag.toUpperCase(), namespaceURI: 'http://www.w3.org/1999/xhtml',
      childNodes: children, getAttribute(name) { return attrs[name] ?? null; },
      getRootNode() { return { activeElement: null }; }, ...extra };
  }
  const text = (textContent) => ({ nodeType: 3, textContent });
  const body = element('body', {}, [text('Hello & <world> '), element('input', { type: 'password' }, [], { type: 'password', value: 'secret' }),
    element('input', { type: 'text' }, [], { type: 'text', value: '123-45' }),
    element('a', { href: '#part' }, [text('same page')]),
    element('div', {}, [], { shadowRoot: { childNodes: [text('shadow')] } }),
  ]);
  const document = { location: { href: URL_VALUE }, body, title: 'T', baseURI: URL_VALUE };
  const context = vm.createContext({ document, Node: { TEXT_NODE: 3, ELEMENT_NODE: 1 }, URL,
    window: { getComputedStyle() { return { display: 'inline', whiteSpace: 'normal' }; } } });
  const value = vm.runInContext(`(${readPage.toString()})(${JSON.stringify(URL_VALUE)})`, context);
  assert.equal(value.text, 'Hello &amp; &lt;world&gt; <input type="password"/><input type="text" value=""/>same pageshadow');
  assert.equal(value.truncated, false); assert.equal(value.url, URL_VALUE);
});
test('page effective path has no 80k text cap', () => {
  const long = 'x'.repeat(80_001), body = { nodeType: 1, tagName: 'BODY', namespaceURI: 'http://www.w3.org/1999/xhtml',
    getAttribute() { return null; }, childNodes: [{ nodeType: 3, textContent: long }] };
  const context = vm.createContext({ document: { location: { href: URL_VALUE }, body, title: 'T' },
    Node: { TEXT_NODE: 3, ELEMENT_NODE: 1 }, window: { getComputedStyle() { return { display: 'block', whiteSpace: 'normal' }; } } });
  const value = vm.runInContext(`(${readPage.toString()})(${JSON.stringify(URL_VALUE)})`, context);
  assert.equal(value.text.length, 80_001); assert.equal(value.truncated, false);
});
async function workspaceFixture(bytes, truncate, limit) {
  let cancelled = false, sent = false;
  const context = vm.createContext({ location: { origin: 'https://docs.google.com' }, Uint8Array, URL, Number, String, Math,
    btoa: (value) => Buffer.from(value, 'binary').toString('base64'),
    fetch: async () => ({ ok: true, url: 'https://docs.google.com/document/d/x/export', headers: new Map(),
      body: { getReader() { return { async read() { if (sent) return { done: true }; sent = true; return { value: Uint8Array.from(bytes) }; }, async cancel() { cancelled = true; } }; } } }),
  });
  const value = await vm.runInContext(`(${readWorkspaceExport.toString()})('https://docs.google.com','https://docs.google.com/document/d/x/export',${limit},'too large',${truncate})`, context);
  return { value, cancelled };
}
test('Workspace actual body respects byte limit and avoids partial UTF-8 text', async () => {
  const { value, cancelled } = await workspaceFixture(Buffer.from('a😀z'), true, 4);
  assert.equal(Buffer.from(value.base64, 'base64').toString(), 'a'); assert.equal(value.truncated, true); assert.equal(cancelled, true);
  const binary = await workspaceFixture(Buffer.from('%PDF-content'), false, 4);
  assert.equal(binary.value.errorMessage, 'too large'); assert.equal(binary.cancelled, true);
});
test('YouTube transcript validates event shapes and keeps timestamps and truncation', () => {
  const observation = { pageUrl: 'https://youtube.com/watch?v=abcdefghijk', captionLanguage: 'en', captionKind: 'asr',
    body: JSON.stringify({ events: [{ tStartMs: -1, segs: [{ utf8: 'invalid' }] },
      { tStartMs: 3_661_000, segs: [{ utf8: ' Hello\n world ' }] },
      { tStartMs: 3_662_000, segs: [{ utf8: 'next' }] }] }) };
  const actual = formatYoutubeTranscript('abcdefghijk', observation, { maxItems: 1, maxJsonBytes: 10000, maxTextBytes: 10000 });
  assert.equal(actual.text, 'YouTube transcript\nVideo ID: abcdefghijk\nLanguage: en\nCaptions: auto-generated\n\n[1:01:01] Hello world\n\n[Transcript truncated]');
  assert.equal(actual.truncated, true); assert.equal(actual.pageUrl, observation.pageUrl);
});
