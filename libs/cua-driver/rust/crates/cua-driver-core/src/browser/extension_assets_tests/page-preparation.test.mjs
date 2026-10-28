// SPDX-License-Identifier: MIT

import assert from 'node:assert/strict';
import test from 'node:test';
import vm from 'node:vm';
import {
  installPopupBridge,
  installPopupHook,
  removePopupBridge,
  removePopupHook,
  installForeignFrameMonitor,
  removeForeignFrameMonitor,
} from '../extension_assets/page-preparation.mjs';

// A small deterministic event/DOM fixture checks the serialized functions, not browser conformance.
function page() {
  const context = vm.createContext({ URL });
  vm.runInContext(
    `
    class Events {
      listeners = [];
      addEventListener(type, callback, options) {
        const capture = options === true || options?.capture === true;
        if (!this.listeners.some(x => x.type === type && x.callback === callback && x.capture === capture))
          this.listeners.push({type, callback, capture, once: options?.once === true});
      }
      removeEventListener(type, callback, options) {
        const capture = options === true || options?.capture === true;
        this.listeners = this.listeners.filter(x => !(x.type === type && x.callback === callback && x.capture === capture));
      }
      dispatchEvent(event) {
        for (const x of [...this.listeners]) if (x.type === event.type) {
          x.callback(event);
          if (x.once) this.removeEventListener(x.type, x.callback, x.capture);
        }
        return !event.defaultPrevented;
      }
    }
    class CustomEvent {
      constructor(type, options = {}) { this.type = type; Object.assign(this, options); this.defaultPrevented = false; }
      preventDefault() { if (this.cancelable) this.defaultPrevented = true; }
    }
    class Element { constructor(tagName = 'DIV') { this.tagName = tagName; this.children = []; this.attrs = new Map(); } }
    class HTMLElement extends Element {
      getAttribute(name) { return this.attrs.get(name) ?? null; }
      setAttribute(name, value) { this.attrs.set(name, value); }
    }
    class HTMLIFrameElement extends HTMLElement {
      constructor(src) { super('IFRAME'); if (src !== undefined) this.setAttribute('src', src); }
      get src() { return this.getAttribute('src') ?? ''; }
    }
    class HTMLAnchorElement extends HTMLElement {
      constructor(href, target = '_blank') { super('A'); this.href = href; this.target = target; this.origin = new URL(href).origin; }
      hasAttribute(name) { return this.attrs.has(name); }
    }
    class ShadowRoot extends Element {}
    class Document extends Events {
      children = [];
      baseURI = 'https://fixture.test/base/';
      querySelectorAll() { return this.namedFrames ?? []; }
      createTreeWalker(root) {
        const nodes = [];
        const add = n => { for (const c of n.children) { nodes.push(c); add(c); } };
        add(root); let at = 0;
        return {nextNode: () => nodes[at++] ?? null};
      }
    }
    const observers = [];
    class MutationObserver {
      constructor(callback) { this.callback = callback; this.roots = []; this.disconnected = false; observers.push(this); }
      observe(root, options) { this.roots.push({root, options}); }
      disconnect() { this.disconnected = true; }
    }
    const NodeFilter = {SHOW_ELEMENT: 1};
    const document = new Document();
    const window = new Events();
    window.location = new URL(document.baseURI);
    const ordinary = [];
    const nativeOpen = (...args) => { ordinary.push(args); return 'ordinary'; };
    window.open = nativeOpen;
    const navigator = {userActivation: {isActive: true}};
    const messages = [];
    const chrome = {runtime: {id: 'own-extension', sendMessage: async message => {messages.push(message);}},
      dom: {openOrClosedShadowRoot: element => element.closedRoot ?? element.shadowRoot ?? null}};
    function gesture(type = 'click', trusted = true) { document.dispatchEvent({type, isTrusted: trusted}); }
    function click(anchor, {button = 0, canceled = false, pageHandler = () => {}} = {}) {
      const event = {type: 'click', isTrusted: true, button, defaultPrevented: canceled,
        composedPath: () => [anchor], preventDefault() {this.defaultPrevented = true;}};
      gesture();
      for (const x of [...window.listeners]) if (x.type === 'click' && x.capture) x.callback(event);
      pageHandler(event);
      for (const x of [...window.listeners]) if (x.type === 'click' && !x.capture) {
        x.callback(event); if (x.once) window.removeEventListener(x.type, x.callback, false);
      }
      return event;
    }
    Object.assign(globalThis, {CustomEvent, Element, HTMLElement, HTMLIFrameElement, HTMLAnchorElement,
      ShadowRoot, Document, MutationObserver, NodeFilter, document, window, navigator, chrome,
      observers, ordinary, nativeOpen, messages, gesture, click});
  `,
    context,
  );
  const run = (source) => vm.runInContext(source, context);
  const inject = (fn, ...args) => run(`(${fn.toString()})(...${JSON.stringify(args)})`);
  return { context, run, inject };
}

function popupPage() {
  const f = page();
  assert.equal(f.inject(installPopupBridge, 'bridge', 'lease', 'request', 'popup'), true);
  assert.equal(f.inject(installPopupHook, 'main', 'lease', 'request'), true);
  return f;
}

test('popup wrapper delegates navigation and invalid/inactive URLs without changing their arguments', () => {
  const f = popupPage();
  for (const expression of [
    `window.open(null, '_blank', 'width=10')`,
    `window.open('', '_blank')`,
    `window.open('https://else.test', '_SELF')`,
    `window.open('data:text/plain,own', '_blank')`,
  ])
    assert.equal(f.run(expression), 'ordinary', expression);
  f.run(
    `const named = new HTMLIFrameElement(); named.setAttribute('name','details'); document.namedFrames=[named];`,
  );
  assert.equal(f.run(`window.open('https://else.test','details')`), 'ordinary');
  f.run('navigator.userActivation.isActive = false');
  assert.equal(f.run(`window.open('https://else.test','_blank')`), 'ordinary');
  assert.equal(f.run('messages.length'), 0);
  assert.equal(f.run('ordinary.length'), 6);
  assert.equal(f.run(`ordinary[0][2]`), 'width=10');
});

test('one transient-activation popup is forwarded until the next trusted click or keydown', () => {
  const f = popupPage();
  assert.equal(f.run(`window.open('../next','_blank').closed`), false);
  assert.equal(f.run('messages[0].url'), 'https://fixture.test/next');
  assert.equal(f.run(`window.open('https://second.test','_blank')`), null);
  f.run(`gesture('click', false)`);
  assert.equal(f.run(`window.open('https://third.test','_blank')`), null);
  f.run(`gesture('keydown', true)`);
  assert.equal(f.run(`window.open('https://fourth.test','_blank', 'noopener=yes')`), null);
  assert.equal(f.run('messages.length'), 2);
  assert.equal(f.run('ordinary.length'), 0);
});

test('opener policy is preserved for feature values and undefined activation information', () => {
  const f = popupPage();
  f.run('navigator.userActivation = undefined');
  assert.equal(f.run(`window.open('https://else.test','_blank', 'noopener=0').closed`), false);
  f.run(`gesture('keydown')`);
  assert.equal(f.run(`window.open('https://else.test','_blank', 'noreferrer')`), null);
  assert.equal(f.run('messages.length'), 2);
});

test('targeted links observe page cancellation, button and same-origin download behavior', () => {
  const f = popupPage();
  f.run(`const a = new HTMLAnchorElement('https://else.test/next');`);
  assert.equal(f.run(`click(a,{pageHandler:e=>e.preventDefault()}).defaultPrevented`), true);
  assert.equal(f.run('messages.length'), 0);
  assert.equal(f.run(`click(a,{button:1}).defaultPrevented`), false);
  assert.equal(f.run(`click(a).defaultPrevented`), true);
  assert.equal(f.run('messages.length'), 1);
  f.run(
    `a.href='https://fixture.test/file'; a.origin='https://fixture.test'; a.setAttribute('download','own');`,
  );
  assert.equal(f.run(`click(a).defaultPrevented`), false);
  f.run(`a.href='https://else.test/file'; a.origin='https://else.test';`);
  assert.equal(f.run(`click(a).defaultPrevented`), true);
  assert.equal(f.run('messages.length'), 2);
});

test('cleanup preserves a subsequent page wrapper and removes only the exact lease listeners', () => {
  const f = popupPage();
  assert.equal(f.inject(removePopupHook, 'main', 'other-lease'), true);
  assert.equal(f.run('window.open === nativeOpen'), false);
  f.run(`const replacement = () => 'replacement'; window.open = replacement;`);
  assert.equal(f.inject(removePopupHook, 'main', 'lease'), true);
  assert.equal(f.run('window.open === replacement'), true);
  assert.equal(f.inject(removePopupBridge, 'bridge', 'lease'), true);
  assert.equal(f.run('window.listeners.length + document.listeners.length'), 0);
  assert.equal(f.run(`'main' in globalThis || 'bridge' in globalThis`), false);
});

test('foreign monitor handles existing frames and open/closed roots while retaining own extension frames', () => {
  const f = page();
  f.run(`
    const own = new HTMLIFrameElement('chrome-extension://own-extension/own');
    const foreign = new HTMLIFrameElement(' chrome-extension://foreign-extension/page ');
    const legacy = new HTMLElement('FRAME'); legacy.setAttribute('src','chrome-extension://foreign-extension/frame');
    const normalFrame = new HTMLIFrameElement('https://fixture.test/frame');
    const host = new HTMLElement(); host.closedRoot = new ShadowRoot();
    const closed = new HTMLIFrameElement('chrome-extension://foreign-extension/closed'); host.closedRoot.children.push(closed);
    document.children.push(own,foreign,legacy,normalFrame,host);
    Object.assign(globalThis,{own,foreign,legacy,closed,host,ordinaryFrame:normalFrame});
  `);
  assert.equal(f.inject(installForeignFrameMonitor, 'monitor', 'lease'), true);
  assert.equal(f.run(`foreign.getAttribute('srcdoc')`), '');
  assert.equal(f.run(`legacy.getAttribute('src')`), 'about:blank');
  assert.equal(f.run(`closed.getAttribute('srcdoc')`), '');
  assert.equal(f.run(`own.getAttribute('srcdoc')`), null);
  assert.equal(f.run(`ordinaryFrame.getAttribute('srcdoc')`), null);
  assert.equal(f.run('observers[0].roots.length'), 2);
  assert.equal(f.inject(installForeignFrameMonitor, 'monitor', 'lease'), true);
  assert.equal(f.run('observers.length'), 1);
});

test('foreign monitor processes source mutations and newly added subtrees, then disconnects exactly', () => {
  const f = page();
  assert.equal(f.inject(installForeignFrameMonitor, 'monitor', 'lease'), true);
  f.run(`
    const changed = new HTMLIFrameElement('chrome-extension://foreign-extension/changed');
    const added = new HTMLElement(); const nested = new HTMLIFrameElement('chrome-extension://foreign-extension/nested'); added.children.push(nested);
    observers[0].callback([{type:'attributes',target:changed,addedNodes:[]},{type:'childList',addedNodes:[added]}]);
    Object.assign(globalThis,{changed,nested});
  `);
  assert.equal(f.run(`changed.getAttribute('srcdoc')`), '');
  assert.equal(f.run(`nested.getAttribute('srcdoc')`), '');
  assert.equal(f.inject(removeForeignFrameMonitor, 'monitor', 'other'), true);
  assert.equal(f.run('observers[0].disconnected'), false);
  assert.equal(f.inject(removeForeignFrameMonitor, 'monitor', 'lease'), true);
  assert.equal(f.run('observers[0].disconnected'), true);
  assert.equal(f.run(`'monitor' in globalThis`), false);
});
