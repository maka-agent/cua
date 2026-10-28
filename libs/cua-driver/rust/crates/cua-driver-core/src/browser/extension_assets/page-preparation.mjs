// SPDX-License-Identifier: MIT

// These fixed functions are serialized by Chrome, with no executable wire input.
export function popupHookStatus(slot, scope) {
  return globalThis[slot]?.scope === scope;
}

export function installPopupBridge(slot, scope, requestEvent, messageType) {
  const previous = globalThis[slot];
  if (previous?.scope === scope) return true;
  if (previous) return false;
  let used = false;
  const reset = (event) => {
    if (event.isTrusted) used = false;
  };
  const request = (event) => {
    if (!(event instanceof CustomEvent) || navigator.userActivation?.isActive === false) return;
    if (used) {
      event.preventDefault();
      return;
    }
    if (typeof event.detail !== 'string') return;
    used = true;
    void chrome.runtime.sendMessage({ type: messageType, url: event.detail }).catch(() => {});
  };
  document.addEventListener('click', reset, true);
  document.addEventListener('keydown', reset, true);
  document.addEventListener(requestEvent, request);
  globalThis[slot] = { scope, reset, request, requestEvent };
  return true;
}

export function installPopupHook(slot, scope, requestEvent) {
  const previous = globalThis[slot];
  if (previous?.scope === scope) return true;
  if (previous) return false;
  const original = window.open;
  const existingTarget = (name) => {
    if (['_self', '_parent', '_top', '_unfencedtop'].includes(name.toLowerCase())) return true;
    return Array.from(document.querySelectorAll('iframe, frame')).some(
      (frame) => frame.getAttribute('name') === name,
    );
  };
  const ask = (address) => {
    if (navigator.userActivation?.isActive === false) return undefined;
    let resolved;
    try {
      resolved = new URL(address, document.baseURI);
    } catch {
      return undefined;
    }
    if (resolved.protocol !== 'http:' && resolved.protocol !== 'https:') return undefined;
    return document.dispatchEvent(
      new CustomEvent(requestEvent, { cancelable: true, detail: resolved.href }),
    );
  };
  const suppressesProxy = (features) =>
    features?.split(',').some((part) => {
      const [name, ...values] = part
        .trim()
        .toLowerCase()
        .split(/\s*=\s*/);
      return (
        (name === 'noopener' || name === 'noreferrer') &&
        (values.length === 0 || (values.length === 1 && ['1', 'yes', 'true'].includes(values[0])))
      );
    });
  const open = function (address, target, features) {
    if (address == null || address === '' || existingTarget(String(target ?? '')))
      return original.call(window, address, target, features);
    const accepted = ask(String(address));
    if (accepted === undefined) return original.call(window, address, target, features);
    if (!accepted || suppressesProxy(features)) return null;
    return { closed: false, focus() {} };
  };
  const bubble = (event) => {
    if (event.defaultPrevented || event.button !== 0) return;
    const anchor = event.composedPath().find((node) => node instanceof HTMLAnchorElement);
    if (!anchor) return;
    if (anchor.hasAttribute('download') && anchor.origin === window.location.origin) return;
    const target = anchor.target;
    if (target === '' || existingTarget(target)) return;
    if (ask(anchor.href) !== undefined) event.preventDefault();
  };
  const capture = () => {
    // Run after the page's handlers have had their opportunity to cancel navigation.
    window.removeEventListener('click', bubble);
    window.addEventListener('click', bubble, { once: true });
  };
  window.open = open;
  window.addEventListener('click', capture, true);
  globalThis[slot] = { scope, original, open, bubble, capture };
  return true;
}

export function removePopupHook(slot, scope) {
  const state = globalThis[slot];
  if (state?.scope !== scope) return true;
  window.removeEventListener('click', state.capture, true);
  window.removeEventListener('click', state.bubble);
  if (window.open === state.open) window.open = state.original;
  Reflect.deleteProperty(globalThis, slot);
  return true;
}

export function removePopupBridge(slot, scope) {
  const state = globalThis[slot];
  if (state?.scope !== scope) return true;
  document.removeEventListener('click', state.reset, true);
  document.removeEventListener('keydown', state.reset, true);
  document.removeEventListener(state.requestEvent, state.request);
  Reflect.deleteProperty(globalThis, slot);
  return true;
}

export function foreignMonitorStatus(slot, scope) {
  return globalThis[slot]?.scope === scope;
}

export function installForeignFrameMonitor(slot, scope) {
  const previous = globalThis[slot];
  if (previous?.scope === scope) return true;
  if (previous) return false;
  const roots = new WeakSet();
  const shadowOf = (element) => {
    const privileged = chrome.dom?.openOrClosedShadowRoot;
    if (typeof privileged === 'function') {
      try {
        return privileged(element);
      } catch {
        // Ordinary open roots remain observable when the privileged query refuses.
      }
    }
    return element.shadowRoot;
  };
  const foreign = (address) => {
    if (!address?.startsWith('chrome-extension://')) return false;
    try {
      const id = new URL(address).host;
      return id.length > 0 && id !== chrome.runtime.id;
    } catch {
      return false;
    }
  };
  const inspect = (element) => {
    if (!(element instanceof HTMLElement)) return;
    if (element.tagName === 'IFRAME' || element.tagName === 'FRAME') {
      const attribute = element.getAttribute('src')?.trim() ?? '';
      const property = element instanceof HTMLIFrameElement ? (element.src?.trim() ?? '') : '';
      if (foreign(attribute) || foreign(property)) {
        if (element instanceof HTMLIFrameElement) {
          if (element.getAttribute('srcdoc') !== '') element.setAttribute('srcdoc', '');
        } else element.setAttribute('src', 'about:blank');
      }
    }
    const shadow = shadowOf(element);
    if (shadow) watch(shadow);
  };
  const scan = (node) => {
    if (!(node instanceof Document || node instanceof ShadowRoot || node instanceof Element))
      return;
    if (node instanceof Element) inspect(node);
    const walker = document.createTreeWalker(node, NodeFilter.SHOW_ELEMENT);
    for (let node = walker.nextNode(); node; node = walker.nextNode()) inspect(node);
  };
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      if (mutation.type === 'attributes') inspect(mutation.target);
      for (const node of mutation.addedNodes) scan(node);
    }
  });
  function watch(root) {
    if (roots.has(root)) return;
    roots.add(root);
    observer.observe(root, {
      attributes: true,
      attributeFilter: ['src'],
      childList: true,
      subtree: true,
    });
    scan(root);
  }
  globalThis[slot] = { scope, observer, roots };
  try {
    watch(document);
  } catch (error) {
    observer.disconnect();
    Reflect.deleteProperty(globalThis, slot);
    throw error;
  }
  return true;
}

export function removeForeignFrameMonitor(slot, scope) {
  const state = globalThis[slot];
  if (state?.scope !== scope) return true;
  state.observer.disconnect();
  Reflect.deleteProperty(globalThis, slot);
  return true;
}
