// SPDX-License-Identifier: MIT

import { ConnectorError } from './connector.mjs';

const COLORS = new Set(['blue', 'mint', 'violet', 'amber', 'rose', 'cyan']);
const OPERATIONS = new Set(['configure', 'state', 'update', 'control', 'controlStop', 'hide', 'remove', 'finalize']);
const ACTIONS = new Set(['idle', 'click', 'key', 'scroll', 'drag', 'observe']);
const ASSET = 'maka-ui-cursor.js';
const MAX_EPOCH = 18446744073709551615n;
const PUBLIC_WAIT_EXPIRED = Symbol('fixed-ui-public-wait-expired');
const PUBLIC_WAIT_MS = 1000;
const exact = (value, fields) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === fields.length
  && fields.every((field) => Object.prototype.hasOwnProperty.call(value, field));
const invalid = (message) => { throw new ConnectorError('invalid_request', message); };

export function validateFixedUiRequest(value, { initial = false } = {}) {
  if (!exact(value, ['operation', 'cursor', 'ownerEpoch', 'point', 'action'])
    || !OPERATIONS.has(value.operation) || !ACTIONS.has(value.action)
    || !exact(value.cursor, ['id', 'label', 'color', 'enabled', 'reducedMotion'])
    || typeof value.cursor.id !== 'string' || !value.cursor.id
    || typeof value.cursor.label !== 'string' || !COLORS.has(value.cursor.color)
    || typeof value.cursor.enabled !== 'boolean' || typeof value.cursor.reducedMotion !== 'boolean'
    || typeof value.ownerEpoch !== 'string' || !/^[1-9][0-9]*$/.test(value.ownerEpoch)
    || BigInt(value.ownerEpoch) > MAX_EPOCH
    || (value.point !== null && (!Array.isArray(value.point) || value.point.length !== 2
      || !value.point.every((number) => typeof number === 'number' && Number.isFinite(number)))))
    invalid('fixed UI accepts only the closed cursor, epoch, point, action and operation DTO');
  if (initial && (value.operation !== 'control' || value.point !== null))
    invalid('fixed session preparation requires a control publication without a point');
  return Object.freeze({
    operation: value.operation,
    cursor: Object.freeze({ ...value.cursor }),
    ownerEpoch: value.ownerEpoch,
    point: value.point === null ? null : Object.freeze([...value.point]),
    action: value.action,
  });
}

// Chrome serializes this fixed function. There is no executable wire input.
function invokeRenderer(input) {
  if (typeof globalThis.drawCursor !== 'function') return null;
  return globalThis.drawCursor(input);
}
function renderState(value) {
  if (!exact(value, ['status', 'visible', 'requestedPosition']) || value.status !== 'ready'
    || typeof value.visible !== 'boolean'
    || (value.requestedPosition !== null && (!Array.isArray(value.requestedPosition)
      || value.requestedPosition.length !== 2 || !value.requestedPosition.every(Number.isFinite))))
    return null;
  return value;
}
const injectionTarget = (tabId, target) => target.documentId
  ? { tabId, documentIds: [target.documentId] }
  : { tabId, frameIds: [0] };
const actualTopResult = (results, target) => {
  if (!Array.isArray(results)) return null;
  const candidates = results.filter((item) => item?.frameId === 0
    && (!target.documentId || item.documentId === target.documentId));
  return candidates.length === 1 ? candidates[0] : null;
};

export class FixedUi {
  constructor(chrome, { resolveCurrent, isGone, currentScopes }) {
    if (typeof resolveCurrent !== 'function' || typeof isGone !== 'function'
      || typeof currentScopes !== 'function')
      throw new ConnectorError('invalid_configuration', 'fixed UI requires the existing resource resolvers');
    this.chrome = chrome;
    this.resolveCurrent = resolveCurrent;
    this.isGone = isGone;
    this.currentScopes = currentScopes;
    chrome.windows?.onFocusChanged?.addListener((windowId) => {
      for (const [record, scope] of this.currentScopes()) {
        const state = scope.uiState;
        if (state && (state.observed || state.windowId === windowId))
          void this.refresh(record, scope).catch(() => {});
      }
    });
  }
  available() {
    return typeof this.chrome.scripting?.executeScript === 'function'
      && typeof this.chrome.webNavigation?.getAllFrames === 'function';
  }
  current(record, scope, mode = 'live') {
    return this.resolveCurrent(record, scope, mode) === true;
  }
  assertCurrent(record, scope, mode = 'live') {
    if (!this.current(record, scope, mode))
      throw new ConnectorError('scope_unavailable', 'fixed UI resource is no longer current');
  }
  state(scope) {
    if (!scope.uiState) scope.uiState = {
      pending: new Set(), documents: new Map(), lastInput: null, wireContext: null,
      stopping: false, stopPromise: null, cleanupConfirmed: false,
      windowId: null, observed: false,
    };
    return scope.uiState;
  }
  track(state, factory) {
    // Registration is synchronous; sealing cannot miss an admitted operation.
    const operation = Promise.resolve().then(factory);
    state.pending.add(operation);
    void operation.then((ack) => { state.lastAck = ack; }).catch(() => {});
    void operation.finally(() => state.pending.delete(operation)).catch(() => {});
    return operation;
  }
  ordinaryScript(state, request) {
    // Public publication waits are bounded; the actual Chrome call is not
    // cancelled or forgotten when that wait expires. Scope cleanup drains this
    // exact promise before finalization, including replies arriving much later.
    const actual = Promise.resolve().then(() => this.chrome.scripting.executeScript(request));
    state.pending.add(actual);
    void actual.finally(() => state.pending.delete(actual)).catch(() => {});
    let timer;
    const expired = new Promise((resolve) => {
      timer = setTimeout(() => resolve(PUBLIC_WAIT_EXPIRED), PUBLIC_WAIT_MS);
    });
    return Promise.race([actual, expired]).finally(() => clearTimeout(timer));
  }
  prepare(record, scope, value, wireContext) {
    if (!this.available())
      throw new ConnectorError('unsupported', 'fixed UI service is unavailable');
    const input = validateFixedUiRequest(value, { initial: true });
    this.assertCurrent(record, scope);
    const state = this.state(scope);
    state.lastInput = input;
    state.wireContext = wireContext;
    return this.track(state, () => this.perform(record, scope, input, wireContext));
  }
  invoke(record, scope, value, wireContext) {
    const input = validateFixedUiRequest(value);
    this.assertCurrent(record, scope);
    const state = this.state(scope);
    if (state.stopping) throw new ConnectorError('scope_unavailable', 'fixed UI scope is ending');
    if (!state.lastInput || input.cursor.id !== state.lastInput.cursor.id)
      throw new ConnectorError('scope_unavailable', 'fixed UI cursor differs from its issued resource');
    if (BigInt(input.ownerEpoch) < BigInt(state.lastInput.ownerEpoch)) {
      // The canonical renderer also guards epochs; retain its actual state result.
      return this.track(state, () => this.perform(record, scope,
        Object.freeze({ ...state.lastInput, operation: 'state', point: null, action: 'idle' }), wireContext));
    }
    state.lastInput = input;
    return this.track(state, () => this.perform(record, scope, input, wireContext));
  }
  refresh(record, scope) {
    if (!this.current(record, scope) || !scope.uiState?.lastInput) return Promise.resolve({ status: 'notAttempted' });
    const state = scope.uiState;
    if (state.stopping) return Promise.resolve({ status: 'notAttempted' });
    const input = Object.freeze({ ...state.lastInput, operation: 'control', point: null, action: 'idle' });
    return this.track(state, () => this.perform(record, scope, input, state.wireContext));
  }
  async topDocument(record, scope) {
    this.assertCurrent(record, scope);
    try {
      const frames = await this.chrome.webNavigation.getAllFrames({ tabId: record.tabId });
      this.assertCurrent(record, scope);
      const roots = Array.isArray(frames) ? frames.filter((frame) => frame?.frameId === 0) : [];
      if (roots.length === 1 && typeof roots[0].documentId === 'string' && roots[0].documentId)
        return { documentId: roots[0].documentId };
    } catch (error) {
      this.assertCurrent(record, scope);
    }
    // This is the Chatgpt's real top-tab transport fallback, not a made-up document stamp.
    return { documentId: null };
  }
  async observation(record, scope, state) {
    this.assertCurrent(record, scope);
    let observed = false;
    try {
      const tab = await this.chrome.tabs.get(record.tabId);
      this.assertCurrent(record, scope);
      if (tab?.id !== record.tabId) throw new Error('extension tab changed during fixed UI metadata');
      state.windowId = Number.isSafeInteger(tab.windowId) ? tab.windowId : null;
      if (tab.active === true && state.windowId !== null && typeof this.chrome.windows?.get === 'function') {
        const window = await this.chrome.windows.get(state.windowId);
        this.assertCurrent(record, scope);
        observed = window?.id === state.windowId && window.focused === true && window.state !== 'minimized';
      }
    } catch (error) {
      this.assertCurrent(record, scope);
    }
    state.observed = observed;
    return observed;
  }
  async perform(record, scope, input, wireContext) {
    this.assertCurrent(record, scope);
    const state = this.state(scope);
    let target = Object.freeze(await this.topDocument(record, scope));
    this.assertCurrent(record, scope);
    // A weak top-frame address is an individual in-flight attempt. Concurrent
    // fallbacks may resolve to different documents and must never share a
    // mutable cleanup address.
    let key = target.documentId ?? Symbol('top-frame-without-document-proof');
    let document = state.documents.get(key);
    if (!document) {
      document = { target, loaded: false, attempted: false, lastInput: input };
      state.documents.set(key, document);
    }
    if (!document.loaded) {
      this.assertCurrent(record, scope);
      try {
        const results = await this.ordinaryScript(state, {
          target: injectionTarget(record.tabId, target), world: 'ISOLATED',
          injectImmediately: true, files: [ASSET],
        });
        this.assertCurrent(record, scope);
        if (results === PUBLIC_WAIT_EXPIRED) return { status: 'unknown' };
        const result = actualTopResult(results, target);
        if (!result) return { status: 'unknown' };
        if (!target.documentId && typeof result.documentId === 'string' && result.documentId) {
          state.documents.delete(key);
          target = Object.freeze({ documentId: result.documentId });
          key = target.documentId;
          document = state.documents.get(key);
          if (!document) {
            document = { target, loaded: false, attempted: false, lastInput: input };
            state.documents.set(key, document);
          }
        }
        document.loaded = true;
      } catch (error) {
        this.assertCurrent(record, scope);
        return { status: 'unknown' };
      }
    }
    const operation = input.operation === 'configure' ? 'update' : input.operation;
    const nativeControl = operation === 'control'
      ? { running: true, observed: await this.observation(record, scope, state),
        sessionId: wireContext.hostSessionId, turnId: wireContext.hostTurnId }
      : undefined;
    this.assertCurrent(record, scope);
    // A passive publication can overlap configuration while metadata is awaited.
    // Re-read the current Spec at release; never promote an old epoch's point.
    const latest = state.lastInput ?? input;
    const released = BigInt(input.ownerEpoch) < BigInt(latest.ownerEpoch)
      ? { ...latest, operation: 'state', point: null, action: 'idle' }
      : { ...input, cursor: latest.cursor, operation };
    const request = { ...released,
      ...(released.operation === 'control' && nativeControl ? { nativeControl } : {}) };
    document.lastInput = released;
    document.attempted = true;
    state.cleanupConfirmed = false;
    try {
      const results = await this.ordinaryScript(state, {
        target: injectionTarget(record.tabId, target), world: 'ISOLATED', injectImmediately: true,
        func: invokeRenderer, args: [request],
      });
      this.assertCurrent(record, scope);
      if (results === PUBLIC_WAIT_EXPIRED) return { status: 'unknown' };
      const result = actualTopResult(results, target);
      const actual = renderState(result?.result);
      return actual
        ? { status: 'attempted', acknowledged: true, state: actual }
        : { status: 'attempted', acknowledged: false };
    } catch (error) {
      this.assertCurrent(record, scope);
      return { status: 'unknown' };
    }
  }
  stop(record, scope) {
    const state = scope.uiState;
    if (!state) return Promise.resolve({ cleanupConfirmed: true });
    if (state.stopPromise) {
      if (this.isGone(record) !== true) return state.stopPromise;
      // A later real removal is new monotonic evidence, not a retry of cleanup RPCs.
      const previous = state.stopPromise;
      const recovered = Promise.allSettled([...state.pending, previous]).then(() => {
        state.cleanupConfirmed = this.isGone(record) === true;
        return { cleanupConfirmed: state.cleanupConfirmed };
      });
      state.stopPromise = recovered;
      return recovered;
    }
    state.stopping = true;
    const operation = (async () => {
      await Promise.allSettled([...state.pending]);
      if (this.isGone(record) === true) {
        state.cleanupConfirmed = true;
        return { cleanupConfirmed: true };
      }
      this.assertCurrent(record, scope, 'cleanup');
      let confirmed = true;
      for (const document of state.documents.values()) {
        if (!document.attempted) continue;
        this.assertCurrent(record, scope, 'cleanup');
        try {
          const input = { ...document.lastInput, operation: 'finalize', point: null, action: 'idle' };
          const results = await this.chrome.scripting.executeScript({
            target: injectionTarget(record.tabId, document.target), world: 'ISOLATED', injectImmediately: true,
            func: invokeRenderer, args: [input],
          });
          if (this.isGone(record) === true) break;
          this.assertCurrent(record, scope, 'cleanup');
          const actual = renderState(actualTopResult(results, document.target)?.result);
          // A weak frame address never proves that an older document was cleaned.
          if (!document.target.documentId || !actual || actual.visible || actual.requestedPosition !== null)
            confirmed = false;
        } catch {
          if (this.isGone(record) !== true) confirmed = false;
        }
      }
      state.cleanupConfirmed = this.isGone(record) === true || confirmed;
      return { cleanupConfirmed: state.cleanupConfirmed };
    })();
    state.stopPromise = operation;
    void operation.catch(() => {});
    return operation;
  }
}
