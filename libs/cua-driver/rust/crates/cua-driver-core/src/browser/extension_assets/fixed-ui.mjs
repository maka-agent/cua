// SPDX-License-Identifier: MIT

import { ConnectorError } from './connector.mjs';

const COLORS = new Set(['blue', 'mint', 'violet', 'amber', 'rose', 'cyan']);
const OPERATIONS = new Set(['configure', 'state', 'update', 'control', 'controlStop', 'hide', 'remove', 'finalize', 'finalizeDeliverable', 'finalizeHandoff']);
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
  if (['finalizeDeliverable', 'finalizeHandoff'].includes(value.operation)
    && (value.point !== null || value.action !== 'idle'))
    invalid('retained presentation accepts only an idle publication without a point');
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
  constructor(chrome, { resolveCurrent, isGone, currentScopes, retention = null }) {
    if (typeof resolveCurrent !== 'function' || typeof isGone !== 'function'
      || typeof currentScopes !== 'function')
      throw new ConnectorError('invalid_configuration', 'fixed UI requires the existing resource resolvers');
    this.chrome = chrome;
    this.retention = retention;
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
    if (state.stopping || state.retentionFinalized) return Promise.resolve({ status: 'notAttempted' });
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
    if (['finalizeDeliverable', 'finalizeHandoff'].includes(input.operation)) {
      if (!this.retention?.initialized) return { status: 'notAttempted' };
      const status = input.operation === 'finalizeDeliverable' ? 'deliverable' : 'handoff';
      state.retentionFinalized = true;
      document.lastInput = input; document.attempted = true; state.cleanupConfirmed = false;
      // Stop the existing cursor before changing its tab's finalized badge.
      const cursorReply = await this.ordinaryScript(state, {
        target: injectionTarget(record.tabId, target), world: 'ISOLATED', injectImmediately: true,
        func: invokeRenderer, args: [{ ...input, operation: 'controlStop', point: null, action: 'idle' }],
      });
      this.assertCurrent(record, scope);
      const cursorState = cursorReply === PUBLIC_WAIT_EXPIRED ? null
        : renderState(actualTopResult(cursorReply, target)?.result);
      const observed = await this.retention.finalized(record, status);
      this.assertCurrent(record, scope);
      const rendered = await this.retention.publish(record, { status: observed ? null : status,
        execute: (request) => this.ordinaryScript(state, request) });
      this.assertCurrent(record, scope);
      return { status: 'attempted', acknowledged: cursorState !== null && rendered?.acknowledged === true,
        ...(cursorState ? { state: cursorState } : {}), retention: {
          tabId: record.tabId, status, observed: record.finalizationObservation === true, intentPersisted: true,
          rendererAcknowledged: rendered?.acknowledged === true, badgeApplied: rendered?.applied === true,
          sourceFaviconAvailable: rendered?.available === true, documentId: rendered?.documentId ?? null,
        } };
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

// A closed page presentation function. It accepts no Agent script or markup.
// The original page image is runtime page data; Maka's glyph is drawn here.
async function paintRetainedFavicon(input) {
  if (!input || !['active', 'deliverable', 'handoff', null].includes(input.status)
    || typeof input.chromeSessionId !== 'string' || !input.chromeSessionId
    || !Number.isSafeInteger(input.publicationEpoch) || input.publicationEpoch <= 0
    || (input.faviconDataUrl !== null && (typeof input.faviconDataUrl !== 'string'
      || !input.faviconDataUrl.startsWith('data:image/'))))
    return { acknowledged: false, applied: false };
  const key = Symbol.for('org.apache.maka.retained-favicon.v1');
  const attribute = 'data-maka-retained-favicon';
  const original = 'data-maka-favicon-original';
  const created = 'data-maka-favicon-created';
  const owns = (href) => typeof href === 'string' && href.startsWith('data:image/svg+xml,')
    && (() => { try { return decodeURIComponent(href.slice(19)).includes('data-maka-retained-favicon="v1"'); } catch { return false; } })();
  const previous = globalThis[key];
  if (previous && (previous.version !== 1 || previous.chromeSessionId !== input.chromeSessionId
    || previous.epoch > input.publicationEpoch)) return { acknowledged: false, applied: false };
  const restoring = input.status === null || input.faviconDataUrl === null;
  const rels = [];
  if (restoring) for (const link of document.querySelectorAll(`link[${attribute}="v1"]`)) {
    if (owns(link.getAttribute('href')) && link.getAttribute(created) !== 'true') {
      rels.push([link, link.getAttribute('rel')]); link.setAttribute('rel', 'apple-touch-icon');
    }
  }
  const state = previous ?? { version: 1, chromeSessionId: input.chromeSessionId, epoch: 0, edits: new Map() };
  state.epoch = input.publicationEpoch; globalThis[key] = state;
  const restore = (link, saved) => {
    const href = link.getAttribute('href');
    // A page-authored replacement wins over the old presentation.
    if (href === saved.paint || owns(href)) {
      if (saved.created) link.remove();
      else if (saved.href === null) link.removeAttribute('href');
      else link.setAttribute('href', saved.href);
    }
    link.removeAttribute(attribute); link.removeAttribute(original); link.removeAttribute(created);
  };
  for (const [link, saved] of state.edits) restore(link, saved);
  state.edits.clear();
  // A content-world reload may leave DOM metadata from its previous invocation.
  for (const link of document.querySelectorAll(`link[${attribute}="v1"]`)) {
    const paint = link.getAttribute('href');
    if (!owns(paint)) { link.removeAttribute(attribute); link.removeAttribute(original); link.removeAttribute(created); continue; }
    let href = null;
    try { href = JSON.parse(link.getAttribute(original) ?? 'null'); } catch {}
    restore(link, { href: typeof href === 'string' ? href : null,
      created: link.getAttribute(created) === 'true', paint });
  }
  if (restoring) {
    await new Promise((resolve) => setTimeout(resolve, 0));
    for (const [link, rel] of rels) if (link.isConnected && link.getAttribute('rel') === 'apple-touch-icon') {
      if (rel === null) link.removeAttribute('rel'); else link.setAttribute('rel', rel);
    }
    return { acknowledged: state.epoch === input.publicationEpoch, applied: false };
  }
  if (!['active', 'deliverable', 'handoff'].includes(input.status)
    || typeof input.faviconDataUrl !== 'string' || !input.faviconDataUrl.startsWith('data:image/'))
    return { acknowledged: false, applied: false };
  const namespace = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(namespace, 'svg');
  for (const [name, value] of Object.entries({ xmlns: namespace, width: '32', height: '32', viewBox: '0 0 32 32', [attribute]: 'v1' })) svg.setAttribute(name, value);
  const image = document.createElementNS(namespace, 'image');
  image.setAttribute('href', input.faviconDataUrl); image.setAttribute('width', '32'); image.setAttribute('height', '32');
  if (input.status === 'active') image.setAttribute('opacity', '0.3');
  svg.appendChild(image);
  if (input.status === 'active') {
    // Independently authored Maka mark; no Original glyph or image is embedded.
    const label = document.createElementNS(namespace, 'text');
    for (const [name, value] of Object.entries({ x: '1', y: '26', 'font-size': '28', 'font-family': 'system-ui,sans-serif', 'font-weight': '900', fill: '#111827', stroke: '#ffffff', 'stroke-width': '2', 'paint-order': 'stroke fill' })) label.setAttribute(name, value);
    label.textContent = 'M'; svg.appendChild(label);
  } else {
    const dot = document.createElementNS(namespace, 'circle');
    for (const [name, value] of Object.entries({ cx: '24', cy: '24', r: '7', fill: input.status === 'deliverable' ? '#22c55e' : '#facc15' })) dot.setAttribute(name, value);
    svg.appendChild(dot);
  }
  const paint = `data:image/svg+xml,${encodeURIComponent(new XMLSerializer().serializeToString(svg))}`;
  const links = [...document.querySelectorAll('link[rel~="icon"]')];
  if (links.length === 0) {
    const link = document.createElement('link'); link.rel = 'icon';
    (document.head ?? document.documentElement).appendChild(link); links.push(link);
    link.setAttribute(created, 'true');
  }
  for (const link of links) {
    const saved = { href: link.getAttribute('href'), created: link.getAttribute(created) === 'true', paint };
    state.edits.set(link, saved);
    link.setAttribute(attribute, 'v1'); link.setAttribute(original, JSON.stringify(saved.href));
    link.setAttribute('href', paint);
  }
  return { acknowledged: true, applied: true };
}

const PRESENTATION_KEY = 'org.apache.maka.retained-presentation.v1';
const PRESENTATION_STATES = new Set(['deliverable', 'handoff']);
const MAX_FAVICON_BYTES = 65536;

// Presentation metadata is a facet of the existing records, never an ownership
// registry. No owner, claim, prepared grant or Agent expression is stored here.
export class RetainedTabPresentation {
  constructor(chrome, { records, chromeSessionId }) {
    this.chrome = chrome; this.records = records; this.chromeSessionId = chromeSessionId;
    this.writes = Promise.resolve(); this.publications = Promise.resolve(); this.initialized = false; this.storageFailure = null; this.nextEpoch = 0;
    chrome.tabs.onActivated?.addListener(({ tabId }) => { void this.seen(tabId).catch(() => {}); });
    chrome.windows?.onFocusChanged?.addListener((id) => {
      if (id === chrome.windows.WINDOW_ID_NONE) return;
      void chrome.tabs.query({ active: true, windowId: id }).then((tabs) => {
        for (const tab of tabs) if (Number.isSafeInteger(tab.id)) void this.seen(tab.id).catch(() => {});
      }).catch(() => {});
    });
    chrome.tabs.onUpdated?.addListener((id, change) => {
      const realIconChange = typeof change.favIconUrl === 'string' && !this.ownedImage(change.favIconUrl);
      if (change.url || realIconChange) { const record = records().get(id); if (record) delete record.faviconSource; }
      if (change.url || change.status === 'complete' || realIconChange) this.schedule(id);
    });
    chrome.tabs.onRemoved?.addListener((id) => { const record = records().get(id); if (record) { delete record.finalizedBadge; delete record.faviconSource; } void this.persist().catch(() => {}); });
    chrome.tabs.onReplaced?.addListener((added, removed) => {
      const record = records().get(removed), status = record?.finalizedBadge;
      if (!status) return;
      delete record.finalizedBadge; delete record.faviconSource;
      const replacement = this.metadataRecord(added); replacement.finalizedBadge = status;
      void this.persist().then(() => this.schedule(added)).catch(() => {});
    });
  }
  metadataRecord(id) {
    const records = this.records(); let record = records.get(id);
    if (!record) { record = { tabId: id, owner: null, generation: null, physical: null, physicalGone: false, tabRemoved: false, presentationMetadata: true }; records.set(id, record); }
    return record;
  }
  ownedImage(value) {
    if (typeof value !== 'string' || !value.startsWith('data:image/svg+xml,')) return false;
    try { return decodeURIComponent(value.slice(19)).includes('data-maka-retained-favicon="v1"'); } catch { return false; }
  }
  effective(record) { return record?.logicalLease?.phase === 'live' ? 'active' : record?.finalizedBadge ?? null; }
  async initialize() {
    const stored = (await this.chrome.storage.session.get(PRESENTATION_KEY))[PRESENTATION_KEY];
    if (stored !== undefined) {
      if (!(exact(stored, ['chromeSessionId', 'entries']) || exact(stored, ['chromeSessionId', 'entries', 'nextEpoch']))
        || typeof stored.chromeSessionId !== 'string'
        || (stored.nextEpoch !== undefined && (!Number.isSafeInteger(stored.nextEpoch) || stored.nextEpoch < 0))
        || !Array.isArray(stored.entries))
        throw new ConnectorError('storage_invalid', 'retained presentation metadata is not recognized');
      if (stored.chromeSessionId === this.chromeSessionId()) {
        this.nextEpoch = stored.nextEpoch ?? 0;
        const seen = new Set();
        for (const item of stored.entries) {
          if (!exact(item, ['tabId', 'status']) || !Number.isSafeInteger(item.tabId) || item.tabId <= 0
            || (item.status !== null && !PRESENTATION_STATES.has(item.status)) || seen.has(item.tabId))
            throw new ConnectorError('storage_invalid', 'retained presentation metadata has an invalid entry');
          seen.add(item.tabId); const record = this.metadataRecord(item.tabId);
          if (item.status === null) record.pendingRestore = true; else record.finalizedBadge = item.status;
        }
      }
    }
    for (const record of this.records().values()) if (record.logicalLease?.phase === 'live') { delete record.finalizedBadge; delete record.pendingRestore; }
    this.initialized = true; await this.persist();
    for (const [id, record] of this.records()) if (this.effective(record) !== null || record.pendingRestore) this.schedule(id);
  }
  async persist() {
    if (!this.initialized) return;
    const write = this.writes.then(async () => {
      const entries = [...this.records().values()].filter((record) => !record.tabRemoved
        && (PRESENTATION_STATES.has(record.finalizedBadge) || record.pendingRestore))
        .map((record) => ({ tabId: record.tabId, status: record.finalizedBadge ?? null }));
      await this.chrome.storage.session.set({ [PRESENTATION_KEY]: { chromeSessionId: this.chromeSessionId(), entries, nextEpoch: this.nextEpoch } });
    });
    this.writes = write.catch(() => {});
    try { await write; } catch (error) { this.storageFailure = String(error?.message ?? error); throw error; }
  }
  async visible(id) {
    try { const tab = await this.chrome.tabs.get(id); return tab.active === true && Number.isSafeInteger(tab.windowId)
      && (await this.chrome.windows.get(tab.windowId)).focused === true; } catch { return false; }
  }
  async finalized(record, status) {
    if (!this.initialized || this.storageFailure || this.records().get(record.tabId) !== record || !PRESENTATION_STATES.has(status))
      throw new ConnectorError('scope_unavailable', 'retained presentation has no admitted existing record');
    const observed = await this.visible(record.tabId);
    if (this.records().get(record.tabId) !== record) throw new ConnectorError('scope_unavailable', 'retained presentation record was replaced');
    if (observed) delete record.finalizedBadge; else record.finalizedBadge = status;
    record.finalizationObservation = observed;
    record.presentationRevision = (record.presentationRevision ?? 0) + 1;
    await this.persist(); return observed;
  }
  async active(record) { record.presentationRevision = (record.presentationRevision ?? 0) + 1;
    delete record.finalizationObservation; delete record.pendingRestore; delete record.finalizedBadge; await this.persist(); this.schedule(record.tabId); }
  async seen(id) { const record = this.records().get(id); if (!record?.finalizedBadge) return;
    delete record.finalizedBadge; record.pendingRestore = true; record.finalizationObservation = true;
    record.presentationRevision = (record.presentationRevision ?? 0) + 1;
    await this.persist(); this.schedule(id); }
  schedule(id) {
    if (!this.initialized || !this.records().has(id)) return;
    void this.publish(this.records().get(id)).catch(() => {});
  }
  async image(record, tab) {
    if (record.faviconSource?.pageUrl === tab.url) return record.faviconSource.data;
    if (typeof tab.url !== 'string' || !tab.url || typeof tab.favIconUrl !== 'string' || !tab.favIconUrl || this.ownedImage(tab.favIconUrl)) return null;
    const address = new URL(this.chrome.runtime.getURL('/_favicon/')); address.searchParams.set('pageUrl', tab.url); address.searchParams.set('size', '32');
    const abort = new AbortController(); const timer = setTimeout(() => abort.abort(), 2000);
    try {
      const response = await fetch(address, { credentials: 'omit', signal: abort.signal });
      if (!response.ok || !response.headers.get('content-type')?.startsWith('image/')) return null;
      const length = Number(response.headers.get('content-length')); if (Number.isFinite(length) && length > MAX_FAVICON_BYTES) { await response.body?.cancel(); return null; }
      const reader = response.body?.getReader(); if (!reader) return null;
      const pieces = []; let size = 0;
      for (;;) { const { done, value } = await reader.read(); if (done) break; if (!value) continue;
        size += value.length; if (size > MAX_FAVICON_BYTES) { await reader.cancel(); return null; } pieces.push(value); }
      let binary = ''; for (const piece of pieces) for (let offset = 0; offset < piece.length; offset += 8192) binary += String.fromCharCode(...piece.subarray(offset, offset + 8192));
      const data = `data:${response.headers.get('content-type')};base64,${btoa(binary)}`;
      const current = await this.chrome.tabs.get(record.tabId);
      if (this.records().get(record.tabId) !== record || current.url !== tab.url || current.favIconUrl !== tab.favIconUrl) return null;
      record.faviconSource = { pageUrl: tab.url, data }; return data;
    } catch { return null; } finally { clearTimeout(timer); }
  }
  publish(record, options = {}) {
    const actual = this.publications.then(() => this.publishOnce(record, options));
    this.publications = actual.catch(() => {}); return actual;
  }
  async publishOnce(record, { status = undefined, execute = null } = {}) {
    if (!record || this.records().get(record.tabId) !== record || record.tabRemoved) return null;
    const revision = record.presentationRevision ?? 0;
    const current = () => this.records().get(record.tabId) === record && !record.tabRemoved
      && (record.presentationRevision ?? 0) === revision;
    const selected = status === undefined ? this.effective(record) : status;
    let tab; try { tab = await this.chrome.tabs.get(record.tabId); } catch { return null; }
    const image = selected === null ? null : await this.image(record, tab);
    if (!current()) return null;
    const frames = await this.chrome.webNavigation.getAllFrames({ tabId: record.tabId });
    const roots = Array.isArray(frames) ? frames.filter((frame) => frame.frameId === 0) : [];
    const documentId = roots.length === 1 && typeof roots[0].documentId === 'string' ? roots[0].documentId : null;
    if (!current()) return null;
    if (!Number.isSafeInteger(this.nextEpoch + 1)) throw new ConnectorError('presentation_budget', 'presentation epoch exhausted');
    const publicationEpoch = ++this.nextEpoch;
    await this.persist();
    if (!current()) return null;
    const request = { target: injectionTarget(record.tabId, { documentId }), world: 'ISOLATED', injectImmediately: true,
      func: paintRetainedFavicon, args: [{ status: selected, faviconDataUrl: image,
        chromeSessionId: this.chromeSessionId(), publicationEpoch }] };
    record.presentationTracked = true;
    const results = await (execute ? execute(request) : this.chrome.scripting.executeScript(request));
    if (results === PUBLIC_WAIT_EXPIRED) return { acknowledged: false, applied: false, available: image !== null, documentId };
    const result = actualTopResult(results, { documentId })?.result;
    if (!current()) this.schedule(record.tabId);
    else if (result?.acknowledged === true && selected === null) {
      delete record.pendingRestore;
      if (!record.logicalLease && !record.logicalPreparation && !record.physical
        && record.owner === null && !record.finalizedBadge) this.records().delete(record.tabId);
      await this.persist();
    }
    return { acknowledged: result?.acknowledged === true, applied: result?.applied === true,
      available: image !== null, documentId };
  }
}
