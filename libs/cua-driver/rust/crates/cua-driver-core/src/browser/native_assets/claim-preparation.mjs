// SPDX-License-Identifier: MIT

import { ConnectorError } from './connector.mjs';
import {
  popupHookStatus,
  installPopupBridge,
  installPopupHook,
  removePopupHook,
  removePopupBridge,
  foreignMonitorStatus,
  installForeignFrameMonitor,
  removeForeignFrameMonitor,
} from './page-preparation.mjs';

const POPUP_SLOT = '__makaClaimPopup';
const FOREIGN_SLOT = '__makaClaimForeignFrames';
const POPUP_EVENT = 'maka:claim-popup-request';
const POPUP_MESSAGE = 'MAKA_OPEN_BACKGROUND_POPUP';

const acknowledged = (results) =>
  Array.isArray(results) && results.length > 0 && results.every((item) => item.result === true);

export class ClaimPreparation {
  constructor(chrome, { resolveClaim, emit, onCleanup }) {
    this.chrome = chrome;
    this.resolveClaim = resolveClaim;
    this.emit = emit;
    this.onCleanup = onCleanup;
    this.tabs = new Map();
    chrome.webNavigation?.onCommitted?.addListener((event) => this.onCommitted(event));
    chrome.tabs.onUpdated?.addListener((id, change, tab) => {
      if (change.status !== 'loading') return;
      const state = this.invalidate(id, false);
      if (!state || !this.current(state)) return;
      if (typeof tab?.url === 'string' && /^(chrome|edge|brave|opera|vivaldi):/.test(tab.url))
        return;
      this.reprepare(state);
    });
    chrome.tabs.onReplaced?.addListener((_added, removed) => {
      const state = this.tabs.get(removed);
      if (state) void this.stop(state.record, { gone: true }).catch(() => {});
    });
    chrome.runtime.onMessage?.addListener((message, sender) => {
      this.onMessage(message, sender);
      return false;
    });
  }

  available() {
    return (
      typeof this.chrome.scripting?.executeScript === 'function' &&
      typeof this.chrome.webNavigation?.getAllFrames === 'function'
    );
  }

  current(state) {
    return (
      !state.ending &&
      this.tabs.get(state.record.tabId) === state &&
      state.logicalScope === state.record.logicalPreparation &&
      this.resolveClaim(state.record) === true
    );
  }

  state(record) {
    if (record.preparation) return record.preparation;
    if (this.resolveClaim(record) !== true)
      throw new ConnectorError(
        'claim_revoked',
        'preparation requires an owned live physical claim',
      );
    const state = {
      record,
      scope: record.preparationKey ?? record.token,
      logicalScope: record.logicalPreparation,
      ending: false,
      popupEnabled: false,
      popupPending: null,
      foreignPending: null,
      foreignVersion: 0,
      pending: new Set(),
      documents: new Set(),
      effects: new Set(),
      cleanupConfirmed: false,
      cleanupPending: null,
    };
    record.preparation = state;
    this.tabs.set(record.tabId, state);
    return state;
  }

  execute(state, func, { world = 'ISOLATED', documentIds, args } = {}) {
    if (typeof this.chrome.scripting?.executeScript !== 'function')
      throw new ConnectorError('unsupported', 'fixed page preparation API is unavailable');
    const target = documentIds
      ? { tabId: state.record.tabId, documentIds }
      : { tabId: state.record.tabId, allFrames: true };
    if (func === installPopupHook) state.effects.add('main_popup');
    if (func === installPopupBridge) state.effects.add('isolated_popup');
    if (func === installForeignFrameMonitor) state.effects.add('foreign');
    return this.chrome.scripting.executeScript({
      target,
      world,
      injectImmediately: true,
      func,
      args,
    });
  }

  async prepare(record, { popupEnabled = false, headerEnabled = false } = {}) {
    const state = this.state(record);
    if (!this.current(state))
      throw new ConnectorError('claim_revoked', 'physical claim ended before preparation');
    state.popupEnabled ||= popupEnabled || headerEnabled;
    const [foreignInstalled, popupInstalled] = await Promise.all([
      this.foreign(state),
      state.popupEnabled ? this.popup(state) : Promise.resolve(false),
    ]);
    if (headerEnabled && !popupInstalled && this.current(state)) {
      const tab = await this.chrome.tabs.get(record.tabId);
      if (this.current(state) && tab.id === record.tabId && tab.url !== 'about:blank')
        throw new ConnectorError(
          'preparation_failed',
          'Unable to prepare popup request headers. Retry the browser command.',
        );
    }
    return { foreignInstalled, popupInstalled };
  }

  popup(state) {
    if (state.popupPending) return state.popupPending;
    const operation = this.installPopup(state).finally(() => {
      if (state.popupPending === operation) state.popupPending = null;
      state.pending.delete(operation);
    });
    state.popupPending = operation;
    state.pending.add(operation);
    return operation;
  }

  async installPopup(state) {
    if (!this.current(state)) return false;
    const scope = state.scope;
    try {
      const existing = await this.execute(state, popupHookStatus, {
        world: 'MAIN',
        args: [POPUP_SLOT, scope],
      });
      if (!this.current(state)) return false;
      if (acknowledged(existing)) return true;
      const bridge = await this.execute(state, installPopupBridge, {
        args: [POPUP_SLOT, scope, POPUP_EVENT, POPUP_MESSAGE],
      });
      if (!this.current(state) || !acknowledged(bridge)) return false;
      const main = await this.execute(state, installPopupHook, {
        world: 'MAIN',
        args: [POPUP_SLOT, scope, POPUP_EVENT],
      });
      return this.current(state) && acknowledged(main);
    } catch {
      return false;
    }
  }

  foreign(state) {
    if (state.foreignPending) return state.foreignPending;
    const operation = this.installForeign(state, state.foreignVersion).finally(() => {
      if (state.foreignPending === operation) state.foreignPending = null;
      state.pending.delete(operation);
    });
    state.foreignPending = operation;
    state.pending.add(operation);
    return operation;
  }

  currentDocuments(state, version) {
    return this.current(state) && state.foreignVersion === version;
  }

  async installForeign(state, version) {
    if (!this.currentDocuments(state, version)) return false;
    try {
      const frames = await this.chrome.webNavigation.getAllFrames({ tabId: state.record.tabId });
      if (!this.currentDocuments(state, version)) return false;
      if (
        !Array.isArray(frames) ||
        !frames.some((frame) => frame.frameId === 0) ||
        frames.some(
          (frame) =>
            !frame.documentId || frame.errorOccurred || frame.documentLifecycle !== 'active',
        )
      )
        return this.foreignFallback(state, version);
      const currentDocuments = new Set(frames.map((frame) => frame.documentId));
      for (const id of state.documents) if (!currentDocuments.has(id)) state.documents.delete(id);
      const missing = [...currentDocuments].filter((id) => !state.documents.has(id));
      if (missing.length) {
        const result = await this.execute(state, installForeignFrameMonitor, {
          documentIds: missing,
          args: [FOREIGN_SLOT, state.scope],
        });
        if (!this.currentDocuments(state, version)) return false;
        for (const item of result ?? [])
          if (item.result === true && missing.includes(item.documentId))
            state.documents.add(item.documentId);
        if (missing.some((id) => !state.documents.has(id)))
          return this.foreignFallback(state, version);
      }
      return this.currentDocuments(state, version);
    } catch {
      return this.foreignFallback(state, version);
    }
  }

  async foreignFallback(state, version) {
    if (!this.currentDocuments(state, version)) return false;
    try {
      const existing = await this.execute(state, foreignMonitorStatus, {
        args: [FOREIGN_SLOT, state.scope],
      });
      if (!this.currentDocuments(state, version)) return false;
      if (acknowledged(existing)) return true;
      const result = await this.execute(state, installForeignFrameMonitor, {
        args: [FOREIGN_SLOT, state.scope],
      });
      return this.currentDocuments(state, version) && acknowledged(result);
    } catch {
      return false;
    }
  }

  invalidate(id, childOnly) {
    const state = this.tabs.get(id);
    if (state) {
      state.foreignVersion++;
      state.foreignPending = null;
      if (!childOnly) state.documents.clear();
    }
    return state;
  }

  onCommitted(event) {
    const state = this.invalidate(event.tabId, event.frameId !== 0);
    if (!state || !this.current(state)) return;
    this.reprepare(state);
  }

  reprepare(state) {
    void this.prepare(state.record, {
      popupEnabled: state.popupEnabled,
      headerEnabled: state.record.popupHeaderEnabled === true,
    }).catch(() => {});
  }

  onMessage(message, sender) {
    if (message?.type !== POPUP_MESSAGE || typeof message.url !== 'string') return;
    if (sender?.id !== this.chrome.runtime.id || !Number.isSafeInteger(sender.tab?.id)) return;
    const state = this.tabs.get(sender.tab.id);
    if (!state || !state.popupEnabled || !this.current(state)) return;
    let url;
    try {
      url = new URL(message.url);
    } catch {
      return;
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return;
    const record = state.record;
    this.emit({
      kind: 'popup_requested',
      protocol: 1,
      generation: record.generation,
      owner: record.owner,
      claim: record.token,
      tabId: record.tabId,
      ...(state.logicalScope ? { wireContext: state.logicalScope.wireContext } : {}),
      url: url.href,
      ...(Number.isSafeInteger(sender.frameId) ? { frameId: sender.frameId } : {}),
      ...(typeof sender.documentId === 'string' ? { documentId: sender.documentId } : {}),
      ...(typeof sender.url === 'string' ? { sourceUrl: sender.url } : {}),
    });
  }

  cleanupConfirmed(record) {
    return !record.preparation || record.preparation.cleanupConfirmed;
  }

  stop(record, { gone = false } = {}) {
    const state = record.preparation;
    if (!state) return Promise.resolve({ cleanupConfirmed: true });
    state.ending = true;
    if (this.tabs.get(record.tabId) === state) this.tabs.delete(record.tabId);
    if (gone) {
      state.gone = true;
      state.cleanupConfirmed = true;
      if (state.cleanupPending)
        return Promise.resolve({ cleanupConfirmed: true, proof: 'tab_removed' });
    }
    if (state.cleanupPending) return state.cleanupPending;
    const operation = (async () => {
      await Promise.allSettled([...state.pending]);
      if (state.gone) return { cleanupConfirmed: true, proof: 'tab_removed' };
      const scope = state.scope;
      const requests = [];
      if (state.effects.has('main_popup'))
        requests.push(
          this.execute(state, removePopupHook, { world: 'MAIN', args: [POPUP_SLOT, scope] }),
        );
      if (state.effects.has('isolated_popup'))
        requests.push(this.execute(state, removePopupBridge, { args: [POPUP_SLOT, scope] }));
      if (state.effects.has('foreign'))
        requests.push(
          this.execute(state, removeForeignFrameMonitor, { args: [FOREIGN_SLOT, scope] }),
        );
      const results = await Promise.allSettled(requests);
      // Actual tab destruction is monotonic. Late script failures cannot revoke
      // the absence of the documents in which those scripts used to run.
      if (state.gone) {
        state.cleanupConfirmed = true;
        return { cleanupConfirmed: true, proof: 'tab_removed' };
      }
      state.cleanupConfirmed = results.every(
        (result) => result.status === 'fulfilled' && acknowledged(result.value),
      );
      if (!state.cleanupConfirmed)
        throw new ConnectorError(
          'outcome_unknown',
          'owned page preparation cleanup is unconfirmed',
        );
      return { cleanupConfirmed: true, proof: 'fixed_script_ack' };
    })()
      .catch((error) => {
        if (state.gone) {
          state.cleanupConfirmed = true;
          return { cleanupConfirmed: true, proof: 'tab_removed' };
        }
        state.cleanupConfirmed = false;
        if (error instanceof ConnectorError && error.kind === 'outcome_unknown') throw error;
        throw new ConnectorError(
          'outcome_unknown',
          'owned page preparation cleanup is unconfirmed',
          {
            cause: error instanceof Error ? error.message : String(error),
          },
        );
      })
      .finally(() => this.onCleanup(record));
    state.cleanupPending = operation;
    void operation.catch(() => {});
    return operation;
  }
}
