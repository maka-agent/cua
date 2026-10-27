// Composition of own Chrome transport leaves. Host retains its existing logical ledger and engine.
import { ConnectorError } from './connector.mjs';
import { NativeDownloads } from './native-downloads.mjs';
import { PreparedBrowserConnector } from './prepared-connector.mjs';
import {
  CreatedTabPresentation,
  CreatedTabPresentationError,
} from './created-tab-presentation.mjs';
import { TabPreparation } from './tab-preparation.mjs';
export class NativeBrowserConnector extends PreparedBrowserConnector {
  constructor(chrome, options = {}) {
    super(chrome, options);
    this.tabPreparation = new TabPreparation(chrome, {
      family: options.browserFamily ?? 'chrome',
      assertAdmission: (context, id) => this.admittedTab(context.owner, id, context.generation),
      ...(options.now ? { now: options.now } : {}),
      ...(options.sleep ? { sleep: options.sleep } : {}),
    });
    this.prepareUserTab = (owner, params, context) =>
      this.tabPreparation.prepare({ owner, generation: context.generation }, params.tabId);
    this.presentation = new CreatedTabPresentation(chrome, {
      resolveCreated: (scope) => this.currentCreationScope(scope),
      randomUUID: this.randomUUID,
    });
    this.downloadObserver = new NativeDownloads(chrome, {
      hasActiveControl: () =>
        this.accepting &&
        ([...this.records.values()].some(
          (record) => record.state === 'owned' && record.attachedAck && this.live(record),
        ) ||
          [...this.creations.values()].some(
            (receipt) =>
              !receipt.closed &&
              !receipt.closeStarted &&
              receipt.generation === this.generation &&
              !this.closedOwners.has(receipt.owner),
          )),
      emit: (download) => {
        if (!this.accepting || !this.generation) return;
        this.emit({ kind: 'download_changed', protocol: 1, generation: this.generation, download });
      },
    });
    this.activationSequence = 0;
    chrome.tabs.onActivated.addListener((info) => this.onActivated(info));
  }
  hello() {
    const result = super.hello();
    result.capabilities.userTabsOrder = 'host';
    result.capabilities.headerScope = 'claim';
    result.capabilities.createdPresentationOwner = 'host';
    result.capabilities.cursorPresentationOwner = 'host';
    result.capabilities.cursorHideOwner = 'host';
    result.capabilities.turnLifecycleOwner = 'host';
    result.capabilities.downloadNotifications = true;
    result.capabilities.tabPreparation = true;
    result.capabilities.createdPresentation = true;
    return result;
  }
  async metadata(tab) {
    const result = await super.metadata(tab);
    if (!result) return result;
    result.providerTabId = String(tab.id);
    if (Number.isFinite(tab.lastAccessed) && tab.lastAccessed > 0)
      result.lastOpened = new Date(tab.lastAccessed).toISOString();
    if (typeof tab.pendingUrl === 'string') result.pendingUrl = tab.pendingUrl;
    if (typeof tab.active === 'boolean') result.active = tab.active;
    return result;
  }
  admittedTab(owner, id, expectedGeneration) {
    if (this.generation !== expectedGeneration || !this.accepting || this.closedOwners.has(owner))
      throw new ConnectorError('owner_closed', 'Host admission owner is no longer active');
    const record = this.records.get(id);
    if (
      record &&
      (record.owner !== owner ||
        record.generation !== this.generation ||
        !this.live(record) ||
        record.state !== 'owned')
    )
      throw new ConnectorError(
        'tab_busy',
        'a competing claim or uncertain cleanup still owns the tab',
      );
    const creation = [...this.creations.values()].find(
      (receipt) => receipt.tabId === id && !receipt.closed,
    );
    if (
      creation &&
      (creation.owner !== owner || creation.generation !== this.generation || creation.closeStarted)
    )
      throw new ConnectorError('tab_busy', 'another client created this tab');
  }
  createdScope(owner, token) {
    if (typeof token !== 'string')
      throw new ConnectorError('creation_required', 'exact creation receipt is required');
    const receipt = this.creations.get(token);
    if (
      !this.accepting ||
      this.closedOwners.has(owner) ||
      !receipt ||
      receipt.closed ||
      receipt.closeStarted ||
      receipt.owner !== owner ||
      receipt.generation !== this.generation ||
      !Number.isSafeInteger(receipt.tabId)
    )
      throw new ConnectorError(
        'creation_unavailable',
        'creation receipt does not belong to this active owner and generation',
      );
    return Object.freeze({
      creation: token,
      owner,
      generation: receipt.generation,
      tabId: receipt.tabId,
    });
  }
  currentCreationScope(scope) {
    if (!scope || typeof scope !== 'object')
      throw new ConnectorError('creation_required', 'admitted creation scope is required');
    const current = this.createdScope(scope.owner, scope.creation);
    if (scope.generation !== current.generation || scope.tabId !== current.tabId)
      throw new ConnectorError(
        'creation_unavailable',
        'creation scope changed before native presentation',
      );
    return current;
  }
  async dispatch(owner, method, params) {
    try {
      switch (method) {
        case 'muteCreatedTab':
          return await this.presentation.muteCreatedIfInactive(
            this.createdScope(owner, params.creation),
          );
        case 'unmuteCreatedTabIfActive':
          return await this.presentation.unmuteCreatedIfActiveAndOwnExtension(
            this.createdScope(owner, params.creation),
          );
        case 'ensureCreatedTabGroup':
          return await this.presentation.ensureCreatedTabGroup(
            this.createdScope(owner, params.creation),
            params.presentation ?? {},
          );
        case 'updateCreatedTabGroup':
          return await this.presentation.updateManagedGroup(
            this.createdScope(owner, params.creation),
            params.group,
            params.presentation ?? {},
          );
        case 'releaseCreatedTabGroup':
          return await this.presentation.releaseCreatedTabGroup(
            this.createdScope(owner, params.creation),
            params.group,
          );
        default:
          return await super.dispatch(owner, method, params);
      }
    } catch (error) {
      if (error instanceof CreatedTabPresentationError)
        throw new ConnectorError(error.kind, error.message, error.details);
      throw error;
    }
  }
  async onActivated(info) {
    if (!Number.isSafeInteger(info?.tabId)) return;
    const sequence = ++this.activationSequence;
    const generation = this.generation;
    for (const receipt of this.creations.values()) {
      if (receipt.tabId !== info.tabId || receipt.closed) continue;
      let scope;
      try {
        scope = this.createdScope(receipt.owner, receipt.token);
      } catch {
        continue;
      }
      // This observes actual Chrome activation, never creates physical focus or a logical turn.
      void this.presentation.unmuteCreatedIfActiveAndOwnExtension(scope).catch(() => {});
    }
    let activeTabs;
    try {
      activeTabs = await this.chrome.tabs.query({ active: true });
    } catch (error) {
      if (sequence !== this.activationSequence || generation !== this.generation || !this.accepting)
        return;
      for (const record of this.records.values())
        if (record.state === 'owned' && record.attachedAck && this.live(record))
          this.emit({
            kind: 'tab_state_unknown',
            protocol: 1,
            generation: record.generation,
            owner: record.owner,
            claim: record.token,
            tabId: record.tabId,
            error: { kind: 'chrome_rejected', message: String(error?.message ?? error) },
          });
      return;
    }
    if (sequence !== this.activationSequence || generation !== this.generation || !this.accepting)
      return;
    const active = new Map(
      activeTabs
        .filter((tab) => Number.isSafeInteger(tab.id) && tab.id >= 0)
        .map((tab) => [tab.id, tab]),
    );
    for (const record of this.records.values())
      if (record.state === 'owned' && record.attachedAck && this.live(record)) {
        const tab = active.get(record.tabId);
        this.emit({
          kind: 'tab_state_changed',
          protocol: 1,
          generation: record.generation,
          owner: record.owner,
          claim: record.token,
          tabId: record.tabId,
          ...(Number.isSafeInteger(tab?.windowId) ? { windowId: tab.windowId } : {}),
          active: !!tab,
        });
      }
  }
}
