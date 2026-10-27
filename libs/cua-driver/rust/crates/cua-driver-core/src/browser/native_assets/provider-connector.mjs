// Composition of own Chrome transport leaves. Host retains its existing logical ledger and engine.
import { ConnectorError } from './connector.mjs';
import { ClaimPreparation } from './claim-preparation.mjs';
import { validateExpandedHeaders } from './scoped-headers.mjs';
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
    this.claimPreparation = new ClaimPreparation(chrome, {
      resolveClaim: (record) => this.logicalPreparationCurrent(record),
      emit: (message) => this.emit(message),
      onCleanup: (record) => {
        this.emit({
          kind: 'effects_cleanup',
          protocol: 1,
          generation: record.generation,
          owner: record.owner,
          claim: record.token,
          effect: 'fixed_preparation',
          cleanupConfirmed: this.claimPreparation.cleanupConfirmed(record),
          ...(record.logicalPreparation
            ? { wireContext: record.logicalPreparation.wireContext }
            : {}),
        });
        this.retire(record);
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
    // attach() only observes target identity around debugger attachment.
    result.capabilities.attachmentPreparation = 'metadata_only';
    result.capabilities.explicitClaimPreparation = true;
    result.capabilities.sessionTabResolution = true;
    result.capabilities.sessionCommittedUrl = true;
    result.capabilities.downloadNotifications = true;
    result.capabilities.tabPreparation = true;
    result.capabilities.createdPresentation = true;
    return result;
  }
  // Internal trusted Host seam. This is intentionally separate from prepareUserTab:
  // normalizing a new-tab page is also used before document Origin admission.
  captureLogicalPreparation(record, value) {
    const wire = value?.wireContext;
    const document = value?.document;
    const nonempty = (text) =>
      typeof text === 'string' && text.trim().length > 0 && text.length <= 4096;
    if (
      !nonempty(wire?.hostSessionId) ||
      !nonempty(wire?.hostTurnId) ||
      typeof value?.popupEnabled !== 'boolean' ||
      typeof value?.headerEnabled !== 'boolean' ||
      !nonempty(document?.frameId) ||
      !nonempty(document?.loaderId) ||
      typeof document?.url !== 'string'
    )
      throw new ConnectorError(
        'invalid_request',
        'full preparation requires captured Host context, policy and current document proof',
      );
    let expandedHeaders;
    try {
      expandedHeaders = validateExpandedHeaders(value.headers);
    } catch (error) {
      throw new ConnectorError(error.kind ?? 'invalid_request', String(error.message ?? error));
    }
    const headers = value.headerEnabled ? expandedHeaders : null;
    if (value.headerEnabled && headers.length === 0)
      throw new ConnectorError('invalid_request', 'enabled headers require expanded Host policy');
    const wireContext = Object.freeze({
      hostSessionId: wire.hostSessionId,
      hostTurnId: wire.hostTurnId,
    });
    return Object.freeze({
      wireContext,
      document: Object.freeze({
        frameId: document.frameId,
        loaderId: document.loaderId,
        url: document.url,
      }),
      popupEnabled: value.popupEnabled,
      headerEnabled: value.headerEnabled,
      headers,
      key: JSON.stringify([
        record.generation,
        record.owner,
        record.token,
        wireContext.hostSessionId,
        wireContext.hostTurnId,
      ]),
    });
  }
  logicalPreparationCurrent(record) {
    return (
      this.live(record) &&
      !!record.logicalPreparation &&
      !record.preparation?.ending &&
      record.preparationKey === record.logicalPreparation.key
    );
  }
  async checkPreparationDocument(record, scope) {
    const result = await this.cdp(record, { method: 'Page.getFrameTree', params: {} });
    const frame = result?.result?.frameTree?.frame;
    const fragment = Object.prototype.hasOwnProperty.call(frame ?? {}, 'urlFragment')
      ? frame.urlFragment
      : '';
    if (
      !this.live(record) ||
      frame?.id !== scope.document.frameId ||
      frame?.loaderId !== scope.document.loaderId ||
      typeof frame?.url !== 'string' ||
      typeof fragment !== 'string' ||
      (fragment !== '' && !fragment.startsWith('#')) ||
      frame.url + fragment !== scope.document.url
    )
      throw new ConnectorError(
        'document_changed',
        'full preparation document no longer matches the issued Host proof',
      );
  }
  async prepareLogicalClaim(owner, token, capturedPreparation) {
    const record = this.owned(owner, token);
    if (record.state !== 'owned' || !record.attachedAck || !this.live(record))
      throw new ConnectorError('claim_revoked', 'full preparation needs the current owned claim');
    const requested = this.captureLogicalPreparation(record, capturedPreparation);
    const fingerprint = JSON.stringify([
      requested.key,
      requested.document,
      requested.popupEnabled,
      requested.headerEnabled,
      requested.headers,
    ]);
    if (record.logicalPreparationPending) {
      if (record.logicalPreparationPending.fingerprint === fingerprint)
        return record.logicalPreparationPending.promise;
      throw new ConnectorError('preparation_pending', 'another logical preparation is unsettled');
    }
    const pending = { key: requested.key, fingerprint };
    record.logicalPreparationPending = pending;
    const operation = this.prepareReservedLogicalClaim(record, requested).finally(() => {
      if (record.logicalPreparationPending === pending) record.logicalPreparationPending = null;
    });
    pending.promise = operation;
    return operation;
  }
  async prepareReservedLogicalClaim(record, requested) {
    // No fixed script or DNR effect runs until the original engine's actual
    // frame/loader/full URL stamp matches the Host's already admitted document.
    await this.checkPreparationDocument(record, requested);
    const previous = record.logicalPreparation;
    // Persist only lifetime identity in the existing record. Expanded policy
    // stays with this in-flight call and the existing ScopedHeaders owner.
    const scope =
      previous?.key === requested.key
        ? previous
        : Object.freeze({
            key: requested.key,
            wireContext: requested.wireContext,
          });
    if (previous && previous.key !== scope.key) {
      await this.stopRecordPreparation(record);
      if (!this.claimPreparation.cleanupConfirmed(record))
        throw new ConnectorError('outcome_unknown', 'previous logical preparation is not clean');
      if (!this.live(record))
        throw new ConnectorError('claim_revoked', 'claim ended during logical preparation cleanup');
      record.preparation = null;
    }
    record.logicalPreparation = scope;
    record.preparationKey = scope.key;
    record.popupHeaderEnabled = requested.headerEnabled;
    record.headerScope = this.scope(record);
    record.headerCleanupPromise = null;
    try {
      await this.headers.setScopedHeaders(
        record.token,
        scope.wireContext.hostSessionId,
        requested.headers,
      );
      if (!this.logicalPreparationCurrent(record) || record.logicalPreparation !== scope)
        throw new ConnectorError('claim_revoked', 'logical preparation ended during headers');
      await this.checkPreparationDocument(record, requested);
      const prepared = await this.claimPreparation.prepare(record, requested);
      if (!this.logicalPreparationCurrent(record) || record.logicalPreparation !== scope)
        throw new ConnectorError(
          'claim_revoked',
          'logical preparation ended before acknowledgement',
        );
      return { claim: record.token, ...prepared, preparationKey: scope.key };
    } catch (error) {
      // The submitted policy/script work can survive a failed or cancelled
      // waiter. Existing claim custody, not an invented preparation ACK,
      // carries those effects until their own cleanup is acknowledged.
      throw new ConnectorError('outcome_unknown', String(error.message ?? error), {
        causeKind: error.kind ?? 'connector_failure',
        custody: this.claimResult(record),
      });
    }
  }
  // Called only after the existing Host has reserved its pending popup creation.
  // The page intent never calls this method and contributes no session/turn proof.
  createPopupTab(owner, token, capturedWireContext) {
    const record = this.owned(owner, token);
    const scope = record.logicalPreparation;
    if (
      !scope ||
      !this.logicalPreparationCurrent(record) ||
      scope.wireContext.hostSessionId !== capturedWireContext?.hostSessionId ||
      scope.wireContext.hostTurnId !== capturedWireContext?.hostTurnId
    )
      throw new ConnectorError('claim_revoked', 'popup source logical scope is no longer current');
    return this.createTab(owner, {}, { record, logicalScope: scope });
  }
  async prepareAttachment(record, capturedPreparation) {
    // A new unattached full-preparation path needs a Chrome document-ID DTO.
    // It is not inferred from a URL or enabled by ordinary metadata attachment.
    if (capturedPreparation !== undefined)
      throw new ConnectorError(
        'unsupported',
        'unattached full preparation needs admitted Chrome document identity',
      );
    return super.prepareAttachment(record);
  }
  stopRecordPreparation(record, options) {
    return this.claimPreparation.stop(record, options);
  }
  attachmentCleanupConfirmed(record) {
    return (
      this.claimPreparation.cleanupConfirmed(record) &&
      (!record.headerScope || this.headers.statusForClaim(record.headerScope).cleanupConfirmed)
    );
  }
  async cleanupAttachment(record) {
    const results = await Promise.allSettled([
      this.stopRecordPreparation(record),
      this.clearRecordHeaders(record),
    ]);
    if (
      results.some((result) => result.status === 'rejected') ||
      !this.attachmentCleanupConfirmed(record)
    )
      throw new ConnectorError('outcome_unknown', 'fixed preparation cleanup is unconfirmed');
    return { cleanupConfirmed: true };
  }
  cleanupProven(record) {
    return super.cleanupProven(record) && (this.claimPreparation?.cleanupConfirmed(record) ?? true);
  }
  retire(record) {
    if (
      record.preparation &&
      (record.ending || record.revoked || record.physicalGone || record.detachedAck) &&
      !this.claimPreparation.cleanupConfirmed(record)
    ) {
      void this.stopRecordPreparation(record, { gone: record.physicalGone === true }).catch(
        () => {},
      );
      return;
    }
    if (
      !record.attachedAck &&
      record.attachSettled &&
      record.ending &&
      this.attachmentCleanupConfirmed(record)
    ) {
      if (this.records.get(record.tabId) === record) this.records.delete(record.tabId);
      this.claims.delete(record.token);
      return;
    }
    super.retire(record);
  }
  onDetach(source, reason) {
    const record = this.recordForSource(source);
    if (record?.preparation) void this.stopRecordPreparation(record).catch(() => {});
    super.onDetach(source, reason);
  }
  onRemoved(id) {
    const record = this.records.get(id);
    if (record?.preparation)
      void this.stopRecordPreparation(record, { gone: true }).catch(() => {});
    super.onRemoved(id);
  }
  cleanupIdentity(record, operation) {
    return Object.freeze({
      claim: record.token,
      tabId: record.tabId,
      ...(typeof record.targetId === 'string' && record.targetId
        ? { targetId: record.targetId }
        : {}),
      operation,
    });
  }
  canonicalPhysicalFailureProof(error, issued) {
    // This error is the rejection of the exact super.detach/closeTab call below.
    // Only PreparedBrowserConnector's direct header-cleanup error can carry its
    // actual physical result. Never traverse arbitrary nested peer error JSON.
    if (
      !(error instanceof ConnectorError) ||
      error.kind !== 'outcome_unknown' ||
      typeof error.details?.headerError !== 'string'
    )
      return undefined;
    const proof = error.details.physicalProof;
    if (!proof || typeof proof !== 'object' || Array.isArray(proof)) return undefined;
    for (const key of ['claim', 'tabId', 'targetId'])
      if (Object.prototype.hasOwnProperty.call(proof, key) && proof[key] !== issued[key])
        return undefined;
    const detached =
      issued.operation === 'detach' &&
      proof.detached === true &&
      !Object.prototype.hasOwnProperty.call(proof, 'closed') &&
      ['detach_ack', 'detach_event', 'tab_removed'].includes(proof.proof);
    const closed =
      issued.operation === 'close' &&
      proof.closed === true &&
      !Object.prototype.hasOwnProperty.call(proof, 'detached') &&
      ['close_ack', 'tab_removed'].includes(proof.proof);
    if (!detached && !closed) return undefined;
    return {
      ...(detached ? { detached: true } : { closed: true }),
      proof: proof.proof,
      claim: issued.claim,
      tabId: issued.tabId,
      ...(issued.targetId ? { targetId: issued.targetId } : {}),
    };
  }
  async withPreparationCleanup(record, physical, issued) {
    const preparation = this.stopRecordPreparation(record);
    const [result, cleanup] = await Promise.allSettled([physical, preparation]);
    if (cleanup.status === 'rejected' || !this.claimPreparation.cleanupConfirmed(record)) {
      const recovered =
        result.status === 'rejected'
          ? this.canonicalPhysicalFailureProof(result.reason, issued)
          : undefined;
      throw new ConnectorError(
        'outcome_unknown',
        'physical cleanup and fixed preparation have separate proof',
        {
          ...(result.status === 'fulfilled' ? { physicalProof: result.value } : {}),
          ...(recovered
            ? { physicalProof: recovered, headerError: result.reason.details.headerError }
            : {}),
          ...(result.status === 'rejected' ? { physicalError: String(result.reason) } : {}),
          preparationError:
            cleanup.status === 'rejected'
              ? String(cleanup.reason)
              : 'fixed preparation cleanup is unconfirmed',
        },
      );
    }
    if (result.status === 'rejected') throw result.reason;
    return { ...result.value, preparationCleanupConfirmed: true };
  }
  detach(record) {
    const issued = this.cleanupIdentity(record, 'detach');
    const physical = super.detach(record);
    return record.preparation ? this.withPreparationCleanup(record, physical, issued) : physical;
  }
  closeTab(record) {
    const issued = this.cleanupIdentity(record, 'close');
    const physical = super.closeTab(record);
    return record.preparation ? this.withPreparationCleanup(record, physical, issued) : physical;
  }
  async closeOwner(owner) {
    const records = [...this.records.values()].filter((record) => record.owner === owner);
    const preparations = records.map((record) => this.stopRecordPreparation(record));
    const physical = super.closeOwner(owner);
    const [result] = await Promise.all([physical, Promise.allSettled(preparations)]);
    return {
      ...result,
      cleanupConfirmed:
        result.cleanupConfirmed &&
        records.every((record) => this.attachmentCleanupConfirmed(record)),
    };
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
  async dispatch(owner, method, params, wireContext) {
    try {
      switch (method) {
        case 'prepareClaim': {
          const exactKeys = (value, keys) =>
            value &&
            typeof value === 'object' &&
            !Array.isArray(value) &&
            Object.keys(value).length === keys.length &&
            keys.every((key) => Object.prototype.hasOwnProperty.call(value, key));
          if (
            !exactKeys(params, ['claim', 'document', 'policy']) ||
            !exactKeys(params.document, ['frameId', 'loaderId', 'url']) ||
            !exactKeys(params.policy, ['popupEnabled', 'headerEnabled', 'headers']) ||
            !Array.isArray(params.policy.headers)
          )
            throw new ConnectorError(
              'invalid_request',
              'prepareClaim requires only exact claim, document and policy fields',
            );
          // Only the native envelope supplies captured Host context. Neither params
          // nor the page runtime bridge is consulted for session/turn metadata.
          return await this.prepareLogicalClaim(owner, params.claim, {
            wireContext,
            document: params.document,
            ...params.policy,
          });
        }
        case 'createPopupTab':
          if (
            Object.keys(params).length !== 1 ||
            !Object.prototype.hasOwnProperty.call(params, 'claim')
          )
            throw new ConnectorError(
              'invalid_request',
              'createPopupTab requires only its exact opener claim',
            );
          return await this.createPopupTab(owner, params.claim, wireContext);
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
          return await super.dispatch(owner, method, params, wireContext);
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
