// Adds scoped DNR effects to the same physical connector, without a second session/ref ledger.
import { BrowserConnector, ConnectorError } from './connector.mjs';
import { ScopedHeaders, ScopedHeaderError } from './scoped-headers.mjs';
function converted(error) {
  return error instanceof ScopedHeaderError
    ? new ConnectorError(error.kind, error.message, error.details)
    : error;
}
export class PreparedBrowserConnector extends BrowserConnector {
  constructor(chrome, options = {}) {
    const observer = { failed: false, failures: 0, lastError: null };
    let instance;
    const emit = (message) => {
      try {
        options.emit?.(message);
      } catch (error) {
        observer.failures = Math.min(Number.MAX_SAFE_INTEGER, observer.failures + 1);
        observer.lastError = error instanceof Error ? error.message : String(error);
        if (!observer.failed) {
          observer.failed = true;
          if (instance) {
            instance.accepting = false;
            queueMicrotask(() => {
              void instance.disconnect().catch(() => {});
            });
          }
        }
      }
    };
    super(chrome, { ...options, emit });
    instance = this;
    this.observer = observer;
    this.headersInitialized = false;
    this.prepareUserTab = options.prepareUserTab;
    this.headers = new ScopedHeaders(chrome, {
      resolveClaim: (subject) => this.resolveHeaderSubject(subject),
    });
  }
  resolveHeaderSubject(subject) {
    if (subject && typeof subject === 'object') {
      const { record, scope } = subject;
      if (scope?.kind !== 'session' || record?.logicalPreparation !== scope
        || scope.ending || !this.resourceLive(record))
        throw new ConnectorError('claim_unavailable', 'fixed header scope is no longer current');
      return { token: scope.scopeId, generation: record.generation, owner: record.owner, tabId: record.tabId };
    }
    const record = this.claims.get(subject);
    if (!record?.physical?.attachedAck || record.physical.token !== subject
      || record.state !== 'owned' || !this.live(record))
      throw new ConnectorError('claim_unavailable',
        'scoped headers require a current acknowledged owned physical claim');
    return record;
  }
  async initialize() {
    try {
      const result = await this.headers.initialize();
      this.headersInitialized = true;
      return result;
    } catch (error) {
      throw converted(error);
    }
  }
  bind(generation) {
    if (this.observer.failed)
      throw new ConnectorError(
        'observer_unavailable',
        'event transport failed and must be replaced',
      );
    if (!this.headersInitialized)
      throw new ConnectorError(
        'headers_not_ready',
        'startup scoped-rule cleanup is not acknowledged',
      );
    return super.bind(generation);
  }
  hello() {
    const result = super.hello();
    result.capabilities.scopedHeaders =
      this.headersInitialized && !this.headers.uncertain && !this.observer.failed;
    return result;
  }
  scope(record) {
    return {
      claim: record.token,
      generation: record.generation,
      owner: record.owner,
      tabId: record.tabId,
    };
  }
  async dispatch(owner, method, params, wireContext) {
    if (method === 'prepareUserTab') {
      const sessionOnly = this.sessionOnlyRequested(params, wireContext);
      if (typeof this.prepareUserTab !== 'function')
        throw new ConnectorError('unsupported', 'tab preparation has no reviewed provider leaf');
      const prepared = await this.prepareUserTab(owner, params, { generation: this.generation });
      const tab = await this.metadata(prepared?.tab);
      if (!tab)
        throw new ConnectorError(
          'target_unavailable',
          'preparation returned no exact extension tab identity',
        );
      if (typeof prepared.tab.pendingUrl === 'string') tab.pendingUrl = prepared.tab.pendingUrl;
      if (typeof prepared.tab.active === 'boolean') tab.active = prepared.tab.active;
      return {
        tab,
        normalized: prepared.normalized === true,
        ...(sessionOnly ? { sessionOnly: true } : {}),
      };
    }
    if (method === 'setScopedHeaders') {
      const record = this.owned(owner, params.claim);
      if (record.logicalPreparation?.kind === 'session')
        throw new ConnectorError('preparation_pending', 'clear the exact fixed session scope before changing physical headers');
      let pending;
      try {
        pending = this.headers.setScopedHeaders(record.token, params.sessionId, params.headers);
      } catch (error) {
        throw converted(error);
      }
      // A failed DNR ACK retains this exact effect receipt in the existing physical record.
      record.headerScope = this.scope(record);
      record.headerCleanupPromise = null;
      try {
        return await pending;
      } catch (error) {
        throw converted(error);
      }
    }
    if (method === 'clearScopedHeaders') {
      const record = this.owned(owner, params.claim);
      if (record.logicalPreparation?.kind === 'session')
        throw new ConnectorError('preparation_pending', 'fixed session headers require their exact logical cleanup');
      return this.clearRecordHeaders(record);
    }
    return super.dispatch(owner, method, params, wireContext);
  }
  clearRecordHeaders(record) {
    if (!record.headerScope)
      return Promise.resolve({
        stateConfirmed: true,
        cleanupConfirmed: true,
        active: false,
        pendingRemoval: false,
      });
    const confirmed = this.headers.statusForClaim(record.headerScope);
    if (confirmed.cleanupConfirmed)
      return Promise.resolve({ scope: record.headerScope, ...confirmed });
    if (record.headerCleanupPromise) return record.headerCleanupPromise;
    const scope = record.headerScope;
    let pending;
    try {
      pending = this.headers.clearClaim(scope);
    } catch (error) {
      return Promise.reject(converted(error));
    }
    const operation = pending.then(
      (result) => {
        if (record.headerCleanupPromise === operation) record.headerCleanupError = null;
        if (record.logicalPreparation?.kind !== 'session') this.emit({
          kind: 'effects_cleanup',
          protocol: 1,
          generation: record.generation,
          owner: record.owner,
          claim: record.token,
          effect: 'scoped_headers',
          cleanupConfirmed: true,
        });
        this.retire(record);
        return result;
      },
      (error) => {
        const failure = converted(error);
        if (record.headerCleanupPromise === operation) record.headerCleanupError = failure;
        if (record.logicalPreparation?.kind !== 'session') this.emit({
          kind: 'effects_cleanup',
          protocol: 1,
          generation: record.generation,
          owner: record.owner,
          claim: record.token,
          effect: 'scoped_headers',
          cleanupConfirmed: false,
          error: { kind: failure.kind ?? 'connector_failure', message: failure.message },
        });
        throw failure;
      },
    );
    record.headerCleanupPromise = operation;
    // Natural Chrome revoke events have no request awaiting their cleanup Promise.
    void operation.catch(() => {});
    return operation;
  }
  retire(record) {
    const logicalActive = record.logicalPreparation?.kind === 'session'
      && !record.logicalEnding && !record.physicalGone && !this.closedOwners.has(record.owner);
    if (record.headerScope && !logicalActive && super.cleanupProven(record)) {
      const status = this.headers.statusForClaim(record.headerScope);
      if (!status.cleanupConfirmed) {
        void this.clearRecordHeaders(record).catch(() => {});
        return;
      }
    }
    super.retire(record);
  }
  cleanupProven(record) {
    return (
      !(record.logicalPreparation && !record.logicalEnding && !record.physicalGone
        && !this.closedOwners.has(record.owner)) &&
      super.cleanupProven(record) &&
      (!record.headerScope || this.headers.statusForClaim(record.headerScope).cleanupConfirmed)
    );
  }
  onDetach(source, reason) {
    const record = this.recordForSource(source);
    super.onDetach(source, reason);
    if (record?.headerScope && record.logicalPreparation?.kind !== 'session')
      void this.clearRecordHeaders(record).catch(() => {});
  }
  onRemoved(id) {
    const record = this.records.get(id);
    super.onRemoved(id);
    if (record?.headerScope) void this.clearRecordHeaders(record).catch(() => {});
  }
  async detach(record) {
    if (!record.physical)
      throw new ConnectorError('claim_unavailable', 'logical preparation cannot detach a debugger');
    if (record.logicalPreparation?.kind === 'session') return super.detach(record);
    let result, physicalError;
    try {
      result = await super.detach(record);
    } catch (error) {
      physicalError = error;
    }
    try {
      await this.clearRecordHeaders(record);
    } catch (error) {
      throw new ConnectorError(
        'outcome_unknown',
        'physical detach and scoped-header cleanup have separate proof',
        {
          physicalProof: result,
          physicalError: physicalError?.message,
          headerError: error.message,
        },
      );
    }
    if (physicalError) throw physicalError;
    return { ...result, scopedHeadersCleanupConfirmed: true };
  }
  async closeTab(record) {
    const result = await super.closeTab(record);
    try {
      await this.clearRecordHeaders(record);
    } catch (error) {
      throw new ConnectorError(
        'outcome_unknown',
        'tab removal was acknowledged but scoped-header cleanup was not',
        { physicalProof: result, headerError: error.message },
      );
    }
    return { ...result, scopedHeadersCleanupConfirmed: true };
  }
  async closeCreation(receipt) {
    const record = this.records.get(receipt.tabId);
    const result = await super.closeCreation(receipt);
    if (record) {
      try {
        await this.clearRecordHeaders(record);
      } catch (error) {
        throw new ConnectorError(
          'outcome_unknown',
          'created tab is gone but scoped-header cleanup remains unknown',
          { physicalProof: result, headerError: error.message },
        );
      }
    }
    return { ...result, scopedHeadersCleanupConfirmed: true };
  }
  async closeOwner(owner) {
    // The core synchronously fences this owner before its first await.
    const physical = super.closeOwner(owner);
    const header = this.headers.clearOwner(owner);
    const settled = await Promise.allSettled([physical, header]);
    for (const record of [...this.records.values()])
      if (record.owner === owner) this.retire(record);
    const remaining = [...this.records.values()].filter((record) => record.owner === owner);
    const pendingAttachments = remaining.filter((record) => record.physical && !record.attachSettled).length;
    const unconfirmedClaims = remaining.filter((record) => !this.cleanupProven(record)).length;
    const headers = this.headers.statusForOwner(owner);
    const cleanupConfirmed =
      pendingAttachments === 0 &&
      unconfirmedClaims === 0 &&
      headers.cleanupConfirmed &&
      ![...this.creations.values()].some((receipt) => receipt.owner === owner && !receipt.closed
        && !this.records.get(receipt.tabId)?.logicalLease);
    const diagnostics = settled
      .filter((result) => result.status === 'rejected')
      .map((result) => String(result.reason));
    if (!headers.cleanupConfirmed)
      throw new ConnectorError(
        'outcome_unknown',
        'owner ended but scoped-header cleanup is unconfirmed',
        { pendingAttachments, unconfirmedClaims, headers, diagnostics },
      );
    return {
      cleanupConfirmed,
      pendingAttachments,
      unconfirmedClaims,
      scopedHeadersCleanupConfirmed: true,
      diagnostics,
    };
  }
  /** Trusted Host recovery of desired effect state; it never reacquires or replays a physical claim. */
  async reconcileHeaders({ forceLive = false } = {}) {
    let result;
    try {
      result = await this.headers.reconcile({ forceLive });
    } catch (error) {
      throw converted(error);
    }
    for (const record of [...this.records.values()]) this.retire(record);
    return result;
  }
}
