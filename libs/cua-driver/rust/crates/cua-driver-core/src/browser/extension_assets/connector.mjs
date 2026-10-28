// Maka public-Chrome-API transport. No selectors, injected JS, input or screenshot implementation.
export class ConnectorError extends Error {
  constructor(kind, message, details) {
    super(message);
    this.kind = kind;
    this.details = details;
  }
}
const fail = (kind, message) => {
  throw new ConnectorError(kind, message);
};
const maka = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
const tabId = (value) => {
  if (!Number.isSafeInteger(value) || value < 0)
    fail('invalid_request', 'tabId must be a nonnegative safe integer');
  return value;
};
// One tab resource owns its logical effects and, independently, at most one
// actual debugger attachment. These accessors retain the existing leaf view;
// every physical value has only one authoritative home in the optional facet.
const PHYSICAL_FIELDS = [
  'targetId', 'state', 'attachSettled', 'attachedAck', 'ending', 'revoked',
  'detachedEvent', 'detachEventAfterAck', 'detachedAck', 'detachStarted',
  'detachSettled', 'children', 'inFlight', 'settlement', 'resolveSettlement',
  'detachPromise', 'pendingTargetAttaches', 'closeStarted', 'closePromise',
];
function resourceRecord(tabId, owner, generation, resourceId) {
  const record = { tabId, owner, generation, resourceId, physical: null,
    physicalGone: false, tabRemoved: false };
  Object.defineProperty(record, 'token', {
    get() { return this.physical?.token ?? this.resourceId; },
  });
  for (const field of PHYSICAL_FIELDS) {
    Object.defineProperty(record, field, {
      get() { return this.physical?.[field]; },
      set(value) {
        if (!this.physical) fail('claim_unavailable', 'tab has no physical attachment facet');
        this.physical[field] = value;
      },
    });
  }
  return record;
}
async function chromeCall(call) {
  try {
    return await call();
  } catch (error) {
    throw new ConnectorError(
      'chrome_rejected',
      error instanceof Error ? error.message : String(error),
    );
  }
}

export class BrowserConnector {
  constructor(chrome, { emit, randomUUID = () => crypto.randomUUID(), maxPending = 64 } = {}) {
    this.chrome = chrome;
    this.emit = emit ?? (() => {});
    this.randomUUID = randomUUID;
    this.instanceId = randomUUID();
    this.maxPending = maxPending;
    this.generation = null;
    this.accepting = false;
    this.highWater = 0n;
    this.pending = 0;
    this.pendingCleanup = new Set();
    this.closedOwners = new Set();
    this.records = new Map();
    this.claims = new Map();
    this.creations = new Map();
    chrome.debugger.onEvent.addListener((source, method, params) =>
      this.onEvent(source, method, params),
    );
    chrome.debugger.onDetach.addListener((source, reason) => this.onDetach(source, reason));
    chrome.tabs.onRemoved.addListener((id) => this.onRemoved(id));
  }
  hello() {
    return {
      kind: 'hello',
      protocol: 1,
      extensionId: this.chrome.runtime.id,
      instanceId: this.instanceId,
      capabilities: {
        metadata: true,
        rawTabCdp: true,
        cdpEventSourceTarget: true,
        flatChildSessions: true,
        tabLifecycle: true,
        browserManagement: false,
        nativeWindowProof: false,
      },
    };
  }
  bind(generation) {
    if (this.accepting) fail('invalid_state', 'extension port is already bound');
    if (typeof generation !== 'string' || !generation)
      fail('invalid_request', 'generation is required');
    this.generation = generation;
    this.accepting = true;
    this.highWater = 0n;
    this.closedOwners.clear();
  }
  async request(message) {
    let id = message?.id;
    try {
      if (
        !message ||
        message.kind !== 'request' ||
        message.protocol !== 1 ||
        typeof id !== 'string' ||
        !/^[1-9][0-9]{0,19}$/.test(id) ||
        BigInt(id) > 18446744073709551615n ||
        typeof message.owner !== 'string' ||
        !message.owner
      )
        fail('invalid_request', 'invalid request envelope');
      if (!this.accepting || message.generation !== this.generation)
        fail('generation_lost', 'extension generation is not active');
      if (this.closedOwners.has(message.owner)) fail('owner_closed', 'client owner has ended');
      if (BigInt(id) <= this.highWater)
        fail('duplicate_request', 'request IDs cannot be replayed or dispatched out of order');
      this.highWater = BigInt(id);
      const cleanup = ['detach', 'stopCreatedTab', 'clearScopedHeaders', 'clearSessionPreparation']
        .includes(message.method);
      const cleanupKey = cleanup
        ? JSON.stringify([
            message.owner,
            message.method,
            message.params?.claim ?? message.params?.creation ?? message.params?.scopeId,
          ])
        : null;
      if (cleanup && this.pendingCleanup.has(cleanupKey))
        fail('cleanup_pending', 'this exact cleanup operation is already awaiting proof');
      if (cleanup && this.pendingCleanup.size >= this.maxPending)
        fail('request_budget', 'reserved cleanup capacity is occupied');
      if (!cleanup && this.pending >= this.maxPending && message.method !== 'closeOwner')
        fail('request_budget', 'too many in-flight connector requests');
      const generation = this.generation;
      let result;
      this.pending++;
      if (cleanupKey) this.pendingCleanup.add(cleanupKey);
      try {
        result = await this.dispatch(
          message.owner,
          message.method,
          message.params ?? {},
          message.wireContext,
        );
      } finally {
        this.pending--;
        if (cleanupKey) this.pendingCleanup.delete(cleanupKey);
      }
      if (
        !this.accepting ||
        this.generation !== generation ||
        (message.method !== 'closeOwner' && this.closedOwners.has(message.owner))
      )
        throw new ConnectorError(
          'outcome_unknown',
          'connection or owner ended before the reply could be acknowledged',
          { acknowledgedResult: result },
        );
      return { kind: 'response', protocol: 1, generation, id, result };
    } catch (error) {
      return {
        kind: 'response',
        protocol: 1,
        generation: message?.generation,
        id,
        error: {
          kind: error instanceof ConnectorError ? error.kind : 'connector_failure',
          message: error instanceof Error ? error.message : String(error),
          ...(error instanceof ConnectorError && error.details ? { details: error.details } : {}),
        },
      };
    }
  }
  sessionOnlyRequested(params, wireContext) {
    if (maka(params, 'sessionOnly') && typeof params.sessionOnly !== 'boolean')
      fail('invalid_request', 'sessionOnly must be a boolean when provided');
    if (params.sessionOnly !== true) return false;
    const nonempty = (value) =>
      typeof value === 'string' && value.trim().length > 0 && value.length <= 4096;
    if (!nonempty(wireContext?.hostSessionId) || !nonempty(wireContext?.hostTurnId))
      fail('invalid_request', 'session-only resolution requires captured Host session and turn');
    // Purpose confirmation only. The Host owns logical tab membership and admission.
    return true;
  }
  async dispatch(owner, method, params, wireContext) {
    switch (method) {
      case 'inventory': {
        const sessionOnly = this.sessionOnlyRequested(params, wireContext);
        if (!sessionOnly) {
          if (maka(params, 'knownTabIds'))
            fail('invalid_request', 'candidate IDs require sessionOnly:true');
          return { tabs: await this.inventory() };
        }
        if (!Array.isArray(params.knownTabIds))
          fail('invalid_request', 'session inventory requires candidate IDs');
        const ids = new Set();
        for (const id of params.knownTabIds) {
          if (!Number.isSafeInteger(id) || id <= 0 || ids.has(id))
            fail('invalid_request', 'session inventory candidates must be unique positive safe IDs');
          ids.add(id);
        }
        // The Host owns membership. This single request observes its actual
        // candidates without creating another logical-session registry.
        const rows = await Promise.all(params.knownTabIds.map(async (id) => {
          let tab;
          try { tab = await chromeCall(() => this.chrome.tabs.get(id)); }
          catch { return null; }
          const metadata = await this.metadata(tab);
          if (metadata?.id !== id)
            fail('target_unavailable', 'Chrome returned a different session inventory target');
          return metadata;
        }));
        return { tabs: rows.filter((tab) => tab !== null), sessionOnly: true };
      }
      case 'resolve': {
        // Extension-provider compatibility only. Public grammar remains with the Host.
        const sessionOnly = this.sessionOnlyRequested(params, wireContext);
        if (maka(params, 'committedUrlOnly') && typeof params.committedUrlOnly !== 'boolean')
          fail('invalid_request', 'committedUrlOnly must be a boolean when provided');
        const committedUrlOnly = params.committedUrlOnly === true;
        if (committedUrlOnly && !sessionOnly)
          fail('invalid_request', 'committed URL resolution requires sessionOnly:true');
        if (typeof params.rawId !== 'string' || !params.rawId)
          fail('invalid_request', 'rawId string is required');
        const id = Number(params.rawId);
        if (!Number.isInteger(id) || id <= 0)
          fail('invalid_request', 'extension tab ID does not resolve to a positive integer');
        const tab = await chromeCall(() => this.chrome.tabs.get(id));
        if (committedUrlOnly) {
          if (!Number.isSafeInteger(tab?.id) || tab.id !== id || typeof tab.url !== 'string')
            fail('target_unavailable', 'Chrome returned no exact committed tab URL string');
          return { url: tab.url, sessionOnly: true, committedUrlOnly: true };
        }
        const metadata = await this.metadata(tab);
        if (sessionOnly && metadata?.id !== id)
          fail('target_unavailable', 'Chrome metadata did not match the requested session tab');
        return { tab: metadata, ...(sessionOnly ? { sessionOnly: true } : {}) };
      }
      case 'createTab':
        return this.createTab(owner, params);
      case 'closeTab':
        return this.closeTab(this.owned(owner, params.claim));
      case 'stopCreatedTab':
        return this.stopCreatedTab(owner, params.creation);
      case 'attach':
        return this.attach(owner, tabId(params.tabId));
      case 'detach':
        return this.detach(this.owned(owner, params.claim));
      case 'cdp':
        return this.cdp(this.owned(owner, params.claim), params);
      case 'closeOwner':
        return this.closeOwner(owner);
      default:
        fail('unsupported', 'operation has no reviewed transport implementation');
    }
  }
  async metadata(tab) {
    if (!tab || !Number.isSafeInteger(tab.id) || tab.id < 0) return null;
    const result = { id: tab.id };
    for (const key of ['windowId', 'index', 'groupId'])
      if (Number.isSafeInteger(tab[key])) result[key] = tab[key];
    if (typeof tab.title === 'string') result.titleJson = JSON.stringify(tab.title);
    if (typeof tab.url === 'string') result.url = tab.url;
    if (typeof tab.lastAccessed === 'number' && Number.isFinite(tab.lastAccessed))
      result.lastAccessed = tab.lastAccessed;
    if (typeof tab.groupId === 'number' && tab.groupId !== -1 && this.chrome.tabGroups) {
      try {
        const group = await this.chrome.tabGroups.get(tab.groupId);
        const title = typeof group?.title === 'string' ? group.title.trim() : '';
        if (title) result.groupTitleJson = JSON.stringify(title);
      } catch {
        /* Optional metadata is unavailable; never invent a group. */
      }
    }
    return result;
  }
  async inventory() {
    const tabs = await chromeCall(() => this.chrome.tabs.query({}));
    const result = [];
    const ids = new Set();
    for (const tab of tabs) {
      const dto = await this.metadata(tab);
      if (dto && !ids.has(dto.id)) {
        ids.add(dto.id);
        result.push(dto);
      }
    }
    return result;
  }
  async pageTarget(id) {
    const targets = await chromeCall(() => this.chrome.debugger.getTargets());
    const matches = targets.filter((target) => target.type === 'page' && target.tabId === id);
    if (matches.length !== 1 || typeof matches[0].id !== 'string' || !matches[0].id)
      fail('target_unavailable', 'tab has no unique current Chrome page target');
    return matches[0];
  }
  claimResult(record) {
    if (!record.physical)
      fail('claim_unavailable', 'logical preparation is not a physical attachment receipt');
    return { claim: record.physical.token, tabId: record.tabId, targetId: record.targetId };
  }
  resourceLive(record) {
    return (
      this.accepting &&
      record.generation === this.generation &&
      !this.closedOwners.has(record.owner) &&
      !record.physicalGone &&
      this.records.get(record.tabId) === record
    );
  }
  reserveResource(owner, id) {
    if (!this.accepting || !this.generation || this.closedOwners.has(owner))
      fail('owner_closed', 'tab resource owner is not active');
    const existing = this.records.get(id);
    if (existing) {
      if (existing.owner !== owner || !this.resourceLive(existing))
        fail('tab_busy', 'another resource or unconfirmed cleanup owns this tab');
      return existing;
    }
    const record = resourceRecord(id, owner, this.generation, this.randomUUID());
    this.records.set(id, record);
    return record;
  }
  sessionPreparationCurrent(record) {
    return this.resourceLive(record) && record.logicalPreparation?.kind === 'session'
      && !record.logicalEnding;
  }
  live(record) {
    return (
      this.resourceLive(record) &&
      !!record.physical &&
      !record.ending &&
      !record.revoked &&
      !record.detachedAck
    );
  }
  owned(owner, token) {
    if (typeof token !== 'string') fail('claim_required', 'physical claim token is required');
    const record = this.claims.get(token);
    if (!record || !record.physical || record.physical.token !== token
      || record.owner !== owner || record.generation !== this.generation)
      fail('claim_unavailable', 'claim does not belong to this owner and generation');
    return record;
  }
  // Subclasses may prepare only the already reserved exact record. The default attach
  // remains metadata-only; an admitted full-preparation caller supplies its captured scope.
  async prepareAttachment(_record, _preparation) {}
  async cleanupAttachment(_record) {
    return { cleanupConfirmed: true };
  }
  attachmentCleanupConfirmed(_record) {
    return true;
  }
  async attach(owner, id, preparation) {
    const created = [...this.creations.values()].find(
      (receipt) => receipt.tabId === id && !receipt.closed,
    );
    if (created && created.owner !== owner)
      fail('tab_busy', 'another client created and owns this tab');
    const existing = this.records.get(id);
    if (existing?.logicalPreparation?.kind === 'session'
      && (existing.logicalEnding || existing.logicalPreparation.ending
        || existing.logicalPreparation.phase !== 'ready'))
      fail('tab_busy', 'fixed preparation or cleanup is still unsettled');
    if (existing?.physical) {
      if (existing.owner === owner && existing.attachedAck
        && existing.state === 'owned' && this.live(existing))
        return this.claimResult(existing);
      fail('tab_busy', 'a physical attachment or unconfirmed cleanup already owns this tab');
    }
    // Reserve before the first asynchronous Chrome query. Competing requests cannot both attach.
    const record = this.reserveResource(owner, id);
    const physical = {
      token: this.randomUUID(),
      targetId: null,
      state: 'attaching',
      attachSettled: false,
      attachedAck: false,
      ending: false,
      revoked: false,
      detachedEvent: false,
      detachEventAfterAck: false,
      detachedAck: false,
      detachStarted: false,
      detachSettled: false,
      children: new Map(),
      inFlight: new Set(),
    };
    physical.settlement = new Promise((resolve) => {
      physical.resolveSettlement = resolve;
    });
    record.physical = physical;
    this.claims.set(physical.token, record);
    try {
      const before = await this.pageTarget(id);
      record.targetId = before.id;
      if (before.attached)
        fail('foreign_debugger', 'Chrome reports an attachment not owned by this connector');
      await this.prepareAttachment(record, preparation);
      if (!this.live(record)) fail('generation_lost', 'attachment was cancelled before dispatch');
      await chromeCall(() => this.chrome.debugger.attach({ tabId: id }, '1.3'));
      record.attachedAck = true;
      if (!this.live(record)) {
        if (!record.detachEventAfterAck && !record.physicalGone) await this.detach(record);
        fail('outcome_unknown', 'attachment ended before a live claim could be returned');
      }
      const after = await this.pageTarget(id);
      if (after.id !== record.targetId || !after.attached) {
        record.ending = true;
        await this.detach(record);
        fail('target_changed', 'Chrome page target changed during attachment');
      }
      if (!this.live(record)) {
        if (!record.detachEventAfterAck && !record.physicalGone) await this.detach(record);
        fail('outcome_unknown', 'attachment was revoked before claim acknowledgement');
      }
      record.state = 'owned';
      return this.claimResult(record);
    } catch (error) {
      if (!record.attachedAck) {
        // Fixed preparation can precede the debugger effect. Keep that same reserved
        // record until its cleanup is proven, including late installation replies.
        record.ending = true;
        if (!this.sessionPreparationCurrent(record)) {
          try {
            await this.cleanupAttachment(record);
          } catch {
            // Cleanup custody remains in this record; it is never converted to absence.
          }
        }
        if (!this.sessionPreparationCurrent(record) && !this.attachmentCleanupConfirmed(record)) {
          record.state = 'cleanup_unknown';
          throw new ConnectorError(
            'outcome_unknown',
            'pre-attachment effects require confirmed cleanup',
            {
              cause: error instanceof Error ? error.message : String(error),
              custody: this.claimResult(record),
            },
          );
        }
        physical.rejectedBeforeAttachment = true;
      } else {
        record.ending = true;
        if (!record.detachedAck && !record.detachEventAfterAck && !record.physicalGone) {
          try {
            await this.detach(record);
          } catch {
            /* Preserve unknown physical custody below. */
          }
        }
        if (!record.detachedAck && !record.detachEventAfterAck && !record.physicalGone)
          throw new ConnectorError(
            'outcome_unknown',
            'attachment was acknowledged but cleanup is unconfirmed',
            {
              cause: error instanceof Error ? error.message : String(error),
              custody: this.claimResult(record),
            },
          );
        if (error instanceof ConnectorError && error.kind === 'chrome_rejected')
          throw new ConnectorError(
            'attach_aborted',
            'post-attachment observation failed; owned attachment was cleaned',
            { cause: error.message, cleanupConfirmed: true },
          );
      }
      throw error;
    } finally {
      physical.attachSettled = true;
      physical.resolveSettlement();
      this.retire(record);
    }
  }
  async detach(record) {
    if (!record.physical)
      fail('claim_unavailable', 'logical preparation cannot detach a debugger');
    if (record.detachStarted) return record.detachPromise;
    if (!record.attachedAck)
      fail('attachment_pending', 'cannot detach an unacknowledged attachment');
    if (record.detachEventAfterAck || record.physicalGone)
      return { detached: true, proof: record.physicalGone ? 'tab_removed' : 'detach_event' };
    if (this.records.get(record.tabId) !== record)
      fail('claim_unavailable', 'physical epoch was replaced');
    record.ending = true;
    record.state = 'detaching';
    record.detachStarted = true;
    record.detachPromise = (async () => {
      try {
        await chromeCall(() => this.chrome.debugger.detach({ tabId: record.tabId }));
        record.detachedAck = true;
        record.state = record.detachedEvent ? 'released' : 'awaiting_detach_event';
        return { detached: true, proof: 'detach_ack' };
      } catch (error) {
        record.state = record.revoked ? 'revoked' : 'cleanup_unknown';
        throw error;
      } finally {
        record.detachSettled = true;
        this.retire(record);
      }
    })();
    return record.detachPromise;
  }
  retire(record) {
    const physical = record.physical;
    if (physical) {
      if (
        !(physical.detachEventAfterAck || record.physicalGone || physical.rejectedBeforeAttachment) ||
        !physical.attachSettled ||
        (physical.detachStarted && !physical.detachSettled)
      ) return;
      if (record.logicalPreparation?.kind !== 'session' && !this.attachmentCleanupConfirmed(record))
        return;
      this.claims.delete(physical.token);
      record.physical = null;
    }
    if ((record.logicalPreparation && !record.logicalEnding)
      || !this.attachmentCleanupConfirmed(record)) return;
    record.logicalPreparation = null;
    if (this.records.get(record.tabId) === record) this.records.delete(record.tabId);
  }
  async cdp(record, params) {
    const physical = record.physical;
    if (!physical?.attachedAck || physical.state !== 'owned' || !this.live(record))
      fail('claim_revoked', 'physical claim is not active');
    if (typeof params.method !== 'string' || !/^[A-Za-z]+\.[A-Za-z]+$/.test(params.method))
      fail('invalid_request', 'CDP method is required');
    const method = params.method;
    const commandParams = params.params ?? {};
    if (
      method === 'Target.createTarget' ||
      method === 'Target.createBrowserContext' ||
      method === 'Target.disposeBrowserContext' ||
      method === 'Target.attachToBrowserTarget'
    )
      fail(
        'host_scope_required',
        'this command creates or changes a global browser resource outside the tracked tab creator',
      );
    if (method.startsWith('Target.') && maka(commandParams, 'targetId')) {
      const targetId = commandParams.targetId;
      const observed =
        targetId === physical.targetId ||
        [...physical.children.values()].some(
          (child) => child.active !== false && child.targetId === targetId,
        );
      if (typeof targetId !== 'string' || !targetId || !observed)
        fail('target_unavailable', 'target was not observed under this physical claim');
    }
    if (
      method === 'Target.attachToTarget' &&
      (typeof commandParams.targetId !== 'string' || !commandParams.targetId)
    )
      fail('invalid_request', 'attach requires an exact observed targetId');
    if (
      method === 'Target.detachFromTarget' &&
      (typeof commandParams.sessionId !== 'string' ||
        !this.activeChild(record, commandParams.sessionId))
    )
      fail('child_session_unavailable', 'detach requires an observed child session');
    if (
      method === 'Target.setAutoAttach' &&
      (params.params?.flatten !== true || params.params?.waitForDebuggerOnStart !== false)
    )
      fail('invalid_request', 'auto-attach requires flat non-pausing child sessions');
    const source = { tabId: record.tabId };
    if (maka(params, 'sessionId')) {
      if (typeof params.sessionId !== 'string' || !this.activeChild(record, params.sessionId))
        fail(
          'child_session_unavailable',
          'child session was not observed under this physical claim',
        );
      source.sessionId = params.sessionId;
    }
    const attaching = method === 'Target.attachToTarget';
    if (attaching) physical.pendingTargetAttaches = (physical.pendingTargetAttaches ?? 0) + 1;
    const call = chromeCall(async () => {
      if (method === 'Target.getTargets') {
        const targets = await this.chrome.debugger.getTargets();
        return { targetInfos: targets.map((target) => ({ ...target, targetId: target.id })) };
      }
      // Chrome owns method support, including its restricted Browser domain.
      return this.chrome.debugger.sendCommand(source, method, commandParams);
    });
    physical.inFlight.add(call);
    try {
      const result = await call;
      if (record.physical !== physical || !this.live(record))
        fail('outcome_unknown', 'claim ended during CDP command; do not replay');
      if (method === 'Target.attachToTarget') {
        const sessionId = result?.sessionId;
        if (typeof sessionId !== 'string' || !sessionId)
          throw new ConnectorError(
            'outcome_unknown',
            'target attach returned no exact Chrome session identity',
            { acknowledgedResult: result },
          );
        if (source.sessionId && !this.activeChild(record, source.sessionId))
          throw new ConnectorError(
            'outcome_unknown',
            'parent session ended during target attach; do not replay',
            { acknowledgedResult: result, parentSessionId: source.sessionId },
          );
        const child = physical.children.get(sessionId);
        const parent = source.sessionId ?? null;
        if (
          child &&
          (child.active === false ||
            child.targetId !== commandParams.targetId ||
            child.parent !== parent)
        )
          throw new ConnectorError(
            'outcome_unknown',
            'target attach acknowledgement disagrees with its observed child event',
            { acknowledgedResult: result },
          );
        physical.children.set(sessionId, { targetId: commandParams.targetId, parent });
      } else if (method === 'Target.detachFromTarget') {
        this.removeChild(record, commandParams.sessionId);
      }
      if (['DOM.describeNode', 'Runtime.getProperties', 'Target.getTargets'].includes(method))
        return { resultJson: JSON.stringify(result ?? null) };
      return { result: result ?? null };
    } finally {
      physical.inFlight.delete(call);
      if (attaching) {
        physical.pendingTargetAttaches--;
        if (physical.pendingTargetAttaches === 0)
          for (const [id, child] of physical.children)
            if (child.active === false) physical.children.delete(id);
      }
    }
  }
  activeChild(record, sessionId) {
    const child = record.children.get(sessionId);
    return child && child.active !== false ? child : undefined;
  }
  recordForSource(source) {
    if (Number.isSafeInteger(source?.tabId)) return this.records.get(source.tabId);
    if (typeof source?.targetId === 'string') {
      const found = [...this.records.values()].filter(
        (record) => record.targetId === source.targetId,
      );
      return found.length === 1 ? found[0] : undefined;
    }
  }
  onEvent(source, method, params = {}) {
    const record = this.recordForSource(source);
    if (!record || !record.attachedAck || record.revoked || record.detachedAck) return;
    if (source.sessionId && !this.activeChild(record, source.sessionId)) return;
    if (method === 'Target.attachedToTarget') {
      if (
        typeof params.sessionId !== 'string' ||
        !params.sessionId ||
        typeof params.targetInfo?.targetId !== 'string'
      )
        return;
      record.children.set(params.sessionId, {
        targetId: params.targetInfo.targetId,
        parent: source.sessionId ?? null,
      });
    } else if (method === 'Target.detachedFromTarget' && typeof params.sessionId === 'string') {
      this.removeChild(record, params.sessionId, source.sessionId ?? null);
    }
    this.emit({
      kind: 'event',
      protocol: 1,
      generation: record.generation,
      owner: record.owner,
      claim: record.token,
      method,
      ...(method === 'Target.attachedToTarget' ? { paramsJson: JSON.stringify(params) } : { params }),
      ...(source.sessionId ? { sessionId: source.sessionId } : {}),
      ...(source.targetId != null ? { sourceTargetId: source.targetId } : {}),
    });
  }
  removeChild(record, sessionId, parent = null) {
    for (const [id, child] of record.children)
      if (child.parent === sessionId && child.active !== false)
        this.removeChild(record, id, sessionId);
    if (record.pendingTargetAttaches > 0) {
      // Keep this actual detach observation only while an attach ACK could
      // still name it. The ACK must not resurrect a session Chrome retired.
      const child = record.children.get(sessionId);
      if (child) child.active = false;
      else record.children.set(sessionId, { targetId: null, parent, active: false });
    } else {
      record.children.delete(sessionId);
    }
  }
  onDetach(source, reason) {
    const record = this.recordForSource(source);
    if (!record?.physical) return;
    record.revoked = true;
    record.detachedEvent = true;
    if (record.attachedAck) record.detachEventAfterAck = true;
    record.state = 'revoked';
    record.children.clear();
    this.emit({
      kind: 'revoked',
      protocol: 1,
      generation: record.generation,
      owner: record.owner,
      claim: record.token,
      reason,
    });
    this.retire(record);
  }
  onRemoved(id) {
    for (const [token, receipt] of this.creations)
      if (receipt.tabId === id) {
        receipt.closed = true;
        this.creations.delete(token);
      }
    const record = this.records.get(id);
    if (!record) return;
    record.physicalGone = true;
    record.tabRemoved = true;
    this.onDetach({ tabId: id }, 'target_closed');
  }
  cleanupProven(record) {
    return !record.physical || record.detachedAck || record.detachEventAfterAck || record.physicalGone;
  }
  async createTab(owner, params, openerScope) {
    if (Object.keys(params).some((key) => key !== 'windowId'))
      fail('invalid_request', 'createTab accepts only a preferred windowId');
    if (maka(params, 'windowId') && (!Number.isSafeInteger(params.windowId) || params.windowId < 0))
      fail('invalid_request', 'preferred windowId must be a nonnegative safe integer');
    const receipt = {
      token: this.randomUUID(),
      owner,
      generation: this.generation,
      tabId: null,
      settled: false,
      closed: false,
      closeStarted: false,
    };
    receipt.settlement = new Promise((resolve) => {
      receipt.resolveSettlement = resolve;
    });
    this.creations.set(receipt.token, receipt);
    try {
      let tab;
      if (openerScope) {
        const record = openerScope.record;
        const current = () => record.owner === owner
          && record.logicalPreparation === openerScope.logicalScope
          && (openerScope.logicalScope.kind === 'session'
            ? this.sessionPreparationCurrent(record) && !openerScope.logicalScope.ending
            : this.live(record) && record.state === 'owned' && record.attachedAck
              && !record.preparation?.ending);
        if (!current()) fail('claim_revoked', 'popup opener logical claim is no longer current');
        const opener = await chromeCall(() => this.chrome.tabs.get(record.tabId));
        if (!current()) fail('claim_revoked', 'popup opener ended before creation dispatch');
        if (
          opener.id !== record.tabId ||
          !Number.isSafeInteger(opener.windowId) ||
          opener.windowId < 0
        )
          fail('target_unavailable', 'popup opener has no actual current window identity');
        tab = await chromeCall(() =>
          this.chrome.tabs.create({
            active: false,
            openerTabId: record.tabId,
            url: 'about:blank',
            windowId: opener.windowId,
          }),
        );
        receipt.creationAck = true;
      } else {
        const windows = await chromeCall(() =>
          this.chrome.windows.getAll({ windowTypes: ['normal'] }),
        );
        const normal = windows.filter((window) => window.type === 'normal');
        const selected =
          normal.find((window) => window.id === params.windowId) ??
          normal.find((window) => window.focused) ??
          normal[0];
        if (
          !this.accepting ||
          receipt.generation !== this.generation ||
          this.closedOwners.has(owner)
        )
          fail('owner_closed', 'owner ended before tab creation dispatch');
        if (selected) {
          tab = await chromeCall(() =>
            this.chrome.tabs.create({ active: false, url: 'about:blank', windowId: selected.id }),
          );
          receipt.creationAck = true;
        } else {
          const window = await chromeCall(() =>
            this.chrome.windows.create({ focused: false, type: 'normal', url: 'about:blank' }),
          );
          receipt.creationAck = true;
          receipt.windowId = window.id;
          tab = window.tabs?.find(
            (candidate) => Number.isSafeInteger(candidate.id) && candidate.id >= 0,
          );
          if (!tab)
            throw new ConnectorError(
              'outcome_unknown',
              'new window was acknowledged without a tab identity',
              { windowId: window.id },
            );
        }
      }
      if (!tab || !Number.isSafeInteger(tab.id) || tab.id < 0)
        fail('outcome_unknown', 'Chrome acknowledged creation without an exact tab ID');
      receipt.tabId = tab.id;
      const result = { creation: receipt.token, tab: await this.metadata(tab) };
      return result;
    } catch (error) {
      if (!receipt.creationAck) {
        receipt.closed = true;
        this.creations.delete(receipt.token);
      } else if (receipt.tabId === null)
        throw new ConnectorError(
          'outcome_unknown',
          'creation acknowledged without exact tab identity',
          {
            creation: receipt.token,
            windowId: receipt.windowId,
            cause: error instanceof Error ? error.message : String(error),
          },
        );
      if (receipt.creationAck && receipt.tabId !== null)
        throw new ConnectorError(
          'outcome_unknown',
          'created tab was acknowledged but its metadata was not confirmed',
          {
            acknowledgedResult: { creation: receipt.token, tab: { id: receipt.tabId } },
            cause: error instanceof Error ? error.message : String(error),
          },
        );
      throw error;
    } finally {
      receipt.settled = true;
      receipt.resolveSettlement();
    }
  }
  async closeTab(record) {
    const physical = record.physical;
    if (physical?.closeStarted) return physical.closePromise;
    if (!physical?.attachedAck || !this.live(record) || physical.state !== 'owned')
      fail('claim_revoked', 'explicit close requires a current owned physical claim');
    physical.ending = true;
    physical.closeStarted = true;
    // Keep the submitted close on its original facet: onRemoved may retire it.
    physical.closePromise = chromeCall(() => this.chrome.tabs.remove(record.tabId)).then(() => {
      this.onRemoved(record.tabId);
      return { closed: true, proof: 'close_ack' };
    });
    const receipt = [...this.creations.values()].find(
      (candidate) => candidate.tabId === record.tabId && candidate.owner === record.owner,
    );
    if (receipt) {
      receipt.closeStarted = true;
      receipt.closePromise = physical.closePromise;
    }
    return physical.closePromise;
  }
  async stopCreatedTab(owner, token) {
    if (typeof token !== 'string')
      fail('creation_required', 'creation receipt is required for automatic close');
    const receipt = this.creations.get(token);
    if (!receipt || receipt.owner !== owner || receipt.generation !== this.generation)
      fail('creation_unavailable', 'creation receipt does not belong to this owner and generation');
    return this.closeCreation(receipt);
  }
  async closeCreation(receipt) {
    await receipt.settlement;
    if (receipt.closed) return { closed: true, proof: 'tab_removed' };
    if (receipt.closeStarted) return receipt.closePromise;
    if (receipt.tabId === null)
      fail('outcome_unknown', 'created window has no proven tab identity for cleanup');
    receipt.closeStarted = true;
    receipt.closePromise = (async () => {
      const record = this.records.get(receipt.tabId);
      if (record?.physical && record.owner === receipt.owner) {
        record.ending = true;
        if (!record.attachSettled) await record.settlement;
        if (record.attachedAck && !this.cleanupProven(record)) {
          try {
            await this.detach(record);
          } catch {
            /* Exact created-tab close can still prove physical removal. */
          }
        }
      }
      if (receipt.closed || record?.physicalGone) return { closed: true, proof: 'tab_removed' };
      await chromeCall(() => this.chrome.tabs.remove(receipt.tabId));
      this.onRemoved(receipt.tabId);
      return { closed: true, proof: 'close_ack' };
    })();
    return receipt.closePromise;
  }
  async closeOwner(owner) {
    this.closedOwners.add(owner);
    const results = [];
    for (const record of this.records.values()) {
      if (record.owner !== owner) continue;
      if (!record.physical) {
        this.retire(record);
        continue;
      }
      record.ending = true;
      if (record.closeStarted) {
        results.push(
          record.closePromise.catch(async (error) => {
            if (record.attachedAck && !this.cleanupProven(record)) await this.detach(record);
            throw error;
          }),
        );
        continue;
      }
      if (!record.attachSettled) results.push(record.settlement);
      if (record.attachedAck && !this.cleanupProven(record)) results.push(this.detach(record));
    }
    for (const receipt of this.creations.values())
      if (receipt.owner === owner) results.push(this.closeCreation(receipt));
    const settled = await Promise.allSettled(results);
    const remaining = [...this.records.values()].filter((record) => record.owner === owner);
    const pendingAttachments = remaining.filter((record) => record.physical && !record.attachSettled).length;
    const unconfirmedClaims = remaining.filter((record) => !this.cleanupProven(record)).length;
    return {
      cleanupConfirmed:
        pendingAttachments === 0 &&
        unconfirmedClaims === 0 &&
        ![...this.creations.values()].some((receipt) => receipt.owner === owner && !receipt.closed),
      pendingAttachments,
      unconfirmedClaims,
      diagnostics: settled
        .filter((result) => result.status === 'rejected')
        .map((result) => String(result.reason)),
    };
  }
  async disconnect() {
    this.accepting = false;
    const owners = new Set(
      [...this.records.values(), ...this.creations.values()].map((record) => record.owner),
    );
    return Promise.allSettled([...owners].map((owner) => this.closeOwner(owner)));
  }
}
