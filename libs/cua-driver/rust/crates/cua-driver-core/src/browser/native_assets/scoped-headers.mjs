// Own narrow DNR adapter. Host resolves brand, templates, consent, session and turn policy.
// Session rules outlive a service-worker restart: initialize removes this extension's
// dedicated interval before accepting fresh scope state; it never adopts unknown claims.
export const HEADER_RULE_START = 2_000_000;
export const HEADER_RULE_END = 2_004_999;
const RESERVED = new Set([
  'authorization',
  'proxy-authorization',
  'cookie',
  'cookie2',
  'host',
  'connection',
  'content-length',
  'transfer-encoding',
  'upgrade',
  'te',
  'trailer',
  'origin',
  'referer',
  'accept-encoding',
]);
const TOKEN = /^[!#$%&'*+\-.^_`|~0-9a-z]+$/;
const FRAMES = ['main_frame', 'sub_frame', 'object'];
const own = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
export class ScopedHeaderError extends Error {
  constructor(kind, message, details) {
    super(message);
    this.kind = kind;
    this.details = details;
  }
}
const reject = (kind, message) => {
  throw new ScopedHeaderError(kind, message);
};
const nonempty = (value) => typeof value === 'string' && value.length > 0;
function snapshot(value) {
  const claim = value?.claim ?? value?.token;
  if (
    !nonempty(claim) ||
    !nonempty(value?.generation) ||
    !nonempty(value?.owner) ||
    !Number.isSafeInteger(value?.tabId) ||
    value.tabId < 0
  )
    reject('claim_unavailable', 'an exact authenticated physical claim is required');
  return Object.freeze({
    claim,
    generation: value.generation,
    owner: value.owner,
    tabId: value.tabId,
  });
}
const keyOf = (scope) => JSON.stringify([scope.generation, scope.owner, scope.claim]);
const sameScope = (a, b) =>
  a.claim === b.claim &&
  a.generation === b.generation &&
  a.owner === b.owner &&
  a.tabId === b.tabId;

/** Accepts fully expanded headers only. It neither expands templates nor chooses a label. */
export function validateExpandedHeaders(value) {
  if (!Array.isArray(value) || value.length > 16)
    reject('invalid_request', 'expanded headers must be an array of at most 16 items');
  const result = [];
  const names = new Set();
  let total = 0;
  for (const entry of value) {
    if (
      !entry ||
      typeof entry !== 'object' ||
      Array.isArray(entry) ||
      Object.keys(entry).length !== 2 ||
      !own(entry, 'name') ||
      !own(entry, 'value') ||
      typeof entry.name !== 'string' ||
      typeof entry.value !== 'string'
    )
      reject('invalid_request', 'each expanded header must contain only name and value strings');
    const name = entry.name.toLowerCase();
    if (
      !name ||
      name.length > 256 ||
      !TOKEN.test(name) ||
      name.startsWith('sec-') ||
      name.startsWith('proxy-') ||
      RESERVED.has(name) ||
      names.has(name)
    )
      reject('invalid_request', 'expanded header name is invalid, sensitive or duplicated');
    if (
      entry.value.length > 8192 ||
      /[^\x20-\x7e]/.test(entry.value) ||
      /[{}]/.test(entry.name + entry.value)
    )
      reject(
        'invalid_request',
        'expanded header value is not bounded printable ASCII or has unexpanded braces',
      );
    total += name.length + entry.value.length;
    if (total > 32768)
      reject('invalid_request', 'expanded headers exceed the total name/value budget');
    names.add(name);
    result.push(Object.freeze({ name, value: entry.value }));
  }
  return Object.freeze(result);
}

/** Internal trusted bridge API; never expose raw rule IDs or raw tab IDs as model input. */
export class ScopedHeaders {
  constructor(chrome, { resolveClaim, idStart = HEADER_RULE_START, idEnd = HEADER_RULE_END } = {}) {
    if (typeof resolveClaim !== 'function')
      reject('invalid_configuration', 'physical claim resolver is required');
    if (
      !Number.isSafeInteger(idStart) ||
      !Number.isSafeInteger(idEnd) ||
      idStart < 1 ||
      idEnd < idStart ||
      idEnd - idStart + 1 > 5000 ||
      (idEnd - idStart + 1) % 2
    )
      reject(
        'invalid_configuration',
        'dedicated header rule interval must contain at most 5000 complete pairs',
      );
    if (!nonempty(chrome?.runtime?.id))
      reject('invalid_configuration', 'actual extension identity is required');
    this.chrome = chrome;
    this.resolveClaim = resolveClaim;
    this.idStart = idStart;
    this.idEnd = idEnd;
    this.entries = new Map();
    this.blockedOwners = new Map();
    this.initialized = false;
    this.uncertain = true;
    this.queue = Promise.resolve();
  }
  enqueue(work) {
    const result = this.queue.then(work, work);
    this.queue = result.catch(() => {});
    return result;
  }
  requireReady() {
    if (!this.initialized)
      reject('headers_not_ready', 'startup scoped-rule cleanup has not been acknowledged');
  }
  /** Explicit fresh-worker cleanup; it removes only this extension's dedicated interval. */
  initialize() {
    return this.enqueue(async () => {
      if (this.initialized) return this.status();
      await this.synchronize();
      this.initialized = true;
      return this.status();
    });
  }
  setScopedHeaders(physicalClaim, sessionId, expandedHeaders) {
    if (!nonempty(sessionId)) reject('invalid_request', 'actual Host session ID is required');
    const scope = snapshot(this.resolveClaim(physicalClaim));
    const headers = expandedHeaders === null ? null : validateExpandedHeaders(expandedHeaders);
    return this.enqueue(async () => {
      this.requireReady();
      if (this.blockedOwners.has(scope.owner))
        reject('owner_closed', 'scoped-header owner is being cleaned');
      const current = snapshot(this.resolveClaim(physicalClaim));
      if (!sameScope(scope, current))
        reject('claim_unavailable', 'physical claim changed before scoped-header dispatch');
      const key = keyOf(scope);
      for (const [otherKey, entry] of this.entries) {
        if (otherKey !== key && entry.scope.tabId === scope.tabId)
          reject(
            'header_tab_busy',
            'another scope or unknown cleanup still owns headers on this tab',
          );
      }
      const entry = this.entries.get(key);
      if (entry && !sameScope(entry.scope, scope))
        reject('claim_unavailable', 'physical header scope changed');
      if (headers === null) {
        if (entry) entry.active = false;
      } else {
        // Desired policy commits before DNR. A failed API ACK never rolls it back.
        this.entries.set(key, { scope, sessionId, headers, active: true, confirmed: false });
      }
      await this.synchronize(() => {
        if (this.blockedOwners.has(scope.owner))
          reject('owner_closed', 'scoped-header owner ended before dispatch');
        if (!sameScope(scope, snapshot(this.resolveClaim(physicalClaim))))
          reject('claim_unavailable', 'physical claim changed at scoped-header dispatch');
      });
      return { scope, applied: true, stateConfirmed: true, ...this.statusForClaim(scope) };
    });
  }
  /** Cleanup uses the exact previously returned scope after physical revocation; no new claim is acquired. */
  clearClaim(headerScope) {
    const scope = snapshot(headerScope);
    return this.enqueue(async () => {
      this.requireReady();
      const entry = this.entries.get(keyOf(scope));
      if (entry && !sameScope(entry.scope, scope))
        reject('claim_unavailable', 'header cleanup scope changed');
      if (entry) entry.active = false;
      await this.synchronize();
      return { scope, ...this.statusForClaim(scope) };
    });
  }
  clearOwner(owner) {
    if (!nonempty(owner)) reject('invalid_request', 'authenticated owner is required');
    // Fence queued/in-flight set calls before the asynchronous cleanup reaches the queue.
    this.blockedOwners.set(owner, (this.blockedOwners.get(owner) ?? 0) + 1);
    const result = this.enqueue(async () => {
      this.requireReady();
      for (const entry of this.entries.values())
        if (entry.scope.owner === owner) entry.active = false;
      await this.synchronize();
      return this.statusForOwner(owner);
    });
    return result.finally(() => {
      const remaining = this.blockedOwners.get(owner) - 1;
      if (remaining) this.blockedOwners.set(owner, remaining);
      else this.blockedOwners.delete(owner);
    });
  }
  /** Host may request source-proven live-tab reconciliation; there is no new heartbeat daemon. */
  reconcile({ forceLive = false } = {}) {
    return this.enqueue(async () => {
      this.requireReady();
      const missing = [];
      if (forceLive) {
        let tabs;
        try {
          tabs = await this.chrome.tabs.query({});
        } catch (error) {
          throw this.unknown(error);
        }
        const live = new Set(
          tabs.filter((tab) => Number.isSafeInteger(tab.id) && tab.id >= 0).map((tab) => tab.id),
        );
        for (const entry of this.entries.values())
          if (!live.has(entry.scope.tabId)) {
            entry.active = false;
            missing.push(entry.scope);
          }
      }
      await this.synchronize();
      return { ...this.status(), physicallyMissingScopes: missing };
    });
  }
  status() {
    const entries = [...this.entries.values()];
    return {
      stateConfirmed:
        this.initialized && !this.uncertain && entries.every((entry) => entry.confirmed),
      cleanupConfirmed:
        this.initialized &&
        !this.uncertain &&
        entries.every((entry) => entry.confirmed && (!entry.active || entry.headers.length === 0)),
    };
  }
  statusForOwner(owner) {
    const entries = [...this.entries.values()].filter((entry) => entry.scope.owner === owner);
    return {
      cleanupConfirmed:
        this.initialized &&
        !this.uncertain &&
        entries.every((entry) => entry.confirmed && (!entry.active || entry.headers.length === 0)),
      stateConfirmed:
        this.initialized && !this.uncertain && entries.every((entry) => entry.confirmed),
      activeScopes: entries.filter((entry) => entry.active).length,
      pendingRemovalScopes: entries.filter((entry) => !entry.active).length,
    };
  }
  statusForClaim(headerScope) {
    const scope = snapshot(headerScope);
    const entry = this.entries.get(keyOf(scope));
    return {
      cleanupConfirmed:
        this.initialized &&
        !this.uncertain &&
        (!entry || (entry.confirmed && entry.headers.length === 0)),
      stateConfirmed: this.initialized && !this.uncertain && (!entry || entry.confirmed),
      active: entry?.active ?? false,
      pendingRemoval: entry ? !entry.active : false,
    };
  }
  rules() {
    const groups = new Map();
    for (const entry of this.entries.values()) {
      if (!entry.active || entry.headers.length === 0) continue;
      const key = JSON.stringify([entry.sessionId, entry.headers]);
      if (!groups.has(key)) groups.set(key, { headers: entry.headers, tabs: new Set() });
      groups.get(key).tabs.add(entry.scope.tabId);
    }
    const sorted = [...groups].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    if (sorted.length * 2 > this.idEnd - this.idStart + 1)
      reject('header_capacity', 'scoped-header groups exceed this dedicated rule interval');
    const rules = [];
    for (const [, group] of sorted) {
      const tabIds = [...group.tabs].sort((a, b) => a - b);
      const requestHeaders = group.headers.map((header) => ({
        header: header.name,
        operation: 'set',
        value: header.value,
      }));
      const action = { type: 'modifyHeaders', requestHeaders };
      rules.push({
        id: this.idStart + rules.length,
        priority: 1,
        action,
        condition: { tabIds, resourceTypes: [...FRAMES] },
      });
      rules.push({
        id: this.idStart + rules.length,
        priority: 1,
        action: {
          type: 'modifyHeaders',
          requestHeaders: requestHeaders.map((header) => ({ ...header })),
        },
        condition: {
          tabIds: [...tabIds],
          excludedResourceTypes: [...FRAMES],
          excludedInitiatorDomains: [this.chrome.runtime.id],
        },
      });
    }
    return rules;
  }
  unknown(error) {
    this.uncertain = true;
    for (const entry of this.entries.values()) entry.confirmed = false;
    return new ScopedHeaderError(
      'outcome_unknown',
      'scoped header update or cleanup was not acknowledged',
      { cause: error instanceof Error ? error.message : String(error) },
    );
  }
  async synchronize(beforeWrite) {
    try {
      const addRules = this.rules();
      const current = await this.chrome.declarativeNetRequest.getSessionRules();
      const removeRuleIds = current
        .filter(
          (rule) =>
            Number.isSafeInteger(rule.id) && rule.id >= this.idStart && rule.id <= this.idEnd,
        )
        .map((rule) => rule.id);
      if (beforeWrite) beforeWrite();
      if (removeRuleIds.length || addRules.length)
        await this.chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds, addRules });
      this.uncertain = false;
      for (const [key, entry] of this.entries) {
        if (!entry.active) this.entries.delete(key);
        else entry.confirmed = true;
      }
    } catch (error) {
      throw this.unknown(error);
    }
  }
}
