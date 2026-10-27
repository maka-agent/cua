// Own Chrome tab presentation primitives. Host owns session/turn/group selection policy.
export const GROUP_COLORS = Object.freeze([
  'grey',
  'blue',
  'red',
  'yellow',
  'green',
  'pink',
  'purple',
  'cyan',
  'orange',
]);
export class CreatedTabPresentationError extends Error {
  constructor(kind, message, details) {
    super(message);
    this.kind = kind;
    this.details = details;
  }
}
const fail = (kind, message, details) => {
  throw new CreatedTabPresentationError(kind, message, details);
};
const nonempty = (value) => typeof value === 'string' && value.length > 0;
const own = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
function createdScope(value) {
  const creation = value?.creation ?? value?.token;
  if (
    !nonempty(creation) ||
    !nonempty(value?.owner) ||
    !nonempty(value?.generation) ||
    !Number.isSafeInteger(value?.tabId) ||
    value.tabId < 0
  )
    fail('creation_unavailable', 'a live causal created-tab receipt is required');
  return Object.freeze({
    creation,
    owner: value.owner,
    generation: value.generation,
    tabId: value.tabId,
  });
}
const sameScope = (a, b) =>
  a.creation === b.creation &&
  a.owner === b.owner &&
  a.generation === b.generation &&
  a.tabId === b.tabId;
async function chromeCall(call) {
  try {
    return await call();
  } catch (error) {
    throw new CreatedTabPresentationError(
      'chrome_rejected',
      error instanceof Error ? error.message : String(error),
    );
  }
}
function presentation(value = {}) {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.keys(value).some((key) => key !== 'title' && key !== 'color')
  )
    fail('invalid_request', 'group presentation accepts only Host-resolved title and color');
  const result = {};
  if (own(value, 'title')) {
    if (typeof value.title !== 'string' || !value.title.trim())
      fail('invalid_request', 'Host-resolved group title must be a nonempty string');
    result.title = value.title.trim();
  }
  if (own(value, 'color')) {
    if (!GROUP_COLORS.includes(value.color))
      fail('invalid_request', 'group color must be a native Chrome color');
    result.color = value.color;
  }
  return result;
}

/** resolveCreated must reject plain UserClaim receipts and ended/wrong owner/generation. */
export class CreatedTabPresentation {
  constructor(chrome, { resolveCreated, randomUUID = () => crypto.randomUUID() } = {}) {
    if (typeof resolveCreated !== 'function' || !nonempty(chrome?.runtime?.id))
      fail(
        'invalid_configuration',
        'actual extension identity and created-tab receipt resolver are required',
      );
    this.chrome = chrome;
    this.resolveCreated = resolveCreated;
    this.randomUUID = randomUUID;
    this.groups = new Map();
    this.tabQueues = new Map();
    chrome.tabGroups?.onRemoved?.addListener((group) => {
      for (const [token, record] of this.groups)
        if (record.groupId === group.id) this.groups.delete(token);
    });
  }
  current(receipt, expected) {
    const actual = createdScope(this.resolveCreated(receipt));
    if (expected && !sameScope(actual, expected))
      fail('creation_unavailable', 'created-tab physical scope changed');
    return actual;
  }
  serializeTab(scope, work) {
    const key = JSON.stringify([scope.generation, scope.owner, scope.creation]);
    const previous = this.tabQueues.get(key) ?? Promise.resolve();
    const result = previous.then(work, work);
    this.tabQueues.set(key, result);
    void result
      .finally(() => {
        if (this.tabQueues.get(key) === result) this.tabQueues.delete(key);
      })
      .catch(() => {});
    return result;
  }
  async tab(scope) {
    const tab = await chromeCall(() => this.chrome.tabs.get(scope.tabId));
    if (!tab || tab.id !== scope.tabId)
      fail('tab_unavailable', 'Chrome did not return the exact created tab');
    return tab;
  }
  requireAfterAck(receipt, scope, details) {
    try {
      this.current(receipt, scope);
    } catch (error) {
      throw new CreatedTabPresentationError(
        'outcome_unknown',
        'created-tab scope ended after a presentation effect was acknowledged',
        { ...details, cause: error instanceof Error ? error.message : String(error) },
      );
    }
  }
  async muteCreatedIfInactive(receipt) {
    const scope = this.current(receipt);
    let tab;
    try {
      tab = await this.tab(scope);
    } catch (error) {
      if (error.kind !== 'chrome_rejected') throw error;
      return {
        attempted: false,
        mutationAcknowledged: false,
        changed: false,
        diagnostic: error.message,
      };
    }
    if (tab.active !== false || tab.mutedInfo?.muted === true)
      return {
        attempted: false,
        mutationAcknowledged: false,
        changed: false,
        reason: tab.active !== false ? 'not_inactive' : 'already_muted',
      };
    this.current(receipt, scope);
    try {
      await chromeCall(() => this.chrome.tabs.update(scope.tabId, { muted: true }));
    } catch (error) {
      return {
        attempted: true,
        mutationAcknowledged: false,
        changed: null,
        diagnostic: error.message,
      };
    }
    this.requireAfterAck(receipt, scope, {
      tabId: scope.tabId,
      muted: true,
      mutationAcknowledged: true,
    });
    return { attempted: true, mutationAcknowledged: true, changed: true };
  }
  /** Host calls this for a real tabs.onActivated event after resolving its current creation. */
  async unmuteCreatedIfActiveAndOwnExtension(receipt) {
    const scope = this.current(receipt);
    let tab;
    try {
      tab = await this.tab(scope);
    } catch (error) {
      if (error.kind !== 'chrome_rejected') throw error;
      return {
        attempted: false,
        mutationAcknowledged: false,
        changed: false,
        diagnostic: error.message,
      };
    }
    if (
      tab.active !== true ||
      tab.mutedInfo?.muted !== true ||
      tab.mutedInfo.reason !== 'extension' ||
      tab.mutedInfo.extensionId !== this.chrome.runtime.id
    )
      return {
        attempted: false,
        mutationAcknowledged: false,
        changed: false,
        reason: 'not_active_own_extension_mute',
      };
    this.current(receipt, scope);
    try {
      await chromeCall(() => this.chrome.tabs.update(scope.tabId, { muted: false }));
    } catch (error) {
      return {
        attempted: true,
        mutationAcknowledged: false,
        changed: null,
        diagnostic: error.message,
      };
    }
    this.requireAfterAck(receipt, scope, {
      tabId: scope.tabId,
      muted: false,
      mutationAcknowledged: true,
    });
    return { attempted: true, mutationAcknowledged: true, changed: true };
  }
  groupReceipt(record) {
    return Object.freeze({
      group: record.token,
      owner: record.owner,
      generation: record.generation,
      groupId: record.groupId,
      windowId: record.windowId,
    });
  }
  groupRecord(receipt, scope) {
    const record = this.groups.get(receipt?.group);
    if (
      !record ||
      record.owner !== scope.owner ||
      record.generation !== scope.generation ||
      receipt.owner !== record.owner ||
      receipt.generation !== record.generation ||
      receipt.groupId !== record.groupId ||
      receipt.windowId !== record.windowId
    )
      fail('group_unavailable', 'group receipt does not belong to this owner and generation');
    return record;
  }
  currentGroup(record) {
    if (this.groups.get(record.token) !== record)
      fail('group_unavailable', 'managed group was removed');
  }
  async provenGroup(record, tab) {
    const group = await chromeCall(() => this.chrome.tabGroups.get(record.groupId));
    if (!group || group.id !== record.groupId || group.windowId !== tab.windowId)
      fail('group_unavailable', 'managed group is not in the current created-tab window');
    return group;
  }
  ensureCreatedTabGroup(receipt, options = {}) {
    const scope = this.current(receipt);
    if (
      !options ||
      typeof options !== 'object' ||
      Array.isArray(options) ||
      Object.keys(options).some((key) => !['existingGroup', 'title', 'color'].includes(key))
    )
      fail(
        'invalid_request',
        'group creation accepts only an owned existing group and Host presentation',
      );
    if (
      own(options, 'existingGroup') &&
      options.existingGroup !== null &&
      (!options.existingGroup ||
        typeof options.existingGroup !== 'object' ||
        Array.isArray(options.existingGroup))
    )
      fail('invalid_request', 'existingGroup must be an owned group receipt or null');
    const update = presentation(
      Object.fromEntries(Object.entries(options).filter(([key]) => key !== 'existingGroup')),
    );
    return this.serializeTab(scope, async () => {
      this.current(receipt, scope);
      const tab = await this.tab(scope);
      if (!Number.isSafeInteger(tab.windowId) || tab.windowId < 0)
        fail('tab_unavailable', 'created tab has no actual window identity');
      let record;
      if (options.existingGroup) record = this.groupRecord(options.existingGroup, scope);
      else
        record = [...this.groups.values()].find(
          (candidate) =>
            candidate.owner === scope.owner &&
            candidate.generation === scope.generation &&
            candidate.groupId === tab.groupId,
        );
      let groupingAcknowledged = false;
      try {
        if (record) {
          await this.provenGroup(record, tab);
          if (tab.groupId !== record.groupId) {
            this.current(receipt, scope);
            this.currentGroup(record);
            const id = await chromeCall(() =>
              this.chrome.tabs.group({ groupId: record.groupId, tabIds: [scope.tabId] }),
            );
            groupingAcknowledged = true;
            if (id !== record.groupId)
              fail('outcome_unknown', 'Chrome acknowledged a different group ID', {
                observedGroupId: id,
              });
          }
        } else {
          this.current(receipt, scope);
          const id = await chromeCall(() =>
            this.chrome.tabs.group({
              createProperties: { windowId: tab.windowId },
              tabIds: [scope.tabId],
            }),
          );
          groupingAcknowledged = true;
          if (!Number.isSafeInteger(id) || id < 0)
            fail('outcome_unknown', 'Chrome acknowledged grouping without an exact group ID');
          record = {
            token: this.randomUUID(),
            owner: scope.owner,
            generation: scope.generation,
            groupId: id,
            windowId: tab.windowId,
          };
          this.groups.set(record.token, record);
        }
        if (groupingAcknowledged)
          this.requireAfterAck(receipt, scope, {
            groupingAcknowledged,
            group: this.groupReceipt(record),
          });
        else this.current(receipt, scope);
        const actualTab = await this.tab(scope);
        if (actualTab.groupId !== record.groupId)
          fail(
            groupingAcknowledged ? 'outcome_unknown' : 'group_unavailable',
            'created tab is no longer in the selected managed group',
          );
        await this.provenGroup(record, actualTab);
        this.currentGroup(record);
        if (Object.keys(update).length) await this.updateGroup(receipt, scope, record, update);
        return { group: this.groupReceipt(record), groupingAcknowledged };
      } catch (error) {
        if (groupingAcknowledged || error.kind === 'outcome_unknown') {
          throw new CreatedTabPresentationError(
            'outcome_unknown',
            'managed-group preparation did not complete',
            {
              groupingAcknowledged,
              ...(record ? { group: this.groupReceipt(record) } : {}),
              cause: error.message,
            },
          );
        }
        throw error;
      }
    });
  }
  async updateGroup(receipt, scope, record, update) {
    this.current(receipt, scope);
    this.currentGroup(record);
    if (!Object.keys(update).length)
      return { group: this.groupReceipt(record), presentationAcknowledged: false };
    const result = await chromeCall(() => this.chrome.tabGroups.update(record.groupId, update));
    this.requireAfterAck(receipt, scope, {
      group: this.groupReceipt(record),
      presentationAcknowledged: true,
    });
    if (result && result.id !== record.groupId)
      fail('outcome_unknown', 'Chrome returned a different updated group');
    return { group: this.groupReceipt(record), presentationAcknowledged: true };
  }
  updateManagedGroup(receipt, group, value) {
    const scope = this.current(receipt);
    const record = this.groupRecord(group, scope);
    const update = presentation(value);
    return this.serializeTab(scope, async () => {
      const tab = await this.tab(scope);
      if (tab.groupId !== record.groupId)
        fail('group_unavailable', 'created tab does not belong to this managed group');
      await this.provenGroup(record, tab);
      return this.updateGroup(receipt, scope, record, update);
    });
  }
  releaseCreatedTabGroup(receipt, group) {
    const scope = this.current(receipt);
    const record = this.groupRecord(group, scope);
    return this.serializeTab(scope, async () => {
      const tab = await this.tab(scope);
      if (tab.groupId !== record.groupId) return { released: true, proof: 'already_not_member' };
      await this.provenGroup(record, tab);
      this.current(receipt, scope);
      this.currentGroup(record);
      await chromeCall(() => this.chrome.tabs.ungroup(scope.tabId));
      this.requireAfterAck(receipt, scope, {
        group: this.groupReceipt(record),
        releaseAcknowledged: true,
      });
      return { released: true, proof: 'ungroup_ack' };
    });
  }
}
