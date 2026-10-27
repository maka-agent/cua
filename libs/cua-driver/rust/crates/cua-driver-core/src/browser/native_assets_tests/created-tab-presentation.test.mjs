import test from 'node:test';
import assert from 'node:assert/strict';
import {
  CreatedTabPresentation,
  CreatedTabPresentationError,
  GROUP_COLORS,
} from '../native_assets/created-tab-presentation.mjs';
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((a, b) => {
    resolve = a;
    reject = b;
  });
  return { promise, resolve, reject };
};
const tick = () => new Promise((resolve) => setImmediate(resolve));
const event = () => {
  const handlers = [];
  return {
    addListener(fn) {
      handlers.push(fn);
    },
    fire(...args) {
      for (const fn of handlers) fn(...args);
    },
  };
};
function fixture() {
  const calls = [];
  const hooks = {};
  const scopes = new Map([
    ['created-1', { creation: 'created-1', owner: 'owner-a', generation: 'gen-1', tabId: 1 }],
    ['created-2', { creation: 'created-2', owner: 'owner-a', generation: 'gen-1', tabId: 2 }],
    ['created-3', { creation: 'created-3', owner: 'owner-b', generation: 'gen-1', tabId: 3 }],
  ]);
  const tabs = new Map(
    [1, 2, 3].map((id) => [
      id,
      { id, windowId: 7, active: false, groupId: -1, mutedInfo: { muted: false } },
    ]),
  );
  const groups = new Map();
  let nextGroup = 20,
    nextToken = 0;
  const chrome = {
    runtime: { id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' },
    tabs: {
      async get(id) {
        calls.push(['getTab', id]);
        if (hooks.getTab) await hooks.getTab(id);
        if (!tabs.has(id)) throw new Error('No tab');
        return { ...tabs.get(id) };
      },
      async update(id, value) {
        calls.push(['updateTab', id, value]);
        if (hooks.updateTab) await hooks.updateTab(id, value);
        if (!tabs.has(id)) throw new Error('No tab');
        const tab = tabs.get(id);
        if ('muted' in value)
          tab.mutedInfo = {
            muted: value.muted,
            reason: 'extension',
            extensionId: chrome.runtime.id,
          };
        return { ...tab };
      },
      async group(value) {
        calls.push(['group', value]);
        if (hooks.group) await hooks.group(value);
        const id = value.groupId ?? nextGroup++;
        if (!groups.has(id))
          groups.set(id, {
            id,
            windowId: value.createProperties.windowId,
            title: '',
            color: 'grey',
          });
        for (const tabId of value.tabIds) tabs.get(tabId).groupId = id;
        return id;
      },
      async ungroup(id) {
        calls.push(['ungroup', id]);
        if (hooks.ungroup) await hooks.ungroup(id);
        tabs.get(id).groupId = -1;
      },
    },
    tabGroups: {
      onRemoved: event(),
      async get(id) {
        calls.push(['getGroup', id]);
        if (hooks.getGroup) await hooks.getGroup(id);
        if (!groups.has(id)) throw new Error('No group');
        return { ...groups.get(id) };
      },
      async update(id, value) {
        calls.push(['updateGroup', id, value]);
        if (hooks.updateGroup) await hooks.updateGroup(id, value);
        if (!groups.has(id)) throw new Error('No group');
        Object.assign(groups.get(id), value);
        return { ...groups.get(id) };
      },
    },
  };
  const resolver = (receipt) => {
    const id = typeof receipt === 'string' ? receipt : receipt?.creation;
    const scope = scopes.get(id);
    if (!scope)
      throw new CreatedTabPresentationError('creation_unavailable', 'not current created receipt');
    return { ...scope };
  };
  const leaf = new CreatedTabPresentation(chrome, {
    resolveCreated: resolver,
    randomUUID: () => `group-token-${++nextToken}`,
  });
  return { calls, hooks, scopes, tabs, groups, chrome, leaf };
}
async function createGroup(f, receipt = 'created-1') {
  const result = await f.leaf.ensureCreatedTabGroup(receipt, { title: 'Maka', color: 'blue' });
  return result.group;
}

test('inactive unmuted created tab is muted without activating or focusing it', async () => {
  const f = fixture();
  assert.deepEqual(await f.leaf.muteCreatedIfInactive('created-1'), {
    attempted: true,
    mutationAcknowledged: true,
    changed: true,
  });
  assert.deepEqual(f.calls, [
    ['getTab', 1],
    ['updateTab', 1, { muted: true }],
  ]);
  assert.equal(f.tabs.get(1).active, false);
});
test('active or already-muted tabs are left unchanged', async () => {
  const f = fixture();
  f.tabs.get(1).active = true;
  assert.equal((await f.leaf.muteCreatedIfInactive('created-1')).attempted, false);
  f.tabs.get(1).active = false;
  f.tabs.get(1).mutedInfo = { muted: true, reason: 'user' };
  assert.equal((await f.leaf.muteCreatedIfInactive('created-1')).attempted, false);
  assert.equal(
    f.calls.some((call) => call[0] === 'updateTab'),
    false,
  );
});
test('Chrome mute failure is swallowed but never reported as acknowledged or unchanged', async () => {
  const f = fixture();
  f.hooks.updateTab = () => {
    throw new Error('update rejected');
  };
  const result = await f.leaf.muteCreatedIfInactive('created-1');
  assert.equal(result.mutationAcknowledged, false);
  assert.equal(result.changed, null);
  assert.match(result.diagnostic, /update rejected/);
  f.hooks.getTab = () => {
    throw new Error('read rejected');
  };
  const read = await f.leaf.muteCreatedIfInactive('created-2');
  assert.equal(read.attempted, false);
  assert.equal(read.mutationAcknowledged, false);
});
test('a released creation during a metadata read cannot dispatch mute', async () => {
  const f = fixture();
  const gate = deferred();
  f.hooks.getTab = () => gate.promise;
  const pending = f.leaf.muteCreatedIfInactive('created-1');
  await tick();
  f.scopes.delete('created-1');
  gate.resolve();
  await assert.rejects(pending, (error) => error.kind === 'creation_unavailable');
  assert.equal(
    f.calls.some((call) => call[0] === 'updateTab'),
    false,
  );
});
test('owner end after mute acknowledgement is unknown with effect facts', async () => {
  const f = fixture();
  f.hooks.updateTab = () => {
    f.scopes.delete('created-1');
  };
  await assert.rejects(
    f.leaf.muteCreatedIfInactive('created-1'),
    (error) =>
      error.kind === 'outcome_unknown' &&
      error.details.muted === true &&
      error.details.mutationAcknowledged === true,
  );
});
test('activation unmute is limited to actual own-extension mute and an active tab', async () => {
  const f = fixture();
  for (const info of [
    { muted: true, reason: 'user' },
    { muted: true, reason: 'capture' },
    { muted: true, reason: 'extension', extensionId: 'other' },
    { muted: false, reason: 'extension', extensionId: f.chrome.runtime.id },
  ]) {
    f.tabs.get(1).active = true;
    f.tabs.get(1).mutedInfo = info;
    assert.equal((await f.leaf.unmuteCreatedIfActiveAndOwnExtension('created-1')).attempted, false);
  }
  f.tabs.get(1).active = false;
  f.tabs.get(1).mutedInfo = { muted: true, reason: 'extension', extensionId: f.chrome.runtime.id };
  assert.equal((await f.leaf.unmuteCreatedIfActiveAndOwnExtension('created-1')).attempted, false);
  f.tabs.get(1).active = true;
  assert.equal(
    (await f.leaf.unmuteCreatedIfActiveAndOwnExtension('created-1')).mutationAcknowledged,
    true,
  );
  assert.deepEqual(
    f.calls.filter((call) => call[0] === 'updateTab'),
    [['updateTab', 1, { muted: false }]],
  );
});
test('group creation uses actual window, creates a physical capability and applies Host presentation', async () => {
  const f = fixture();
  const group = await createGroup(f);
  assert.deepEqual(f.calls.find((call) => call[0] === 'group')[1], {
    createProperties: { windowId: 7 },
    tabIds: [1],
  });
  assert.deepEqual(
    f.calls.find((call) => call[0] === 'updateGroup'),
    ['updateGroup', 20, { title: 'Maka', color: 'blue' }],
  );
  assert.deepEqual(group, {
    group: 'group-token-1',
    owner: 'owner-a',
    generation: 'gen-1',
    groupId: 20,
    windowId: 7,
  });
  assert.equal(Object.isFrozen(group), true);
});
test('existing owned managed group can collect another current created tab without a second group creation', async () => {
  const f = fixture();
  const group = await createGroup(f);
  const result = await f.leaf.ensureCreatedTabGroup('created-2', {
    existingGroup: group,
    title: ' Work ',
    color: 'green',
  });
  assert.equal(result.group.group, group.group);
  assert.deepEqual(
    f.calls.filter((call) => call[0] === 'group').map((call) => call[1]),
    [
      { createProperties: { windowId: 7 }, tabIds: [1] },
      { groupId: 20, tabIds: [2] },
    ],
  );
  assert.equal(f.groups.get(20).title, 'Work');
  assert.equal(f.tabs.get(2).groupId, 20);
});
test('a user raw tab ID, forged group, other owner or generation cannot mutate a group', async () => {
  const f = fixture();
  await assert.rejects(
    async () => f.leaf.muteCreatedIfInactive(1),
    (error) => error.kind === 'creation_unavailable',
  );
  const group = await createGroup(f);
  const before = f.calls.filter((call) => ['group', 'updateGroup'].includes(call[0])).length;
  await assert.rejects(
    async () => f.leaf.ensureCreatedTabGroup('created-3', { existingGroup: group }),
    (error) => error.kind === 'group_unavailable',
  );
  await assert.rejects(
    async () =>
      f.leaf.updateManagedGroup('created-1', { ...group, owner: 'owner-b' }, { title: 'bad' }),
    (error) => error.kind === 'group_unavailable',
  );
  f.scopes.get('created-1').generation = 'gen-2';
  await assert.rejects(
    async () => f.leaf.updateManagedGroup('created-1', group, { title: 'bad' }),
    (error) => error.kind === 'group_unavailable',
  );
  assert.equal(f.calls.filter((call) => ['group', 'updateGroup'].includes(call[0])).length, before);
});
test('managed group in a different window refuses instead of moving or mutating user windows', async () => {
  const f = fixture();
  const group = await createGroup(f);
  f.tabs.get(2).windowId = 8;
  const before = f.calls.filter((call) => call[0] === 'group').length;
  await assert.rejects(
    f.leaf.ensureCreatedTabGroup('created-2', { existingGroup: group }),
    (error) => error.kind === 'group_unavailable',
  );
  assert.equal(f.calls.filter((call) => call[0] === 'group').length, before);
});
test('group preparation failure after grouping ACK keeps exact managed-group custody', async () => {
  const f = fixture();
  f.hooks.updateGroup = () => {
    throw new Error('presentation denied');
  };
  let receipt;
  await assert.rejects(
    f.leaf.ensureCreatedTabGroup('created-1', { title: 'Maka', color: 'blue' }),
    (error) => {
      receipt = error.details.group;
      return error.kind === 'outcome_unknown' && error.details.groupingAcknowledged;
    },
  );
  assert.equal(receipt.groupId, 20);
  assert.equal(f.leaf.groups.size, 1);
  assert.equal(f.tabs.get(1).groupId, 20);
  f.hooks.updateGroup = null;
  await f.leaf.ensureCreatedTabGroup('created-1', { title: 'Maka', color: 'blue' });
  assert.equal(f.calls.filter((call) => call[0] === 'group').length, 1);
});
test('owner end after group ACK prevents presentation and retains known group receipt', async () => {
  const f = fixture();
  const original = f.chrome.tabs.group;
  f.chrome.tabs.group = async (value) => {
    const id = await original(value);
    f.scopes.delete('created-1');
    return id;
  };
  await assert.rejects(
    f.leaf.ensureCreatedTabGroup('created-1', { title: 'Maka' }),
    (error) => error.kind === 'outcome_unknown' && error.details.group.groupId === 20,
  );
  assert.equal(f.calls.filter((call) => call[0] === 'updateGroup').length, 0);
  assert.equal(f.leaf.groups.size, 1);
});
test('only documented presentation fields/colors are accepted; no focus or collapsed mutation is invented', async () => {
  const f = fixture();
  for (const options of [
    { title: 'Maka', color: 'not-a-color' },
    { title: '  ' },
    { title: 'Maka', collapsed: true },
    { title: 'Maka', groupId: 123 },
  ])
    await assert.rejects(
      async () => f.leaf.ensureCreatedTabGroup('created-1', options),
      (error) => error.kind === 'invalid_request',
    );
  assert.equal(f.calls.length, 0);
  assert.deepEqual(GROUP_COLORS, [
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
});
test('release removes only its created tab from the exact own managed group', async () => {
  const f = fixture();
  const group = await createGroup(f);
  await f.leaf.ensureCreatedTabGroup('created-2', { existingGroup: group });
  assert.deepEqual(await f.leaf.releaseCreatedTabGroup('created-1', group), {
    released: true,
    proof: 'ungroup_ack',
  });
  assert.equal(f.tabs.get(1).groupId, -1);
  assert.equal(f.tabs.get(2).groupId, 20);
  assert.deepEqual(
    f.calls.filter((call) => call[0] === 'ungroup'),
    [['ungroup', 1]],
  );
});
test('release does not ungroup a tab that a user moved elsewhere', async () => {
  const f = fixture();
  const group = await createGroup(f);
  f.tabs.get(1).groupId = 99;
  assert.equal(
    (await f.leaf.releaseCreatedTabGroup('created-1', group)).proof,
    'already_not_member',
  );
  assert.equal(
    f.calls.some((call) => call[0] === 'ungroup'),
    false,
  );
});
test('group removal invalidates capability without adopting a later ambient group ID', async () => {
  const f = fixture();
  const group = await createGroup(f);
  f.chrome.tabGroups.onRemoved.fire({ id: 20 });
  f.groups.delete(20);
  await assert.rejects(
    async () => f.leaf.updateManagedGroup('created-1', group, { title: 'wrong' }),
    (error) => error.kind === 'group_unavailable',
  );
  assert.equal(f.leaf.groups.size, 0);
});
test('concurrent ensures for one creation serialize and never create two physical groups', async () => {
  const f = fixture();
  const gate = deferred();
  f.hooks.group = () => gate.promise;
  const first = f.leaf.ensureCreatedTabGroup('created-1', { title: 'Maka' });
  const second = f.leaf.ensureCreatedTabGroup('created-1', { title: 'Maka' });
  await tick();
  assert.equal(f.calls.filter((call) => call[0] === 'group').length, 1);
  gate.resolve();
  const [a, b] = await Promise.all([first, second]);
  assert.equal(a.group.group, b.group.group);
  assert.equal(f.calls.filter((call) => call[0] === 'group').length, 1);
  await tick();
  assert.equal(f.leaf.tabQueues.size, 0);
});
test('malformed existing-group markers refuse before creating an unexpected new group', async () => {
  const f = fixture();
  for (const existingGroup of [false, 0, '', [], 42])
    await assert.rejects(
      async () => f.leaf.ensureCreatedTabGroup('created-1', { existingGroup }),
      (error) => error.kind === 'invalid_request',
    );
  assert.equal(f.calls.length, 0);
});
test('existing-group read rejection before mutation stays a known Chrome rejection', async () => {
  const f = fixture();
  const group = await createGroup(f);
  const before = f.calls.filter((call) => call[0] === 'group').length;
  f.hooks.getGroup = () => {
    throw new Error('read denied');
  };
  await assert.rejects(
    f.leaf.ensureCreatedTabGroup('created-2', { existingGroup: group }),
    (error) => error.kind === 'chrome_rejected',
  );
  assert.equal(f.calls.filter((call) => call[0] === 'group').length, before);
});
test('owner end while reading an already-member group is a local refusal before any mutation', async () => {
  const f = fixture();
  await createGroup(f);
  const before = f.calls.filter((call) => ['group', 'updateGroup'].includes(call[0])).length;
  f.hooks.getGroup = () => {
    f.scopes.delete('created-1');
  };
  await assert.rejects(
    f.leaf.ensureCreatedTabGroup('created-1', { title: 'new' }),
    (error) => error.kind === 'creation_unavailable',
  );
  assert.equal(f.calls.filter((call) => ['group', 'updateGroup'].includes(call[0])).length, before);
});
test('presentation rejection for an existing member has no invented grouping ACK', async () => {
  const f = fixture();
  await createGroup(f);
  const before = f.calls.filter((call) => call[0] === 'group').length;
  f.hooks.updateGroup = () => {
    throw new Error('update rejected');
  };
  await assert.rejects(
    f.leaf.ensureCreatedTabGroup('created-1', { title: 'new' }),
    (error) => error.kind === 'chrome_rejected',
  );
  assert.equal(f.calls.filter((call) => call[0] === 'group').length, before);
});
test('group removal during a metadata await fences grouping and ungrouping before dispatch', async () => {
  const f = fixture();
  const group = await createGroup(f);
  const before = f.calls.filter((call) => call[0] === 'group').length;
  f.hooks.getGroup = () => {
    f.chrome.tabGroups.onRemoved.fire({ id: 20 });
  };
  await assert.rejects(
    f.leaf.ensureCreatedTabGroup('created-2', { existingGroup: group }),
    (error) => error.kind === 'group_unavailable',
  );
  assert.equal(f.calls.filter((call) => call[0] === 'group').length, before);
  const g = fixture();
  const ownGroup = await createGroup(g);
  g.hooks.getGroup = () => {
    g.chrome.tabGroups.onRemoved.fire({ id: 20 });
  };
  await assert.rejects(
    g.leaf.releaseCreatedTabGroup('created-1', ownGroup),
    (error) => error.kind === 'group_unavailable',
  );
  assert.equal(
    g.calls.some((call) => call[0] === 'ungroup'),
    false,
  );
});
