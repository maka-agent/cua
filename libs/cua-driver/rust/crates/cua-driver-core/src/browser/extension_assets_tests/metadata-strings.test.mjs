// SPDX-License-Identifier: MIT
import assert from 'node:assert/strict';
import test from 'node:test';
import { BrowserConnector } from '../extension_assets/connector.mjs';

function connector(tabs, groupTitle) {
  const noEvent = { addListener() {} };
  return new BrowserConnector({
    tabs: { query: async () => tabs, onRemoved: noEvent },
    tabGroups: { get: async () => ({ title: groupTitle }) },
    debugger: { onEvent: noEvent, onDetach: noEvent },
  }, { randomUUID: () => 'fixture-instance' });
}

test('real connector metadata preserves isolated title/group code units before the native JSON boundary', async () => {
  const title = '\ud800 title \udc00 \\ud800 😀';
  const group = '\udc00 group';
  const actual = connector([{ id: 17, title, groupId: 3, url: 'https://fixture.test/' }], group);
  const row = JSON.parse(JSON.stringify((await actual.inventory())[0]));
  assert.equal(row.titleJson.isWellFormed(), true);
  assert.equal(row.groupTitleJson.isWellFormed(), true);
  assert.equal(JSON.parse(row.titleJson), title);
  assert.equal(JSON.parse(row.groupTitleJson), group);
  assert.equal(Object.hasOwn(row, 'title'), false);
  assert.equal(Object.hasOwn(row, 'groupTitle'), false);
  assert.equal(row.id, 17);
  assert.equal(row.url, 'https://fixture.test/');
});

test('metadata preserves missing/empty and quoted legacy-looking title contents without a guess', async () => {
  const actual = connector([{ id: 1 }, { id: 2, title: '' }, { id: 3, title: '"quoted"' }]);
  const rows = await actual.inventory();
  assert.equal(Object.hasOwn(rows[0], 'titleJson'), false);
  assert.equal(rows[1].titleJson, '""');
  assert.equal(JSON.parse(rows[2].titleJson), '"quoted"');
});
