import assert from 'node:assert/strict';
import test from 'node:test';
import { userHistory } from '../extension_assets/user-history.mjs';

test('history joins per-query results, keeps newest URL, sorts then applies one global limit', async () => {
  const calls = [];
  const chrome = { history: { async search(query) {
    calls.push(query);
    return query.text === 'one'
      ? [{ url: 'https://same.test', title: 'old', lastVisitTime: 1000 },
          { url: 'https://second.test', lastVisitTime: 3000 }, { url: null, lastVisitTime: 5000 }]
      : [{ url: 'https://same.test', title: 'new', lastVisitTime: 4000 },
          { url: 'https://third.test', lastVisitTime: 2000 }, { url: 'bad', lastVisitTime: NaN }];
  } } };
  const rows = await userHistory(chrome, { queries: ['one', 'two'], limit: 2,
    from: '1970-01-01T00:00:00.000Z', to: '1970-01-02T00:00:00.000Z' });
  assert.deepEqual(rows.map((row) => row.url), ['https://same.test', 'https://second.test']);
  assert.equal(rows[0].title, 'new');
  assert.equal(rows[0].dateVisited, '1970-01-01T00:00:04.000Z');
  assert.deepEqual(calls, [
    { text: 'one', maxResults: 2, startTime: 0, endTime: 86400000 },
    { text: 'two', maxResults: 2, startTime: 0, endTime: 86400000 },
  ]);
});

test('defaults query whole history with limit 100; invalid filters never call Chrome', async () => {
  const calls = [];
  const chrome = { history: { async search(query) { calls.push(query); return []; } } };
  await userHistory(chrome);
  assert.deepEqual(calls, [{ text: '', maxResults: 100, startTime: 0 }]);
  calls.length = 0;
  await assert.rejects(userHistory(chrome, { queries: [] }), /non-empty array of strings/);
  await assert.rejects(userHistory(chrome, { limit: 0 }), /positive integer/);
  await assert.rejects(userHistory(chrome, { from: 'bad' }), /valid date/);
  assert.equal(calls.length, 0);
  await assert.rejects(userHistory({}, {}), /history permission is unavailable/);
});
