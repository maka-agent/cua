import test from 'node:test';
import assert from 'node:assert/strict';
import { TabPreparation } from '../native_assets/tab-preparation.mjs';
function fixture(tab, { family = 'chrome' } = {}) {
  const calls = [];
  let current = { id: 1, ...tab };
  let admitted = true;
  let time = 0;
  const api = {
    tabs: {
      async get(id) {
        calls.push(['get', id]);
        return { ...current };
      },
      async update(id, params) {
        calls.push(['update', id, params]);
        current = { ...current, ...params, pendingUrl: undefined };
        return { ...current };
      },
    },
  };
  const prep = new TabPreparation(api, {
    family,
    assertAdmission() {
      if (!admitted) throw new Error('not admitted');
    },
    now: () => time,
    sleep: async (ms) => {
      time += ms;
    },
  });
  return {
    api,
    calls,
    prep,
    end() {
      admitted = false;
    },
    set(tab) {
      current = { id: 1, ...tab };
    },
    advance() {
      time += 5000;
    },
  };
}
test('exact Chrome new-tab aliases normalize only fixed about:blank without active/focus flags', async () => {
  for (const url of [
    'chrome://newtab/',
    'chrome://new-tab-page/',
    'chrome://new-tab-page-third-party/',
  ]) {
    const f = fixture({ url });
    const r = await f.prep.prepare('owner', 1);
    assert.equal(r.normalized, true);
    assert.equal(r.tab.url, 'about:blank');
    assert.deepEqual(
      f.calls.find((c) => c[0] === 'update'),
      ['update', 1, { url: 'about:blank' }],
    );
  }
});
test('nonexact aliases and pending browser internal URL are refused without navigation', async () => {
  for (const tab of [
    { url: 'chrome://newtab' },
    { url: 'chrome://newtab/?x=1' },
    { url: 'https://example.test/', pendingUrl: 'chrome://settings/' },
  ]) {
    const f = fixture(tab);
    await assert.rejects(
      f.prep.prepare('owner', 1),
      (error) => error.kind === 'internal_tab_refused',
    );
    assert.equal(
      f.calls.some((c) => c[0] === 'update'),
      false,
    );
  }
});
test('known family schemes remain explicit, not a universal URL classifier', async () => {
  const f = fixture({ url: 'brave://newtab/' }, { family: 'brave' });
  assert.equal((await f.prep.prepare('owner', 1)).tab.url, 'about:blank');
  const g = fixture({ url: 'about:blank' });
  assert.equal((await g.prep.prepare('owner', 1)).normalized, false);
});
test('admission refusal prevents all Chrome calls and no numeric public grammar is introduced', async () => {
  const f = fixture({ url: 'chrome://newtab/' });
  f.end();
  await assert.rejects(f.prep.prepare('owner', 1), /not admitted/);
  assert.equal(f.calls.length, 0);
  for (const id of ['1', -1, 1.5, Number.MAX_SAFE_INTEGER + 1])
    await assert.rejects(f.prep.prepare('owner', id), (error) => error.kind === 'invalid_request');
});
test('normalization ACK followed by owner loss retains unknown causal tab identity', async () => {
  const f = fixture({ url: 'chrome://newtab/' });
  f.api.tabs.update = async () => {
    f.end();
    return { id: 1, url: 'about:blank' };
  };
  await assert.rejects(
    f.prep.prepare('owner', 1),
    (error) => error.kind === 'outcome_unknown' && error.details.tabId === 1,
  );
});
test('normalization timeout is unknown and never replays tabs.update', async () => {
  const f = fixture({ url: 'chrome://newtab/' });
  let updates = 0;
  f.api.tabs.update = async () => {
    updates++;
    f.advance();
    return { id: 1, url: 'https://not-blank.test/' };
  };
  f.api.tabs.get = async () => {
    f.advance();
    return { id: 1, url: updates ? 'https://not-blank.test/' : 'chrome://newtab/' };
  };
  await assert.rejects(f.prep.prepare('owner', 1), (error) => error.kind === 'outcome_unknown');
  assert.equal(updates, 1);
});
test('mismatched initial Chrome identity cannot cause normalization or successful metadata', async () => {
  const f = fixture({ url: 'chrome://newtab/' });
  f.api.tabs.get = async () => ({ id: 2, url: 'chrome://newtab/' });
  await assert.rejects(f.prep.prepare('owner', 1), (error) => error.kind === 'target_unavailable');
  assert.equal(
    f.calls.some((c) => c[0] === 'update'),
    false,
  );
});
test('async admission cannot run Chrome work before a later denial', async () => {
  let calls = 0;
  const prep = new TabPreparation(
    {
      tabs: {
        async get() {
          calls++;
          return { id: 1, url: 'about:blank' };
        },
      },
    },
    {
      assertAdmission: async () => {
        throw Error('denied');
      },
    },
  );
  await assert.rejects(prep.prepare('owner', 1), (error) => error.kind === 'invalid_configuration');
  assert.equal(calls, 0);
});
test('normalization ACK with nonblank URL triggers an immediate exact read before timed polling', async () => {
  const f = fixture({ url: 'chrome://newtab/' });
  let reads = 0;
  f.api.tabs.get = async () => ({ id: 1, url: ++reads === 1 ? 'chrome://newtab/' : 'about:blank' });
  f.api.tabs.update = async () => ({ id: 1, url: 'https://waiting.test/' });
  assert.equal((await f.prep.prepare('owner', 1)).tab.url, 'about:blank');
  assert.equal(reads, 2);
});
