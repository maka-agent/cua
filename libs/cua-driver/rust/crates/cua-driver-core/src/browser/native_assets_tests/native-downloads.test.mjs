import assert from 'node:assert/strict';
import { setImmediate } from 'node:timers/promises';
import test from 'node:test';
import { NativeDownloads } from '../native_assets/native-downloads.mjs';

function event() {
  const listeners = new Set();
  return {
    addListener(listener) {
      listeners.add(listener);
    },
    removeListener(listener) {
      listeners.delete(listener);
    },
    fire(payload) {
      for (const listener of [...listeners]) listener(payload);
    },
    snapshot() {
      return [...listeners];
    },
  };
}
function fixture(emitOverride) {
  const chrome = { downloads: { onCreated: event(), onChanged: event() } };
  let active = false;
  const emitted = [];
  const observer = new NativeDownloads(chrome, {
    emit: emitOverride ?? ((value) => emitted.push(value)),
    hasActiveControl: () => active,
  });
  return {
    observer,
    chrome,
    emitted,
    active(value) {
      active = value;
    },
    created(value) {
      chrome.downloads.onCreated.fire(value);
    },
    changed(value) {
      chrome.downloads.onChanged.fire(value);
    },
  };
}

test('starts only during actual control and preserves native zero ID, empty filename and final URL', () => {
  const f = fixture();
  f.created({ id: 7, filename: '/unobserved', finalUrl: 'https://final/old' });
  f.active(true);
  f.changed({ id: 7, filename: { current: '/guessed' }, state: { current: 'complete' } });
  f.created({
    id: 0,
    filename: '',
    url: 'https://initial/redirect',
    finalUrl: 'https://final/download',
    tabId: 34,
    bytesReceived: 123,
    totalBytes: 456,
  });
  assert.deepEqual(f.emitted, [
    { id: '0', filename: '', url: 'https://final/download', status: 'started' },
  ]);
});

test('ignores malformed native IDs and metadata without substituting URL or filename', () => {
  const f = fixture();
  f.active(true);
  for (const id of [-1, 1.5, NaN, Infinity, '1', null])
    f.created({ id, filename: '/file', finalUrl: 'https://final/file' });
  f.created({ id: 1, filename: null, finalUrl: 'https://final/file' });
  f.created({ id: 2, filename: '/file', url: 'https://initial/file' });
  f.created({ id: 3, filename: '/actual', finalUrl: '' });
  for (const id of [-1, 1.5, NaN, Infinity, '3', null])
    f.changed({ id, state: { current: 'complete' } });
  f.changed({ id: 3, state: { current: 'complete' } });
  assert.deepEqual(f.emitted, [
    { id: '3', filename: '/actual', url: '', status: 'started' },
    { id: '3', filename: '/actual', url: '', status: 'complete' },
  ]);
});

test('updates filename from actual delta even without a state and preserves empty strings', () => {
  const f = fixture();
  f.active(true);
  f.created({ id: 11, filename: '/partial', finalUrl: 'https://final/file' });
  f.changed({ id: 11, filename: { current: '' } });
  f.changed({
    id: 11,
    filename: { current: null },
    finalUrl: { current: 'https://untrusted/replacement' },
    state: { current: 'in_progress' },
  });
  f.changed({ id: 11, filename: { current: '/actual/final' }, state: { current: 'complete' } });
  assert.deepEqual(f.emitted, [
    { id: '11', filename: '/partial', url: 'https://final/file', status: 'started' },
    { id: '11', filename: '', url: 'https://final/file', status: 'in_progress' },
    { id: '11', filename: '/actual/final', url: 'https://final/file', status: 'complete' },
  ]);
});

test('maps native state and error exactly without inventing cancellation', () => {
  const f = fixture();
  f.active(true);
  f.created({ id: 12, filename: '/file', finalUrl: 'https://final/file' });
  f.changed({ id: 12, error: { current: 'USER_CANCELED' } });
  f.changed({ id: 12, state: { current: 'unknown' }, error: { current: 'USER_CANCELED' } });
  f.changed({ id: 12, state: { current: 'interrupted' }, error: { current: 'USER_CANCELED' } });
  f.changed({ id: 12, state: { current: 'interrupted' }, error: { current: 'NETWORK_FAILED' } });
  f.changed({ id: 12, state: { current: 'interrupted' } });
  f.changed({ id: 12, state: { current: 'in_progress' }, error: { current: 'USER_CANCELED' } });
  assert.deepEqual(f.emitted, [
    { id: '12', filename: '/file', url: 'https://final/file', status: 'started' },
    { id: '12', filename: '/file', url: 'https://final/file', status: 'canceled' },
    { id: '12', filename: '/file', url: 'https://final/file', status: 'failed' },
    { id: '12', filename: '/file', url: 'https://final/file', status: 'failed' },
    { id: '12', filename: '/file', url: 'https://final/file', status: 'in_progress' },
  ]);
});

test('never bootstraps an unknown changed ID from supplied filename or a current control session', () => {
  const f = fixture();
  f.active(true);
  f.changed({ id: 99, filename: { current: '/unknown' }, state: { current: 'complete' } });
  f.created({ id: 98, filename: '/known', finalUrl: 'https://final/known' });
  f.changed({ id: 99, state: { current: 'interrupted' }, error: { current: 'USER_CANCELED' } });
  f.changed({ id: 98, state: { current: 'complete' } });
  assert.deepEqual(f.emitted, [
    { id: '98', filename: '/known', url: 'https://final/known', status: 'started' },
    { id: '98', filename: '/known', url: 'https://final/known', status: 'complete' },
  ]);
});

test('known native events remain metadata when control ends, including late terminal filename updates', () => {
  const f = fixture();
  f.active(true);
  f.created({ id: 23, filename: '/before', finalUrl: 'https://final/known' });
  f.active(false);
  f.created({ id: 24, filename: '/not-observed', finalUrl: 'https://final/new' });
  f.changed({ id: 23, state: { current: 'complete' } });
  f.changed({ id: 23, filename: { current: '/renamed-after-complete' } });
  f.changed({ id: 23, state: { current: 'complete' } });
  assert.deepEqual(f.emitted, [
    { id: '23', filename: '/before', url: 'https://final/known', status: 'started' },
    { id: '23', filename: '/before', url: 'https://final/known', status: 'complete' },
    {
      id: '23',
      filename: '/renamed-after-complete',
      url: 'https://final/known',
      status: 'complete',
    },
  ]);
});

test('native EOF and dropped notifications cause neither replay nor synthetic terminal events', () => {
  let connected = false;
  const delivered = [];
  const f = fixture((value) => {
    if (!connected) return false;
    delivered.push(value);
  });
  f.active(true);
  f.created({ id: 31, filename: '/file', finalUrl: 'https://final/file' });
  connected = true;
  assert.deepEqual(delivered, []);
  f.changed({ id: 31, state: { current: 'in_progress' } });
  connected = false;
  f.active(false);
  f.changed({ id: 31, state: { current: 'complete' } });
  connected = true;
  assert.deepEqual(delivered, [
    { id: '31', filename: '/file', url: 'https://final/file', status: 'in_progress' },
  ]);
  f.changed({ id: 31, filename: { current: '/actual/final' }, state: { current: 'complete' } });
  assert.deepEqual(delivered, [
    { id: '31', filename: '/file', url: 'https://final/file', status: 'in_progress' },
    { id: '31', filename: '/actual/final', url: 'https://final/file', status: 'complete' },
  ]);
});

test('transport throw or rejected send never replays or changes physical status', async () => {
  const offered = [];
  let failure = 'throw';
  const f = fixture((value) => {
    offered.push(value);
    if (failure === 'throw') throw new Error('native EOF');
    if (failure === 'reject') return Promise.reject(new Error('native ACK lost'));
  });
  f.active(true);
  f.created({ id: 41, filename: '/file', finalUrl: 'https://final/file' });
  failure = 'reject';
  f.changed({ id: 41, state: { current: 'in_progress' } });
  await setImmediate();
  failure = null;
  f.changed({ id: 41, state: { current: 'complete' } });
  assert.deepEqual(offered, [
    { id: '41', filename: '/file', url: 'https://final/file', status: 'started' },
    { id: '41', filename: '/file', url: 'https://final/file', status: 'in_progress' },
    { id: '41', filename: '/file', url: 'https://final/file', status: 'complete' },
  ]);
});

test('dispose ends observation, clears only metadata, and never cancels a physical download', () => {
  const f = fixture();
  f.active(true);
  const [oldCreated] = f.chrome.downloads.onCreated.snapshot();
  const [oldChanged] = f.chrome.downloads.onChanged.snapshot();
  f.created({ id: 51, filename: '/file', finalUrl: 'https://final/file' });
  f.observer.dispose();
  f.observer.dispose();
  f.changed({ id: 51, state: { current: 'complete' } });
  f.created({ id: 52, filename: '/later', finalUrl: 'https://final/later' });
  oldCreated({ id: 53, filename: '/late-callback', finalUrl: 'https://final/late-callback' });
  oldChanged({ id: 51, state: { current: 'interrupted' }, error: { current: 'USER_CANCELED' } });
  assert.deepEqual(f.emitted, [
    { id: '51', filename: '/file', url: 'https://final/file', status: 'started' },
  ]);
  assert.equal(f.chrome.downloads.onCreated.snapshot().length, 0);
  assert.equal(f.chrome.downloads.onChanged.snapshot().length, 0);
});
