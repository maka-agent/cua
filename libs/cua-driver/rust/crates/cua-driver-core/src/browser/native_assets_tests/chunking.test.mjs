import test from 'node:test';
import assert from 'node:assert/strict';
import {
  fragment,
  Reassembler,
  HOST_FRAME_LIMIT,
  CHROME_FRAME_LIMIT,
} from '../native_assets/chunking.mjs';
const context = { generation: 'gen-1', owner: 'owner-a', logicalId: '1' };
const message = () => ({
  kind: 'request',
  generation: 'gen-1',
  owner: 'owner-a',
  id: '1',
  params: { text: '汉🙂'.repeat(200000) },
});
const assembler = () => {
  const r = new Reassembler();
  r.reset('gen-1');
  return r;
};
test('multi-byte request reassembles once, never dispatches a partial request', () => {
  const input = message();
  const frames = fragment(input, context);
  assert.ok(frames.length > 1);
  const r = assembler();
  for (const frame of frames.slice(0, -1)) {
    assert.ok(Buffer.byteLength(JSON.stringify(frame)) <= HOST_FRAME_LIMIT);
    assert.equal(r.accept(frame), null);
  }
  assert.deepEqual(r.accept(frames.at(-1)), input);
  assert.equal(r.reserved, 0);
  assert.throws(() => r.accept(frames[0]), /replays/);
});
test('duplicate previous fragment poisons whole assembly, tail cannot dispatch', () => {
  const frames = fragment(message(), context);
  const r = assembler();
  assert.equal(r.accept(frames[0]), null);
  assert.throws(() => r.accept(frames[0]), /duplicated/);
  assert.equal(r.open.size, 0);
  assert.equal(r.reserved, 0);
  assert.throws(() => r.accept(frames[1]), /starts late/);
});
test('generation, owner and logical message identity do not cross streams', () => {
  const frames = fragment(message(), context);
  const r = assembler();
  r.accept(frames[0]);
  assert.throws(() => r.accept({ ...frames[1], generation: 'other' }), /identity/);
  assert.throws(() => r.accept({ ...frames[1], owner: 'other' }), /starts late/);
  r.reset('new');
  assert.equal(r.open.size, 0);
  assert.throws(() => r.accept(frames[1]), /identity/);
});
test('close-owner discards pending bytes and cannot resume partial message', () => {
  const frames = fragment(message(), context);
  const r = assembler();
  r.accept(frames[0]);
  r.closeOwner('owner-a');
  assert.equal(r.reserved, 0);
  assert.throws(() => r.accept(frames[1]), /starts late/);
});
test('declaration budget is enforced before decoding or accumulating body', () => {
  const frames = fragment(message(), context);
  const r = assembler();
  assert.throws(() => r.accept({ ...frames[0], bytes: CHROME_FRAME_LIMIT + 1 }), /bounds/);
  assert.equal(r.open.size, 0);
  assert.throws(() => r.accept({ ...frames[0], parts: 1.5 }), /bounds/);
  assert.throws(() => r.accept({ ...frames[0], data: '!' }), /base64/);
  assert.equal(r.open.size, 0);
});
test('Chrome-to-host screenshot-sized replies legitimately exceed host-to-Chrome1MiB', () => {
  const payload = {
    generation: 'gen-1',
    owner: 'owner-a',
    result: { data: 'x'.repeat(HOST_FRAME_LIMIT + 100) },
  };
  const frames = fragment(payload, context, CHROME_FRAME_LIMIT);
  assert.equal(frames.length, 1);
  assert.equal(frames[0], payload);
  assert.ok(Buffer.byteLength(JSON.stringify(payload)) > HOST_FRAME_LIMIT);
});
test('complete chunk identity mismatch never dispatches JSON under a different owner', () => {
  const input = message();
  input.owner = 'owner-b';
  const frames = fragment(input, context);
  const r = assembler();
  for (const frame of frames.slice(0, -1)) r.accept(frame);
  assert.throws(() => r.accept(frames.at(-1)), /identity disagrees/);
  assert.equal(r.open.size, 0);
  assert.equal(r.reserved, 0);
});
test('claim-route cancellation discards only its exact partial logical message and never dispatches', () => {
  const frames = fragment(message(), context);
  const r = assembler();
  r.accept(frames[0]);
  assert.equal(
    r.accept({
      kind: 'cancelChunk',
      protocol: 1,
      generation: 'gen-1',
      owner: 'owner-b',
      logicalId: '1',
    }),
    null,
  );
  assert.equal(r.open.size, 1);
  assert.equal(
    r.accept({
      kind: 'cancelChunk',
      protocol: 1,
      generation: 'gen-1',
      owner: 'owner-a',
      logicalId: '1',
    }),
    null,
  );
  assert.equal(r.open.size, 0);
  assert.equal(r.reserved, 0);
  assert.throws(() => r.accept(frames[1]), /starts late/);
  assert.throws(() => r.accept(frames[0]), /replays/);
});
test('cancel-before-first-fragment fences that logical request without dispatch', () => {
  const frames = fragment(message(), context);
  const r = assembler();
  r.accept({
    kind: 'cancelChunk',
    protocol: 1,
    generation: 'gen-1',
    owner: 'owner-a',
    logicalId: '1',
  });
  assert.throws(() => r.accept(frames[0]), /replays/);
  assert.equal(r.open.size, 0);
  assert.throws(
    () =>
      r.accept({
        kind: 'cancelChunk',
        protocol: 1,
        generation: 'gen-1',
        owner: 'owner-a',
        logicalId: '18446744073709551616',
      }),
    /identity/,
  );
});
