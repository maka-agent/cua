// Transport fragmentation only. No logical request is exposed until complete JSON validation.
import { ConnectorError } from './connector.mjs';
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
export const HOST_FRAME_LIMIT = 1024 * 1024;
export const CHROME_FRAME_LIMIT = 64 * 1024 * 1024;
const fail = (message) => {
  throw new ConnectorError('invalid_chunk', message);
};
function base64(bytes) {
  let text = '';
  for (let i = 0; i < bytes.length; i += 8192)
    text += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return btoa(text);
}
function unbase64(text) {
  if (
    typeof text !== 'string' ||
    text.length % 4 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text)
  )
    fail('invalid base64 payload');
  const binary = atob(text);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}
export function fragment(
  message,
  { generation, owner, logicalId },
  maxFrameBytes = HOST_FRAME_LIMIT,
) {
  const bytes = encoder.encode(JSON.stringify(message));
  if (bytes.length > CHROME_FRAME_LIMIT) fail('logical message exceeds the 64MiB transport budget');
  if (bytes.length <= maxFrameBytes) return [message];
  const partBytes = Math.min(192 * 1024, Math.floor(((maxFrameBytes - 1024) * 3) / 4));
  if (partBytes <= 0) fail('frame budget is too small');
  const parts = Math.ceil(bytes.length / partBytes);
  const result = [];
  for (let part = 0; part < parts; part++) {
    const frame = {
      kind: 'chunk',
      protocol: 1,
      generation,
      owner,
      logicalId,
      part,
      parts,
      bytes: bytes.length,
      data: base64(bytes.subarray(part * partBytes, (part + 1) * partBytes)),
    };
    if (encoder.encode(JSON.stringify(frame)).length > maxFrameBytes)
      fail('chunk exceeds the native frame limit');
    result.push(frame);
  }
  return result;
}
export class Reassembler {
  constructor({
    maxFrameBytes = HOST_FRAME_LIMIT,
    maxBytes = CHROME_FRAME_LIMIT,
    maxAssemblies = 8,
  } = {}) {
    this.maxFrameBytes = maxFrameBytes;
    this.maxBytes = maxBytes;
    this.maxAssemblies = maxAssemblies;
    this.reset(null);
  }
  reset(generation) {
    this.generation = generation;
    this.open = new Map();
    this.highWater = 0n;
    this.reserved = 0;
  }
  closeOwner(owner) {
    for (const [key, state] of this.open)
      if (state.owner === owner) {
        this.reserved -= state.expectedBytes;
        this.open.delete(key);
      }
  }
  accept(frame) {
    if (encoder.encode(JSON.stringify(frame)).length > this.maxFrameBytes)
      fail('incoming native frame exceeds limit');
    if (frame?.kind === 'cancelChunk') {
      if (
        frame.protocol !== 1 ||
        frame.generation !== this.generation ||
        typeof frame.owner !== 'string' ||
        !frame.owner ||
        typeof frame.logicalId !== 'string' ||
        !/^[1-9][0-9]{0,19}$/.test(frame.logicalId) ||
        BigInt(frame.logicalId) > 18446744073709551615n
      )
        fail('invalid chunk cancellation identity');
      const key = JSON.stringify([frame.generation, frame.owner, frame.logicalId]);
      const state = this.open.get(key);
      if (BigInt(frame.logicalId) > this.highWater) this.highWater = BigInt(frame.logicalId);
      if (state) {
        this.open.delete(key);
        this.reserved -= state.expectedBytes;
      }
      return null;
    }
    if (frame?.kind !== 'chunk') return frame;
    if (
      frame.protocol !== 1 ||
      frame.generation !== this.generation ||
      typeof frame.owner !== 'string' ||
      !frame.owner ||
      typeof frame.logicalId !== 'string' ||
      !/^[1-9][0-9]{0,19}$/.test(frame.logicalId) ||
      BigInt(frame.logicalId) > 18446744073709551615n ||
      !Number.isSafeInteger(frame.part) ||
      !Number.isSafeInteger(frame.parts) ||
      frame.parts < 1 ||
      frame.parts > 4096 ||
      frame.part < 0 ||
      frame.part >= frame.parts ||
      !Number.isSafeInteger(frame.bytes) ||
      frame.bytes < 1 ||
      frame.bytes > this.maxBytes
    )
      fail('invalid chunk identity or bounds');
    const key = JSON.stringify([frame.generation, frame.owner, frame.logicalId]);
    let state = this.open.get(key);
    if (!state) {
      if (frame.part !== 0 || BigInt(frame.logicalId) <= this.highWater)
        fail('chunk starts late or replays a logical ID');
      if (this.open.size >= this.maxAssemblies || this.reserved + frame.bytes > this.maxBytes)
        fail('chunk assembly budget exhausted');
      state = {
        owner: frame.owner,
        expectedBytes: frame.bytes,
        parts: frame.parts,
        next: 0,
        received: 0,
        buffers: [],
      };
      this.open.set(key, state);
      this.highWater = BigInt(frame.logicalId);
      this.reserved += frame.bytes;
    }
    let keepPending = false;
    try {
      if (
        frame.part !== state.next ||
        frame.parts !== state.parts ||
        frame.bytes !== state.expectedBytes
      )
        fail('chunk sequence changed or duplicated');
      const bytes = unbase64(frame.data);
      if (!bytes.length || state.received + bytes.length > state.expectedBytes)
        fail('chunk byte count exceeds declaration');
      state.buffers.push(bytes);
      state.received += bytes.length;
      state.next++;
      if (state.next !== state.parts) {
        keepPending = true;
        return null;
      }
      if (state.received !== state.expectedBytes) fail('logical message is truncated');
      const joined = new Uint8Array(state.received);
      let offset = 0;
      for (const bytes of state.buffers) {
        joined.set(bytes, offset);
        offset += bytes.length;
      }
      const message = JSON.parse(decoder.decode(joined));
      if (
        message?.generation !== frame.generation ||
        message?.owner !== frame.owner ||
        message?.id !== frame.logicalId
      )
        fail('reassembled identity disagrees with envelope');
      return message;
    } finally {
      if (!keepPending) {
        this.open.delete(key);
        this.reserved -= state.expectedBytes;
      }
    }
  }
}
