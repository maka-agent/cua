// Maka Chrome download metadata observer. These events prove no tab ownership or approval.
export class ExtensionDownloads {
  #chrome;
  #emit;
  #hasActiveControl;
  #observed = new Map();
  #disposed = false;
  #createdListener;
  #changedListener;

  constructor(chrome, { emit, hasActiveControl }) {
    if (typeof emit !== 'function' || typeof hasActiveControl !== 'function')
      throw new TypeError('emit and hasActiveControl must be synchronous functions');
    this.#chrome = chrome;
    this.#emit = emit;
    this.#hasActiveControl = hasActiveControl;
    this.#createdListener = (item) => this.#created(item);
    this.#changedListener = (delta) => this.#changed(delta);
    chrome.downloads.onCreated.addListener(this.#createdListener);
    chrome.downloads.onChanged.addListener(this.#changedListener);
  }

  #created(item) {
    if (
      this.#disposed ||
      !validId(item?.id) ||
      typeof item.filename !== 'string' ||
      typeof item.finalUrl !== 'string'
    )
      return;
    // The existing controller supplies this fact; the observer owns no sessions or leases.
    if (this.#hasActiveControl() !== true || this.#disposed) return;
    const metadata = { filename: item.filename, url: item.finalUrl };
    this.#observed.set(item.id, metadata);
    this.#send({ id: String(item.id), ...metadata, status: 'started' });
  }

  #changed(delta) {
    if (this.#disposed || !validId(delta?.id)) return;
    const metadata = this.#observed.get(delta.id);
    if (!metadata) return;
    if (typeof delta.filename?.current === 'string') metadata.filename = delta.filename.current;
    let status;
    switch (delta.state?.current) {
      case 'complete':
        status = 'complete';
        break;
      case 'interrupted':
        status = delta.error?.current === 'USER_CANCELED' ? 'canceled' : 'failed';
        break;
      case 'in_progress':
        status = 'in_progress';
        break;
      default:
        return;
    }
    // Match Chatgpt observer-lifetime retention, including terminal entries. Host caches paths.
    // There is no history query, cap, TTL, terminal eviction, or extension-port reconnect replay.
    this.#send({ id: String(delta.id), ...metadata, status });
  }

  #send(event) {
    try {
      // The adapter owns delivery/retirement. A dropped notification is never cancellation.
      Promise.resolve(this.#emit(event)).catch(() => {});
    } catch {
      // No retry: the transport may have accepted this event before its acknowledgement was lost.
    }
  }

  dispose() {
    if (this.#disposed) return;
    this.#disposed = true;
    this.#chrome.downloads.onCreated.removeListener(this.#createdListener);
    this.#chrome.downloads.onChanged.removeListener(this.#changedListener);
    this.#observed.clear();
  }
}

function validId(id) {
  return typeof id === 'number' && Number.isInteger(id) && id >= 0;
}
