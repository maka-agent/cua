import { NativeBrowserConnector } from './provider-connector.mjs';
import { Reassembler, fragment, CHROME_FRAME_LIMIT } from './chunking.mjs';
const NATIVE_HOST = 'org.apache.maka.browser_connector';
let port = null;
let generation = null;
const assembler = new Reassembler();
const connector = new NativeBrowserConnector(chrome, {
  emit: (event) => {
    if (port && event.generation === generation) send(event, port);
  },
});
function retire(current, error) {
  if (port !== current) return;
  if (error)
    console.error(
      'Maka connector transport ended:',
      error instanceof Error ? error.message : String(error),
    );
  port = null;
  generation = null;
  assembler.reset(null);
  // Keep old physical custody in the controller; reconnect never adopts/replays it.
  void connector
    .disconnect()
    .catch((error) => console.error('Maka connector cleanup unknown:', String(error)));
  try {
    current.disconnect();
  } catch {
    /* The port may already have closed. */
  }
}
function send(message, current = port) {
  if (!current || port !== current) return;
  try {
    // Complete all fragments synchronously before emitting the next logical message.
    for (const frame of fragment(
      message,
      { generation, owner: message.owner ?? 'transport', logicalId: message.id ?? '1' },
      CHROME_FRAME_LIMIT,
    ))
      current.postMessage(frame);
  } catch (error) {
    retire(current, error);
  }
}
let connecting = false;
async function connect() {
  if (port || connecting) return;
  connecting = true;
  try {
    let ready = await connector.initialize();
    if (ready.cleanupConfirmed !== true)
      ready = await connector.reconcileHeaders({ forceLive: true });
    if (ready.cleanupConfirmed !== true) throw new Error('scoped-rule cleanup is not acknowledged');
  } catch (error) {
    console.error('Maka startup scoped-rule cleanup unknown:', String(error));
    connecting = false;
    return;
  }
  let current;
  try {
    current = chrome.runtime.connectNative(NATIVE_HOST);
  } catch (error) {
    console.error('Maka native host unavailable:', String(error));
    connecting = false;
    return;
  }
  port = current;
  connecting = false;
  current.onMessage.addListener((message) => {
    if (port !== current) return;
    try {
      if (
        message?.kind === 'bound' &&
        message.protocol === 1 &&
        typeof message.generation === 'string'
      ) {
        connector.bind(message.generation);
        generation = message.generation;
        assembler.reset(generation);
        return;
      }
      const request = assembler.accept(message);
      if (!request) return;
      if (request.method === 'closeOwner') assembler.closeOwner(request.owner);
      connector.request(request).then(
        (response) => {
          if (port === current && response.generation === generation) send(response, current);
        },
        (error) => retire(current, error),
      );
    } catch (error) {
      retire(current, error);
    }
  });
  current.onDisconnect.addListener(() => {
    void chrome.runtime.lastError;
    retire(current);
  });
  send(connector.hello(), current);
}
chrome.action.onClicked.addListener(connect);
chrome.runtime.onStartup.addListener(connect);
connect();
