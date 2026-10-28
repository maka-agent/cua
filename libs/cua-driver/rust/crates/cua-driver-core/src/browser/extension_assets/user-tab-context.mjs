// SPDX-License-Identifier: MIT
// Fixed, URL-guarded user-tab reads. This does not attach a debugger, focus,
// prepare or claim a tab. The embedding connector retains Host admission.
const CHANGED = 'The selected tab changed while being read';
const TOO_LARGE = 'Google Workspace export is too large for in-memory tab context';
const EXPORT_BYTES = 32 * 1024 * 1024;
const SELECTION_UNITS = 80_000;
const TRANSCRIPT = Object.freeze({
  fetchTimeoutMs: 8000, maxItems: 5000, maxJsonBytes: 5 * 1024 * 1024,
  maxTextBytes: 500_000, observationTimeoutMs: 4000,
});

export async function readUserTab(chrome, params, checkAdmission) {
  const { tabId, expectedUrl, read } = params;
  if (!Number.isSafeInteger(tabId) || tabId <= 0)
    throw new Error('Tab reads require a positive safe tab ID');
  let url;
  try { url = new URL(expectedUrl); } catch { /* same closed failure below */ }
  if (!url || !['http:', 'https:'].includes(url.protocol))
    throw new Error('Tab reads require an HTTP or HTTPS URL');
  const check = async () => {
    await checkAdmission();
    const tab = await chrome.tabs.get(tabId);
    if (tab?.id !== tabId || tab.incognito === true || tab.url !== expectedUrl)
      throw new Error(CHANGED);
  };
  await check();
  const execute = async (func, args, world = 'ISOLATED') => {
    const results = await chrome.scripting.executeScript({ target: { tabId }, func, args, world });
    return results[0]?.result ?? null;
  };
  let result;
  switch (read?.kind) {
    case 'page': result = await execute(readPage, [expectedUrl]); break;
    case 'selection': result = await execute(readSelection, [expectedUrl, SELECTION_UNITS]); break;
    case 'googleWorkspaceExport': {
      const doc = workspaceDocument(url);
      if (!doc || !doc.formats.includes(read.format)) throw new Error('Unsupported Google Workspace export');
      const endpoint = new URL(`https://docs.google.com/${doc.type}/d/${doc.id}/export`);
      endpoint.searchParams.set('format', read.format);
      if (url.searchParams.has('tab')) endpoint.searchParams.set('tab', url.searchParams.get('tab'));
      endpoint.hash = url.hash;
      result = await execute(readWorkspaceExport,
        [url.origin, endpoint.href, EXPORT_BYTES, TOO_LARGE, read.format === 'md']);
      break;
    }
    case 'youtubeTranscript': {
      const video = youtubeVideo(url);
      if (!video) throw new Error('Unsupported YouTube page');
      const observation = await execute(observeYoutubeCaptions, [video, TRANSCRIPT], 'MAIN');
      result = formatYoutubeTranscript(video, observation, TRANSCRIPT);
      break;
    }
    default: throw new Error('Unsupported tab read');
  }
  await check();
  return result ?? null;
}

function workspaceDocument(url) {
  if (url.host !== 'docs.google.com') return null;
  const path = url.pathname.split('/').filter(Boolean);
  const formats = { document: ['md', 'pdf'], presentation: ['pdf'], spreadsheets: ['xlsx', 'pdf'] }[path[0]];
  const index = path.indexOf('d', 1);
  if (!formats || index < 0 || !path[index + 1] || path.at(-1) === 'pub') return null;
  return { id: path[index + 1], type: path[0], formats };
}
function youtubeVideo(url) {
  const id = url.searchParams.get('v');
  return url.protocol === 'https:' && ['www.youtube.com', 'youtube.com'].includes(url.hostname)
    && url.pathname === '/watch' && /^[A-Za-z0-9_-]{11}$/u.test(id ?? '') ? id : null;
}

// Each script is self-contained because Chrome serializes only the function.
export function readSelection(expectedUrl, limit) {
  if (location.href !== expectedUrl) return null;
  const selected = window.getSelection()?.toString().trim() ?? '';
  return selected ? { text: selected.slice(0, limit), truncated: selected.length > limit } : null;
}

export function readPage(expectedUrl) {
  if (document.location.href !== expectedUrl) return null;
  const escapeText = (value) => value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
  const escapeAttribute = (value) => escapeText(value).replaceAll('"', '&quot;');
  const attribute = (element, name) => {
    const value = element.getAttribute(name);
    return value === null ? '' : ` ${name}="${escapeAttribute(value)}"`;
  };
  const readableValue = (value) => value.length < 32 && /\p{Decimal_Number}/u.test(value)
    && /^[\p{Decimal_Number}\p{Punctuation}\p{White_Space}]+$/u.test(value) ? '' : value;
  let content = '', separator = '', glued = false;
  const write = (text, preserve = false) => {
    if (!text) return;
    const value = preserve ? text : text.replace(/^[ \t\n\r]+|[ \t\n\r]+$/gu, '');
    if (!preserve && !value) {
      if (content && !glued && separator !== '\n\n') separator = ' ';
      return;
    }
    const prefix = separator || (!preserve && !glued && /^[ \t\n\r]/u.test(text) && content ? ' ' : '');
    content += prefix + value;
    glued = false;
    separator = !preserve && /[ \t\n\r]$/u.test(text) ? ' ' : '';
  };
  const raw = (text, trim) => {
    if (trim === 'before' || trim === 'both') separator = '';
    write(text, true);
    glued = trim === 'after' || trim === 'both';
  };
  const block = () => { if (content && !glued && !content.endsWith('\n\n')) separator = '\n\n'; };
  const field = (element) => {
    const value = readableValue(element.value);
    const { selectionStart: start, selectionEnd: end } = element;
    if (element.getRootNode().activeElement !== element || start === null || end === null) {
      write(escapeAttribute(value), true); return;
    }
    write(escapeAttribute(value.slice(0, start)), true);
    if (start === end) raw('<user__cursor>');
    else {
      raw('<user__selection>');
      write(escapeAttribute(value.slice(start, end)), true);
      raw('</user__selection>');
    }
    write(escapeAttribute(value.slice(end)), true);
  };
  const visit = (node, preformatted = false) => {
    if (node.nodeType === Node.TEXT_NODE) { write(escapeText(node.textContent ?? ''), preformatted); return; }
    if (node.nodeType !== Node.ELEMENT_NODE) return;
    const tag = node.tagName.toLowerCase();
    if (/^(base|head|link|meta|noscript|script|style)$/u.test(tag)
        || tag === 'title' && node.namespaceURI !== 'http://www.w3.org/2000/svg') return;
    const html = node.namespaceURI === 'http://www.w3.org/1999/xhtml';
    const editable = /^(|true|plaintext-only)$/iu.test(node.getAttribute('contenteditable') ?? 'false');
    const style = window.getComputedStyle(node);
    const boundary = /^(block|flex|grid|list-item|flow-root|table|table-row)$/u.test(style.display);
    if (boundary) block();
    let closing = null, closingTrim, children = true;
    if (html) {
      if (tag === 'input') {
        const type = node.type.toLowerCase(), toggle = ['checkbox', 'radio'].includes(type);
        const opening = `<input${attribute(node, 'aria-label')}${attribute(node, 'type')}${toggle && node.checked ? ' checked="true"' : ''}`;
        if (toggle || type === 'password') raw(`${opening}/>`);
        else { raw(`${opening} value="`); field(node); raw('"/>'); }
        children = false;
      } else if (tag === 'textarea') {
        raw(`<textarea${attribute(node, 'aria-label')}>`);
        if (node.getRootNode().activeElement === node) field(node);
        else write(escapeText(readableValue(node.value)), true);
        raw('</textarea>'); children = false;
      } else if (tag === 'select') {
        raw(`<select${attribute(node, 'aria-label')}>`, 'both');
        for (const option of node.options) {
          raw(`<option${attribute(option, 'aria-label')} value="${escapeAttribute(option.value)}"${option.selected ? ' selected="true"' : ''}>`, 'both');
          write(escapeText(option.label), true); raw('</option>', 'both');
        }
        raw('</select>', 'both'); children = false;
      } else if (tag === 'img') {
        let name = '';
        try {
          const source = node.currentSrc || node.getAttribute('src');
          if (source != null) {
            const url = new URL(source, document.baseURI);
            if (url.protocol !== 'data:') name = url.pathname.split('/').at(-1) ?? '';
          }
        } catch { /* absent image metadata */ }
        raw(`<img src="${escapeAttribute(name)}" alt="`);
        write(escapeAttribute(node.getAttribute('alt') ?? ''), true);
        raw(`"${attribute(node, 'aria-label')}/>`); children = false;
      } else if (tag === 'br') { block(); return; }
      else if (tag === 'a') {
        let href;
        try {
          const source = node.getAttribute('href');
          if (source !== null) {
            const url = new URL(source, document.baseURI);
            if (url.href.split('#', 1)[0] !== expectedUrl.split('#', 1)[0]) href = url.href;
          }
        } catch { /* no usable destination */ }
        if (href != null) { raw(`<a href="${escapeAttribute(href)}"${attribute(node, 'aria-label')}>`); closing = '</a>'; }
      } else if (tag === 'button') {
        raw(`<button${attribute(node, 'name')}${attribute(node, 'aria-label')}${attribute(node, 'title')}>`);
        closing = '</button>'; closingTrim = 'before';
      } else if (editable) {
        raw(`<contenteditable${attribute(node, 'aria-label')}>`, 'both');
        closing = '</contenteditable>'; closingTrim = 'both';
      } else if (['table', 'tr', 'td', 'th'].includes(tag)) {
        raw(`<${tag}>`, tag === 'table' ? 'after' : 'both');
        closing = `</${tag}>`; closingTrim = tag === 'table' ? 'before' : 'both';
      }
    }
    if (children) {
      const preserve = preformatted || tag === 'pre' || tag === 'code'
        || /^(pre|pre-wrap|break-spaces)$/u.test(style.whiteSpace);
      for (const parent of [node, node.shadowRoot]) {
        if (parent) for (const child of parent.childNodes) visit(child, preserve);
      }
    }
    if (closing) raw(closing, closingTrim);
    if (boundary) block();
  };
  if (document.body) visit(document.body);
  // The effective Original call explicitly disables both optional page limits.
  if (/[\uD800-\uDBFF]$/u.test(content)) content = content.slice(0, -1);
  return { text: content, title: document.title, url: expectedUrl, truncated: false };
}

export async function readWorkspaceExport(origin, exportUrl, limit, tooLarge, truncateText) {
  if (location.origin !== origin) return { errorMessage: 'The tab origin changed before export.' };
  const response = await fetch(exportUrl, { method: 'GET' });
  if (!response.ok) throw new Error(`GSuite export request failed with HTTP ${response.status}`);
  try {
    if (new URL(response.url).origin !== new URL(exportUrl).origin) {
      await response.body?.cancel().catch(() => {}); return { redirectUrl: response.url };
    }
  } catch { return { errorMessage: 'The export returned an invalid URL.' }; }
  const declaredSize = Number(response.headers.get('content-length') ?? NaN);
  const knownLarge = Number.isFinite(declaredSize) && declaredSize > limit;
  if (knownLarge && !truncateText) {
    await response.body?.cancel().catch(() => {}); return { errorMessage: tooLarge };
  }
  const pieces = []; let total = 0, truncated = false;
  const reader = response.body?.getReader();
  if (!reader) {
    if (knownLarge) return { errorMessage: tooLarge };
    const blob = await response.blob();
    if (blob.size > limit && !truncateText) return { errorMessage: tooLarge };
    truncated = blob.size > limit;
    pieces.push(new Uint8Array(await blob.slice(0, limit).arrayBuffer())); total = pieces[0].length;
  } else {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      if (total + value.length > limit) {
        if (!truncateText) { await reader.cancel(); return { errorMessage: tooLarge }; }
        if (total < limit) pieces.push(value.slice(0, limit - total));
        total = limit; truncated = true; await reader.cancel(); break;
      }
      pieces.push(value.slice()); total += value.length;
    }
  }
  let bytes = new Uint8Array(total), offset = 0;
  for (const piece of pieces) { bytes.set(piece, offset); offset += piece.length; }
  if (truncated && bytes.length) {
    let continuation = 0;
    while (continuation < bytes.length && (bytes[bytes.length - continuation - 1] & 0xc0) === 0x80) continuation++;
    const leadIndex = bytes.length - continuation - 1, lead = bytes[leadIndex];
    const width = lead < 0x80 ? 1 : lead >= 0xc2 && lead <= 0xdf ? 2
      : lead >= 0xe0 && lead <= 0xef ? 3 : lead >= 0xf0 && lead <= 0xf4 ? 4 : 0;
    if (leadIndex < 0 || !width || width !== 1 && continuation !== width - 1)
      bytes = bytes.subarray(0, Math.max(0, leadIndex));
  }
  let binary = '';
  for (let index = 0; index < bytes.length; index += 32768)
    binary += String.fromCharCode(...bytes.subarray(index, index + 32768));
  return { base64: btoa(binary), truncated };
}

export async function observeYoutubeCaptions(videoId, limits) {
  const call = (object, name) => typeof object?.[name] === 'function' ? object[name]() : undefined;
  const snapshot = () => {
    const component = document.querySelector('ytd-player');
    const candidate = typeof component?.getPlayer === 'function' ? component.getPlayer() : null;
    const player = candidate != null && typeof candidate === 'object' ? candidate : document.querySelector('#movie_player');
    let currentUrl; try { currentUrl = new URL(location.href); } catch { return { player }; }
    return { player, playerId: call(player, 'getVideoData')?.video_id, urlId: currentUrl.searchParams.get('v') };
  };
  const matches = (state) => state.player != null && state.playerId === videoId && state.urlId === videoId;
  const initial = snapshot();
  if (!matches(initial)) return null;
  const player = initial.player;
  if (['getVideoData', 'isSubtitlesOn', 'toggleSubtitles', 'toggleSubtitlesOn'].some((method) => typeof player[method] !== 'function')) return null;
  const started = performance.now(); let timedtext = null;
  const observer = new PerformanceObserver((list) => {
    for (const entry of list.getEntries()) {
      if (entry.startTime + 0.5 < started) continue;
      try {
        const url = new URL(entry.name);
        if (url.protocol === 'https:' && url.hostname === 'www.youtube.com'
            && url.pathname === '/api/timedtext' && url.searchParams.get('v') === videoId) timedtext = url.href;
      } catch { /* unrelated resource */ }
    }
  });
  observer.observe({ type: 'resource', buffered: true });
  const enabled = !!call(player, 'isSubtitlesOn');
  try {
    if (enabled) call(player, 'toggleSubtitles');
    call(player, 'toggleSubtitlesOn');
    const deadline = Date.now() + limits.observationTimeoutMs;
    while (timedtext === null && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 150));
  } finally {
    try {
      const current = snapshot();
      if (matches(current) && current.player === player) {
        const now = !!call(player, 'isSubtitlesOn');
        if (enabled && !now) call(player, 'toggleSubtitlesOn');
        else if (!enabled && now) call(player, 'toggleSubtitles');
      }
    } finally { observer.disconnect(); }
  }
  if (timedtext === null || !matches(snapshot())) return null;
  const endpoint = new URL(timedtext); endpoint.searchParams.set('fmt', 'json3');
  const abort = new AbortController(), timeout = setTimeout(() => abort.abort(), limits.fetchTimeoutMs);
  try {
    const response = await fetch(endpoint.href, { credentials: 'include', signal: abort.signal });
    if (!response.ok || !response.headers.get('content-type')?.toLowerCase().includes('application/json')) return null;
    const size = Number(response.headers.get('content-length') ?? NaN);
    if (Number.isFinite(size) && size > limits.maxJsonBytes) { abort.abort(); return null; }
    let body;
    const reader = response.body?.getReader();
    if (!reader) {
      body = await response.text();
      if (new TextEncoder().encode(body).length > limits.maxJsonBytes) return null;
    } else {
      const parts = []; let size = 0;
      for (;;) {
        const { done, value } = await reader.read(); if (done) break;
        if (!value) continue;
        size += value.length;
        if (size > limits.maxJsonBytes) { await reader.cancel(); return null; }
        parts.push(value.slice());
      }
      const bytes = new Uint8Array(size); let offset = 0;
      for (const part of parts) { bytes.set(part, offset); offset += part.length; }
      body = new TextDecoder().decode(bytes);
    }
    return matches(snapshot()) ? { body, captionKind: endpoint.searchParams.get('kind'),
      captionLanguage: endpoint.searchParams.get('lang'), pageUrl: location.href } : null;
  } catch { return null; } finally { clearTimeout(timeout); }
}

export function formatYoutubeTranscript(videoId, observation, limits = TRANSCRIPT) {
  if (!observation || typeof observation !== 'object' || Array.isArray(observation)
      || Object.keys(observation).length !== 4 || typeof observation.body !== 'string'
      || typeof observation.pageUrl !== 'string'
      || !['captionKind', 'captionLanguage'].every((key) => observation[key] === null
        || typeof observation[key] === 'string' && observation[key].length <= 100)) return null;
  const encoder = new TextEncoder();
  if (encoder.encode(observation.body).length > limits.maxJsonBytes) return null;
  let events;
  try { events = JSON.parse(observation.body)?.events; } catch { return null; }
  if (!Array.isArray(events)) return null;
  const lines = ['YouTube transcript', `Video ID: ${videoId}`, `Language: ${observation.captionLanguage ?? 'unknown'}`,
    `Captions: ${observation.captionKind === 'asr' ? 'auto-generated' : 'authored or unspecified'}`, ''];
  let count = 0, bytes = encoder.encode(lines.join('\n')).length, truncated = false;
  for (const event of events) {
    if (count >= limits.maxItems) { truncated = true; break; }
    if (!event || !Number.isFinite(event.tStartMs) || event.tStartMs < 0 || !Array.isArray(event.segs)
        || !event.segs.every((segment) => segment && typeof segment === 'object' && !Array.isArray(segment)
          && (segment.utf8 === undefined || typeof segment.utf8 === 'string'))) continue;
    const text = event.segs.map((segment) => segment.utf8 ?? '').join('').replace(/\s+/gu, ' ').trim();
    if (!text) continue;
    const seconds = Math.floor(event.tStartMs / 1000), hours = Math.floor(seconds / 3600);
    const minutes = Math.floor(seconds % 3600 / 60), second = String(seconds % 60).padStart(2, '0');
    const stamp = hours > 0 ? `${hours}:${String(minutes).padStart(2, '0')}:${second}` : `${minutes}:${second}`;
    const line = `[${stamp}] ${text}`, length = encoder.encode(`\n${line}`).length;
    if (bytes + length > limits.maxTextBytes) { truncated = true; break; }
    lines.push(line); bytes += length; count++;
  }
  if (!count) return null;
  if (truncated) lines.push('', '[Transcript truncated]');
  return { pageUrl: observation.pageUrl, text: lines.join('\n'), truncated };
}
