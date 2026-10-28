// SPDX-License-Identifier: MIT
// Whole-profile history transport. The Host owns distinct history consent.
import { ConnectorError } from './connector.mjs';

export async function userHistory(chrome, options = {}) {
  const limit = options.limit ?? 100;
  if (!Number.isInteger(limit) || limit <= 0)
    throw new ConnectorError('invalid_request', 'getUserHistory requires limit to be a positive integer');
  const time = (key, fallback) => {
    if (options[key] == null) return fallback;
    const result = typeof options[key] === 'string' ? Date.parse(options[key]) : NaN;
    if (!Number.isFinite(result))
      throw new ConnectorError('invalid_request', `getUserHistory requires ${key} to be a valid date`);
    return result;
  };
  const startTime = time('from', 0);
  const endTime = time('to', undefined);
  const queries = options.queries ?? [''];
  if (!Array.isArray(queries) || queries.length === 0 || queries.some((query) => typeof query !== 'string'))
    throw new ConnectorError('invalid_request', 'getUserHistory requires queries to be a non-empty array of strings');
  if (typeof chrome.history?.search !== 'function')
    throw new ConnectorError('unsupported', 'browser-wide history permission is unavailable');
  const batches = await Promise.all(queries.map((text) => chrome.history.search({
    text, maxResults: limit, startTime, ...(endTime === undefined ? {} : { endTime }),
  })));
  const ordered = batches.flat().filter((item) => typeof item.url === 'string' &&
    typeof item.lastVisitTime === 'number' && Number.isFinite(item.lastVisitTime))
    .map((item) => ({ url: item.url, ...(item.title == null ? {} : { title: item.title }),
      dateVisited: new Date(item.lastVisitTime).toISOString() }))
    .sort((left, right) => right.dateVisited.localeCompare(left.dateVisited));
  const seen = new Set();
  return ordered.filter((item) => {
    if (seen.has(item.url)) return false;
    seen.add(item.url);
    return true;
  }).slice(0, limit);
}
