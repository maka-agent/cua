// SPDX-License-Identifier: MIT

import { ConnectorError } from './connector.mjs';
import { validateExpandedHeaders } from './scoped-headers.mjs';
import { validateFixedUiRequest } from './fixed-ui.mjs';

export function exactFields(value, fields) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === fields.length
    && fields.every((field) => Object.prototype.hasOwnProperty.call(value, field));
}

export function captureSessionContext(value) {
  const nonempty = (text) => typeof text === 'string' && text.trim().length > 0
    && text.length <= 4096;
  if (!exactFields(value, ['hostSessionId', 'hostTurnId'])
    || !nonempty(value.hostSessionId) || !nonempty(value.hostTurnId))
    throw new ConnectorError('invalid_request', 'fixed session preparation requires captured Host context');
  return Object.freeze({ hostSessionId: value.hostSessionId, hostTurnId: value.hostTurnId });
}

export function sameSessionContext(left, right) {
  return left.hostSessionId === right.hostSessionId && left.hostTurnId === right.hostTurnId;
}

export function captureFixedSession(params, wireContext) {
  if (!exactFields(params, ['tabId', 'scopeId', 'policy', 'ui'])
    || !Number.isSafeInteger(params.tabId) || params.tabId < 0
    || typeof params.scopeId !== 'string'
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(params.scopeId)
    || !exactFields(params.policy, ['popupEnabled', 'headerEnabled', 'headers'])
    || typeof params.policy.popupEnabled !== 'boolean'
    || typeof params.policy.headerEnabled !== 'boolean')
    throw new ConnectorError('invalid_request', 'fixed session preparation requires exact tab, scope, policy and UI fields');
  const context = captureSessionContext(wireContext);
  let headers;
  try {
    headers = validateExpandedHeaders(params.policy.headers);
  } catch (error) {
    throw new ConnectorError(error.kind ?? 'invalid_request', String(error.message ?? error));
  }
  for (const header of headers) Object.freeze(header);
  Object.freeze(headers);
  if (params.policy.headerEnabled && headers.length === 0)
    throw new ConnectorError('invalid_request', 'enabled headers require expanded Host policy');
  const ui = validateFixedUiRequest(params.ui, { initial: true });
  return {
    tabId: params.tabId,
    scopeId: params.scopeId,
    wireContext: context,
    policy: Object.freeze({
      popupEnabled: params.policy.popupEnabled,
      headerEnabled: params.policy.headerEnabled,
      headers,
    }),
    ui,
  };
}

export function captureSessionScope(params, wireContext, ui = false) {
  if (!exactFields(params, ui ? ['tabId', 'scopeId', 'ui'] : ['tabId', 'scopeId'])
    || !Number.isSafeInteger(params.tabId) || params.tabId < 0
    || typeof params.scopeId !== 'string' || params.scopeId.length === 0)
    throw new ConnectorError('invalid_request', 'exact fixed session scope is required');
  return {
    tabId: params.tabId,
    scopeId: params.scopeId,
    wireContext: captureSessionContext(wireContext),
    ...(ui ? { ui: validateFixedUiRequest(params.ui) } : {}),
  };
}
