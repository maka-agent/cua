// Thin provider preparation only. Host performs admission, origin policy and turn ownership.
import { ConnectorError } from './connector.mjs';
const SCHEMES = Object.freeze({
  chrome: ['chrome'],
  edge: ['edge'],
  brave: ['brave', 'chrome'],
  opera: ['opera', 'chrome'],
  vivaldi: ['vivaldi', 'chrome'],
});
const NEW_TAB_PATHS = ['newtab/', 'new-tab-page/', 'new-tab-page-third-party/'];
export class TabPreparation {
  constructor(
    chrome,
    {
      assertAdmission,
      family = 'chrome',
      now = () => Date.now(),
      sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
    } = {},
  ) {
    if (typeof assertAdmission !== 'function' || !SCHEMES[family])
      throw new ConnectorError(
        'invalid_configuration',
        'known browser family and Host admission checker are required',
      );
    this.chrome = chrome;
    this.assertAdmission = assertAdmission;
    this.schemes = SCHEMES[family];
    this.now = now;
    this.sleep = sleep;
  }
  checkAdmission(owner, id) {
    const result = this.assertAdmission(owner, id);
    if (result && typeof result.then === 'function') {
      // Synchronous dispatch fences cannot be replaced with an unobserved async decision.
      void Promise.resolve(result).catch(() => {});
      throw new ConnectorError(
        'invalid_configuration',
        'admission checker must synchronously throw on denial',
      );
    }
    if (result === false) throw new ConnectorError('owner_closed', 'Host admission was denied');
  }
  async prepare(owner, rawTabId) {
    if (!Number.isSafeInteger(rawTabId) || rawTabId < 0)
      throw new ConnectorError('invalid_request', 'exact native tab ID is required');
    this.checkAdmission(owner, rawTabId);
    let tab;
    try {
      tab = await this.chrome.tabs.get(rawTabId);
    } catch (error) {
      throw new ConnectorError('chrome_rejected', String(error?.message ?? error));
    }
    if (!Number.isSafeInteger(tab?.id) || tab.id !== rawTabId)
      throw new ConnectorError(
        'target_unavailable',
        'Chrome metadata did not match the admitted exact tab',
      );
    this.checkAdmission(owner, rawTabId);
    const urls = (tab) => [tab.url, tab.pendingUrl].filter((value) => typeof value === 'string');
    const isNewTab = (url) =>
      this.schemes.some((scheme) => NEW_TAB_PATHS.some((path) => url === `${scheme}://${path}`));
    let normalized = false;
    if (urls(tab).some(isNewTab)) {
      try {
        tab = await this.chrome.tabs.update(rawTabId, { url: 'about:blank' });
      } catch (error) {
        throw new ConnectorError('chrome_rejected', String(error?.message ?? error));
      }
      normalized = true;
      try {
        if (!Number.isSafeInteger(tab?.id) || tab.id !== rawTabId)
          throw new Error('Chrome acknowledged normalization without the admitted tab identity');
        const deadline = this.now() + 5000;
        if (tab.url !== 'about:blank') {
          this.checkAdmission(owner, rawTabId);
          tab = await this.chrome.tabs.get(rawTabId);
          if (tab.id !== rawTabId) throw new Error('tab identity changed after normalization');
        }
        while (tab.url !== 'about:blank') {
          this.checkAdmission(owner, rawTabId);
          if (this.now() >= deadline)
            throw new Error('new-tab normalization did not reach about:blank within five seconds');
          await this.sleep(25);
          tab = await this.chrome.tabs.get(rawTabId);
          if (tab.id !== rawTabId) throw new Error('tab identity changed during normalization');
        }
      } catch (error) {
        throw new ConnectorError(
          'outcome_unknown',
          'acknowledged tab normalization was not confirmed',
          { tabId: rawTabId, cause: String(error?.message ?? error) },
        );
      }
    }
    try {
      this.checkAdmission(owner, rawTabId);
    } catch (error) {
      if (normalized)
        throw new ConnectorError(
          'outcome_unknown',
          'owner ended after acknowledged normalization',
          { tabId: rawTabId },
        );
      throw error;
    }
    if (urls(tab).some((url) => this.schemes.some((scheme) => url.startsWith(`${scheme}://`))))
      throw new ConnectorError(
        'internal_tab_refused',
        'this browser-internal tab cannot be claimed',
      );
    return { tab, normalized };
  }
}
