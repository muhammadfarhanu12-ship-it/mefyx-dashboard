import test from 'node:test';
import assert from 'node:assert/strict';

import { copyTextToClipboard, describeApiKeyError, FULL_KEY_UNAVAILABLE_MESSAGE } from '../lib/apiKeys';

// Mirrors the real HttpError shape from services/authenticatedFetch.ts
class FakeHttpError extends Error {
  status: number;
  payload: any;
  constructor(message: string, status: number, payload: any = null) {
    super(message);
    this.name = 'HttpError';
    this.status = status;
    this.payload = payload;
  }
}

test('plan limit 403 (the exact error from the console) becomes an actionable message', () => {
  const info = describeApiKeyError(new FakeHttpError('The FREE plan allows up to 1 active API key(s).', 403));
  assert.equal(info.kind, 'plan_limit');
  assert.match(info.message, /FREE plan allows up to 1 active API key/);
  assert.match(info.message, /Revoke an existing key/);
  assert.match(info.message, /upgrade/i);
});

test('server detail in the payload is used when the message is generic', () => {
  const info = describeApiKeyError(new FakeHttpError('Request failed', 403, { detail: 'The PRO plan allows up to 5 active API key(s).' }));
  assert.equal(info.kind, 'plan_limit');
  assert.match(info.message, /PRO plan allows up to 5/);
});

test('401 asks the user to sign in again', () => {
  assert.equal(describeApiKeyError(new FakeHttpError('Unauthorized', 401)).kind, 'auth');
  assert.match(describeApiKeyError(new FakeHttpError('Unauthorized', 401)).message, /sign in again/i);
});

test('other 403 is a permission message, not a plan-limit one', () => {
  const info = describeApiKeyError(new FakeHttpError('Forbidden', 403));
  assert.equal(info.kind, 'auth');
});

test('429, 5xx and network failures have friendly messages', () => {
  assert.equal(describeApiKeyError(new FakeHttpError('x', 429)).kind, 'rate_limited');
  assert.equal(describeApiKeyError(new FakeHttpError('x', 503)).kind, 'unavailable');
  assert.equal(describeApiKeyError(new TypeError('Failed to fetch')).kind, 'unavailable');
  assert.equal(describeApiKeyError(undefined).kind, 'unavailable');
});

test('unknown client errors fall back to the server text', () => {
  const info = describeApiKeyError(new FakeHttpError('Name is too long', 422));
  assert.equal(info.kind, 'unknown');
  assert.equal(info.message, 'Name is too long');
});

test('FULL_KEY_UNAVAILABLE_MESSAGE tells the user what to do', () => {
  assert.match(FULL_KEY_UNAVAILABLE_MESSAGE, /only shown once/);
  assert.match(FULL_KEY_UNAVAILABLE_MESSAGE, /revoke it and generate a new one/i);
});

test('copy uses the async clipboard API when available', async () => {
  let written = '';
  const ok = await copyTextToClipboard('sentinel_sk_abc', { clipboard: { writeText: async (t) => { written = t; } }, document: null });
  assert.equal(ok, true);
  assert.equal(written, 'sentinel_sk_abc');
});

test('copy falls back to execCommand when the clipboard API is blocked (http / insecure context)', async () => {
  const appended: any[] = [];
  const removed: any[] = [];
  let copyCommand = '';
  const textarea: any = { style: {}, setAttribute() {}, focus() {}, select() {}, setSelectionRange() {}, value: '' };
  const ok = await copyTextToClipboard('sentinel_sk_abc', {
    clipboard: { writeText: async () => { throw new Error('NotAllowedError'); } },
    document: {
      createElement: () => textarea,
      body: { appendChild: (n) => appended.push(n), removeChild: (n) => removed.push(n) },
      execCommand: (c) => { copyCommand = c; return true; },
    },
  });
  assert.equal(ok, true);
  assert.equal(copyCommand, 'copy');
  assert.equal(textarea.value, 'sentinel_sk_abc');
  assert.equal(appended.length, 1);
  assert.equal(removed.length, 1, 'temporary textarea must be cleaned up');
});

test('copy reports failure instead of throwing when nothing works', async () => {
  assert.equal(await copyTextToClipboard('x', { clipboard: null, document: null }), false);
  assert.equal(await copyTextToClipboard('', { clipboard: { writeText: async () => {} }, document: null }), false);
  const ok = await copyTextToClipboard('x', {
    clipboard: null,
    document: { createElement: () => ({ style: {} }), body: { appendChild() {}, removeChild() {} }, execCommand: () => false },
  });
  assert.equal(ok, false);
});