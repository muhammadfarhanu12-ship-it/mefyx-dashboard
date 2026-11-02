import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { runInNewContext } from 'node:vm';
import { build } from 'esbuild';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import type * as AuthService from '../services/authApi';
import type { loadTurnstile, TurnstileApi } from '../services/turnstile';
import type { Turnstile as TurnstileComponent } from '../components/Turnstile';

const require = createRequire(import.meta.url);
const bundles = new Map<string, Promise<string>>();

async function loadModule<T>(entry: string, globals: Record<string, unknown> = {}): Promise<T> {
  if (!bundles.has(entry)) {
    bundles.set(entry, build({
      absWorkingDir: fileURLToPath(new URL('../../', import.meta.url)),
      entryPoints: [entry], bundle: true, write: false, platform: 'node', format: 'cjs',
      external: ['react', 'react/jsx-runtime'],
      define: { 'import.meta.env': JSON.stringify({ PROD: true, VITE_API_BASE_URL: 'https://backend.example' }) },
    }).then((result) => result.outputFiles[0].text));
  }
  const module = { exports: {} };
  runInNewContext(await bundles.get(entry)!, {
    module, exports: module.exports, require, console, URL, URLSearchParams, Headers,
    FormData, AbortController, DOMException, Error, setTimeout, clearTimeout, ...globals,
  });
  return module.exports as T;
}

test('widget imports and prerenders without window, document, or a secret', async () => {
  const { Turnstile } = await loadModule<{ Turnstile: typeof TurnstileComponent }>('src/components/Turnstile.tsx');
  const markup = renderToStaticMarkup(createElement(Turnstile, { action: 'signup', onToken: () => {} }));
  assert.match(markup, /Security verification/);
  assert.doesNotMatch(markup, /<script|SECRET|secret/);
  const service = await loadModule<{ loadTurnstile: typeof loadTurnstile }>('src/services/turnstile.ts');
  await assert.rejects(service.loadTurnstile(), /requires a browser/);
});

type FakeScript = {
  src: string;
  onload: (() => void) | null;
  onerror: (() => void) | null;
  remove(): void;
  removed: boolean;
};

async function createBrowser() {
  const scripts: FakeScript[] = [];
  let expire: (() => void) | undefined;
  let cleared = 0;
  const window: { turnstile?: TurnstileApi; setTimeout: Function; clearTimeout: Function } = {
    setTimeout: (callback: () => void) => { expire = callback; return 1; },
    clearTimeout: () => { cleared++; },
  };
  const document = {
    createElement: () => {
      const script: FakeScript = { src: '', onload: null, onerror: null, removed: false, remove() { this.removed = true; } };
      return script;
    },
    head: { appendChild: (script: FakeScript) => scripts.push(script) },
  };
  const service = await loadModule<{ loadTurnstile: typeof loadTurnstile }>('src/services/turnstile.ts', { window, document });
  return { service, scripts, window, expire: () => expire!(), cleared: () => cleared };
}

test('concurrent widgets load one official script and wait for API readiness', async () => {
  const browser = await createBrowser();
  const first = browser.service.loadTurnstile();
  let ready: (() => void) | undefined;
  const api: TurnstileApi = { ready: (callback) => { ready = callback; }, render: () => 'widget', remove: () => {} };
  browser.window.turnstile = api;
  browser.scripts[0].onload!();
  const second = browser.service.loadTurnstile();
  assert.equal(first, second);
  assert.equal(browser.scripts.length, 1);
  assert.equal(browser.scripts[0].src, 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit');
  ready!();
  assert.equal(await first, api);
  assert.equal(browser.cleared(), 1);
});

for (const reason of ['network failure', 'timeout'] as const) {
  test(`script ${reason} fails closed and permits a later retry`, async () => {
    const browser = await createBrowser();
    const first = browser.service.loadTurnstile();
    const failed = assert.rejects(first, /Unable to load security verification/);
    if (reason === 'timeout') browser.expire();
    else browser.scripts[0].onerror!();
    await failed;
    assert.equal(browser.scripts[0].removed, true);

    const retry = browser.service.loadTurnstile();
    assert.equal(browser.scripts.length, 2);
    const api: TurnstileApi = { ready: (callback) => callback(), render: () => 'widget', remove: () => {} };
    browser.window.turnstile = api;
    browser.scripts[1].onload!();
    assert.equal(await retry, api);
  });
}

test('all public auth requests include their challenge while preserving login session verification', async () => {
  const requests: { url: string; init: RequestInit }[] = [];
  const service = await loadModule<typeof AuthService>('src/services/authApi.ts', {
    window: { location: { origin: 'https://mefyx.com' }, setTimeout, clearTimeout },
    fetch: async (url: string, init: RequestInit) => {
      requests.push({ url, init });
      return Response.json({ data: url.endsWith('/login') ? { access_token: 'signed-access-token' } : { message: 'Success' } });
    },
  });
  await service.signupWithEmail({ email: 'ada@example.com', password: 'TestPassword123', turnstile_token: 'signup-token' });
  await service.signInWithEmail(' ada@example.com ', 'TestPassword123', 'login-token');
  await service.requestPasswordReset(' ada@example.com ', 'forgot-token');
  await service.resetPasswordWithToken('emailed-reset-token', 'NewPassword123', 'reset-token');
  await service.resendVerificationEmail(' ada@example.com ', 'resend-token');

  const posts = requests.filter(({ init }) => init.method === 'POST');
  assert.deepEqual(posts.map(({ url, init }) => [new URL(url).pathname, JSON.parse(String(init.body)).turnstile_token]), [
    ['/api/v1/auth/signup', 'signup-token'],
    ['/api/v1/auth/login', 'login-token'],
    ['/api/v1/auth/forgot-password', 'forgot-token'],
    ['/api/v1/auth/reset-password', 'reset-token'],
    ['/api/v1/auth/resend-verification', 'resend-token'],
  ]);
  const reset = JSON.parse(String(posts[3].init.body));
  assert.equal(reset.token, 'emailed-reset-token');
  assert.equal(reset.new_password, 'NewPassword123');
  const session = requests.find(({ init }) => init.method === 'GET')!;
  assert.equal(session.url, 'https://backend.example/api/v1/auth/me');
  assert.equal(new Headers(session.init.headers).get('Authorization'), 'Bearer signed-access-token');
});

test('invalid auth challenges report the server error and are never automatically retried', async () => {
  let calls = 0;
  const service = await loadModule<typeof AuthService>('src/services/authApi.ts', {
    window: { location: { origin: 'https://mefyx.com' }, setTimeout, clearTimeout },
    fetch: async () => {
      calls++;
      return Response.json({ detail: 'Security verification failed. Please try again.' }, { status: 400 });
    },
  });
  await assert.rejects(service.signInWithEmail('ada@example.com', 'TestPassword123', 'expired-token'), /Security verification failed/);
  assert.equal(calls, 1);
});
