import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

// Bundle the real page + store (Vite's import.meta.env supplied in memory, like the other tests) and render it.
const projectDir = fileURLToPath(new URL('../../', import.meta.url));

// A stand-in for the zustand store: zustand server-renders from its *initial* state, so tests could not
// otherwise put keys into it. Everything else (the real page component, its helpers, UI components) is real.
const storeStub = `
  let state = {};
  export const __setState = (next) => { state = next; };
  export const useStore = (selector) => (typeof selector === 'function' ? selector(state) : state);
`;

async function loadRenderer(): Promise<(keys: unknown[]) => string> {
  const result = await build({
    absWorkingDir: projectDir,
    stdin: {
      contents: `
        import React from 'react';
        import { renderToString } from 'react-dom/server';
        import ApiKeys from './src/pages/ApiKeys';
        import { __setState } from 'store-stub';
        export function render(keys) {
          __setState({
            apiKeys: keys, isLoading: false,
            fetchApiKeys: () => {}, generateApiKey: async () => ({}), revokeApiKey: async () => {},
          });
          return renderToString(React.createElement(ApiKeys));
        }
      `,
      resolveDir: projectDir,
      loader: 'tsx',
    },
    plugins: [
      {
        name: 'store-stub',
        setup(b) {
          b.onResolve({ filter: /^store-stub$/ }, () => ({ path: 'store-stub', namespace: 'stub' }));
          b.onResolve({ filter: /stores\/useStore$/ }, () => ({ path: 'store-stub', namespace: 'stub' }));
          b.onLoad({ filter: /.*/, namespace: 'stub' }, () => ({ contents: storeStub, loader: 'js' }));
        },
      },
    ],
    bundle: true,
    write: false,
    platform: 'node',
    format: 'cjs',
    define: { 'import.meta.env': JSON.stringify({ PROD: true, VITE_API_BASE_URL: 'https://backend.example/api/v1' }) },
    logLevel: 'silent',
  });
  const dir = mkdtempSync(join(tmpdir(), 'apikeys-page-'));
  const file = join(dir, 'bundle.cjs');
  writeFileSync(file, result.outputFiles[0].text);
  const loaded = createRequire(import.meta.url)(file) as { render: (keys: unknown[]) => string };
  return loaded.render;
}

const rendererPromise = loadRenderer();

// React inserts <!-- --> between adjacent text nodes when server-rendering; remove them before matching text.
const plain = (html: string) => html.replace(/<!-- -->/g, '');

const existingKey = {
  id: '1',
  name: 'Workspace Primary',
  created_at: '2026-04-14T10:00:00Z',
  last_used: '2026-06-03T10:00:00Z',
  status: 'active',
  usage_count: 20,
};

test('an existing key (secret not recoverable) explains why and keeps Revoke available', async () => {
  const html = plain((await rendererPromise)([existingKey]));
  assert.ok(html.includes('Workspace Primary'));
  assert.ok(html.includes('1 active key'), 'shows how many active keys there are');
  assert.ok(html.includes('Why can I not copy this key?'), 'copy button is explained, not dead');
  assert.ok(html.includes('Why can I not see this key?'), 'view button is explained, not dead');
  assert.ok(html.includes('Revoke this key and generate a new one'), 'tells the user how to get a new key');
  assert.ok(html.includes('Revoke'));
  assert.ok(!html.includes('role="alert"'), 'no error banner before anything fails');
});

test('a key whose one-time secret is in memory gets working view and copy controls', async () => {
  const secret = 'sentinel_sk_gateway_abcdefghijklmnopqrstuvwxyz123456';
  const html = plain((await rendererPromise)([{ ...existingKey, id: '2', name: 'New Key 2', key: secret }]));
  assert.ok(html.includes('aria-label="Copy key"'));
  assert.ok(html.includes('aria-label="Show key"'));
  assert.ok(!html.includes('abcdefghijklmnopqrstuvwxyz123456'), 'secret stays masked until the user clicks show');
});

test('with no keys the page still renders a Generate button', async () => {
  const html = plain((await rendererPromise)([]));
  assert.ok(html.includes('Generate New Key'));
  assert.ok(html.includes('0 active keys'));
});