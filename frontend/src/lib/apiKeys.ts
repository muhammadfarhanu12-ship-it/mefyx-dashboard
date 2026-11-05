/**
 * Helpers for the API Keys page.
 *
 * Kept free of React and of the store so they can be unit-tested with plain `node --test`.
 */

export const FULL_KEY_UNAVAILABLE_MESSAGE =
  'For security, the full key is only shown once, when it is created, and Mefyx stores only a one-way hash of it. ' +
  'If you no longer have this key, revoke it and generate a new one.';

export type ApiKeyErrorKind = 'plan_limit' | 'auth' | 'rate_limited' | 'unavailable' | 'unknown';

export interface ApiKeyErrorInfo {
  kind: ApiKeyErrorKind;
  message: string;
}

interface ErrorLike {
  status?: unknown;
  message?: unknown;
  payload?: unknown;
}

function serverDetail(error: ErrorLike): string {
  const payload = error.payload as { detail?: unknown; message?: unknown; error?: unknown } | undefined;
  for (const candidate of [payload?.detail, payload?.message, payload?.error, error.message]) {
    if (typeof candidate === 'string' && candidate.trim()) return candidate.trim();
  }
  return '';
}

/** Turn any failure from "generate API key" into a message a user can act on. */
export function describeApiKeyError(error: unknown): ApiKeyErrorInfo {
  const err: ErrorLike = error && typeof error === 'object' ? (error as ErrorLike) : {};
  const status = typeof err.status === 'number' ? err.status : 0;
  const detail = serverDetail(err);

  if (status === 403 && /allows up to|active api key/i.test(detail)) {
    return {
      kind: 'plan_limit',
      message: `${detail.replace(/\.?\s*$/, '.')} Revoke an existing key below to create a new one, or upgrade your plan for more keys.`,
    };
  }
  if (status === 401 || status === 403) {
    return {
      kind: 'auth',
      message: status === 401 ? 'Your session has expired. Please sign in again.' : detail || 'You do not have permission to create API keys.',
    };
  }
  if (status === 429) {
    return { kind: 'rate_limited', message: 'Too many requests. Please wait a moment and try again.' };
  }
  if (status >= 500 || status === 0) {
    return {
      kind: 'unavailable',
      message: 'The server could not create the key right now. Please try again in a moment.',
    };
  }
  return { kind: 'unknown', message: detail || 'The API key could not be generated.' };
}

export interface ClipboardEnv {
  clipboard?: { writeText?: (text: string) => Promise<void> } | null;
  document?: {
    createElement: (tag: string) => any;
    body?: { appendChild: (node: any) => void; removeChild: (node: any) => void };
    execCommand?: (command: string) => boolean;
  } | null;
}

function defaultEnv(): ClipboardEnv {
  const g = globalThis as any;
  return { clipboard: g.navigator?.clipboard ?? null, document: g.document ?? null };
}

/**
 * Copy text to the clipboard. Returns true on success, false on failure (never throws).
 * `navigator.clipboard` only exists in secure contexts (https / localhost), so fall back to the
 * legacy selection + execCommand("copy") approach.
 */
export async function copyTextToClipboard(text: string, env: ClipboardEnv = defaultEnv()): Promise<boolean> {
  if (!text) return false;

  try {
    if (env.clipboard && typeof env.clipboard.writeText === 'function') {
      await env.clipboard.writeText(text);
      return true;
    }
  } catch {
    // permission denied / insecure context: try the fallback below
  }

  const doc = env.document;
  if (!doc || !doc.body || typeof doc.execCommand !== 'function') return false;
  let textarea: any = null;
  try {
    textarea = doc.createElement('textarea');
    textarea.value = text;
    textarea.setAttribute?.('readonly', '');
    textarea.style && Object.assign(textarea.style, { position: 'fixed', top: '0', left: '-9999px', opacity: '0' });
    doc.body.appendChild(textarea);
    textarea.focus?.();
    textarea.select?.();
    textarea.setSelectionRange?.(0, text.length);
    return doc.execCommand('copy') === true;
  } catch {
    return false;
  } finally {
    try {
      if (textarea) doc.body.removeChild(textarea);
    } catch {
      // ignore
    }
  }
}