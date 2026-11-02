import { ApiRequestError, apiRequest, buildApiUrl, logDevelopmentApiDiagnostic, resolveBackendOrigin } from './api';

export const AUTH_SERVICE_UNAVAILABLE_MESSAGE =
  'Server unavailable. Please check your backend connection and try again.';
export const AUTH_INVALID_CREDENTIALS_MESSAGE = 'Invalid email or password.';
export const AUTH_LOGIN_ENDPOINT_NOT_FOUND_MESSAGE = 'Login endpoint not found. Please contact support.';
export const AUTH_FAILED_MESSAGE = 'Authentication failed. Please try again.';

export const PASSWORD_POLICY_HINT =
  'Use 12+ characters with at least one uppercase letter, one lowercase letter, and one number.';

export type AuthMessageResponse = {
  message?: string;
  email?: string;
  email_sent?: boolean;
};

export type AuthUser = {
  id: string;
  email: string;
  name?: string | null;
  is_verified: boolean;
};

export type LoginResponse = {
  access_token: string;
  refresh_token?: string | null;
  token_type: string;
  user?: AuthUser | null;
};

export type AuthErrorCode =
  | 'server-unavailable'
  | 'invalid-credentials'
  | 'endpoint-not-found'
  | 'validation-error'
  | 'forbidden'
  | 'authentication-failed';

export class AuthApiError extends Error {
  code: AuthErrorCode;
  status?: number;

  constructor(message: string, code: AuthErrorCode, status?: number) {
    super(message);
    this.name = 'AuthApiError';
    this.code = code;
    this.status = status;
  }
}

const passwordPolicyChecks = [
  /[A-Z]/,
  /[a-z]/,
  /\d/,
];

function isAuthServiceUnavailable(error: unknown): boolean {
  if (!(error instanceof Error)) {
    return false;
  }

  const normalizedMessage = error.message.toLowerCase();
  let backendOrigin = '';
  try {
    backendOrigin = resolveBackendOrigin().toLowerCase();
  } catch {
    backendOrigin = '';
  }
  return (
    normalizedMessage.includes('server unavailable') ||
    normalizedMessage.includes('vite_api_base_url') ||
    normalizedMessage.includes('unable to reach') ||
    normalizedMessage.includes('failed to fetch') ||
    normalizedMessage.includes('cors') ||
    normalizedMessage.includes('networkerror') ||
    normalizedMessage.includes('timed out') ||
    Boolean(backendOrigin && normalizedMessage.includes(backendOrigin))
  );
}

function toAuthApiError(error: unknown): AuthApiError {
  if (error instanceof AuthApiError) {
    return error;
  }

  if (error instanceof ApiRequestError) {
    if (error.status === 401) {
      return new AuthApiError(AUTH_INVALID_CREDENTIALS_MESSAGE, 'invalid-credentials', error.status);
    }

    if (error.status === 404) {
      return new AuthApiError(AUTH_LOGIN_ENDPOINT_NOT_FOUND_MESSAGE, 'endpoint-not-found', error.status);
    }

    if (error.status === 403) {
      const message = String(error.message || '');
      if (isEmailVerificationRequired(message)) {
        return new AuthApiError(message, 'forbidden', error.status);
      }
      return new AuthApiError(AUTH_INVALID_CREDENTIALS_MESSAGE, 'invalid-credentials', error.status);
    }

    if (error.status === 422) {
      return new AuthApiError(String(error.message || 'Validation error.'), 'validation-error', error.status);
    }

    if (error.status >= 500 || error.status === 502 || error.status === 503 || error.status === 504) {
      return new AuthApiError(AUTH_SERVICE_UNAVAILABLE_MESSAGE, 'server-unavailable', error.status);
    }

    return new AuthApiError(String(error.message || AUTH_FAILED_MESSAGE), 'authentication-failed', error.status);
  }

  if (error instanceof TypeError || isAuthServiceUnavailable(error)) {
    return new AuthApiError(AUTH_SERVICE_UNAVAILABLE_MESSAGE, 'server-unavailable');
  }

  if (error instanceof Error && error.message.trim()) {
    return new AuthApiError(error.message, 'authentication-failed');
  }

  return new AuthApiError(AUTH_FAILED_MESSAGE, 'authentication-failed');
}

async function authRequest<T>(endpoint: string, init: RequestInit): Promise<T> {
  const controller = new AbortController();
  // Bumped from 15000ms to 30000ms: MongoDB Atlas cold starts on the backend
  // can take up to ~15-20s to establish a connection, which was longer than
  // the old 15s frontend timeout, causing "Server unavailable" even though
  // the backend eventually succeeded.
  const timeoutId = window.setTimeout(() => controller.abort(), 30000);

  try {
    return await apiRequest<T>(endpoint, {
      ...init,
      signal: init.signal || controller.signal,
    });
  } catch (error) {
    throw toAuthApiError(error);
  } finally {
    window.clearTimeout(timeoutId);
  }
}

export async function verifyBackendSession(accessToken: string): Promise<AuthUser> {
  const normalizedAccessToken = String(accessToken || '').trim();
  if (!normalizedAccessToken) {
    throw new AuthApiError(AUTH_FAILED_MESSAGE, 'authentication-failed');
  }

  try {
    return await authRequest<AuthUser>('/api/v1/auth/me', {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${normalizedAccessToken}`,
      },
      cache: 'no-store',
    });
  } catch (error) {
    const mappedError = toAuthApiError(error);
    if (mappedError.code === 'server-unavailable') {
      throw mappedError;
    }
    throw new AuthApiError(AUTH_FAILED_MESSAGE, 'authentication-failed', mappedError.status);
  }
}

export async function signupWithEmail(payload: {
  name?: string;
  email: string;
  password: string;
  turnstile_token?: string;
}): Promise<AuthMessageResponse> {
  return authRequest<AuthMessageResponse>('/api/v1/auth/signup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

export async function signInWithEmail(email: string, password: string, turnstileToken?: string): Promise<LoginResponse> {
  const loginUrl = buildApiUrl('/api/v1/auth/login');
  logDevelopmentApiDiagnostic({
    category: 'login-request-config',
    loginUrl,
  });

  // NOTE: we intentionally do NOT pre-flight /api/v1/health here anymore.
  // The backend's /auth/login endpoint now absorbs a Mongo/Render cold start
  // itself (see mongo_cold_start_wait_middleware in main.py), waiting up to
  // 20s before returning a clear 503. A health pre-check here used to
  // instant-fail on a cold cluster (health uses the fast-fail ping_mongo())
  // and short-circuit before login ever got a chance to wait it out —
  // which is why a fresh sign-in needed a second manual attempt.

  try {
    const data = await authRequest<LoginResponse>('/api/v1/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email: email.trim(),
        password,
        ...(turnstileToken ? { turnstile_token: turnstileToken } : {}),
      }),
    });

    if (!data?.access_token) {
      throw new AuthApiError(AUTH_FAILED_MESSAGE, 'authentication-failed');
    }

    await verifyBackendSession(String(data.access_token));
    return data;
  } catch (error) {
    const mappedError = toAuthApiError(error);
    logDevelopmentApiDiagnostic({
      category: mappedError.code,
      loginUrl,
      status: mappedError.status,
    });
    if (mappedError.code === 'endpoint-not-found') {
      console.warn('[Sentinel Login] login endpoint returned 404', {
        loginUrl,
      });
    }
    throw mappedError;
  }
}

export async function resendVerificationEmail(email: string, turnstileToken?: string): Promise<AuthMessageResponse> {
  return authRequest<AuthMessageResponse>('/api/v1/auth/resend-verification', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: email.trim(), ...(turnstileToken ? { turnstile_token: turnstileToken } : {}) }),
  });
}

export async function requestPasswordReset(email: string, turnstileToken?: string): Promise<AuthMessageResponse> {
  return authRequest<AuthMessageResponse>('/api/v1/auth/forgot-password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: email.trim(), ...(turnstileToken ? { turnstile_token: turnstileToken } : {}) }),
  });
}

export async function resetPasswordWithToken(token: string, newPassword: string, turnstileToken?: string): Promise<AuthMessageResponse> {
  return authRequest<AuthMessageResponse>('/api/v1/auth/reset-password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token, new_password: newPassword, ...(turnstileToken ? { turnstile_token: turnstileToken } : {}) }),
  });
}

export async function verifyEmailToken(token: string): Promise<AuthMessageResponse> {
  return authRequest<AuthMessageResponse>(`/api/v1/auth/verify-email?token=${encodeURIComponent(token)}`, {
    method: 'GET',
  });
}

export async function logoutFromServer(refreshToken?: string | null): Promise<AuthMessageResponse> {
  return authRequest<AuthMessageResponse>('/api/v1/auth/logout', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(refreshToken ? { refresh_token: refreshToken } : {}),
  });
}

export function isEmailVerificationRequired(message: string | null | undefined): boolean {
  const normalized = message?.toLowerCase() || '';
  return normalized.includes('not verified') || normalized.includes('verify your email');
}

export function getPasswordPolicyError(password: string): string | null {
  const normalizedPassword = password.trim();
  if (!normalizedPassword) {
    return 'Password is required.';
  }
  if (normalizedPassword.length < 12) {
    return PASSWORD_POLICY_HINT;
  }
  if (!passwordPolicyChecks.every((pattern) => pattern.test(normalizedPassword))) {
    return PASSWORD_POLICY_HINT;
  }
  return null;
}