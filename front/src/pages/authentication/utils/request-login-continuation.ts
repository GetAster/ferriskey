import { isNavigableRedirect } from '../../../lib/follow-server-redirect.ts'
import type { LoginContinuation } from './continue-login'

export type LoginContinuationResult =
  | { kind: 'unavailable' }
  | { kind: 'continue'; next: LoginContinuation }

// The action cookie identifies the original login, including client, redirect,
// state and PKCE challenge. Do not create a new OAuth transaction.
export async function requestLoginContinuation(
  apiUrl: string,
  realm: string,
  fetcher: typeof fetch = fetch,
): Promise<LoginContinuationResult> {
  const response = await fetcher(
    `${apiUrl.replace(/\/+$/, '')}/realms/${encodeURIComponent(realm)}/login-actions/continue`,
    { method: 'POST', credentials: 'include' },
  )
  if (response.status === 401) return { kind: 'unavailable' }

  const body: unknown = await response.json().catch(() => undefined)
  if (!response.ok) {
    const data = body && typeof body === 'object' ? body as Record<string, unknown> : undefined
    const message = typeof data?.message === 'string' ? data.message : `HTTP ${response.status}`
    throw Object.assign(new Error(message), { status: response.status, data })
  }
  if (body && typeof body === 'object') {
    const next = body as LoginContinuation
    if (isNavigableRedirect(next.url)) {
      return { kind: 'continue', next: { url: next.url } }
    }
    const actions = next.required_actions
    if (Array.isArray(actions) && actions.length > 0 && actions.every(action =>
      ['verify_email', 'configure_otp', 'configure_passkey', 'update_password'].includes(action),
    )) {
      return { kind: 'continue', next: { required_actions: actions } }
    }
  }
  throw new Error('The server did not return a valid login continuation.')
}
