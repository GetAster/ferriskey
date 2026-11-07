import { isNavigableRedirect } from './follow-server-redirect.ts'

// Only responses on a human authentication page can navigate this way. The
// server derives redirect_url from its saved, validated OAuth transaction.
export function authenticationRequirementRedirect(
  error: unknown,
  pathname: string
): string | undefined {
  const match = /^\/realms\/([^/]+)\/authentication(?:\/|$)/.exec(pathname)
  if (!match || !error || typeof error !== 'object') return undefined
  const record = error as Record<string, unknown>
  const body =
    record.data && typeof record.data === 'object'
      ? (record.data as Record<string, unknown>)
      : record
  if (body.reason === 'passkey_authentication_required') {
    return `/realms/${match[1]}/authentication/login?passkey_required=true`
  }
  if (
    body.reason === 'unmet_authentication_requirements' &&
    isNavigableRedirect(body.redirect_url)
  ) {
    return body.redirect_url
  }
  return undefined
}
