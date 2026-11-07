// Query parameters are display hints only, never identity or authorization data.
export function providerDisplayName(alias: string | null): string | undefined {
  if (!alias || !/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/.test(alias)) return undefined
  const known: Record<string, string> = { google: 'Google', microsoft: 'Microsoft', apple: 'Apple' }
  return Object.prototype.hasOwnProperty.call(known, alias.toLowerCase())
    ? known[alias.toLowerCase()]
    : alias
}

export async function declineProviderLink(
  apiUrl: string,
  realm: string,
  fetcher: typeof fetch = fetch
): Promise<void> {
  if (!realm) throw new Error('Missing realm')
  const response = await fetcher(
    `${apiUrl.replace(/\/+$/, '')}/realms/${encodeURIComponent(realm)}/login-actions/decline-provider-link`,
    {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
      redirect: 'error',
    }
  )
  if (response.status === 204) return
  const body: unknown = await response.json().catch(() => undefined)
  const data = body && typeof body === 'object' ? (body as Record<string, unknown>) : undefined
  const message = typeof data?.message === 'string' ? data.message : `HTTP ${response.status}`
  throw Object.assign(new Error(message), { status: response.status, data })
}
