// Device approval is authenticated by the SSO cookie, independently of console tokens.
export async function requestDevice<T>(
  apiUrl: string,
  realm: string,
  request: { userCode: string } | { data: unknown },
  fetcher: typeof fetch = fetch,
): Promise<T> {
  const base = `${apiUrl.replace(/\/+$/, '')}/realms/${encodeURIComponent(realm)}/device`
  const preview = 'userCode' in request
  const response = await fetcher(
    preview ? `${base}/preview?${new URLSearchParams({ user_code: request.userCode })}` : `${base}/verify`,
    preview
      ? { method: 'GET', credentials: 'include' }
      : { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(request.data) },
  )
  const data = await response.json().catch(() => undefined)
  if (!response.ok) {
    const message = typeof data?.message === 'string' ? data.message : `HTTP ${response.status}`
    throw Object.assign(new Error(message), { status: response.status, data })
  }
  if (!data || typeof data !== 'object') throw new Error('Invalid device response')
  return data as T
}
