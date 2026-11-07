// Enter authentication through the server so deployments can route human
// sign-in to their own UI instead of the console's client-side routes.
export function navigateToLogin(realm = 'master', errorMessage?: string): void {
  const params = new URLSearchParams()
  if (errorMessage) params.set('login_error', errorMessage)
  const query = params.toString()
  window.location.replace(`/realms/${encodeURIComponent(realm)}/authentication/login${query ? `?${query}` : ''}`)
}
