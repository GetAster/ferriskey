// Only short-circuit a known empty session. Authentication callbacks and all
// public authentication steps still need the app, as do stored sessions whose
// validity is checked by the existing auth lifecycle after API setup.
export function initialLoginRealm(
  pathname: string,
  session: { accessToken: string | null; refreshToken: string | null; sessionRealm: string | null },
  hasHydrated: boolean,
): string | null {
  if (!hasHydrated || session.accessToken || session.refreshToken) return null
  if (/^\/realms\/[^/]+\/authentication(?:\/|$)/.test(pathname)) return null
  if (session.sessionRealm !== null) return session.sessionRealm
  const realmSegment = pathname.match(/^\/realms\/([^/]+)/)?.[1]
  if (!realmSegment) return 'master'
  try { return decodeURIComponent(realmSegment) } catch { return realmSegment }
}
