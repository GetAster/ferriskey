// PKCE (RFC 7636) for the admin console, which is a public client: it has no
// secret, so the code_verifier is the only thing proving that the browser
// redeeming an authorization code is the one that requested it.

const FLOW_STORAGE_PREFIX = 'oauth_flow:'

type OAuthFlow = {
  codeVerifier: string
  // Kept alongside the verifier so the value sent to the token endpoint is
  // byte-identical to the one sent to /auth, which the server now requires.
  redirectUri: string
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

// RFC 7636 §4.1: 43–128 chars from the unreserved set. 32 random bytes
// base64url-encoded yields exactly 43.
export function generateCodeVerifier(): string {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  return base64UrlEncode(bytes)
}

// RFC 7636 §4.2: BASE64URL(SHA256(ASCII(code_verifier))).
// crypto.subtle needs a secure context, so the console must be served over
// HTTPS (or localhost).
export async function deriveCodeChallenge(codeVerifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier))
  return base64UrlEncode(new Uint8Array(digest))
}

// Shared by tabs on this origin: email links can open a fresh tab. Records
// expire after ten minutes and are removed when read. Authorization codes are
// also single-use server-side (localStorage read/remove is not atomic).
export const OAUTH_FLOW_TTL_MS = 10 * 60 * 1000

function parseFlow(raw: string): OAuthFlow | null {
  try {
    const value = JSON.parse(raw)
    if (!value || typeof value !== 'object' ||
      typeof value.codeVerifier !== 'string' ||
      !/^[A-Za-z0-9._~-]{43,128}$/.test(value.codeVerifier) ||
      typeof value.redirectUri !== 'string' || !value.redirectUri) return null
    if (typeof value.expiresAt !== 'number' ||
      !Number.isFinite(value.expiresAt) || value.expiresAt <= Date.now() ||
      value.expiresAt > Date.now() + OAUTH_FLOW_TTL_MS) return null
    return { codeVerifier: value.codeVerifier, redirectUri: value.redirectUri }
  } catch {
    return null
  }
}

export function storeOAuthFlow(state: string, flow: OAuthFlow): void {
  try {
    // Bound abandoned records without disturbing unrelated browser storage.
    for (let i = localStorage.length - 1; i >= 0; i--) {
      const key = localStorage.key(i)
      if (key?.startsWith(FLOW_STORAGE_PREFIX) &&
        !parseFlow(localStorage.getItem(key) ?? '')) {
        localStorage.removeItem(key)
        localStorage.removeItem(`oauth_state:${key.slice(FLOW_STORAGE_PREFIX.length)}`)
      }
    }
    localStorage.setItem(`${FLOW_STORAGE_PREFIX}${state}`, JSON.stringify({
      ...flow, expiresAt: Date.now() + OAUTH_FLOW_TTL_MS,
    }))
  } catch {
    // Storage unavailable: callback rejects the missing flow before exchange.
  }
}

export function takeOAuthFlow(state: string | null, expectedRedirectUri?: string): OAuthFlow | null {
  if (!state) return null
  const key = `${FLOW_STORAGE_PREFIX}${state}`
  try {
    const raw = localStorage.getItem(key)
    localStorage.removeItem(key)
    const flow = raw !== null ? parseFlow(raw) : null
    if (flow && expectedRedirectUri !== undefined && flow.redirectUri !== expectedRedirectUri) return null
    return flow
  } catch {
    return null
  }
}
