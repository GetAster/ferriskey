import assert from 'node:assert/strict'
import { beforeEach, test } from 'node:test'
import { OAUTH_FLOW_TTL_MS, storeOAuthFlow, takeOAuthFlow } from './pkce.ts'

function memoryStorage(): Storage {
  const entries = new Map<string, string>()
  return {
    get length() { return entries.size },
    key: (index) => [...entries.keys()][index] ?? null,
    getItem: (key) => entries.get(key) ?? null,
    setItem: (key, value) => { entries.set(key, value) },
    removeItem: (key) => { entries.delete(key) },
    clear: () => entries.clear(),
  }
}
const flow = { codeVerifier: 'a'.repeat(43), redirectUri: 'https://console.test/realms/master/authentication/callback' }
beforeEach(() => {
  Object.defineProperty(globalThis, 'localStorage', { value: memoryStorage(), configurable: true })
  Object.defineProperty(globalThis, 'sessionStorage', { value: memoryStorage(), configurable: true })
})

test('email callback in a fresh tab consumes the shared flow once', () => {
  storeOAuthFlow('state', flow)
  Object.defineProperty(globalThis, 'sessionStorage', { value: memoryStorage(), configurable: true })
  assert.deepEqual(takeOAuthFlow('state', flow.redirectUri), flow)
  assert.equal(takeOAuthFlow('state', flow.redirectUri), null)
})

test('different state cannot take another flow', () => {
  storeOAuthFlow('state', flow)
  assert.equal(takeOAuthFlow('other'), null)
  assert.deepEqual(takeOAuthFlow('state'), flow)
})

test('expired and malformed records fail closed and are consumed', (t) => {
  const now = Date.now()
  t.mock.method(Date, 'now', () => now)
  storeOAuthFlow('expired', flow)
  t.mock.method(Date, 'now', () => now + OAUTH_FLOW_TTL_MS)
  assert.equal(takeOAuthFlow('expired'), null)
  for (const raw of ['{', '{}', JSON.stringify({ ...flow, expiresAt: 'tomorrow' }), JSON.stringify({ ...flow, codeVerifier: 'short', expiresAt: now + OAUTH_FLOW_TTL_MS + 1 })]) {
    localStorage.setItem('oauth_flow:bad', raw)
    sessionStorage.setItem('oauth_flow:bad', JSON.stringify(flow))
    assert.equal(takeOAuthFlow('bad'), null)
    assert.equal(localStorage.getItem('oauth_flow:bad'), null)
  }
})

test('rejects a flow for a different callback origin or realm', () => {
  for (const callback of ['https://evil.test/realms/master/authentication/callback', 'https://console.test/realms/other/authentication/callback']) {
    storeOAuthFlow('state', flow)
    assert.equal(takeOAuthFlow('state', callback), null)
    assert.equal(takeOAuthFlow('state', flow.redirectUri), null)
  }
})

test('new flow prunes abandoned flows and their state markers only', () => {
  localStorage.setItem('oauth_flow:old', JSON.stringify({ ...flow, expiresAt: Date.now() - 1 }))
  localStorage.setItem('oauth_state:old', 'old')
  localStorage.setItem('unrelated', 'keep')
  storeOAuthFlow('fresh', flow)
  assert.equal(localStorage.getItem('oauth_flow:old'), null)
  assert.equal(localStorage.getItem('oauth_state:old'), null)
  assert.equal(localStorage.getItem('unrelated'), 'keep')
  assert.deepEqual(takeOAuthFlow('fresh'), flow)
})

test('legacy flow without an expiry requires a fresh sign-in', () => {
  sessionStorage.setItem('oauth_flow:legacy', JSON.stringify(flow))
  assert.equal(takeOAuthFlow('legacy', flow.redirectUri), null)
  assert.equal(takeOAuthFlow('legacy'), null)
})

test('shared flow does not depend on tab storage being available', () => {
  storeOAuthFlow('state', flow)
  Object.defineProperty(globalThis, 'sessionStorage', {
    configurable: true, get() { throw new Error('unavailable') },
  })
  assert.deepEqual(takeOAuthFlow('state', flow.redirectUri), flow)
})

test('unavailable shared storage fails closed', () => {
  Object.defineProperty(globalThis, 'localStorage', {
    configurable: true, get() { throw new Error('unavailable') },
  })
  assert.doesNotThrow(() => storeOAuthFlow('state', flow))
  assert.equal(takeOAuthFlow('state', flow.redirectUri), null)
})
