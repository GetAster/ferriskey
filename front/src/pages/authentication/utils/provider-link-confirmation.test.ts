import assert from 'node:assert/strict'
import { test } from 'node:test'
import { declineProviderLink, providerDisplayName } from './provider-link-confirmation.ts'

test('provider query values are bounded display text with safe fallback', () => {
  assert.equal(providerDisplayName('microsoft'), 'Microsoft')
  assert.equal(providerDisplayName('GOOGLE'), 'Google')
  assert.equal(providerDisplayName('company-login'), 'company-login')
  assert.equal(providerDisplayName('constructor'), 'constructor')
  for (const value of [
    null,
    '',
    '<img src=x onerror=alert(1)>',
    '\u202eevil',
    'x'.repeat(65),
    'https://evil.example',
    'a\nb',
  ]) {
    assert.equal(providerDisplayName(value), undefined)
  }
})

test('decline uses the browser session and an empty JSON POST to the realm endpoint', async () => {
  let calls = 0
  await declineProviderLink('https://idp.example/api/', 'my realm', (async (url, init) => {
    calls++
    assert.equal(
      url,
      'https://idp.example/api/realms/my%20realm/login-actions/decline-provider-link'
    )
    assert.deepEqual(init, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
      redirect: 'error',
    })
    return new Response(null, { status: 204 })
  }) as typeof fetch)
  assert.equal(calls, 1)
})

test('only the expected success response closes a pending connection', async () => {
  for (const status of [200, 302, 400, 401, 403, 429, 500]) {
    await assert.rejects(
      declineProviderLink(
        '',
        'realm',
        (async () =>
          new Response(JSON.stringify({ message: 'Try again' }), { status })) as typeof fetch
      ),
      (error: unknown) => {
        assert.equal((error as { status: number }).status, status)
        assert.equal((error as Error).message, 'Try again')
        return true
      }
    )
  }
})

test('network failures and non-JSON server failures remain retryable errors', async () => {
  await assert.rejects(
    declineProviderLink('', 'realm', (async () => {
      throw new Error('offline')
    }) as typeof fetch),
    /offline/
  )
  await assert.rejects(
    declineProviderLink(
      '',
      'realm',
      (async () => new Response('<html>failure</html>', { status: 502 })) as typeof fetch
    ),
    /HTTP 502/
  )
})

test('missing realm does not send a cancellation request', async () => {
  await assert.rejects(
    declineProviderLink('', '', (async () => {
      assert.fail('must not send')
    }) as typeof fetch),
    /Missing realm/
  )
})
