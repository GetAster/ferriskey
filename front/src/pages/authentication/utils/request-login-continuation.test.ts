import assert from 'node:assert/strict'
import { test } from 'node:test'
import { readFileSync } from 'node:fs'
import { requestLoginContinuation } from './request-login-continuation.ts'

const reply = (body: unknown, status = 200) => (async () => new Response(JSON.stringify(body), { status })) as typeof fetch

test('continuation carries only the original browser cookies, with no client or tab storage dependency', async () => {
  let calls = 0
  const result = await requestLoginContinuation('https://idp.example/', 'my realm', (async (url, init) => {
    calls++
    assert.equal(url, 'https://idp.example/realms/my%20realm/login-actions/continue')
    assert.deepEqual(init, { method: 'POST', credentials: 'include' })
    return new Response(JSON.stringify({ url: 'https://app.example/callback?code=original' }))
  }) as typeof fetch)
  assert.equal(calls, 1)
  assert.deepEqual(result, { kind: 'continue', next: { url: 'https://app.example/callback?code=original' } })
})
test('missing or expired action cookie has a controlled unavailable result', async () => {
  assert.deepEqual(await requestLoginContinuation('', 'realm', reply({ reason: 'invalid_token' }, 401)), { kind: 'unavailable' })
})
test('server errors and unmet second factor never become successful verification navigation', async () => {
  for (const status of [400, 403, 500]) {
    await assert.rejects(requestLoginContinuation('', 'realm', reply({ message: 'failure' }, status)), (error: unknown) => {
      assert.equal((error as { status: number }).status, status)
      return true
    })
  }
  await assert.rejects(requestLoginContinuation('', 'realm', (async () => { throw new Error('offline') }) as typeof fetch), /offline/)
})
test('only usable server continuations are accepted', async () => {
  for (const body of [{}, { url: ' ' }, { url: 'javascript:alert(1)' }, { required_actions: [] }, { required_actions: ['invented'] }]) {
    await assert.rejects(requestLoginContinuation('', 'realm', reply(body)), /valid login continuation/)
  }
  assert.deepEqual(await requestLoginContinuation('', 'realm', reply({ required_actions: ['verify_email'] })), { kind: 'continue', next: { required_actions: ['verify_email'] } })
})
test('email routes do not start a console login or depend on per-tab storage', () => {
  for (const file of ['../feature/verify-email-route.tsx', '../feature/execution/verify-email-feature.tsx', '../feature/execution/verify-email-continue.tsx']) {
    const source = readFileSync(new URL(file, import.meta.url), 'utf8')
    assert.doesNotMatch(source, /security-admin-console|sessionStorage|useAuthenticateMutation/)
  }
  const source = readFileSync(new URL('../ui/page-required-action.tsx', import.meta.url), 'utf8')
  assert.match(source, /<\/PortalLayoutWrapper>\s*<VerifyEmailContinue/)
})
