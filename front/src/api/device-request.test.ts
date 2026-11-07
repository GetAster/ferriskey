import assert from 'node:assert/strict'
import { test } from 'node:test'
import { requestDevice } from './device-request.ts'

test('preview and explicit decision use cookies without console credentials', async () => {
  const requests: Array<{ url: unknown; init: RequestInit | undefined }> = []
  const fetcher = (async (url, init) => {
    requests.push({ url, init })
    return new Response(JSON.stringify({ status: 'approved' }))
  }) as typeof fetch
  await requestDevice('https://idp.example/', 'realm', { userCode: 'ABCD-EFGH' }, fetcher)
  await requestDevice('https://idp.example/', 'realm', { data: { user_code: 'ABCD-EFGH', action: 'approve' } }, fetcher)
  assert.equal(requests.length, 2)
  assert.equal(requests[0].url, 'https://idp.example/realms/realm/device/preview?user_code=ABCD-EFGH')
  assert.deepEqual(requests[0].init, { method: 'GET', credentials: 'include' })
  assert.equal(requests[1].init?.credentials, 'include')
  assert.deepEqual(requests[1].init?.headers, { 'Content-Type': 'application/json' })
})
test('401 preserves login recovery and makes no token refresh request', async () => {
  let calls = 0
  await assert.rejects(requestDevice('', 'realm', { data: {} }, (async () => {
    calls++
    return new Response(JSON.stringify({ error: 'login_required', redirect_uri: '/original-device' }), { status: 401 })
  }) as typeof fetch), (error: unknown) => {
    assert.equal((error as { status: number }).status, 401)
    assert.equal((error as { data: { redirect_uri: string } }).data.redirect_uri, '/original-device')
    return true
  })
  assert.equal(calls, 1)
})
