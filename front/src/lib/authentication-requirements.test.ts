import assert from 'node:assert/strict'
import { test } from 'node:test'
import { authenticationRequirementRedirect as redirect } from './authentication-requirements.ts'
const path = '/realms/my%20realm/authentication/magic-link'
test('step-up preserves the realm and requests a ceremony on the same transaction', () => {
  assert.equal(
    redirect({ data: { reason: 'passkey_authentication_required' } }, path),
    '/realms/my%20realm/authentication/login?passkey_required=true'
  )
})
test('only the explicit unmet requirements error may carry an RP redirect', () => {
  const url = 'https://app.example/callback?error=unmet_authentication_requirements&state=s'
  assert.equal(
    redirect({ data: { reason: 'unmet_authentication_requirements', redirect_url: url } }, path),
    url
  )
  for (const reason of ['invalid_token', 'forbidden', 'internal_server_error']) {
    assert.equal(redirect({ reason, redirect_url: url }, path), undefined)
  }
  assert.equal(
    redirect(
      { reason: 'unmet_authentication_requirements', redirect_url: url },
      '/realms/master/overview'
    ),
    undefined
  )
})
test('malformed and executable error redirects are refused', () => {
  for (const url of [undefined, '', 42, 'javascript:alert(1)', 'data:text/html,bad']) {
    assert.equal(
      redirect({ reason: 'unmet_authentication_requirements', redirect_url: url }, path),
      undefined
    )
  }
  for (const error of [null, undefined, 'failure', new Error('failure')])
    assert.equal(redirect(error, path), undefined)
})

test('fresh authentication stays on the saved transaction', () => {
  assert.equal(redirect({ reason: 'reauthentication_required' }, path),
    '/realms/my%20realm/authentication/login?reauthentication_required=true')
})
