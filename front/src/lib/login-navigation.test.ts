import assert from 'node:assert/strict'
import { test } from 'node:test'
import { navigateToLogin } from './login-navigation.ts'

test('sign-in navigation performs a document request to the local realm login', () => {
  const destinations: string[] = []
  Object.defineProperty(globalThis, 'window', { configurable: true, value: {
    location: { replace: (url: string) => destinations.push(url) },
  } })
  navigateToLogin()
  navigateToLogin('aster', 'Link expired & try again')
  navigateToLogin('//evil.test/path')
  assert.deepEqual(destinations, [
    '/realms/master/authentication/login',
    '/realms/aster/authentication/login?login_error=Link+expired+%26+try+again',
    '/realms/%2F%2Fevil.test%2Fpath/authentication/login',
  ])
})
