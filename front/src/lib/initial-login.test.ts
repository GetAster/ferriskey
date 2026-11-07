import assert from 'node:assert/strict'
import { test } from 'node:test'
import { initialLoginRealm } from './initial-login.ts'

const empty = { accessToken: null, refreshToken: null, sessionRealm: null }

test('empty sessions enter realm sign-in before the console mounts', () => {
  assert.equal(initialLoginRealm('/realms/aster/overview', empty, true), 'aster')
  assert.equal(initialLoginRealm('/', empty, true), 'master')
  assert.equal(initialLoginRealm('/unknown', empty, true), 'master')
  assert.equal(initialLoginRealm('/realms/aster/console/authentication', empty, true), 'aster')
})

test('public authentication routes including callback remain in the app', () => {
  for (const step of ['', '/', '/callback', '/login', '/device', '/required-action', '/magic-link/verify']) {
    assert.equal(initialLoginRealm(`/realms/aster/authentication${step}`, empty, true), null)
  }
})

test('stored sessions and incomplete hydration keep the existing auth lifecycle', () => {
  assert.equal(initialLoginRealm('/realms/aster/overview', { ...empty, accessToken: 'access' }, true), null)
  assert.equal(initialLoginRealm('/realms/aster/overview', { ...empty, refreshToken: 'refresh' }, true), null)
  assert.equal(initialLoginRealm('/realms/aster/overview', empty, false), null)
})

test('an empty former session signs in to its issuing realm', () => {
  assert.equal(initialLoginRealm('/realms/customer/overview', { ...empty, sessionRealm: 'master' }, true), 'master')
})

test('path realm is decoded once before the navigation helper encodes it', () => {
  assert.equal(initialLoginRealm('/realms/%61ster/overview', empty, true), 'aster')
  assert.equal(initialLoginRealm('/realms/bad%/overview', empty, true), 'bad%')
})

test('OAuth-looking queries on root and unknown paths do not suppress sign-in', () => {
  for (const path of ['/', '/unknown']) {
    const url = new URL(`${path}?client_id=app&redirect_uri=https://app.test`, 'https://console.test')
    assert.equal(initialLoginRealm(url.pathname, empty, true), 'master')
  }
})
