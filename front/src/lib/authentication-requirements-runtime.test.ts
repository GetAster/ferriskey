import assert from 'node:assert/strict'
import { test } from 'node:test'
import { readFileSync } from 'node:fs'
import ts from 'typescript'

function load(
  relative: string,
  imports: Record<string, unknown>,
  globals: Record<string, unknown>
) {
  const source = readFileSync(new URL(relative, import.meta.url), 'utf8')
  const js = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText
  const module = { exports: {} as Record<string, (...args: any[]) => any> }
  const require = (name: string) => {
    if (!(name in imports)) throw new Error(`Unexpected import ${name}`)
    return imports[name]
  }
  new Function('require', 'module', 'exports', ...Object.keys(globals), js)(
    require,
    module,
    module.exports,
    ...Object.values(globals)
  )
  return module.exports
}

test('a one-use login action returning step-up is never refreshed or replayed', async () => {
  let calls = 0
  let refreshes = 0
  const api = load(
    '../api/index.ts',
    {
      sonner: { toast: { error: () => assert.fail('unexpected toast') } },
      '@/hooks/auth-refresh-controller.ts': {
        authRefreshController: {
          run: () => {
            refreshes++
            throw new Error('must not refresh')
          },
        },
      },
      '@/store/auth.store.ts': {
        authStore: {
          getState: () => ({
            accessToken: 'console',
            refreshToken: 'refresh',
            sessionRealm: 'master',
          }),
        },
      },
      '@/lib/api-error.ts': { errorMessageFromBody: () => 'Passkey required' },
      '@/lib/i18n': { translate: (s: string) => s },
    },
    {
      fetch: async (_url: URL, init: RequestInit) => {
        calls++
        assert.equal(new Headers(init.headers).has('Authorization'), false)
        return new Response(JSON.stringify({ reason: 'passkey_authentication_required' }), {
          status: 401,
        })
      },
    }
  )
  await assert.rejects(
    api.fetcher({
      url: new URL('https://idp.example/api/realms/aster/login-actions/verify-magic-link'),
      method: 'get',
    }),
    (error: any) => error.status === 401 && error.data.reason === 'passkey_authentication_required'
  )
  assert.equal(calls, 1)
  assert.equal(refreshes, 0)
})

test('step-up cannot schedule or manually trigger a replacement console transaction', async () => {
  const effects: Array<() => void> = []
  let timers = 0,
    restarts = 0
  const hook = load(
    '../pages/authentication/hooks/use-session-refresh.ts',
    {
      react: {
        useCallback: (fn: unknown) => fn,
        useEffect: (fn: () => void) => effects.push(fn),
        useRef: (v: unknown) => ({ current: v }),
        useState: (v: unknown) => [v, () => {}],
      },
      'react-i18next': { useTranslation: () => ({ t: (s: string) => s }) },
      sonner: { toast: { error: () => {} } },
      '../constants': { AUTH_NAMESPACE: 'auth' },
    },
    {
      window: {
        setTimeout: () => {
          timers++
          return 1
        },
        setInterval: () => {
          timers++
          return 2
        },
        clearTimeout: () => {},
        clearInterval: () => {},
        location: { href: '' },
      },
    }
  )
  const result = hook.useSessionRefresh({
    disabled: true,
    isRedirecting: false,
    isSessionError: true,
    getOAuthParams: async () => {
      restarts++
      return { query: '', realm: 'master' }
    },
  })
  for (const effect of effects) effect()
  await result.restartAuthFlow()
  assert.equal(result.showFloatingActionBar, false)
  assert.equal(timers, 0)
  assert.equal(restarts, 0)
})
