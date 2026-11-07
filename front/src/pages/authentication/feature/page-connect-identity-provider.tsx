import { useRef, useState } from 'react'
import { useParams, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Mail, CheckCircle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { apiErrorMessage } from '@/lib/api-error'
import { AUTH_NAMESPACE } from '../constants'
import { declineProviderLink, providerDisplayName } from '../utils/provider-link-confirmation'
import '../ui/page-login.css'

export default function PageConnectIdentityProvider() {
  const { realm_name } = useParams()
  const [params] = useSearchParams()
  const { t } = useTranslation(AUTH_NAMESPACE)
  const [isDeclining, setIsDeclining] = useState(false)
  const [closed, setClosed] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const inFlight = useRef(false)
  const provider =
    providerDisplayName(params.get('provider')) ?? t('connect_provider.generic_provider')

  async function decline() {
    if (!realm_name || inFlight.current || closed) return
    inFlight.current = true
    setIsDeclining(true)
    setError(null)
    try {
      await declineProviderLink(window.apiUrl, realm_name)
      // The transaction is ended. Stay here rather than starting a console login
      // or navigating to a query-controlled return address.
      setClosed(true)
    } catch (cause) {
      setError(apiErrorMessage(cause, t('connect_provider.decline_failed')))
    } finally {
      inFlight.current = false
      setIsDeclining(false)
    }
  }

  return (
    <div className="login-shell relative flex min-h-svh items-center justify-center px-6 py-10">
      <Card className="login-card relative z-10 w-full max-w-md overflow-hidden border p-0 shadow-sm">
        <CardContent className="flex flex-col items-center gap-6 p-8 text-center md:p-10">
          {closed ? (
            <CheckCircle className="h-10 w-10" aria-hidden="true" />
          ) : (
            <Mail className="h-10 w-10" aria-hidden="true" />
          )}
          <div className="space-y-3" aria-live="polite">
            <h1 className="text-2xl font-semibold tracking-tight">
              {t(closed ? 'connect_provider.closed_title' : 'connect_provider.title')}
            </h1>
            <p className="text-sm text-muted-foreground">
              {closed
                ? t('connect_provider.closed_description')
                : t('connect_provider.description', { provider })}
            </p>
            {!closed && (
              <>
                <p className="text-sm text-muted-foreground">
                  {t('connect_provider.browser_hint')}
                </p>
                <p className="text-sm text-muted-foreground">
                  {t('connect_provider.confirmation_hint')}
                </p>
              </>
            )}
          </div>
          {error && (
            <p role="alert" className="text-sm text-destructive">
              {error}
            </p>
          )}
          {!closed && (
            <Button
              variant="outline"
              onClick={() => void decline()}
              disabled={isDeclining || !realm_name}
            >
              {t(isDeclining ? 'connect_provider.declining' : 'connect_provider.decline')}
            </Button>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
