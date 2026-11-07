import { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Button } from '@/components/ui/button'
import { useVerifyEmail } from '@/hooks/use-verify-email'
import { apiErrorMessage } from '@/lib/api-error'
import { PortalLayoutWrapper } from '../components/portal-layout-wrapper'
import PageVerifyEmail from './page-verify-email'
import { AUTH_NAMESPACE, PORTAL_PAGE_TYPE } from '../constants'
import { continueLogin } from '../utils/continue-login'
import { requestLoginContinuation } from '../utils/request-login-continuation'

// Orchestration stays above the theme wrapper so a custom page cannot suppress it.
export default function VerifyEmailRoute() {
  const { state, realm_name } = useVerifyEmail()
  const { t } = useTranslation(AUTH_NAMESPACE)
  const navigate = useNavigate()
  const hasTriedContinuation = useRef(false)
  const inFlight = useRef(false)
  const [continuationError, setContinuationError] = useState<string | null>(null)
  const [isContinuing, setIsContinuing] = useState(false)

  const resumeLogin = useCallback(async () => {
    if (!realm_name || inFlight.current) return
    inFlight.current = true
    setIsContinuing(true)
    setContinuationError(null)
    try {
      const result = await requestLoginContinuation(window.apiUrl, realm_name)
      if (result.kind === 'unavailable') {
        navigate(`/realms/${realm_name}/authentication/email-verified`, { replace: true })
      } else {
        continueLogin(result.next, navigate, realm_name)
      }
    } catch (error) {
      setContinuationError(apiErrorMessage(error, t('verify_email.continue_failed')))
    } finally {
      inFlight.current = false
      setIsContinuing(false)
    }
  }, [navigate, realm_name, t])

  useEffect(() => {
    if (state !== 'success' || hasTriedContinuation.current) return
    hasTriedContinuation.current = true
    void resumeLogin()
  }, [state, resumeLogin])

  // Verification succeeded. Retry only continuation, without reusing the email token.
  if (continuationError) {
    return (
      <div className='flex min-h-screen flex-col items-center justify-center gap-4 p-6 text-center'>
        <h1 className='text-2xl font-semibold'>{t('email_verified.title')}</h1>
        <p>{t('verify_email.continue_failed')}</p>
        <p role='alert'>{continuationError}</p>
        <Button onClick={() => void resumeLogin()} disabled={isContinuing}>
          {t('verify_email.retry_continue')}
        </Button>
      </div>
    )
  }
  return (
    <PortalLayoutWrapper pageType={PORTAL_PAGE_TYPE.VERIFY_EMAIL}>
      <PageVerifyEmail state={state} />
    </PortalLayoutWrapper>
  )
}
