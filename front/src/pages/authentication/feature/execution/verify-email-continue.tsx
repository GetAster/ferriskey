import { Button } from '@/components/ui/button'
import { apiErrorMessage } from '@/lib/api-error'
import { useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate, useParams } from 'react-router'
import { AUTH_NAMESPACE } from '../../constants'
import { continueLogin } from '../../utils/continue-login'
import { requestLoginContinuation } from '../../utils/request-login-continuation'

// Kept outside the replaceable theme tree so verified users can always resume.
export default function VerifyEmailContinue() {
  const { realm_name } = useParams()
  const { t } = useTranslation(AUTH_NAMESPACE)
  const navigate = useNavigate()
  const continuing = useRef(false)
  const [isContinuing, setIsContinuing] = useState(false)
  const [continuationError, setContinuationError] = useState<string | null>(null)

  const handleContinue = async () => {
    if (!realm_name || continuing.current) return
    continuing.current = true
    setIsContinuing(true)
    setContinuationError(null)
    try {
      const result = await requestLoginContinuation(window.apiUrl, realm_name)
      if (result.kind === 'unavailable') {
        setContinuationError(t('verify_email.sign_in_expired'))
      } else if (result.next.required_actions?.[0] === 'verify_email') {
        setContinuationError(t('verify_email.not_verified'))
      } else {
        continueLogin(result.next, navigate, realm_name)
      }
    } catch (error) {
      setContinuationError(apiErrorMessage(error, t('verify_email.continue_failed')))
    } finally {
      continuing.current = false
      setIsContinuing(false)
    }
  }

  return (
    <div className='flex flex-col items-center gap-3 p-4 text-center'>
        <Button onClick={() => void handleContinue()} disabled={isContinuing}>
          {t('verify_email.continue')}
        </Button>
        {continuationError && <p role='alert'>{continuationError}</p>}
    </div>
  )
}
