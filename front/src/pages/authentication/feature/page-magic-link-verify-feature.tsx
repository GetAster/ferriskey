import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useLocation, useParams, useNavigate } from 'react-router'
import { useVerifyMagicLink } from '@/api/trident.api'
import { apiErrorMessage } from '@/lib/api-error'
import PageMagicLinkVerify from '../ui/page-magic-link-verify'
import { AUTH_NAMESPACE } from '../constants'
import { continueLogin } from '../utils/continue-login'

type VerifyStatus = 'loading' | 'error'

export default function PageMagicLinkVerifyFeature() {
  const { realm_name } = useParams()
  const navigate = useNavigate()
  const { t } = useTranslation(AUTH_NAMESPACE)
  const location = useLocation()
  const searchParams = useMemo(() => new URLSearchParams(location.search), [location.search])

  const tokenId = searchParams.get('token_id')
  const magicToken = searchParams.get('magic_token')
  const missingParams = !tokenId || !magicToken

  const [status, setStatus] = useState<VerifyStatus>(missingParams ? 'error' : 'loading')
  const [errorMessage, setErrorMessage] = useState<string | null>(
    missingParams ? t('magic_link.verify.missing_params') : null
  )

  const { mutateAsync: verifyMagicLink } = useVerifyMagicLink()
  const hasStartedVerification = useRef(false)

  useEffect(() => {
    if (missingParams) return
    if (hasStartedVerification.current) return
    hasStartedVerification.current = true

    const realm = realm_name ?? 'master'

    void verifyMagicLink({
      path: { realm_name: realm },
      query: { token_id: tokenId, magic_token: magicToken },
    })
      .then((data) => {
        if (data.url || data.required_actions?.length) {
          continueLogin({ url: data.url, required_actions: data.required_actions ?? [] }, navigate, realm)
        } else if (data.status === 'RequiresOtpChallenge') {
          navigate(`/realms/${realm}/authentication/otp`)
        } else {
          setErrorMessage(t('magic_link.verify.no_redirect'))
          setStatus('error')
        }
      })
      .catch((err: Error) => {
        setErrorMessage(apiErrorMessage(err, t('magic_link.verify.failed')))
        setStatus('error')
      })
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  return <PageMagicLinkVerify status={status} errorMessage={errorMessage} />
}
