import { CheckCircle } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Card, CardContent } from '@/components/ui/card'
import '../ui/page-login.css'
import { AUTH_NAMESPACE } from '../constants'

/**
 * Post-verification success screen. Reached via a redirect from
 * `/verify-email?token=…` once the backend has actually confirmed the
 * email. Kept as the React fallback when the realm admin hasn't built a
 * custom `email_verified` tree in the theme builder — when they have,
 * `<PortalLayoutWrapper>` renders the custom tree and ignores this
 * component.
 */
export default function PageEmailVerifiedFeature() {
  const { t } = useTranslation(AUTH_NAMESPACE)

  return (
    <div className='login-shell relative flex min-h-svh items-center justify-center px-6 py-10'>
      <div className='relative z-10 w-full max-w-sm md:max-w-md lg:max-w-lg'>
        <div className='flex flex-col gap-6'>
          <Card className='login-card overflow-hidden border p-0 shadow-sm'>
            <CardContent className='grid gap-0 p-0'>
              <div className='p-8 md:p-10'>
                <div className='flex flex-col items-center gap-6 text-center'>
                  <div className='flex h-14 w-14 items-center justify-center rounded-full bg-green-100'>
                    <CheckCircle className='h-8 w-8 text-green-600' />
                  </div>
                  <div className='space-y-2'>
                    <h1 className='text-2xl font-semibold tracking-tight'>
                      {t('email_verified.title')}
                    </h1>
                    <p className='text-sm text-muted-foreground'>
                      {t('email_verified.return_to_sign_in')}
                    </p>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}
