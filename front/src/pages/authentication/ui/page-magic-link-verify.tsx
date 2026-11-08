import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import LoaderSpinner from '@/components/ui/loader-spinner'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router'
import { AUTH_NAMESPACE, BRAND_NAME } from '../constants'

export interface PageMagicLinkVerifyProps {
  status: 'loading' | 'error' | 'browser_mismatch'
  errorMessage?: string | null
  signInUrl: string
}

export default function PageMagicLinkVerify({
  status,
  errorMessage,
  signInUrl,
}: PageMagicLinkVerifyProps) {
  const { t } = useTranslation(AUTH_NAMESPACE)
  const [copyStatus, setCopyStatus] = useState<'idle' | 'copied' | 'failed'>('idle')
  const copyLink = async () => {
    try {
      await navigator.clipboard.writeText(signInUrl)
      setCopyStatus('copied')
    } catch {
      setCopyStatus('failed')
    }
  }

  return (
    <div className="login-shell relative flex min-h-svh items-center justify-center px-6 py-10">
      <div className="relative z-10 w-full max-w-sm md:max-w-md">
        <Card className="overflow-hidden border p-0 shadow-sm">
          <CardContent className="p-8 md:p-10">
            <div className="flex flex-col items-center gap-6 text-center">
              <div className="flex items-center gap-3">
                <img
                  src="/logo_ferriskey.png"
                  alt={BRAND_NAME}
                  className="h-7 w-7 object-contain"
                />
                <p className="text-xs font-semibold uppercase tracking-[0.35em] text-muted-foreground">
                  {BRAND_NAME}
                </p>
              </div>

              {status === 'loading' && (
                <>
                  <LoaderSpinner />
                  <p className="text-sm text-muted-foreground">{t('magic_link.verify.checking')}</p>
                </>
              )}

              {status === 'browser_mismatch' && (
                <div className="flex w-full flex-col gap-4">
                  <h1 className="text-xl font-semibold">{t('magic_link.verify.browser_title')}</h1>
                  <p>{t('magic_link.verify.browser_instructions')}</p>
                  <input
                    className="w-full rounded-md border p-3 text-sm"
                    aria-label={t('magic_link.verify.link_label')}
                    readOnly
                    value={signInUrl}
                    onFocus={(event) => event.currentTarget.select()}
                  />
                  <Button onClick={() => void copyLink()}>
                    {t('magic_link.verify.copy_link')}
                  </Button>
                  <p role="status" className="text-sm">
                    {copyStatus === 'copied'
                      ? t('magic_link.verify.link_copied')
                      : copyStatus === 'failed'
                        ? t('magic_link.verify.copy_failed')
                        : null}
                  </p>
                  <p className="text-sm text-muted-foreground">
                    {t('magic_link.verify.not_requested')}
                  </p>
                </div>
              )}

              {status === 'error' && (
                <>
                  <div className="rounded-md border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
                    {errorMessage ?? t('magic_link.verify.invalid')}
                  </div>
                  <Button asChild variant="outline" className="w-full">
                    <Link to={'../login'}>{t('actions.back_to_login')}</Link>
                  </Button>
                </>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
