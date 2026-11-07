import { useMutation, useQuery } from '@tanstack/react-query'
import type { BaseQuery } from '.'
import type { Schemas } from './api.client'
import { requestDevice } from './device-request'

export const useDeviceVerify = () => {
  return useMutation({
    mutationFn: async ({
      realm,
      data,
    }: BaseQuery & { data: Schemas.DeviceVerifyRequest }) => {
      return requestDevice<Schemas.DeviceVerifyResponse>(window.apiUrl, realm ?? 'master', { data })
    },
  })
}

export const useDevicePreview = ({
  realm,
  userCode,
  enabled,
}: BaseQuery & { userCode: string; enabled: boolean }) => {
  return useQuery({
    queryKey: ['device-preview', realm, userCode],
    enabled,
    retry: false,
    staleTime: 0,
    queryFn: async () => {
      return requestDevice<Schemas.DeviceVerificationPreview>(window.apiUrl, realm ?? 'master', { userCode })
    },
  })
}
