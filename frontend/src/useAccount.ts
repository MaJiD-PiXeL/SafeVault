import { useCallback, useEffect, useRef, useState } from 'react'
import { accountApi, ApiError } from './api'
import type { AccountUser } from './api'

export function useAccount() {
  const [user, setUser] = useState<AccountUser | null>(null)
  const [status, setStatus] = useState<'checking' | 'ready' | 'offline'>('checking')
  const sequence = useRef(0)

  const acceptUser = useCallback((value: AccountUser | null) => {
    sequence.current += 1
    setUser(value)
    setStatus('ready')
  }, [])

  const refresh = useCallback(async (signal?: AbortSignal) => {
    const attempt = ++sequence.current
    try {
      const session = await accountApi.session(signal)
      if (attempt === sequence.current && !signal?.aborted) {
        setUser(session.user)
        setStatus('ready')
      }
    } catch (error) {
      if (attempt === sequence.current && !signal?.aborted) {
        if (error instanceof ApiError && [401, 403].includes(error.status)) {
          setUser(null)
          setStatus('ready')
        } else setStatus('offline')
      }
    }
  }, [])

  useEffect(() => {
    const controller = new AbortController()
    const check = () => { if (!document.hidden) void refresh(controller.signal) }
    check()
    window.addEventListener('focus', check)
    window.addEventListener('online', check)
    document.addEventListener('visibilitychange', check)
    const interval = window.setInterval(check, 60000)
    return () => {
      controller.abort()
      sequence.current += 1
      window.removeEventListener('focus', check)
      window.removeEventListener('online', check)
      document.removeEventListener('visibilitychange', check)
      window.clearInterval(interval)
    }
  }, [refresh])

  return { user, status, acceptUser, refresh }
}
