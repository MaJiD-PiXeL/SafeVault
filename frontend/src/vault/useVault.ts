import { useEffect, useLayoutEffect, useState, useSyncExternalStore } from 'react'
import { createVaultApi } from './api'
import { VaultController } from './controller'
import { deriveInWorker } from './derive'

export function useVault(ownerId: number | null, enabled: boolean) {
  const [controller] = useState(() => new VaultController(createVaultApi(), deriveInWorker))
  const snapshot = useSyncExternalStore(controller.subscribe, controller.getSnapshot)
  useLayoutEffect(() => {
    controller.switchAccount(ownerId, enabled)
    return () => controller.lock()
  }, [controller, ownerId, enabled])
  useEffect(() => {
    const activity = () => controller.touch()
    const visibility = () => { if (document.hidden) controller.hidden(); else controller.checkIdle() }
    const pagehide = () => controller.lock()
    for (const event of ['pointerdown', 'keydown', 'scroll']) document.addEventListener(event, activity, { passive: true })
    document.addEventListener('visibilitychange', visibility)
    window.addEventListener('pagehide', pagehide)
    const interval = window.setInterval(controller.checkIdle, 1000)
    return () => {
      for (const event of ['pointerdown', 'keydown', 'scroll']) document.removeEventListener(event, activity)
      document.removeEventListener('visibilitychange', visibility)
      window.removeEventListener('pagehide', pagehide)
      window.clearInterval(interval)
    }
  }, [controller])
  const current = enabled && snapshot.ownerId === ownerId && ownerId !== null
  return { ...snapshot, unlocked: current && snapshot.unlocked, entries: current && snapshot.unlocked ? snapshot.entries : [],
    trash: current && snapshot.unlocked ? snapshot.trash : [], controller }
}
