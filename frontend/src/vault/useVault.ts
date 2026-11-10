import { useEffect, useLayoutEffect, useState, useSyncExternalStore } from 'react'
import { createVaultApi } from './api'
import { VaultController } from './controller'
import { deriveInWorker } from './derive'
import { createOutbox } from './outbox'

export function useVault(ownerId: number | null, enabled: boolean) {
  const [controller] = useState(() => new VaultController(createVaultApi(), deriveInWorker, Date.now, createOutbox()))
  const snapshot = useSyncExternalStore(controller.subscribe, controller.getSnapshot)
  useLayoutEffect(() => {
    controller.switchAccount(ownerId, enabled)
    return () => controller.forgetOffline()
  }, [controller, ownerId, enabled])
  useEffect(() => {
    const activity = () => controller.touch()
    const visibility = () => { if (document.hidden) controller.hidden(); else controller.checkIdle() }
    for (const event of ['pointerdown', 'keydown', 'scroll']) document.addEventListener(event, activity, { passive: true })
    document.addEventListener('visibilitychange', visibility)
    window.addEventListener('pagehide', controller.forgetOffline)
    const interval = window.setInterval(controller.checkIdle, 1000)
    return () => {
      for (const event of ['pointerdown', 'keydown', 'scroll']) document.removeEventListener(event, activity)
      document.removeEventListener('visibilitychange', visibility)
      window.removeEventListener('pagehide', controller.forgetOffline)
      window.clearInterval(interval)
    }
  }, [controller])
  useEffect(() => {
    if (!enabled || ownerId === null) return
    const sync = () => { if (!document.hidden) void controller.sync() }
    window.addEventListener('focus', sync)
    window.addEventListener('online', sync)
    document.addEventListener('visibilitychange', sync)
    const interval = window.setInterval(sync, 20000)
    sync()
    return () => {
      window.removeEventListener('focus', sync)
      window.removeEventListener('online', sync)
      document.removeEventListener('visibilitychange', sync)
      window.clearInterval(interval)
    }
  }, [controller, enabled, ownerId, snapshot.unlocked])
  const current = enabled && snapshot.ownerId === ownerId && ownerId !== null
  return { ...snapshot, unlocked: current && snapshot.unlocked, entries: current && snapshot.unlocked ? snapshot.entries : [],
    trash: current && snapshot.unlocked ? snapshot.trash : [], pending: current && snapshot.unlocked ? snapshot.pending : [], controller }
}
