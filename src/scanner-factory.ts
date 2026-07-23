import type { ScannerImplementation, SocketArtifact } from './types'

export type ScannerConfig = {
  maxSending: number
  maxBatchLength: number
  fetchStrategy: (purls: string[], artifacts: SocketArtifact[]) => Promise<void>
}

export function createScanner({
  maxSending,
  maxBatchLength,
  fetchStrategy,
}: ScannerConfig): ScannerImplementation {
  return async function* (packages) {
    // MUST stay one stable array for the generator's whole life: every flight
    // is handed this exact reference and pushes its results into it AFTER a
    // network round-trip. Rebinding it (`artifacts = []`) to drain would orphan
    // the old array — a flight still in flight then pushes into an array we
    // never yield again, silently dropping its alerts. Drain with `splice(0)`,
    // which empties in place and preserves the reference the flights hold.
    const artifacts: SocketArtifact[] = []
    let batch: Bun.Security.Package[] = []
    let in_flight = 0

    const pending: Set<Promise<void>> = new Set()

    async function startFlight() {
      const purls = batch.map(p => `pkg:npm/${p.name}@${p.version}`)
      batch = []
      in_flight += purls.length

      if (in_flight >= maxSending) {
        if (pending.size !== 0) {
          // oxlint-disable-next-line socket/no-promise-race -- concurrency throttle: block for ANY in-flight fetch to free a slot; `pending` holds at most maxSending promises and every one is awaited by the final drain, so no loser is abandoned
          await Promise.race(pending)
        } else {
          // bug if we get here
        }
      }

      const flight = fetchStrategy(purls, artifacts)

      pending.add(flight)

      // Cleanup runs on BOTH settle paths (like `.finally`), but via
      // `.then(cleanup, cleanup)` so the derived chain never rejects — a bare
      // `.finally` re-rejects into an unhandled rejection. The flight's own
      // rejection still surfaces through `pending` at the final drain.
      const cleanup = () => {
        in_flight -= purls.length
        pending.delete(flight)
      }
      void flight.then(cleanup, cleanup)
    }

    while (packages.length > 0) {
      const item = packages.shift()!
      if (!item) {
        break
      }

      batch.push(item)

      if (batch.length >= maxBatchLength) {
        await startFlight()
        if (artifacts.length > 0) {
          yield artifacts.splice(0)
        }
      }
    }

    if (batch.length > 0) {
      await startFlight()
    }

    // oxlint-disable-next-line socket/prefer-all-settled -- fail-fast: a rejected fetch must surface as a scan error, not be swallowed — silently under-reporting security alerts is the exact failure this scanner guards against
    await Promise.all(pending)
    if (artifacts.length > 0) {
      yield artifacts
    }
  }
}
