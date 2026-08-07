import type { ScannerImplementation, SocketArtifact } from './types'

export type ScannerConfig = {
  /**
   * Ceiling on purls in flight at once. A free-mode strategy issues one HTTP
   * request per purl, so this is the request-concurrency cap — the resource
   * the scanner is actually rationing.
   */
  maxSending: number
  /**
   * Purls handed to `fetchStrategy` per flight. Keep it at or below
   * `maxSending`: a flight is admitted whole, so a batch wider than the cap
   * runs alone and its own width becomes the peak.
   */
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
    let inFlight = 0

    // `pending` shrinks as flights settle, so the throttle can read live load.
    // `flights` keeps every flight ever started: a flight that rejects early is
    // gone from `pending` long before the final drain, and draining only the
    // live set would let that rejection — a non-2xx response — vanish, handing
    // Bun a short advisory list and a green install. The drain awaits `flights`.
    const pending: Set<Promise<void>> = new Set()
    const flights: Array<Promise<void>> = []

    // Single-waiter "a flight settled" signal. Re-racing `pending` each
    // iteration would stack a handler set on every surviving flight; one fresh
    // promise per settle keeps the awaited arm short-lived. Only the generator
    // body waits on it, and it awaits one flight at a time, so there is never
    // more than one waiter.
    let slotFreed = Promise.withResolvers<void>()

    async function startFlight() {
      const purls = batch.map(p => `pkg:npm/${p.name}@${p.version}`)
      batch = []

      // Admit the flight only once its purls fit under the cap, and count them
      // AFTER the wait — counting first made every flight's own purls push the
      // total over `maxSending`, so the cap read as "already exceeded" instead
      // of "no room", and the first flight of every scan sailed past the cap.
      // Each settled flight frees exactly its own purls, so loop until enough
      // are free rather than waking once and proceeding regardless.
      while (pending.size > 0 && inFlight + purls.length > maxSending) {
        await slotFreed.promise
      }

      inFlight += purls.length

      const flight = fetchStrategy(purls, artifacts)

      flights.push(flight)
      pending.add(flight)

      // Cleanup runs on BOTH settle paths (like `.finally`), but via
      // `.then(cleanup, cleanup)` so the derived chain never rejects — a bare
      // `.finally` re-rejects into an unhandled rejection. The flight's own
      // rejection still surfaces through `flights` at the final drain.
      const cleanup = () => {
        inFlight -= purls.length
        pending.delete(flight)

        const waiter = slotFreed
        slotFreed = Promise.withResolvers<void>()
        waiter.resolve()
      }
      void flight.then(cleanup, cleanup)
    }

    while (packages.length > 0) {
      const item = packages.shift()!
      if (!item) {
        // A hole in the caller's array costs that one entry, never the queue
        // behind it — stopping here would leave real packages unscanned.
        continue
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

    // A rejected fetch must surface as a scan error, not be swallowed:
    // silently under-reporting security alerts is the exact failure this
    // scanner guards against.
    // oxlint-disable-next-line socket/prefer-all-settled -- fail-fast scan
    await Promise.all(flights)
    if (artifacts.length > 0) {
      yield artifacts
    }
  }
}
