import type { SocketArtifact, ScannerImplementation } from './types'

type ScannerConfig = {
  maxSending: number
  maxBatchLength: number
  fetchStrategy: (purls: string[], artifacts: SocketArtifact[]) => Promise<void>
}

export function createScanner({ maxSending, maxBatchLength, fetchStrategy }: ScannerConfig): ScannerImplementation {
  return async function*(packages) {
    let artifacts: SocketArtifact[] = []
    let batch: Bun.Security.Package[] = []
    let in_flight = 0

    const pending: Set<Promise<void>> = new Set()

    async function startFlight() {
      const purls = batch.map(p => `pkg:npm/${p.name}@${p.version}`)
      batch = []
      in_flight += purls.length

      if (in_flight >= maxSending) {
        if (pending.size !== 0) {
          await Promise.race([...pending])
        } else {
          // bug if we get here
        }
      }

      const flight = fetchStrategy(purls, artifacts)

      pending.add(flight)

      flight.finally(() => {
        in_flight -= purls.length
        pending.delete(flight)
      })
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
          const tmp = artifacts
          artifacts = []
          yield tmp
        }
      }
    }

    if (batch.length > 0) {
      await startFlight()
    }

    await Promise.all([...pending])
    if (artifacts.length > 0) {
      yield artifacts
    }
  }
}
