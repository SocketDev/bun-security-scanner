import { SocketSdk } from '@socketsecurity/sdk'
import type { ScannerImplementation, SocketArtifact } from '../types'
import { userAgent } from './user-agent'

export function authenticated(apiToken: string): ScannerImplementation {
  // The SDK's node:http transport replaces the hand-rolled fetch loop; batching
  // and concurrency come from batchPackageStream (chunkSize 100, concurrency
  // 10 by default — far cheaper on quota than the old 1-purl-per-request
  // pattern). Query parity with the old endpoint: actions=error,warn.
  const sdk = new SocketSdk(apiToken, { userAgent })

  return async function* (packages) {
    // Drain the caller's array in place — `scan()` loops `while
    // (packages.length)`, so a non-consuming implementation would spin forever.
    const components = packages
      .splice(0)
      .map(pkg => ({ purl: `pkg:npm/${pkg.name}@${pkg.version}` }))

    if (components.length === 0) {
      return
    }

    const stream = sdk.batchPackageStream(
      { components },
      { queryParams: { actions: 'error,warn' } },
    )

    for await (const result of stream) {
      if (!result.success) {
        throw new Error(
          `Socket Security Scanner: Received ${result.status} from server`,
        )
      }
      // batchPackageStream yields one result per artifact.
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the sdk types batch results with its generated openapi SocketArtifact; this narrows to the field subset the scanner consumes (inputPurl + alerts, verified live).
      yield [result.data as SocketArtifact]
    }
  }
}
