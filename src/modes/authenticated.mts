import { SocketSdk } from '@socketsecurity/sdk'
import type { ScannerImplementation, SocketArtifact } from '../types.mts'
import { userAgent } from './user-agent.mts'

export function authenticated(apiToken: string): ScannerImplementation {
  const sdk = new SocketSdk(apiToken, { userAgent })

  return async function* (packages) {
    const components = packages.splice(0).map(pkg => ({
      __proto__: null,
      purl: `pkg:npm/${pkg.name}@${pkg.version}`,
    }))

    for (let index = 0; index < components.length; index += 1024) {
      const result = await sdk.batchPackageFetch(
        { components: components.slice(index, index + 1024) },
        { actions: 'error,warn', compact: false },
      )
      if (!result.success) {
        throw new Error(
          `Socket Security Scanner: Received ${result.status} from server`,
        )
      }
      for (const artifact of result.data) {
        if ('_type' in artifact) {
          continue
        }
        // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the scanner consumes the inputPurl and alerts subset of the SDK artifact.
        yield [artifact as SocketArtifact]
      }
    }
  }
}
