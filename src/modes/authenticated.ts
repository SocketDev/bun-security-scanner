import type { ScannerImplementation } from '../types'
import { createScanner } from '../scanner-factory'
import { userAgent } from './user-agent'

export type SocketBatchEndpointBody = {
  components: Array<{
    purl: string
  }>
}

export function authenticated(apiKey: string): ScannerImplementation {
  return createScanner({
    maxSending: 30,
    maxBatchLength: 1,
    fetchStrategy: async (purls, artifacts) => {
      const body = JSON.stringify({
        components: purls.map(purl => ({ purl })),
      } satisfies SocketBatchEndpointBody)

      // Tests mock global fetch; Bun ships fetch natively in this plugin
      // runtime. socket-lint: allow global-fetch
      const res = await fetch(
        `https://api.socket.dev/v0/purl?actions=error,warn`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${apiKey}`,
            'User-Agent': userAgent,
          },
          body,
        },
      )

      if (!res.ok) {
        throw new Error(
          `Socket Security Scanner: Received ${res.status} from server`,
        )
      }

      const data = await res.text()

      artifacts.push(
        ...data
          .split('\n')
          .filter(Boolean)
          .map(line => JSON.parse(line)),
      )
    },
  })
}
