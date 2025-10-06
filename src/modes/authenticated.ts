import type { ScannerImplementation } from '../types'
import { createScanner } from '../scanner-factory'
import { userAgent } from './user-agent'

type SocketBatchEndpointBody = {
  components: {
    purl: string
  }[]
}

export default function (apiKey: string): ScannerImplementation {
  return createScanner({
    maxSending: 30,
    maxBatchLength: 1,
    fetchStrategy: async (purls, artifacts) => {
      const body = JSON.stringify({
        components: purls.map(purl => ({ purl }))
      } satisfies SocketBatchEndpointBody)

      const res = await fetch(`https://api.socket.dev/v0/purl?actions=error,warn`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey}`,
          'User-Agent': userAgent
        },
        body,
      })

      if (!res.ok) {
        throw new Error(`Socket Security Scanner: Received ${res.status} from server`)
      }

      const data = await res.text()

      artifacts.push(...data.split('\n').filter(Boolean).map(line => JSON.parse(line)))
    }
  })
}
