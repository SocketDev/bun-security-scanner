import type { ScannerImplementation } from '../types'
import { createScanner } from '../scanner-factory'

export default function (): ScannerImplementation {
  return createScanner({
    maxSending: 20,
    maxBatchLength: 50,
    fetchStrategy: async (purls, artifacts) => {
      const urls = purls.map(purl => `https://firewall-api.socket.dev/purl/${encodeURIComponent(purl)}`)
      await Promise.all(urls.map(async url => {
        const res = await fetch(url)
        if (!res.ok) {
          throw new Error(`Socket Security Scanner: Received ${res.status} from server`)
        }
        const data = await res.text()
        artifacts.push(...data.split('\n').filter(Boolean).map(line => JSON.parse(line)))
      }))
    }
  })
}
