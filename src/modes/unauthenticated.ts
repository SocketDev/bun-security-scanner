import type { ScannerImplementation } from '../types'
import { createScanner } from '../scanner-factory'
import { userAgent } from './user-agent'

/**
 * Free-mode scanner. The public firewall endpoint answers a single purl per
 * `GET /purl/<purl>` — it has no batch form, so one purl costs one request and
 * a flight of N purls is N concurrent requests. `maxBatchLength` is therefore
 * kept well under `maxSending`, letting two flights overlap while the peak
 * stays at the advertised cap of 20 concurrent requests.
 */
export function unauthenticated(): ScannerImplementation {
  return createScanner({
    maxSending: 20,
    maxBatchLength: 10,
    fetchStrategy: async (purls, artifacts) => {
      const urls = purls.map(
        purl =>
          `https://firewall-api.socket.dev/purl/${encodeURIComponent(purl)}`,
      )
      // One failed batch aborts the whole scan on purpose.
      // oxlint-disable-next-line socket/prefer-all-settled -- fail-fast scan
      await Promise.all(
        urls.map(async url => {
          // Tests mock global fetch; Bun ships fetch natively in this plugin
          // runtime.
          // oxlint-disable-next-line socket/no-fetch-prefer-http-request -- bun
          const res = await fetch(url, {
            headers: {
              'User-Agent': userAgent,
            },
          })
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
        }),
      )
    },
  })
}
