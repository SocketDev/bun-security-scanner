import type { ScannerImplementation } from '../types'
import { createScanner } from '../scanner-factory'
import { userAgent } from './user-agent'

export function unauthenticated(): ScannerImplementation {
  return createScanner({
    maxSending: 20,
    maxBatchLength: 50,
    fetchStrategy: async (purls, artifacts) => {
      const urls = purls.map(
        purl =>
          `https://firewall-api.socket.dev/purl/${encodeURIComponent(purl)}`,
      )
      // oxlint-disable-next-line socket/prefer-all-settled -- fail-fast: one failed batch aborts the whole scan on purpose
      await Promise.all(
        urls.map(async url => {
          // Tests mock global fetch; Bun ships fetch natively in this plugin
          // runtime. socket-lint: allow global-fetch
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
