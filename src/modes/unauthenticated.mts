import { pRetry } from '@socketsecurity/lib-stable/promises/retry'
import type { ScannerImplementation } from '../types.mts'
import { createScanner } from '../scanner-factory.mts'
import { userAgent } from './user-agent.mts'

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
          const result = await pRetry(
            async () => {
              // oxlint-disable-next-line socket/no-fetch-prefer-http-request -- bun
              const response = await fetch(url, {
                headers: { 'User-Agent': userAgent },
              })
              const data = await response.text()
              if (!response.ok) {
                const error = new Error(
                  `Socket Security Scanner: Received ${response.status} from server`,
                )
                if (
                  response.status === 408 ||
                  response.status === 429 ||
                  response.status >= 500
                ) {
                  throw error
                }
                return { __proto__: null, error }
              }
              return { __proto__: null, data }
            },
            { retries: 4, baseDelayMs: 1000, jitter: false },
          )
          if (!result) {
            throw new Error('Socket Security Scanner: Request aborted')
          }
          if (result.error) {
            throw result.error
          }
          artifacts.push(
            ...result.data
              .split(/\r?\n/)
              .filter(Boolean)
              .map(line => JSON.parse(line)),
          )
        }),
      )
    },
  })
}
