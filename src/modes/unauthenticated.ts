import type { ScannerImplementation } from '../types'
import { createScanner } from '../scanner-factory'
import { userAgent } from './user-agent'

// Per-request wall-clock budget for the free-mode firewall-api fetch. Without
// it a stalled connection has NO deadline: the scan runs during `bun install`,
// and because the batch below fans out with `Promise.all`, a single hung
// request would block the whole install indefinitely rather than surfacing an
// error. 30s matches the SDK's DEFAULT_HTTP_TIMEOUT used by authenticated mode,
// keeping the two paths' timeout behavior consistent.
const REQUEST_TIMEOUT_MS = 30_000

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
            // Bound the request: when the deadline fires, fetch rejects with a
            // TimeoutError that propagates through the fail-fast Promise.all and
            // surfaces as a scan error — never a silent hang.
            signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
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
