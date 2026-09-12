import nock from 'nock'
import { fileURLToPath } from 'node:url'

import { isolateHomeEnv } from '../../fleet/_shared/lib/isolate-home-env.mts'

export const SCANNER_NETWORK_PRELOAD = fileURLToPath(import.meta.url)

isolateHomeEnv()
nock.disableNetConnect()
nock.enableNetConnect(/^(?:127\.0\.0\.1|\[::1\])(?::\d+)?$/u)
const preload = `--import=${import.meta.url}`
if (!process.env['NODE_OPTIONS']?.includes(preload)) {
  process.env['NODE_OPTIONS'] = [process.env['NODE_OPTIONS'], preload]
    .filter(Boolean)
    .join(' ')
}
Object.defineProperty(globalThis, Symbol.for('scanner.test-network-guard'), {
  value: true,
})
