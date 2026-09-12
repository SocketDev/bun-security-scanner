// socket-lint: mirror-exempt — verifies built scanner HTTP transports with mocked providers.
import { existsSync } from 'node:fs'
import path from 'node:path'
import { scannerTransportTests } from './repo/_shared/scanner-transport.mts'

const distEntry = path.join(import.meta.dir, '..', 'dist', 'index.js')
let importCounter = 0
scannerTransportTests({
  name: 'dist scanner transport',
  available: existsSync(distEntry),
  async loadScanner() {
    const { scanner } = await import(
      `${distEntry}?transport-test=${importCounter++}`
    )
    return scanner as Bun.Security.Scanner
  },
})
