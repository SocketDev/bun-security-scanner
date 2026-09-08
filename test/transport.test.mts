// socket-lint: mirror-exempt — verifies both scanner HTTP transports with mocked providers.
import { scannerTransportTests } from './repo/_shared/scanner-transport.mts'

let importCounter = 0
scannerTransportTests({
  name: 'source scanner transport',
  async loadScanner() {
    const { scanner } = await import(
      `../src/index.mts?transport-test=${importCounter++}`
    )
    return scanner
  },
})
