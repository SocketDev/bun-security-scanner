// socket-lint: mirror-exempt — exercises the live Socket API end-to-end (token-gated), a feature suite spanning both scanner modes, not a mirror of one source file
import { afterEach, describe, expect, spyOn, test } from 'bun:test'

import { readSocketApiTokenSync } from '@socketsecurity/lib-stable/secrets/socket-api-token'
import { SocketSdk } from '@socketsecurity/sdk'

const packages: Bun.Security.Package[] = [
  {
    name: 'lodahs',
    version: '0.0.1-security',
    requestedRange: '^0.0.0',
    tarball: 'https://registry.npmjs.org/lodahs/-/lodahs-0.0.1-security.tgz',
  },
]

// The fleet-canonical token alias chain, mirrored from socket-mcp's oauth
// suite: clear every alias before a mode test so a stray local export can't
// mask the path under test, and parametrize the authenticated test over the
// two names the workflows actually export.
// socket-api-token-env: bootstrap -- this array clears/parametrizes the alias-normalization chain.
const SOCKET_API_TOKEN_ALIASES = [
  'SOCKET_API_TOKEN',
  'SOCKET_API_KEY',
  'SOCKET_CLI_API_TOKEN',
  'SOCKET_CLI_API_KEY',
  'SOCKET_SECURITY_API_TOKEN',
  'SOCKET_SECURITY_API_KEY',
] as const

const ORIGINAL_ALIAS_VALUES = new Map<string, string | undefined>(
  SOCKET_API_TOKEN_ALIASES.map(alias => [alias, process.env[alias]]),
)

function clearTokenAliases(): void {
  for (const alias of SOCKET_API_TOKEN_ALIASES) {
    delete process.env[alias]
  }
}

function restoreTokenAliases(): void {
  for (const [alias, value] of ORIGINAL_ALIAS_VALUES) {
    if (value === undefined) {
      delete process.env[alias]
    } else {
      process.env[alias] = value
    }
  }
}

// The scanner resolves its token at module init, so every mode test needs a
// fresh import after arranging the env. Query-busted specifiers defeat the
// module cache; a counter avoids same-millisecond collisions.
let importCounter = 0
async function freshScanner(): Promise<Bun.Security.Scanner> {
  const { scanner } = await import(`../src/index?live-test=${importCounter++}`)
  return scanner
}

// Only run the authenticated tests when a token is available (fleet
// skip-if-unset convention, same as socket-lib's it.skipIf(!BACKEND_OK)
// secret-backed suites). Env-only: the skip check never triggers a keychain
// prompt.
const API_TOKEN = readSocketApiTokenSync({ allowEnvOnly: true })

const EXPECTED_ADVISORY = {
  description: expect.any(String),
  level: 'fatal',
  package: 'pkg:npm/lodahs@0.0.1-security',
  url: 'https://socket.dev/npm/package/lodahs/overview/0.0.1-security',
}

describe('live', () => {
  const fetchSpy = spyOn(global, 'fetch')
  // The SDK's transport is socket-lib httpRequest over node:http — it never
  // touches global fetch — so the authenticated-path evidence is a
  // call-through spy on the SDK method itself (no mockImplementation: the
  // real request still goes out).
  const sdkStreamSpy = spyOn(SocketSdk.prototype, 'batchPackageStream')

  afterEach(() => {
    fetchSpy.mockClear()
    sdkStreamSpy.mockClear()
    restoreTokenAliases()
  })

  // socket-api-token-env: bootstrap -- authenticated mode must work under either exported name.
  for (const alias of ['SOCKET_API_TOKEN', 'SOCKET_API_KEY']) {
    test.skipIf(!API_TOKEN)(`authenticated (${alias})`, async () => {
      clearTokenAliases()
      process.env[alias] = API_TOKEN!

      const scanner = await freshScanner()
      const advisories = await scanner.scan({ packages: [...packages] })

      expect(advisories.length).toBeGreaterThan(0)
      expect(advisories[0]!).toMatchObject(EXPECTED_ADVISORY)

      // Verify the authenticated path went through the Socket SDK
      expect(sdkStreamSpy).toHaveBeenCalled()
      expect(sdkStreamSpy.mock.lastCall?.[0]).toEqual({
        components: [{ purl: 'pkg:npm/lodahs@0.0.1-security' }],
      })
    })
  }

  test('unauthenticated', async () => {
    // Clear the whole alias chain so nothing masks the unauthenticated path.
    clearTokenAliases()

    const scanner = await freshScanner()
    const advisories = await scanner.scan({ packages: [...packages] })

    expect(advisories.length).toBeGreaterThan(0)
    expect(advisories[0]!).toMatchObject(EXPECTED_ADVISORY)

    // Verify the firewall API was called (and the SDK path was not)
    expect(fetchSpy).toHaveBeenCalled()
    expect(fetchSpy.mock.lastCall?.[0]).toMatch('firewall-api.socket.dev')
    expect(sdkStreamSpy).not.toHaveBeenCalled()
  })
})
