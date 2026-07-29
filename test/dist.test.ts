// socket-lint: mirror-exempt — smoke-tests the BUILT dist bundle end-to-end
// (token-gated + self-skipping when dist/ is absent), guarding the rolldown
// lib-stub reachability: a stubbed module that IS reached at runtime crashes
// here, not at bundle time. Not a mirror of one source file.
import { existsSync } from 'node:fs'
import path from 'node:path'
import { afterEach, describe, expect, test } from 'bun:test'

import { readSocketApiTokenSync } from '@socketsecurity/lib-stable/secrets/socket-api-token'

const distEntry = path.join(import.meta.dir, '..', 'dist', 'index.js')
// Self-skip when dist/ hasn't been built (a lint/test CI lane that never runs
// the build step) — never a false block on an unbuilt tree.
const HAS_DIST = existsSync(distEntry)

const packages: Bun.Security.Package[] = [
  {
    name: 'lodahs',
    version: '0.0.1-security',
    requestedRange: '^0.0.0',
    tarball: 'https://registry.npmjs.org/lodahs/-/lodahs-0.0.1-security.tgz',
  },
]

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

// The bundle resolves its token at module init, so each mode test needs a
// fresh import after arranging the env (query-busting defeats the module
// cache, same pattern as live.test.ts).
let importCounter = 0
async function freshDistScanner(): Promise<Bun.Security.Scanner> {
  const { scanner } = await import(`${distEntry}?dist-test=${importCounter++}`)
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the built bundle carries no inline types; its declared shape lives in dist/index.d.ts.
  return scanner as Bun.Security.Scanner
}

const API_TOKEN = readSocketApiTokenSync({ allowEnvOnly: true })

const EXPECTED_ADVISORY = {
  description: expect.any(String),
  level: 'fatal',
  package: 'pkg:npm/lodahs@0.0.1-security',
  url: 'https://socket.dev/npm/package/lodahs/overview/0.0.1-security',
}

describe('dist bundle', () => {
  afterEach(() => {
    restoreTokenAliases()
  })

  test.skipIf(!HAS_DIST || !API_TOKEN)('authenticated mode', async () => {
    clearTokenAliases()
    // socket-api-token-getter: allow direct-env -- arranging the env under test, not reading a token.
    process.env['SOCKET_API_TOKEN'] = API_TOKEN!

    const scanner = await freshDistScanner()
    const advisories = await scanner.scan({ packages: [...packages] })

    expect(advisories.length).toBeGreaterThan(0)
    expect(advisories[0]!).toMatchObject(EXPECTED_ADVISORY)
  })

  test.skipIf(!HAS_DIST)('unauthenticated (free) mode', async () => {
    clearTokenAliases()

    const scanner = await freshDistScanner()
    const advisories = await scanner.scan({ packages: [...packages] })

    expect(advisories.length).toBeGreaterThan(0)
    expect(advisories[0]!).toMatchObject(EXPECTED_ADVISORY)
  })
})
