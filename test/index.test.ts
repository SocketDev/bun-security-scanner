import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import {
  afterAll,
  afterEach,
  beforeEach,
  describe,
  expect,
  spyOn,
  test,
} from 'bun:test'
import type { Mock } from 'bun:test'
import type Bun from 'bun'
import { errorMessage } from '@socketsecurity/lib-stable/errors/message'
import { safeDelete } from '@socketsecurity/lib-stable/fs/safe'
import { SocketSdk } from '@socketsecurity/sdk'
import type { SocketArtifact } from '../src/types'

// Every alias the token bootstrap consults, cleared before each test so a
// stray local export can't flip the module into authenticated mode.
// socket-api-token-env: bootstrap -- this array clears the alias-normalization chain.
const SOCKET_API_TOKEN_ALIASES = [
  'SOCKET_API_TOKEN',
  'SOCKET_API_KEY',
  'SOCKET_CLI_API_TOKEN',
  'SOCKET_CLI_API_KEY',
  'SOCKET_SECURITY_API_TOKEN',
  'SOCKET_SECURITY_API_KEY',
] as const

// The bootstrap also falls back to `<dataHome>/socket/settings`; `dataHome`
// comes from XDG_DATA_HOME (posix) or LOCALAPPDATA (win32). Point both at an
// empty temp dir so the settings-file fallback finds nothing and the module
// deterministically enters free mode — no real developer token can leak in.
const EMPTY_DATA_HOME = mkdtempSync(
  path.join(os.tmpdir(), 'bun-scanner-empty-'),
)
const ENV_KEYS = [
  ...SOCKET_API_TOKEN_ALIASES,
  'XDG_DATA_HOME',
  'LOCALAPPDATA',
] as const
const ORIGINAL_ENV = new Map<string, string | undefined>(
  ENV_KEYS.map(key => [key, process.env[key]]),
)

function arrangeFreeModeEnv(): void {
  for (const alias of SOCKET_API_TOKEN_ALIASES) {
    delete process.env[alias]
  }
  process.env['XDG_DATA_HOME'] = EMPTY_DATA_HOME
  process.env['LOCALAPPDATA'] = EMPTY_DATA_HOME
}

function restoreEnv(): void {
  for (const [key, value] of ORIGINAL_ENV) {
    if (value === undefined) {
      delete process.env[key]
    } else {
      process.env[key] = value
    }
  }
}

// The module resolves its token at init, so each test needs a fresh import
// after arranging the env (query-busting defeats the module cache — the same
// pattern dist.test.ts and live.test.ts use).
//
// Coverage caveat: every query-busted import is a distinct module instance,
// and `bun test --coverage` attributes src/index.ts to ONE representative
// instance rather than the union — so the report can list init-branch lines
// as uncovered even though a test in this file executes and asserts them
// (run this file alone with --coverage and the "missed" set shifts). The
// suite covers every src/index.ts line across instances; treat the per-file
// percentage for this module as a tooling artifact, not a gap.
let importCounter = 0
type ScannerModule = {
  scanner: Bun.Security.Scanner
  parseNpmPurl: (purl: string) => { name: string; version: string } | undefined
}
async function freshScannerModule(): Promise<ScannerModule> {
  return await import(`../src/index?index-test=${importCounter++}`)
}

describe('index (Bun.Security.Scanner conformance)', () => {
  beforeEach(() => {
    arrangeFreeModeEnv()
  })

  afterEach(() => {
    restoreEnv()
  })

  afterAll(async () => {
    await safeDelete(EMPTY_DATA_HOME)
  })

  test('empty-data-home fixture forces the settings-file miss', () => {
    // Guards the free-mode arrangement itself: if a settings file ever existed
    // here the e2e test below would silently hit the authenticated path.
    expect(existsSync(path.join(EMPTY_DATA_HOME, 'socket', 'settings'))).toBe(
      false,
    )
  })

  test('exports a scanner with version "1" and an async scan()', async () => {
    const { scanner } = await freshScannerModule()

    expect(scanner.version).toBe('1')
    expect(typeof scanner.scan).toBe('function')
  })

  test('re-exports parseNpmPurl', async () => {
    const { parseNpmPurl } = await freshScannerModule()

    expect(parseNpmPurl('pkg:npm/lodash@4.17.21')).toEqual({
      name: 'lodash',
      version: '4.17.21',
    })
  })

  describe('scan() end-to-end in free mode', () => {
    let fetchSpy: Mock<typeof fetch>

    beforeEach(() => {
      const mockFetch: typeof fetch = Object.assign(
        () => Promise.resolve(new Response('')),
        { preconnect: () => undefined },
      )
      fetchSpy = spyOn(global, 'fetch').mockImplementation(mockFetch)
    })

    afterEach(() => {
      fetchSpy.mockRestore()
    })

    test('maps a firewall artifact into a fatal advisory', async () => {
      const artifact: SocketArtifact = {
        inputPurl: 'pkg:npm/lodahs@0.0.1-security',
        alerts: [
          {
            action: 'error',
            type: 'malware',
            props: { description: 'Known malicious package' },
          },
        ],
      }
      fetchSpy.mockResolvedValueOnce(new Response(JSON.stringify(artifact)))

      const { scanner } = await freshScannerModule()
      const advisories = await scanner.scan({
        packages: [
          {
            name: 'lodahs',
            version: '0.0.1-security',
            requestedRange: '^0.0.0',
            tarball:
              'https://registry.npmjs.org/lodahs/-/lodahs-0.0.1-security.tgz',
          },
        ],
      })

      expect(advisories).toHaveLength(1)
      expect(advisories[0]).toMatchObject({
        level: 'fatal',
        package: 'pkg:npm/lodahs@0.0.1-security',
        url: 'https://socket.dev/npm/package/lodahs/overview/0.0.1-security',
      })
      expect(advisories[0]!.description).toContain('Known malicious package')
      expect(fetchSpy).toHaveBeenCalledTimes(1)
    })

    test('returns no advisories when the firewall reports no alerts', async () => {
      const { scanner } = await freshScannerModule()
      const advisories = await scanner.scan({
        packages: [
          {
            name: 'lodash',
            version: '4.17.21',
            requestedRange: '^4.0.0',
            tarball: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz',
          },
        ],
      })

      expect(advisories).toEqual([])
    })
  })
})

describe('index settings-file token fallback', () => {
  // A data-home whose `socket/settings` file DOES exist, exercising the
  // base64-decode token fallback the env-alias path skips.
  let dataHome: string

  function writeSettings(contents: string): void {
    const settingsDir = path.join(dataHome, 'socket')
    mkdirSync(settingsDir, { recursive: true })
    writeFileSync(path.join(settingsDir, 'settings'), contents)
  }

  beforeEach(() => {
    dataHome = mkdtempSync(path.join(os.tmpdir(), 'bun-scanner-settings-'))
    for (const alias of SOCKET_API_TOKEN_ALIASES) {
      delete process.env[alias]
    }
    process.env['XDG_DATA_HOME'] = dataHome
    process.env['LOCALAPPDATA'] = dataHome
  })

  afterEach(async () => {
    restoreEnv()
    await safeDelete(dataHome)
  })

  test('reads the base64 apiToken and enters authenticated mode', async () => {
    writeSettings(
      Buffer.from(JSON.stringify({ apiToken: 'settings-token' })).toString(
        'base64',
      ),
    )

    // Prove the authenticated (SDK) path is taken rather than free-mode fetch.
    const streamSpy = spyOn(
      SocketSdk.prototype,
      'batchPackageStream',
    ).mockImplementation(
      // Empty stream — this test only proves the SDK path runs, not what it
      // yields. An empty async generator is assignable to the method type, so
      // no cast is needed.
      async function* () {},
    )
    const fetchSpy = spyOn(global, 'fetch')

    try {
      const { scanner } = await freshScannerModule()
      const advisories = await scanner.scan({
        packages: [
          {
            name: 'lodash',
            version: '4.17.21',
            requestedRange: '^4.0.0',
            tarball: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz',
          },
        ],
      })

      expect(advisories).toEqual([])
      expect(streamSpy).toHaveBeenCalledTimes(1)
      expect(fetchSpy).not.toHaveBeenCalled()
    } finally {
      streamSpy.mockRestore()
      fetchSpy.mockRestore()
    }
  })

  test('throws a clear error when the settings file is unreadable', async () => {
    // Not valid base64-of-JSON → the JSON.parse in the fallback throws.
    writeSettings('%%% not base64 json %%%')

    let thrown: unknown
    try {
      await freshScannerModule()
    } catch (e) {
      thrown = e
    }

    expect(thrown).toBeInstanceOf(Error)
    expect(errorMessage(thrown)).toContain('error reading Socket settings')
  })
})

describe('index platform-specific dataHome fallbacks', () => {
  // The bootstrap's dataHome resolution branches on process.platform; these
  // tests exercise the arms the host platform never takes, by redefining the
  // (configurable) platform getter for the duration of one fresh import.
  const ORIGINAL_PLATFORM = Object.getOwnPropertyDescriptor(
    process,
    'platform',
  )!

  function setPlatform(platform: NodeJS.Platform): void {
    Object.defineProperty(process, 'platform', {
      configurable: true,
      value: platform,
    })
  }

  beforeEach(() => {
    for (const alias of SOCKET_API_TOKEN_ALIASES) {
      delete process.env[alias]
    }
    delete process.env['XDG_DATA_HOME']
    delete process.env['LOCALAPPDATA']
  })

  afterEach(() => {
    Object.defineProperty(process, 'platform', ORIGINAL_PLATFORM)
    restoreEnv()
  })

  test('win32 without %LOCALAPPDATA% fails loud', async () => {
    setPlatform('win32')

    let thrown: unknown
    try {
      await freshScannerModule()
    } catch (e) {
      thrown = e
    }

    expect(thrown).toBeInstanceOf(Error)
    expect(errorMessage(thrown)).toContain('missing %LOCALAPPDATA%')
  })

  test('linux without XDG_DATA_HOME falls back to ~/.local/share', async () => {
    setPlatform('linux')
    // Point homedir at an empty temp dir so the fallback path is exercised
    // deterministically (no real settings file can leak a token in).
    const emptyHome = mkdtempSync(path.join(os.tmpdir(), 'bun-scanner-home-'))
    const homedirSpy = spyOn(os, 'homedir').mockReturnValue(emptyHome)

    try {
      const { scanner } = await freshScannerModule()

      // ~/.local/share/socket/settings does not exist → free mode module,
      // fully initialized.
      expect(scanner.version).toBe('1')
      expect(homedirSpy).toHaveBeenCalled()
    } finally {
      homedirSpy.mockRestore()
      await safeDelete(emptyHome)
    }
  })
})
