import { Buffer } from 'node:buffer'
import path from 'node:path'
import { describe, expect, mock, test } from 'bun:test'
import {
  createSecurityScanner,
  resolveScannerToken,
} from '../src/scanner-bootstrap.mts'
import type { ScannerTokenConfig } from '../src/scanner-bootstrap.mts'

function tokenConfig(): ScannerTokenConfig {
  return {
    envToken: undefined,
    platform: 'linux',
    home: '/fixture/home',
    xdgDataHome: '/fixture/data',
    localAppData: undefined,
    readSettings: mock(async () => undefined),
    warn: mock(() => undefined),
  }
}

function encodeSettings(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64')
}

describe('scanner credential bootstrap', () => {
  test('an explicit environment token takes precedence without reading settings', async () => {
    const config = tokenConfig()
    config.envToken = 'socket-test-env-token'
    config.platform = 'win32'
    expect(await resolveScannerToken(config)).toBe('socket-test-env-token')
    expect(config.readSettings).not.toHaveBeenCalled()
  })

  test.each(['flat', 'directory'])(
    'reads the %s Socket CLI settings layout',
    async layout => {
      const config = tokenConfig()
      const root = path.join('/fixture/data', 'socket', 'settings')
      const target = layout === 'flat' ? root : path.join(root, 'config.json')
      config.readSettings = mock(async filename =>
        filename === target
          ? encodeSettings({ apiToken: 'socket-test-settings-token' })
          : undefined,
      )
      expect(await resolveScannerToken(config)).toBe(
        'socket-test-settings-token',
      )
      expect(config.readSettings).toHaveBeenLastCalledWith(target)
      expect(config.warn).not.toHaveBeenCalled()
    },
  )

  test.each([
    [
      'darwin',
      undefined,
      undefined,
      path.join('/fixture/home', 'Library', 'Application Support'),
    ],
    ['linux', undefined, undefined, '/fixture/home/.local/share'],
    ['win32', '/ignored/xdg', '/fixture/local', '/fixture/local'],
  ] as const)(
    'resolves the %s platform data directory',
    async (platform, xdgDataHome, localAppData, dataHome) => {
      const config = { ...tokenConfig(), platform, xdgDataHome, localAppData }
      expect(await resolveScannerToken(config)).toBeUndefined()
      expect(config.readSettings).toHaveBeenCalledWith(
        path.join(dataHome, 'socket', 'settings'),
      )
    },
  )

  test('missing Windows application data fails explicitly', async () => {
    await expect(
      resolveScannerToken({ ...tokenConfig(), platform: 'win32' }),
    ).rejects.toThrow('LOCALAPPDATA')
  })

  test.each(
    [
      {},
      { apiToken: 42 },
      { apiToken: '' },
      { apiToken: '  ' },
      [],
      'invalid-shape',
    ].map(value => [value] as const),
  )('ignores malformed token shape %j and continues', async value => {
    const config = tokenConfig()
    let count = 0
    config.readSettings = mock(async () =>
      ++count === 1 ? encodeSettings(value) : undefined,
    )
    expect(await resolveScannerToken(config)).toBeUndefined()
    expect(config.warn).toHaveBeenCalledTimes(1)
  })

  test('invalid encoding and read errors never reveal sensitive parser messages', async () => {
    const config = tokenConfig()
    const warnings: string[] = []
    config.warn = message => {
      warnings.push(message)
    }
    let count = 0
    config.readSettings = mock(async () => {
      if (++count === 1) {
        return Buffer.from('secret-test-content{').toString('base64')
      }
      throw new Error('secret-test-read-error')
    })
    expect(await resolveScannerToken(config)).toBeUndefined()
    const messages = warnings.join('\n')
    expect(messages).toContain('SOCKET_API_TOKEN')
    expect(messages).not.toContain('secret-test')
  })

  test('blank environment token and unreadable flat entry can use the directory token', async () => {
    const config = tokenConfig()
    config.envToken = ' '
    let count = 0
    config.readSettings = mock(async () => {
      if (++count === 1) {
        throw new Error('directory')
      }
      return encodeSettings({ apiToken: 'socket-test-directory-token' })
    })
    expect(await resolveScannerToken(config)).toBe(
      'socket-test-directory-token',
    )
  })

  test('scanner composition accumulates batches and preserves fatal advisory mapping', async () => {
    const scanner = createSecurityScanner(async function* (packages) {
      packages.shift()
      yield [
        {
          inputPurl: 'pkg:npm/example-package@1.0.0',
          alerts: [
            {
              action: 'error',
              type: 'malware',
              props: { notes: 'Fixture warning' },
            },
          ],
        },
      ]
    })
    const packageFixture = {
      name: 'example-package',
      version: '1.0.0',
      requestedRange: '1.0.0',
      tarball:
        'https://registry.npmjs.org/example-package/-/example-package-1.0.0.tgz',
    }
    const result = await scanner.scan({
      packages: [packageFixture, packageFixture],
    })
    expect(result).toHaveLength(2)
    expect(result[0]!.level).toBe('fatal')
    expect(result[0]!.description).toContain('Fixture warning')
    expect(await scanner.scan({ packages: [] })).toEqual([])
  })
})
