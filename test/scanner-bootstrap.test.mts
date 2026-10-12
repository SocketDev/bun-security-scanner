import { Buffer } from 'node:buffer'
import { chmod, mkdir, mkdtemp, symlink, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { afterEach, describe, expect, test } from 'bun:test'
import { safeDelete } from '@socketsecurity/lib-stable/fs/safe'
import {
  advanceScannerTokenResolution,
  createSecurityScanner,
  readScannerSettings,
  resolveScannerToken,
} from '../src/scanner-bootstrap.mts'
import type {
  ScannerTokenConfig,
  ScannerTokenResolutionState,
} from '../src/scanner-bootstrap.mts'

const scratchDirectories: string[] = []

async function createScratchDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'bun-scanner-auth-'))
  scratchDirectories.push(directory)
  return directory
}

function tokenConfig(dataHome: string): ScannerTokenConfig {
  return {
    envToken: undefined,
    platform: process.platform,
    home: dataHome,
    xdgDataHome: dataHome,
    localAppData: dataHome,
  }
}

function settingsContents(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64')
}

async function writeFlatSettings(
  dataHome: string,
  contents: string,
): Promise<string> {
  const socketDirectory = path.join(dataHome, 'socket')
  await mkdir(socketDirectory, { recursive: true })
  const filename = path.join(socketDirectory, 'settings')
  await writeFile(filename, contents)
  return filename
}

async function writeDirectorySettings(
  dataHome: string,
  contents: string,
): Promise<string> {
  const settingsDirectory = path.join(dataHome, 'socket', 'settings')
  await mkdir(settingsDirectory, { recursive: true })
  const filename = path.join(settingsDirectory, 'config.json')
  await writeFile(filename, contents)
  return filename
}

afterEach(async () => {
  for (const directory of scratchDirectories.splice(0)) {
    await safeDelete(directory)
  }
})

describe('scanner credential bootstrap', () => {
  test('a nonblank environment token takes precedence without reading settings', async () => {
    const dataHome = await createScratchDirectory()
    const config = tokenConfig(dataHome)
    config.envToken = ' socket-test-env-token '
    await writeFlatSettings(dataHome, 'not valid settings')
    expect(await resolveScannerToken(config)).toBe(config.envToken)
  })

  test.each([undefined, '', ' ', '\t'])(
    'environment token %j permits a valid settings token',
    async envToken => {
      const dataHome = await createScratchDirectory()
      await writeFlatSettings(
        dataHome,
        settingsContents({ apiToken: 'socket-test-settings-token' }),
      )
      expect(
        await resolveScannerToken({ ...tokenConfig(dataHome), envToken }),
      ).toBe('socket-test-settings-token')
    },
  )

  test('accepts base64 settings without padding', async () => {
    const dataHome = await createScratchDirectory()
    const contents = settingsContents({
      apiToken: 'socket-test-settings-token',
    })
    await writeFlatSettings(dataHome, contents.replace(/=+$/, ''))
    expect(await resolveScannerToken(tokenConfig(dataHome))).toBe(
      'socket-test-settings-token',
    )
  })

  test.each(['flat', 'directory'] as const)(
    'reads the %s Socket CLI settings layout',
    async layout => {
      const dataHome = await createScratchDirectory()
      if (layout === 'flat') {
        await writeFlatSettings(
          dataHome,
          settingsContents({ apiToken: 'socket-test-settings-token' }),
        )
      } else {
        await writeDirectorySettings(
          dataHome,
          settingsContents({ apiToken: 'socket-test-settings-token' }),
        )
      }
      expect(await resolveScannerToken(tokenConfig(dataHome))).toBe(
        'socket-test-settings-token',
      )
    },
  )

  test('missing settings are unconfigured', async () => {
    const dataHome = await createScratchDirectory()
    expect(await resolveScannerToken(tokenConfig(dataHome))).toBeUndefined()
  })

  test('an empty settings directory without config.json is unconfigured', async () => {
    const dataHome = await createScratchDirectory()
    await mkdir(path.join(dataHome, 'socket', 'settings'), { recursive: true })
    expect(await resolveScannerToken(tokenConfig(dataHome))).toBeUndefined()
  })

  test.each([
    {
      platform: 'darwin',
      relativeDataHome: ['Library', 'Application Support'],
      isLocalAppData: false,
    },
    {
      platform: 'linux',
      relativeDataHome: ['.local', 'share'],
      isLocalAppData: false,
    },
    {
      platform: 'win32',
      relativeDataHome: ['socket-data'],
      isLocalAppData: true,
    },
  ] as const)(
    'resolves the platform-specific settings data directory',
    async ({ platform, relativeDataHome, isLocalAppData }) => {
      const home = await createScratchDirectory()
      const dataHome = path.join(home, ...relativeDataHome)
      await writeFlatSettings(
        dataHome,
        settingsContents({ apiToken: 'socket-test-platform-token' }),
      )
      expect(
        await resolveScannerToken({
          ...tokenConfig(home),
          platform,
          xdgDataHome: undefined,
          localAppData: isLocalAppData ? dataHome : undefined,
        }),
      ).toBe('socket-test-platform-token')
    },
  )

  test('missing Windows application data fails explicitly', async () => {
    const dataHome = await createScratchDirectory()
    await expect(
      resolveScannerToken({
        ...tokenConfig(dataHome),
        platform: 'win32',
        localAppData: undefined,
      }),
    ).rejects.toThrow('LOCALAPPDATA')
  })

  test('a valid settings object without apiToken followed by ENOTDIR is unconfigured', async () => {
    const dataHome = await createScratchDirectory()
    await writeFlatSettings(dataHome, settingsContents({ other: true }))
    expect(await resolveScannerToken(tokenConfig(dataHome))).toBeUndefined()
  })

  test.each([{}, { unrelated: 'value' }])(
    'settings without an own apiToken are unconfigured: %j',
    async settings => {
      const dataHome = await createScratchDirectory()
      await writeFlatSettings(dataHome, settingsContents(settings))
      expect(await resolveScannerToken(tokenConfig(dataHome))).toBeUndefined()
    },
  )

  test.each([
    { settings: { apiToken: '' } },
    { settings: { apiToken: '   ' } },
    // oxlint-disable-next-line socket/prefer-undefined-over-null -- Invalid persisted JSON null must reject.
    { settings: { apiToken: null } },
    { settings: { apiToken: 17 } },
    { settings: { apiToken: [] } },
    { settings: { apiToken: {} } },
    { settings: [] },
    // oxlint-disable-next-line socket/prefer-undefined-over-null -- Invalid persisted JSON null must reject.
    { settings: null },
    { settings: 'not an object' },
  ])(
    'rejects invalid configured credentials: $settings',
    async ({ settings }) => {
      const dataHome = await createScratchDirectory()
      await writeFlatSettings(dataHome, settingsContents(settings))
      await expect(resolveScannerToken(tokenConfig(dataHome))).rejects.toThrow(
        'Socket credentials could not be read',
      )
    },
  )

  test.each([
    { contents: '' },
    { contents: '%%% not base64 JSON %%%' },
    { contents: Buffer.from('{').toString('base64') },
    {
      contents: Buffer.concat([
        Buffer.from('{"unrelated":"'),
        Buffer.from([0xff]),
        Buffer.from('"}'),
      ]).toString('base64'),
    },
  ])('rejects malformed settings content: $contents', async ({ contents }) => {
    const dataHome = await createScratchDirectory()
    await writeFlatSettings(dataHome, contents)
    await expect(resolveScannerToken(tokenConfig(dataHome))).rejects.toThrow(
      'Socket credentials could not be read',
    )
  })

  test('flat directory layout proceeds to its nested config without failure', async () => {
    const dataHome = await createScratchDirectory()
    await writeDirectorySettings(
      dataHome,
      settingsContents({ apiToken: 'socket-test-directory-token' }),
    )
    expect(await resolveScannerToken(tokenConfig(dataHome))).toBe(
      'socket-test-directory-token',
    )
  })

  test('a directory where config.json should be is rejected', async () => {
    const dataHome = await createScratchDirectory()
    await mkdir(path.join(dataHome, 'socket', 'settings', 'config.json'), {
      recursive: true,
    })
    await expect(resolveScannerToken(tokenConfig(dataHome))).rejects.toThrow(
      'Socket credentials could not be read',
    )
  })

  test.each([
    { blockerSegments: ['socket'], dataHomeSegments: [] },
    {
      blockerSegments: ['blocked'],
      dataHomeSegments: ['blocked', 'ancestor'],
    },
  ])(
    'a file blocking the settings path rejects: $blockerSegments',
    async ({ blockerSegments, dataHomeSegments }) => {
      const root = await createScratchDirectory()
      const blocker = path.join(root, ...blockerSegments)
      const dataHome = path.join(root, ...dataHomeSegments)
      await mkdir(path.dirname(blocker), { recursive: true })
      await writeFile(blocker, 'not a directory')
      await expect(resolveScannerToken(tokenConfig(dataHome))).rejects.toThrow(
        'Socket credentials could not be read',
      )
    },
  )

  test.skipIf(process.platform === 'win32' || process.getuid?.() === 0)(
    'a permission-denied real settings file rejects without exposing its path or contents',
    async () => {
      const dataHome = await createScratchDirectory()
      const filename = await writeFlatSettings(
        dataHome,
        settingsContents({ apiToken: 'socket-test-permission-token' }),
      )
      await chmod(filename, 0)
      try {
        await expect(readScannerSettings(filename)).rejects.toMatchObject({
          code: 'EACCES',
        })
        let failure: string | undefined
        try {
          await resolveScannerToken(tokenConfig(dataHome))
        } catch (error) {
          failure = String(error)
        }
        expect(failure).toContain('Socket credentials could not be read')
        expect(failure).not.toContain(dataHome)
        expect(failure).not.toContain('socket-test-permission-token')
      } finally {
        await chmod(filename, 0o600)
      }
    },
  )

  test.skipIf(process.platform === 'win32')(
    'a real ELOOP settings read rejects',
    async () => {
      const dataHome = await createScratchDirectory()
      const socketDirectory = path.join(dataHome, 'socket')
      await mkdir(socketDirectory)
      const settingsPath = path.join(socketDirectory, 'settings')
      await symlink(settingsPath, settingsPath)
      await expect(readScannerSettings(settingsPath)).rejects.toMatchObject({
        code: 'ELOOP',
      })
      await expect(resolveScannerToken(tokenConfig(dataHome))).rejects.toThrow(
        'Socket credentials could not be read',
      )
    },
  )

  test('selection state accepts a later valid credential after a source failure', () => {
    const initialState: ScannerTokenResolutionState = {
      hadFailure: false,
      token: undefined,
    }
    const failedState = advanceScannerTokenResolution(initialState, {
      kind: 'invalid',
    })
    const validState = advanceScannerTokenResolution(failedState, {
      kind: 'token',
      token: 'socket-test-later-token',
    })
    expect(validState).toEqual({
      hadFailure: true,
      token: 'socket-test-later-token',
    })
    expect(failedState).toEqual({ hadFailure: true, token: undefined })
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
