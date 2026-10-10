import { Buffer } from 'node:buffer'
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { afterEach, describe, expect, test } from 'vitest'
import { safeDelete } from '@socketsecurity/lib-stable/fs/safe'
import {
  parseScannerCredential,
  readScannerCredential,
  resolveScannerCredential,
  selectScannerCredential,
} from '../../../../src/scanner/credentials.mts'

const temporaryDirectories: string[] = []

afterEach(async () => {
  await Promise.allSettled(
    temporaryDirectories.splice(0).map(directory => safeDelete(directory)),
  )
})

function encoded(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64')
}

describe('scanner credential parsing', () => {
  test.each([
    ['object without token', {}, { kind: 'absent' }],
    ['empty token', { apiToken: '' }, { kind: 'invalid' }],
    ['blank token', { apiToken: '  ' }, { kind: 'invalid' }],
    ['wrong token type', { apiToken: 17 }, { kind: 'invalid' }],
    [
      'valid token',
      { apiToken: 'saved-token' },
      { kind: 'token', token: 'saved-token' },
    ],
  ] as const)('%s', (_label, value, expected) => {
    expect(parseScannerCredential(encoded(value))).toEqual(expected)
  })

  test.each(['', 'broken', encoded(null), encoded([]), encoded('text')])(
    'rejects malformed or non-object content %j',
    raw => {
      expect(parseScannerCredential(raw)).toEqual({ kind: 'invalid' })
    },
  )

  test('selects a later token after an earlier failure', () => {
    expect(
      selectScannerCredential([
        { kind: 'read-failure' },
        { kind: 'absent' },
        { kind: 'token', token: 'later-token' },
      ]),
    ).toEqual({ kind: 'token', token: 'later-token' })
  })

  test('reports configured failure after only failures and absent candidates', () => {
    expect(() =>
      selectScannerCredential([
        { kind: 'invalid' },
        { kind: 'absent' },
        { kind: 'read-failure' },
      ]),
    ).toThrow('remove the invalid saved settings file')
  })
})

describe('scanner credential filesystem reader', () => {
  test('reads a valid settings file', async () => {
    const directory = await mkdtemp(
      path.join(os.tmpdir(), 'scanner-credential-'),
    )
    temporaryDirectories.push(directory)
    const filename = path.join(directory, 'settings')
    await writeFile(filename, encoded({ apiToken: 'file-token' }))
    expect(await readScannerCredential(filename)).toEqual({
      kind: 'token',
      token: 'file-token',
    })
  })

  test('treats a flat settings directory as the nested layout', async () => {
    const directory = await mkdtemp(
      path.join(os.tmpdir(), 'scanner-credential-'),
    )
    temporaryDirectories.push(directory)
    const filename = path.join(directory, 'settings')
    await mkdir(filename)
    expect(await readScannerCredential(filename, true)).toEqual({
      kind: 'absent',
    })
    expect(
      await readScannerCredential(path.join(filename, 'config.json')),
    ).toEqual({ kind: 'absent' })
  })

  test('rejects a directory at the nested settings file path', async () => {
    const directory = await mkdtemp(
      path.join(os.tmpdir(), 'scanner-credential-'),
    )
    temporaryDirectories.push(directory)
    const filename = path.join(directory, 'socket', 'settings')
    await mkdir(path.join(filename, 'config.json'), { recursive: true })
    await expect(
      resolveScannerCredential(undefined, {
        platform: 'linux',
        home: directory,
        xdgDataHome: directory,
      }),
    ).rejects.toThrow('configured credentials are invalid or unreadable')
  })

  test('valid environment token wins over invalid saved settings', async () => {
    const directory = await mkdtemp(
      path.join(os.tmpdir(), 'scanner-credential-'),
    )
    temporaryDirectories.push(directory)
    const filename = path.join(directory, 'socket', 'settings')
    await mkdir(path.dirname(filename), { recursive: true })
    await writeFile(filename, 'malformed')
    expect(
      await resolveScannerCredential('environment-token', {
        platform: 'linux',
        home: directory,
        xdgDataHome: directory,
      }),
    ).toEqual({ kind: 'token', token: 'environment-token' })
  })

  test('resolves tokens from flat and nested settings layouts', async () => {
    const flatHome = await mkdtemp(
      path.join(os.tmpdir(), 'scanner-credential-'),
    )
    const nestedHome = await mkdtemp(
      path.join(os.tmpdir(), 'scanner-credential-'),
    )
    temporaryDirectories.push(flatHome, nestedHome)
    const flatFile = path.join(flatHome, 'socket', 'settings')
    await mkdir(path.dirname(flatFile), { recursive: true })
    await writeFile(flatFile, encoded({ apiToken: 'flat-token' }))
    const nestedDirectory = path.join(nestedHome, 'socket', 'settings')
    await mkdir(nestedDirectory, { recursive: true })
    await writeFile(
      path.join(nestedDirectory, 'config.json'),
      encoded({ apiToken: 'nested-token' }),
    )
    expect(
      await resolveScannerCredential(undefined, {
        platform: 'linux',
        home: flatHome,
        xdgDataHome: flatHome,
      }),
    ).toEqual({
      kind: 'token',
      token: 'flat-token',
    })
    expect(
      await resolveScannerCredential(undefined, {
        platform: 'linux',
        home: nestedHome,
        xdgDataHome: nestedHome,
      }),
    ).toEqual({
      kind: 'token',
      token: 'nested-token',
    })
  })

  test('resolves absent for a no-token flat settings file', async () => {
    const directory = await mkdtemp(
      path.join(os.tmpdir(), 'scanner-credential-'),
    )
    temporaryDirectories.push(directory)
    const filename = path.join(directory, 'socket', 'settings')
    await mkdir(path.dirname(filename), { recursive: true })
    await writeFile(filename, encoded({ theme: 'dark' }))
    expect(
      await resolveScannerCredential(undefined, {
        platform: 'linux',
        home: directory,
        xdgDataHome: directory,
      }),
    ).toEqual({
      kind: 'absent',
    })
  })

  test('rejects malformed saved settings without falling back to free mode', async () => {
    const directory = await mkdtemp(
      path.join(os.tmpdir(), 'scanner-credential-'),
    )
    temporaryDirectories.push(directory)
    const filename = path.join(directory, 'socket', 'settings')
    await mkdir(path.dirname(filename), { recursive: true })
    await writeFile(filename, 'malformed')
    await expect(
      resolveScannerCredential(undefined, {
        platform: 'linux',
        home: directory,
        xdgDataHome: directory,
      }),
    ).rejects.toThrow('configured credentials are invalid or unreadable')
  })

  test('returns absent for valid settings without an API token', async () => {
    const directory = await mkdtemp(
      path.join(os.tmpdir(), 'scanner-credential-'),
    )
    temporaryDirectories.push(directory)
    const filename = path.join(directory, 'settings')
    await writeFile(filename, encoded({ theme: 'dark' }))
    expect(await readScannerCredential(filename)).toEqual({ kind: 'absent' })
  })

  test('treats missing nested settings as absent', async () => {
    const directory = await mkdtemp(
      path.join(os.tmpdir(), 'scanner-credential-'),
    )
    temporaryDirectories.push(directory)
    expect(
      await readScannerCredential(
        path.join(directory, 'settings', 'config.json'),
      ),
    ).toEqual({ kind: 'absent' })
  })

  test('sanitizes read failures during credential selection', () => {
    const outcome = { kind: 'read-failure' } as const
    expect(() => selectScannerCredential([outcome])).toThrow(
      'configured credentials are invalid or unreadable',
    )
    try {
      selectScannerCredential([outcome])
    } catch (error) {
      expect(String(error)).not.toContain('unreadable-secret-settings')
    }
  })
})
