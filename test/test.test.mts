import { describe, expect, test } from 'bun:test'
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { safeDelete } from '@socketsecurity/lib-stable/fs/safe'
import { collectScannerTests, scannerTestArgs } from '../scripts/repo/test.mts'

test('test discovery includes repository tests without executing fixture or fleet test files', async () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'scanner-test-discovery-'))
  try {
    for (const name of [
      'test/index.test.mts',
      'test/modes/free.test.mts',
      'test/repo/unit/build.test.mts',
      'test/fleet/shared.test.mts',
      'test/fixtures/input.test.mts',
    ]) {
      const file = path.join(root, name)
      mkdirSync(path.dirname(file), { recursive: true })
      writeFileSync(file, '')
    }
    expect(collectScannerTests(root)).toEqual([
      path.join('test', 'index.test.mts'),
      path.join('test', 'modes', 'free.test.mts'),
      path.join('test', 'repo', 'unit', 'build.test.mts'),
    ])
  } finally {
    await safeDelete(root)
  }
})

describe('scanner test scope', () => {
  const files = [
    'test/index.test.mts',
    'test/scanner-factory-properties.fuzz.test.mts',
    'test/modes/authenticated.test.mts',
  ]
  test('ordinary and --all requests include unit tests without starting fuzz', () => {
    const expected = [
      'test',
      'test/index.test.mts',
      'test/modes/authenticated.test.mts',
    ]
    expect(scannerTestArgs([], files)).toEqual(expected)
    expect(scannerTestArgs(['--all'], files)).toEqual(expected)
  })
  test('the fuzz environment selects only the fuzz harness', () => {
    expect(scannerTestArgs(['--all'], files, { fuzz: true })).toEqual([
      'test',
      'test/scanner-factory-properties.fuzz.test.mts',
    ])
  })
  test('Bun option values do not turn a full run into unbounded directory discovery', () => {
    expect(scannerTestArgs(['--timeout', '5000'], files)).toEqual([
      'test',
      '--timeout',
      '5000',
      'test/index.test.mts',
      'test/modes/authenticated.test.mts',
    ])
  })
  test('explicit Bun paths and arguments remain explicit', () => {
    expect(
      scannerTestArgs(['test/index.test.mts', '--timeout=5000'], files),
    ).toEqual(['test', '--timeout=5000', 'test/index.test.mts'])
  })
  test('empty test scopes fail before spawning Bun', () => {
    expect(() => scannerTestArgs([], [])).toThrow()
    expect(() => scannerTestArgs(['--timeout'], files)).toThrow()
    expect(() =>
      scannerTestArgs(['test/index.test.mts'], files, { fuzz: true }),
    ).toThrow()
  })
  test('reporter and concurrency option values remain flags with a bounded explicit file list', () => {
    const flags = [
      '--reporter',
      'junit',
      '--reporter-outfile',
      'results.xml',
      '--max-concurrency',
      '2',
    ]
    expect(scannerTestArgs(flags, files)).toEqual([
      'test',
      ...flags,
      'test/index.test.mts',
      'test/modes/authenticated.test.mts',
    ])
  })
  test('directory filters expand only to discovered repository files', () => {
    expect(scannerTestArgs(['./test/index.test.mts'], files)).toEqual([
      'test',
      'test/index.test.mts',
    ])
    expect(
      scannerTestArgs([path.resolve('test/index.test.mts')], files),
    ).toEqual(['test', 'test/index.test.mts'])
    expect(scannerTestArgs(['test/modes'], files)).toEqual([
      'test',
      'test/modes/authenticated.test.mts',
    ])
    expect(() =>
      scannerTestArgs(['--unknown-option', 'not-a-test-selector'], files),
    ).toThrow()
  })
})
