import { describe, expect, test } from 'bun:test'
import {
  globSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
} from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { safeDelete } from '@socketsecurity/lib-stable/fs/safe'
import { normalizePath } from '@socketsecurity/lib-stable/paths/normalize'
import { collectScannerTests, scannerTestArgs } from '../scripts/repo/test.mts'
import { repoNodeTestExcludeGlobs } from '../.config/repo/vitest.settings.mts'
import { aggregateExitCode, buildTestPlan } from '../scripts/repo/test-all.mts'

test('test discovery follows exact ownership and excludes fixture and fleet tests', async () => {
  const ownership = repoNodeTestExcludeGlobs()
  const root = mkdtempSync(path.join(os.tmpdir(), 'scanner-test-discovery-'))
  try {
    for (const name of [
      'test/index.test.mts',
      'test/modes/free.test.mts',
      'test/repo/unit/build.test.mts',
      'test/repo/unit/glyph.test.mts',
      'test/fleet/shared.test.mts',
      'test/fixtures/input.test.mts',
      'test/repo/_shared/shared.test.mts',
      'test/repo/unit/unrelated.test.mts',
    ]) {
      const file = path.join(root, name)
      mkdirSync(path.dirname(file), { recursive: true })
      writeFileSync(file, '')
    }
    const expectedFiles = [
      'test/index.test.mts',
      'test/modes/free.test.mts',
      'test/repo/unit/build.test.mts',
    ]
    expect(collectScannerTests(root)).toEqual(expectedFiles)
    expect(collectScannerTests(root, {})).toEqual(expectedFiles)
    expect(collectScannerTests(root, { ownershipGlobs: ownership })).toEqual(
      expectedFiles,
    )
    expect(() => collectScannerTests(root, { ownershipGlobs: [] })).toThrow(
      /ownership/u,
    )
    expect(() =>
      collectScannerTests(root, {
        ownershipGlobs: ['test/missing.test.mts'],
      }),
    ).toThrow(/matched no/u)
  } finally {
    await safeDelete(root)
  }
})

test('Bun ownership excludes every bun:test repository suite from Vitest', () => {
  const ownership = repoNodeTestExcludeGlobs()
  const scannerTests = collectScannerTests(path.resolve('.'), {
    ownershipGlobs: ownership,
  })
  const bunFiles = scannerTests.filter(file =>
    /from\s+['"]bun:test['"]/u.test(readFileSync(file, 'utf8')),
  )
  const repoTestFiles = globSync('test/**/*.test.mts').map(normalizePath)
  const discoveredBunFiles = repoTestFiles
    .filter(file => /from\s+['"]bun:test['"]/u.test(readFileSync(file, 'utf8')))
    .toSorted()
  expect(bunFiles.toSorted()).toEqual(discoveredBunFiles)
  expect(
    discoveredBunFiles.every(file =>
      ownership.some(glob => path.matchesGlob(file, glob)),
    ),
  ).toBe(true)
  expect(scannerTests).not.toContain('test/repo/unit/glyph.test.mts')
})

describe('aggregate test plan', () => {
  const files = [
    'test/repo/unit/build.test.mts',
    'test/repo/unit/prepare.test.mts',
  ]
  const ownership = files
  const vitestFiles = ['test/repo/unit/glyph.test.mts']
  test('default and CI run both owners with their owned flags', () => {
    expect(buildTestPlan([], files, vitestFiles, ownership)).toEqual([
      { args: [], entry: 'scripts/fleet/test.mts' },
      { args: [], entry: 'scripts/repo/test.mts' },
    ])
    expect(buildTestPlan(['--ci'], files, vitestFiles, ownership)).toEqual([
      { args: ['--ci'], entry: 'scripts/fleet/test.mts' },
      { args: ['--all'], entry: 'scripts/repo/test.mts' },
    ])
    expect(buildTestPlan(['--all'], files, vitestFiles, ownership)).toEqual([
      { args: ['--all'], entry: 'scripts/fleet/test.mts' },
      { args: ['--all'], entry: 'scripts/repo/test.mts' },
    ])
  })
  test('staged runs fleet staged tests and the owned Bun suite', () => {
    expect(buildTestPlan(['--staged'], files, vitestFiles, ownership)).toEqual([
      { args: ['--staged'], entry: 'scripts/fleet/test.mts' },
      { args: ['--all'], entry: 'scripts/repo/test.mts' },
    ])
    for (const argv of [
      ['--staged', '--ci'],
      ['--staged', '--all'],
      ['--staged', '--staged'],
      ['--staged', 'test/repo/unit/build.test.mts'],
      ['--staged', '--timeout', '5000'],
    ]) {
      expect(() => buildTestPlan(argv, files, vitestFiles, ownership)).toThrow()
    }
  })
  test('explicit Bun and glyph selectors route to their actual owners', () => {
    expect(
      buildTestPlan(
        ['test\\repo\\unit\\build.test.mts'],
        files,
        vitestFiles,
        ownership,
      ),
    ).toEqual([
      {
        args: ['test/repo/unit/build.test.mts'],
        entry: 'scripts/repo/test.mts',
      },
    ])
    expect(
      buildTestPlan(['test/repo/unit'], files, vitestFiles, ownership),
    ).toEqual([
      {
        args: ['test/repo/unit/glyph.test.mts'],
        entry: 'scripts/fleet/test.mts',
      },
      {
        args: [
          'test/repo/unit/build.test.mts',
          'test/repo/unit/prepare.test.mts',
        ],
        entry: 'scripts/repo/test.mts',
      },
    ])
    expect(
      buildTestPlan(
        ['--timeout', '5000', 'test/repo/unit/build.test.mts'],
        files,
        vitestFiles,
        ownership,
      ),
    ).toEqual([
      {
        args: ['--timeout', '5000', 'test/repo/unit/build.test.mts'],
        entry: 'scripts/repo/test.mts',
      },
    ])
    expect(
      buildTestPlan(
        ['--timeout', '5000', 'test/repo/unit'],
        files,
        vitestFiles,
        ownership,
      ),
    ).toEqual([
      {
        args: ['test/repo/unit/glyph.test.mts'],
        entry: 'scripts/fleet/test.mts',
      },
      {
        args: [
          '--timeout',
          '5000',
          'test/repo/unit/build.test.mts',
          'test/repo/unit/prepare.test.mts',
        ],
        entry: 'scripts/repo/test.mts',
      },
    ])
    expect(
      buildTestPlan(
        ['test/repo/unit/glyph.test.mts'],
        files,
        vitestFiles,
        ownership,
      ),
    ).toEqual([
      {
        args: ['test/repo/unit/glyph.test.mts'],
        entry: 'scripts/fleet/test.mts',
      },
    ])
    expect(
      buildTestPlan(
        ['test/repo/unit/build.test.mts', 'test/repo/unit/glyph.test.mts'],
        files,
        vitestFiles,
        ownership,
      ),
    ).toEqual([
      {
        args: ['test/repo/unit/glyph.test.mts'],
        entry: 'scripts/fleet/test.mts',
      },
      {
        args: ['test/repo/unit/build.test.mts'],
        entry: 'scripts/repo/test.mts',
      },
    ])
  })
  test('unsupported, empty and ownerless requests fail clearly', () => {
    expect(() =>
      buildTestPlan(['--watch'], files, vitestFiles, ownership),
    ).toThrow(/Unsupported/u)
    expect(() =>
      buildTestPlan(['missing'], files, vitestFiles, ownership),
    ).toThrow(/No test owner/u)
    expect(() =>
      buildTestPlan(
        ['--ci', 'test/repo/unit/build.test.mts'],
        files,
        vitestFiles,
        ownership,
      ),
    ).toThrow()
    expect(() => buildTestPlan([], files, vitestFiles, [])).toThrow(
      /ownership/u,
    )
  })
  test('either runner failure keeps the aggregate nonzero', () => {
    expect(aggregateExitCode([1, 0])).toBe(1)
    expect(aggregateExitCode([0, 2])).toBe(2)
    expect(aggregateExitCode([0, 0])).toBe(0)
  })
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
