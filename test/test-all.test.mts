import { describe, expect, test } from 'bun:test'
import { aggregateExitCode, buildTestPlan } from '../scripts/repo/test-all.mts'

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
  test('Bun test-name patterns pass only through to selected Bun tests', () => {
    expect(
      buildTestPlan(
        [
          'test/repo/unit/build.test.mts',
          '--test-name-pattern',
          'credential fallback',
        ],
        files,
        vitestFiles,
        ownership,
      ),
    ).toEqual([
      {
        args: [
          '--test-name-pattern',
          'credential fallback',
          'test/repo/unit/build.test.mts',
        ],
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
