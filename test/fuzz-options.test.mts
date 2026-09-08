import { expect, test } from 'bun:test'
import fc from 'fast-check'
import { scannerFuzzOptions } from '../scripts/repo/fuzz-options.mts'

test('ordinary properties have reproducible defaults and campaign settings override both fields', () => {
  expect(scannerFuzzOptions({})).toEqual({ seed: 20_260_908, numRuns: 100 })
  expect(
    scannerFuzzOptions({
      SCANNER_FUZZ_SEED: '-123',
      SCANNER_FUZZ_RUNS: '1000',
    }),
  ).toEqual({ seed: -123, numRuns: 1000 })
})

test('invalid campaign bounds fail before invoking a property', () => {
  for (const value of ['nope', '2147483648', '-2147483649', '1.5']) {
    expect(() => scannerFuzzOptions({ SCANNER_FUZZ_SEED: value })).toThrow(
      RangeError,
    )
  }
  for (const value of ['0', '-1', '100001', 'NaN', '1.5']) {
    expect(() => scannerFuzzOptions({ SCANNER_FUZZ_RUNS: value })).toThrow(
      RangeError,
    )
  }
})

test('recorded seeds reproduce generated cases and the requested case count', () => {
  const options = scannerFuzzOptions({
    SCANNER_FUZZ_SEED: '42',
    SCANNER_FUZZ_RUNS: '23',
  })
  const first: number[] = []
  const second: number[] = []
  for (const values of [first, second]) {
    fc.assert(
      fc.property(fc.integer(), value => {
        values.push(value)
      }),
      options,
    )
  }
  expect(first).toHaveLength(23)
  expect(second).toEqual(first)
})
