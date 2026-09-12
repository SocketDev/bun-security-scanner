import { expect, test } from 'bun:test'
import { mkdtempSync, readFileSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { safeDeleteSync } from '@socketsecurity/lib-stable/fs/safe'
import { recordFuzzFailure } from '../scripts/repo/fuzz.mts'

test('failed runs retain separate logs and seed settings without claiming a crash input exists', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'scanner-fuzz-evidence-'))
  try {
    const options = { seed: 42, numRuns: 1000 }
    const first = recordFuzzFailure({
      directory: root,
      options,
      code: 1,
      stdout: 'property output',
      stderr: 'property counterexample',
    })
    const second = recordFuzzFailure({
      directory: root,
      options,
      code: 124,
      stdout: '',
      stderr: 'runner deadline',
    })
    expect(first).not.toBe(second)
    expect(readFileSync(path.join(first, 'stdout.log'), 'utf8')).toBe(
      'property output',
    )
    expect(readFileSync(path.join(first, 'stderr.log'), 'utf8')).toBe(
      'property counterexample',
    )
    const result = JSON.parse(
      readFileSync(path.join(second, 'result.json'), 'utf8'),
    )
    expect(result.seed).toBe(42)
    expect(result.numRuns).toBe(1000)
    expect(result.exitCode).toBe(124)
    expect(result.harness).toBe('test/scanner-factory-properties.fuzz.test.mts')
    expect(result.replay).toContain('SCANNER_FUZZ_SEED=42')
  } finally {
    safeDeleteSync(root)
  }
})
