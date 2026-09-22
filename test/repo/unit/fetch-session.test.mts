import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { afterEach, beforeEach, describe, expect, test } from 'bun:test'
import {
  ensurePayload,
  payloadPresent,
  planFetch,
  resolveRepoRoot,
} from '../../../scripts/repo/bootstrap/fetch-session.mts'

let root: string
beforeEach(() => {
  root = mkdtempSync(path.join(os.tmpdir(), 'scanner-fetch-session-'))
  writeFileSync(path.join(root, 'package.json'), '{}')
})
afterEach(() => rmSync(root, { recursive: true, force: true }))

describe('thin-member session bootstrap', () => {
  test('a missing fetcher fails open without inventing payload state', () => {
    expect(payloadPresent(root)).toBe(false)
    expect(planFetch(root)).toEqual({ action: 'no-fetcher' })
    expect(ensurePayload(root)).toBe(0)
  })

  test('an existing hook sentinel needs no fetcher', () => {
    const hooks = path.join(root, '.claude', 'hooks', 'fleet')
    mkdirSync(hooks, { recursive: true })
    writeFileSync(path.join(hooks, 'index.cjs'), '')
    expect(payloadPresent(root)).toBe(true)
    expect(planFetch(root)).toEqual({ action: 'present' })
    expect(ensurePayload(root)).toBe(0)
  })

  test.each([
    [0, false],
    [0, true],
    [1, false],
    [1, true],
  ] as const)(
    'executes the local fetcher and remains fail-open for exit %s with payload present %s',
    (exitCode, present) => {
      if (present) {
        const hooks = path.join(root, '.claude', 'hooks', 'fleet')
        mkdirSync(hooks, { recursive: true })
        writeFileSync(path.join(hooks, 'index.cjs'), '')
      }
      const directory = path.join(root, 'scripts', 'repo', 'bootstrap')
      mkdirSync(directory, { recursive: true })
      const fleet = path.join(directory, 'fleet.mjs')
      writeFileSync(
        fleet,
        `import { writeFileSync } from 'node:fs'; writeFileSync('invoked.json', JSON.stringify(process.argv.slice(2))); process.exitCode = ${exitCode};`,
      )
      expect(planFetch(root)).toEqual({ action: 'ensure', fleet })
      expect(ensurePayload(root)).toBe(0)
      expect(
        JSON.parse(readFileSync(path.join(root, 'invoked.json'), 'utf8')),
      ).toEqual(['--quiet', '--cached'])
    },
  )

  test('discovers the nearest package root from a nested directory', () => {
    const nested = path.join(root, 'scripts', 'repo')
    mkdirSync(nested, { recursive: true })
    expect(resolveRepoRoot(nested)).toBe(root)
  })
})
