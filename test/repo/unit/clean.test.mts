/**
 * @file Unit tests for clean.mts. Exercises cleanDist/cleanTypes against real
 *   files under the repo's own dist/ — the functions target REPO_ROOT
 *   directly, so there is no fixture root to inject.
 */
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import path from 'node:path'

import { afterEach, describe, expect, test } from 'bun:test'

import { REPO_ROOT } from '../../../scripts/fleet/paths.mts'
import { cleanDist, cleanTypes } from '../../../scripts/repo/clean.mts'

const DIST_DIR = path.join(REPO_ROOT, 'dist')
const TSBUILDINFO = path.join(REPO_ROOT, 'clean-test.tsbuildinfo')

function reset(): void {
  rmSync(DIST_DIR, { force: true, recursive: true })
  rmSync(TSBUILDINFO, { force: true })
}

afterEach(reset)

describe('cleanDist', () => {
  test('removes the dist directory and root tsbuildinfo files', () => {
    mkdirSync(path.join(DIST_DIR, 'nested'), { recursive: true })
    writeFileSync(path.join(DIST_DIR, 'index.js'), '', 'utf8')
    writeFileSync(TSBUILDINFO, '{}', 'utf8')

    cleanDist()

    expect(existsSync(DIST_DIR)).toBe(false)
    expect(existsSync(TSBUILDINFO)).toBe(false)
  })

  test('is a no-op when nothing exists', () => {
    expect(() => cleanDist()).not.toThrow()
  })
})

describe('cleanTypes', () => {
  test('removes only the .d.ts files under dist, leaving other output alone', () => {
    mkdirSync(path.join(DIST_DIR, 'nested'), { recursive: true })
    writeFileSync(path.join(DIST_DIR, 'index.js'), '', 'utf8')
    writeFileSync(path.join(DIST_DIR, 'index.d.ts'), 'export {}', 'utf8')
    writeFileSync(
      path.join(DIST_DIR, 'nested', 'index.d.ts'),
      'export {}',
      'utf8',
    )

    cleanTypes()

    expect(existsSync(path.join(DIST_DIR, 'index.d.ts'))).toBe(false)
    expect(existsSync(path.join(DIST_DIR, 'nested', 'index.d.ts'))).toBe(false)
    expect(existsSync(path.join(DIST_DIR, 'index.js'))).toBe(true)
  })
})
