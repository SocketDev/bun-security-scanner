import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import path from 'node:path'
import os from 'node:os'

import { afterEach, beforeEach, describe, expect, test } from 'bun:test'

import { cleanDist, cleanTypes } from '../../../scripts/repo/clean.mts'

let root: string
let DIST_DIR: string
let TSBUILDINFO: string
beforeEach(() => {
  root = mkdtempSync(path.join(os.tmpdir(), 'scanner-clean-test-'))
  DIST_DIR = path.join(root, 'dist')
  TSBUILDINFO = path.join(root, 'clean-test.tsbuildinfo')
})
afterEach(() => rmSync(root, { force: true, recursive: true }))

describe('cleanDist', () => {
  test('removes the dist directory and root tsbuildinfo files', () => {
    mkdirSync(path.join(DIST_DIR, 'nested'), { recursive: true })
    writeFileSync(path.join(DIST_DIR, 'index.js'), '', 'utf8')
    writeFileSync(TSBUILDINFO, '{}', 'utf8')

    cleanDist({ root })

    expect(existsSync(DIST_DIR)).toBe(false)
    expect(existsSync(TSBUILDINFO)).toBe(false)
  })

  test('is a no-op when nothing exists', () => {
    expect(() => cleanDist({ root })).not.toThrow()
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

    writeFileSync(path.join(DIST_DIR, 'module.d.mts'), 'export {}')
    writeFileSync(path.join(DIST_DIR, 'module.d.cts'), 'export {}')
    cleanTypes({ root })
    expect(existsSync(path.join(DIST_DIR, 'module.d.mts'))).toBe(false)
    expect(existsSync(path.join(DIST_DIR, 'module.d.cts'))).toBe(false)

    expect(existsSync(path.join(DIST_DIR, 'index.d.ts'))).toBe(false)
    expect(existsSync(path.join(DIST_DIR, 'nested', 'index.d.ts'))).toBe(false)
    expect(existsSync(path.join(DIST_DIR, 'index.js'))).toBe(true)
  })
})
