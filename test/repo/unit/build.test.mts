/**
 * @file Unit tests for build.mts. The script is only ever run via `node`
 *   (`pnpm run build` shells to `node scripts/repo/build.mts`), and rolldown's
 *   builtin-module detection differs under Bun — so buildSource/buildTypes
 *   are exercised by spawning the real CLI entry with `node`, the same way
 *   production invokes it, rather than importing and calling them in-process
 *   under `bun test`. isBuildNeeded is a pure fs check and is called
 *   directly. buildTypes is verified by parity with a direct tsc invocation
 *   rather than a fixed exit code, since the current source tree carries
 *   pre-existing type errors unrelated to this script.
 */
import { type SpawnSyncReturns, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, writeFileSync } from 'node:fs'
import path from 'node:path'

import { afterAll, describe, expect, test } from 'bun:test'

import { REPO_ROOT } from '../../../scripts/fleet/paths.mts'
import { isBuildNeeded } from '../../../scripts/repo/build.mts'
import { cleanDist, cleanTypes } from '../../../scripts/repo/clean.mts'

const BUILD_SCRIPT = path.join(REPO_ROOT, 'scripts', 'repo', 'build.mts')
const INDEX_JS = path.join(REPO_ROOT, 'dist', 'index.js')
const INDEX_DTS = path.join(REPO_ROOT, 'dist', 'index.d.ts')

afterAll(() => {
  cleanDist()
})

function runBuildScript(args: string[]): SpawnSyncReturns<string> {
  // Never process.execPath: under `bun test` that resolves to the bun binary
  // itself, and rolldown's builtin-module detection misclassifies `bun` as a
  // node builtin when the config module loads under Bun instead of Node.
  return spawnSync('node', [BUILD_SCRIPT, ...args], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
  })
}

function runTscDirectly(): SpawnSyncReturns<string> {
  return spawnSync('pnpm', ['exec', 'tsc', '--project', 'tsconfig.dts.json'], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
  })
}

describe('isBuildNeeded', () => {
  test('is true when the dist artifacts are missing', () => {
    cleanDist()
    expect(isBuildNeeded()).toBe(true)
  })

  test('is false once both the bundle and its declarations exist', () => {
    cleanDist()
    const result = runBuildScript(['--src', '--quiet'])
    expect(result.status).toBe(0)
    // isBuildNeeded only checks existence, so a placeholder declaration file
    // is a real fixture for it — buildTypes' own correctness is covered below.
    mkdirSync(path.dirname(INDEX_DTS), { recursive: true })
    writeFileSync(INDEX_DTS, 'export {}', 'utf8')
    expect(isBuildNeeded()).toBe(false)
  })
})

describe('buildSource (via the real CLI entry)', () => {
  test('bundles the real source into a loadable ESM module', async () => {
    cleanDist()
    const result = runBuildScript(['--src', '--quiet'])

    expect(result.status).toBe(0)
    expect(existsSync(INDEX_JS)).toBe(true)

    const mod = (await import(`${INDEX_JS}?build-test=${Date.now()}`)) as {
      scanner?: unknown
    }
    expect(typeof mod.scanner).toBe('object')
  })
})

describe('buildTypes (via the real CLI entry)', () => {
  test('shells out to the same tsc invocation the project build uses', () => {
    cleanTypes()
    const direct = runTscDirectly()

    cleanTypes()
    const viaScript = runBuildScript(['--types', '--quiet'])

    expect(viaScript.status).toBe(direct.status)
  })
})
