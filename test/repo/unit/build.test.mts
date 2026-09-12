import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { spawnSync } from 'node:child_process'
import { SCANNER_NETWORK_PRELOAD } from '../scripts/network-preload.mts'
import os from 'node:os'
import path from 'node:path'
import process from 'node:process'
import { afterEach, beforeEach, describe, expect, test } from 'bun:test'
import { buildTypes, isBuildNeeded } from '../../../scripts/repo/build.mts'
import { REPO_ROOT } from '../../../scripts/fleet/paths.mts'

let root: string
beforeEach(() => {
  root = mkdtempSync(path.join(os.tmpdir(), 'scanner-build-test-'))
})
afterEach(() => {
  rmSync(root, { force: true, recursive: true })
})

describe('build artifact freshness', () => {
  test('bundles only the public declarations and typechecks a package consumer', async () => {
    const packageRoot = path.join(root, 'node_modules', '@example', 'scanner')
    const outputDirectory = path.join(packageRoot, 'dist')
    expect(await buildTypes({ outputDirectory })).toBe(0)
    expect(readdirSync(outputDirectory)).toEqual(['index.d.mts'])
    const declaration = readFileSync(
      path.join(outputDirectory, 'index.d.mts'),
      'utf8',
    )
    expect(declaration).toContain('parseNpmPurl')
    expect(declaration).toContain('scanner')
    expect(declaration).not.toContain('./advisories.mts')
    expect(declaration).not.toContain('scanner-declarations-')
    const manifest = JSON.parse(
      readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8'),
    )
    writeFileSync(
      path.join(packageRoot, 'package.json'),
      JSON.stringify({
        name: '@example/scanner',
        types: manifest.types,
        exports: manifest.exports,
      }),
    )
    const consumer = path.join(root, 'consumer.mts')
    writeFileSync(
      consumer,
      `import { parseNpmPurl, scanner } from '@example/scanner'
const result: { name: string; version: string } | undefined = parseNpmPurl('pkg:npm/example@1.0.0')
const plugin: Bun.Security.Scanner = scanner
// @ts-expect-error The public parser accepts a purl string.
parseNpmPurl(123)
// @ts-expect-error The Bun scanner has a callable scan property.
const invalidScanner: typeof scanner = { scan: 123 }
void result
void plugin
void invalidScanner
`,
    )
    const result = spawnSync(
      process.execPath,
      [
        '--preload',
        SCANNER_NETWORK_PRELOAD,
        path.join(REPO_ROOT, 'node_modules', 'typescript', 'bin', 'tsc'),
        '--noEmit',
        '--strict',
        '--module',
        'NodeNext',
        '--target',
        'ESNext',
        '--types',
        'bun-types',
        '--typeRoots',
        path.join(REPO_ROOT, 'node_modules'),
        '--skipLibCheck',
        'true',
        consumer,
      ],
      { cwd: root, encoding: 'utf8', timeout: 10_000 },
    )
    expect(result.stderr).toBe('')
    expect(result.stdout).toBe('')
    expect(result.status).toBe(0)
  }, 15_000)
  test('requires both the executable bundle and its actual ESM declaration entry', () => {
    expect(isBuildNeeded({ root })).toBe(true)
    const directory = path.join(root, 'dist')
    mkdirSync(directory)
    writeFileSync(path.join(directory, 'index.js'), 'export {}')
    expect(isBuildNeeded({ root })).toBe(true)
    writeFileSync(path.join(directory, 'index.d.ts'), 'export {}')
    expect(isBuildNeeded({ root })).toBe(true)
    writeFileSync(path.join(directory, 'index.d.mts'), 'export {}')
    expect(isBuildNeeded({ root })).toBe(false)
  })

  test('declarations alone do not count as a built scanner', () => {
    const directory = path.join(root, 'dist')
    mkdirSync(directory)
    writeFileSync(path.join(directory, 'index.d.mts'), 'export {}')
    expect(isBuildNeeded({ root })).toBe(true)
  })
})
