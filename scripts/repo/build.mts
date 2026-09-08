/**
 * @file Build runner. Wraps rolldown's programmatic API behind the same CLI
 *   surface (--src, --types, --needed) the reference fleet build scripts
 *   (socket-packageurl-js / socket-sdk-js) use: source bundle + TypeScript
 *   declarations both land in dist/.
 */

import { existsSync, mkdtempSync } from 'node:fs'
import os from 'node:os'

import { isMainModule } from '../fleet/process/is-main-module.mts'
import { runMain } from '../fleet/process/run-main.mts'
import path from 'node:path'
import process from 'node:process'

import { rolldown } from 'rolldown'
import { dts } from 'rolldown-plugin-dts'

import { parseArgs } from 'node:util'
import { getDefaultLogger } from '@socketsecurity/lib-stable/logger/default'
import { spawn } from '@socketsecurity/lib-stable/process/spawn/child'
import { safeDeleteSync } from '../fleet/fs/safe.mts'

import { configs as rolldownConfigs } from '../../.config/repo/rolldown.config.mts'
import { cleanDist, cleanTypes } from './clean.mts'
import { REPO_ROOT } from '../fleet/paths.mts'

import type { ScriptMeta } from '../fleet/process/run-main.mts'

const logger = getDefaultLogger()

type BuildOptions = {
  quiet?: boolean | undefined
}

/**
 * Bundle the source with rolldown. Returns a process exit code.
 */
export async function buildSource(options: BuildOptions = {}): Promise<number> {
  const { quiet = false } = options
  if (!quiet) {
    logger.substep('Building source bundle')
  }
  try {
    for (const config of rolldownConfigs) {
      const bundle = await rolldown(config)
      try {
        await bundle.write(config.output)
      } finally {
        await bundle.close()
      }
    }
    return 0
  } catch (e) {
    if (!quiet) {
      logger.error('Source build failed')
      logger.fail(e)
    }
    return 1
  }
}

/**
 * Emit TypeScript declarations next to the bundle in dist/. Returns a process
 * exit code.
 */
export async function buildTypes(
  options?:
    | (BuildOptions & { outputDirectory?: string | undefined })
    | undefined,
): Promise<number> {
  const opts = { __proto__: null, ...options } as NonNullable<typeof options>
  const { quiet = false } = opts
  if (!quiet) {
    logger.substep('Building TypeScript declarations')
  }
  const scratch = mkdtempSync(path.join(os.tmpdir(), 'scanner-declarations-'))
  try {
    const emitted = await spawn(
      process.execPath,
      [
        path.join(REPO_ROOT, 'node_modules', 'typescript', 'bin', 'tsc'),
        '--project',
        path.join(REPO_ROOT, '.config/repo/tsconfig.dts.json'),
        '--outDir',
        scratch,
      ],
      {
        cwd: REPO_ROOT,
        stdio: quiet ? 'ignore' : 'inherit',
        throws: false,
        timeout: 30_000,
      },
    )
    if (emitted.code !== 0) {
      return emitted.code ?? 1
    }
    const bundle = await rolldown({
      cwd: scratch,
      input: path.join(scratch, 'index.d.mts'),
      external: ['bun'],
      plugins: [
        dts({
          cwd: scratch,
          generator: 'oxc',
          dtsInput: true,
          emitDtsOnly: true,
        }),
      ],
    })
    try {
      await bundle.write({
        file: path.join(
          opts.outputDirectory ?? path.join(REPO_ROOT, 'dist'),
          'index.d.mts',
        ),
        format: 'esm',
        plugins: [
          {
            name: 'declaration-location-comments',
            renderChunk(code) {
              // Remove generated region lines containing temporary input paths.
              return code.replace(/^\/\/#(?:end)?region[^\n]*(?:\n|$)/gm, '')
            },
          },
        ],
      })
    } finally {
      await bundle.close()
    }
    return 0
  } catch (error) {
    if (!quiet) {
      logger.error('Type declarations build failed')
      logger.fail(error)
    }
    return 1
  } finally {
    safeDeleteSync(scratch, { allowedDirs: [os.tmpdir()] })
  }
}

/**
 * Check whether the built artifacts already exist (`--needed` fast path).
 */
export function isBuildNeeded(
  options?: { root?: string | undefined } | undefined,
): boolean {
  const opts = { __proto__: null, ...options } as NonNullable<typeof options>
  const root = opts.root ?? REPO_ROOT
  return (
    !existsSync(path.join(root, 'dist', 'index.js')) ||
    !existsSync(path.join(root, 'dist', 'index.d.mts'))
  )
}

async function main(): Promise<void> {
  const { values } = parseArgs({
    allowPositionals: false,
    options: {
      needed: { type: 'boolean', default: false },
      quiet: { type: 'boolean', default: false },
      silent: { type: 'boolean', default: false },
      src: { type: 'boolean', default: false },
      types: { type: 'boolean', default: false },
    },
    strict: false,
  })

  const quiet = values['quiet'] === true || values['silent'] === true

  if (values['needed'] && !isBuildNeeded()) {
    if (!quiet) {
      logger.info('Build artifacts exist, skipping build')
    }
    return
  }

  let exitCode = 0
  if (values['types'] && !values['src']) {
    cleanTypes()
    exitCode = await buildTypes({ quiet })
  } else if (values['src'] && !values['types']) {
    exitCode = await buildSource({ quiet })
  } else {
    cleanDist()
    const { 0: srcExit, 1: typesExit } = await Promise.all([
      buildSource({ quiet }),
      buildTypes({ quiet }),
    ])
    exitCode = srcExit !== 0 ? srcExit : typesExit
  }

  if (exitCode !== 0) {
    process.exitCode = exitCode
  } else if (!quiet) {
    logger.success('Build completed successfully!')
  }
}

const SCRIPT_META: ScriptMeta = {
  describe:
    'bundle the source with rolldown and emit TypeScript declarations into dist/',
  help: `Usage: node scripts/repo/build.mts [--src] [--types] [--needed] [--quiet]

  --src     Build the source bundle only
  --types   Build TypeScript declarations only
  --needed  Skip when dist artifacts already exist
  --quiet   Suppress progress messages`,
}

if (isMainModule(import.meta.url)) {
  runMain(main, SCRIPT_META)
}
