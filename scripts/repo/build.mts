/**
 * @file Build runner. Wraps rolldown's programmatic API behind the same CLI
 *   surface (--src, --types, --needed) the reference fleet build scripts
 *   (socket-packageurl-js / socket-sdk-js) use: source bundle + TypeScript
 *   declarations both land in dist/.
 */

import { existsSync } from 'node:fs'
import path from 'node:path'
import process from 'node:process'

import { rolldown } from 'rolldown'

import { isQuiet } from '@socketsecurity/lib-stable/argv/flag-predicates'
import { parseArgs } from '@socketsecurity/lib-stable/argv/parse'
import { WIN32 } from '@socketsecurity/lib-stable/constants/platform'
import { getDefaultLogger } from '@socketsecurity/lib-stable/logger/default'
import { spawn } from '@socketsecurity/lib-stable/process/spawn/child'

import { configs as rolldownConfigs } from '../../.config/repo/rolldown.config.mts'
import { cleanDist, cleanTypes } from './clean.mts'
import { REPO_ROOT } from '../fleet/paths.mts'

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
      await bundle.write(config.output)
      await bundle.close()
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
export async function buildTypes(options: BuildOptions = {}): Promise<number> {
  const { quiet = false } = options
  if (!quiet) {
    logger.substep('Building TypeScript declarations')
  }
  const result = await spawn(
    'pnpm',
    ['exec', 'tsc', '--project', 'tsconfig.dts.json'],
    { cwd: REPO_ROOT, shell: WIN32, stdio: quiet ? 'ignore' : 'inherit' },
  )
  if (result.code !== 0 && !quiet) {
    logger.error('Type declarations build failed')
  }
  return result.code ?? 1
}

/**
 * Check whether the built artifacts already exist (`--needed` fast path).
 */
export function isBuildNeeded(): boolean {
  return (
    !existsSync(path.join(REPO_ROOT, 'dist', 'index.js')) ||
    !existsSync(path.join(REPO_ROOT, 'dist', 'index.d.ts'))
  )
}

async function main(): Promise<void> {
  const { values } = parseArgs({
    allowPositionals: false,
    options: {
      help: { type: 'boolean', default: false },
      needed: { type: 'boolean', default: false },
      quiet: { type: 'boolean', default: false },
      silent: { type: 'boolean', default: false },
      src: { type: 'boolean', default: false },
      types: { type: 'boolean', default: false },
    },
    strict: false,
  })

  if (values['help']) {
    logger.log('Usage: pnpm build [--src] [--types] [--needed] [--quiet]')
    logger.log('')
    logger.log('  --src     Build the source bundle only')
    logger.log('  --types   Build TypeScript declarations only')
    logger.log('  --needed  Skip when dist artifacts already exist')
    logger.log('  --quiet   Suppress progress messages')
    return
  }

  const quiet = isQuiet(values)

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
    const [srcExit, typesExit] = await Promise.all([
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

main().catch((e: unknown) => {
  logger.error(e)
  process.exitCode = 1
})
