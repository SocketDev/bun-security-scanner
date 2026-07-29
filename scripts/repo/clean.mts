/**
 * @file Clean runner for build artifacts. Flag-scoped like the reference fleet
 *   clean scripts (socket-packageurl-js / socket-sdk-js): `--dist` removes the
 *   bundled output + tsbuildinfo, `--types` removes only the emitted
 *   declarations. Everything is a fixed path under the repo root, so plain
 *   `rmSync` covers it without dragging del/fast-glob into the repo.
 */

import { globSync } from 'node:fs'
import path from 'node:path'
import process from 'node:process'

import { isQuiet } from '@socketsecurity/lib-stable/argv/flag-predicates'
import { parseArgs } from '@socketsecurity/lib-stable/argv/parse'
import { safeDeleteSync } from '@socketsecurity/lib-stable/fs/safe'
import { getDefaultLogger } from '@socketsecurity/lib-stable/logger/default'

import { REPO_ROOT } from '../fleet/paths.mts'

const logger = getDefaultLogger()

export function cleanDist(): void {
  safeDeleteSync(path.join(REPO_ROOT, 'dist'))
  for (const info of globSync(path.join(REPO_ROOT, '*.tsbuildinfo'))) {
    safeDeleteSync(info)
  }
}

export function cleanTypes(): void {
  for (const dts of globSync(path.join(REPO_ROOT, 'dist/**/*.d.ts'))) {
    safeDeleteSync(dts)
  }
}

async function main(): Promise<void> {
  const { values } = parseArgs({
    allowPositionals: false,
    options: {
      dist: { type: 'boolean', default: false },
      quiet: { type: 'boolean', default: false },
      silent: { type: 'boolean', default: false },
      types: { type: 'boolean', default: false },
    },
    strict: false,
  })

  const quiet = isQuiet(values)

  if (values['dist'] || (!values['dist'] && !values['types'])) {
    cleanDist()
    if (!quiet) {
      logger.done('Cleaned dist')
    }
  } else if (values['types']) {
    cleanTypes()
    if (!quiet) {
      logger.done('Cleaned dist declarations')
    }
  }
}

main().catch((e: unknown) => {
  logger.error(e)
  process.exitCode = 1
})
