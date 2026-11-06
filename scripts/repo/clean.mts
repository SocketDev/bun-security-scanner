/**
 * @file Clean runner for build artifacts. `--dist` removes the bundled output
 *   and tsbuildinfo; `--types` removes only the emitted declarations. Deletion
 *   is restricted to the chosen root.
 */

import { globSync } from 'node:fs'

import path from 'node:path'

import { parseArgs } from 'node:util'
import { safeDeleteSync } from '@socketsecurity/lib-stable/fs/safe'
import {
  getScriptArgs,
  getScriptLogger,
  isMainModule,
  REPO_ROOT,
  runMain,
} from './runtime.mts'

const logger = getScriptLogger()

export function cleanDist(
  options?: { root?: string | undefined } | undefined,
): void {
  const opts = { __proto__: null, ...options } as NonNullable<typeof options>
  const root = opts.root ?? REPO_ROOT
  safeDeleteSync(path.join(root, 'dist'), { allowedDirs: [root] })
  for (const info of globSync(path.join(root, '*.tsbuildinfo'))) {
    safeDeleteSync(info, { allowedDirs: [root] })
  }
}

export function cleanTypes(
  options?: { root?: string | undefined } | undefined,
): void {
  const opts = { __proto__: null, ...options } as NonNullable<typeof options>
  const root = opts.root ?? REPO_ROOT
  for (const dts of globSync(path.join(root, 'dist/**/*.d.{ts,mts,cts}'))) {
    safeDeleteSync(dts, { allowedDirs: [root] })
  }
}

async function main(): Promise<void> {
  const { values } = parseArgs({
    args: getScriptArgs(),
    allowPositionals: false,
    options: {
      dist: { type: 'boolean', default: false },
      quiet: { type: 'boolean', default: false },
      silent: { type: 'boolean', default: false },
      types: { type: 'boolean', default: false },
    },
    strict: false,
  })

  const quiet = values['quiet'] === true || values['silent'] === true

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

if (isMainModule(import.meta.url)) {
  runMain(main)
}
