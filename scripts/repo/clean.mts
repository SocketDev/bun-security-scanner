/**
 * @file Clean runner for build artifacts. Flag-scoped like the reference fleet
 *   clean scripts (socket-packageurl-js / socket-sdk-js): `--dist` removes the
 *   bundled output + tsbuildinfo, `--types` removes only the emitted
 *   declarations. Deletion uses the fleet root-refusal guard within the chosen
 *   root.
 */

import { globSync } from 'node:fs'

import { isMainModule } from '../fleet/process/is-main-module.mts'
import { runMain } from '../fleet/process/run-main.mts'
import path from 'node:path'

import { parseArgs } from 'node:util'
import { strictDeleteSync } from '../fleet/fs/strict.mts'
import { getDefaultLogger } from '@socketsecurity/lib-stable/logger/default'

import { REPO_ROOT } from '../fleet/paths.mts'

import type { ScriptMeta } from '../fleet/process/run-main.mts'

const logger = getDefaultLogger()

export function cleanDist(
  options?: { root?: string | undefined } | undefined,
): void {
  const opts = { __proto__: null, ...options } as NonNullable<typeof options>
  const root = opts.root ?? REPO_ROOT
  strictDeleteSync(path.join(root, 'dist'), { base: root })
  for (const info of globSync(path.join(root, '*.tsbuildinfo'))) {
    strictDeleteSync(info, { base: root })
  }
}

export function cleanTypes(
  options?: { root?: string | undefined } | undefined,
): void {
  const opts = { __proto__: null, ...options } as NonNullable<typeof options>
  const root = opts.root ?? REPO_ROOT
  for (const dts of globSync(path.join(root, 'dist/**/*.d.{ts,mts,cts}'))) {
    strictDeleteSync(dts, { base: root })
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

const SCRIPT_META: ScriptMeta = {
  describe:
    'remove build output: --dist clears dist/ + *.tsbuildinfo, --types clears only the emitted declarations',
  help: `Usage: node scripts/repo/clean.mts [--dist] [--types] [--quiet]

  --dist   Remove dist/ and *.tsbuildinfo (default when no flag is given)
  --types  Remove only dist/**/*.d.ts
  --quiet  Suppress the summary message`,
}

if (isMainModule(import.meta.url)) {
  runMain(main, SCRIPT_META)
}
